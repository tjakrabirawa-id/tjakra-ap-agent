// Command tjakra-satria-agent is the customer-installed patrol agent. It enrolls with a
// one-time token from the platform, then ships logs up and runs allowlisted,
// platform-signed commands down. It verifies every command against the platform key
// it pinned at enrollment, and treats destructive actions as a dry-run unless started
// with -enforce. By default it runs only the fixed allowlisted actions and never a
// free-form shell command; the one exception is the admin remote console
// (run_command), which is inert unless the agent is started with -console, so an
// operator explicitly consents to interactive control of this host.
//
// Usage:
//
//	tjakra-satria-agent enroll -server https://satria-api.tjakrabirawa.id -token <token>
//	tjakra-satria-agent run [-log-file /var/log/app.log] [-enforce] [-console] [-block-container NAME] [-poll 5s]
//
// Run on the host for full console reach and pass -block-container to keep blocks
// scoped to a target container's network namespace instead of the host.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type config struct {
	Server            string `json:"server"`
	AgentID           string `json:"agentId"`
	AgentKey          string `json:"agentKey"`
	PlatformPublicKey string `json:"platformPublicKey"`
	ResourceID        string `json:"resourceId"`
}

// envelope is the platform's StandardResponse; the payload is at details.reply.data.
type envelope struct {
	Details struct {
		Reply struct {
			Data json.RawMessage `json:"data"`
		} `json:"reply"`
	} `json:"details"`
}

func unwrap(body []byte) json.RawMessage {
	var e envelope
	_ = json.Unmarshal(body, &e)
	return e.Details.Reply.Data
}

// agentVersion is reported on every authenticated request so an operator can
// tell which hosts are still on an old build, and (with the endpoint the
// platform observes) which are still calling a hostname due to be retired.
// Without it a stale agent is indistinguishable from a healthy one, and the
// only failure signal is silence.
const agentVersion = "1.2.0"

func newClient(insecure bool) *http.Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tjakra-satria-agent <enroll|run> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "platform API base URL, e.g. https://satria-api.tjakrabirawa.id")
	token := fs.String("token", "", "one-time enrollment token from the platform")
	confPath := fs.String("config", "tjakra-satria-agent.json", "where to write the agent config")
	insecure := fs.Bool("insecure", false, "skip TLS verification (dev only)")
	_ = fs.Parse(args)
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "enroll needs -server and -token")
		os.Exit(2)
	}
	client := newClient(*insecure)
	body, _ := json.Marshal(map[string]string{"token": *token})
	resp, err := client.Post(strings.TrimRight(*server, "/")+"/api/v1/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, "enroll rejected:", resp.StatusCode, string(raw))
		os.Exit(1)
	}
	var data struct {
		AgentID           string `json:"agentId"`
		AgentKey          string `json:"agentKey"`
		ResourceID        string `json:"resourceId"`
		PlatformPublicKey string `json:"platformPublicKey"`
	}
	if err := json.Unmarshal(unwrap(raw), &data); err != nil || data.AgentKey == "" {
		fmt.Fprintln(os.Stderr, "enroll returned no agent key")
		os.Exit(1)
	}
	cfg := config{
		Server:            strings.TrimRight(*server, "/"),
		AgentID:           data.AgentID,
		AgentKey:          data.AgentKey,
		PlatformPublicKey: data.PlatformPublicKey,
		ResourceID:        data.ResourceID,
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(*confPath, out, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "could not write config:", err)
		os.Exit(1)
	}
	fmt.Printf("enrolled agent %s for resource %s; config written to %s\n", cfg.AgentID, cfg.ResourceID, *confPath)
	if cfg.PlatformPublicKey == "" {
		fmt.Println("warning: the platform returned no signing key, so the command channel is disabled server-side")
	}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	confPath := fs.String("config", "tjakra-satria-agent.json", "agent config written by enroll")
	logFile := fs.String("log-file", "", "optional log file to tail and ship")
	logAllow := fs.String("log-allow", "", "extra comma-separated log paths the read_logs chat may read (a trailing / is a directory prefix); joins the built-in default set and any -log-file")
	enforce := fs.Bool("enforce", false, "actually apply destructive actions (default is a dry-run)")
	console := fs.Bool("console", false, "enable the admin remote console (run_command); off by default")
	blockContainer := fs.String("block-container", "", "apply blocks inside this container's network namespace via nsenter, so a host-run agent keeps blocks scoped to the target instead of the host")
	poll := fs.Duration("poll", 5*time.Second, "command poll interval")
	insecure := fs.Bool("insecure", false, "skip TLS verification (dev only)")
	_ = fs.Parse(args)

	raw, err := os.ReadFile(*confPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not read config, run enroll first:", err)
		os.Exit(1)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg.AgentKey == "" {
		fmt.Fprintln(os.Stderr, "invalid config")
		os.Exit(1)
	}
	client := newClient(*insecure)
	if !*enforce {
		fmt.Println("running in dry-run mode: destructive actions are recorded but not applied (use -enforce to apply)")
	}
	if *console {
		fmt.Println("remote console enabled: an admin operator can run commands on this host through the platform")
	}
	if *blockContainer != "" {
		fmt.Printf("blocks scope to container %q network namespace (nsenter)\n", *blockContainer)
	}
	if *logFile != "" {
		go shipLogs(cfg, client, *logFile)
	}
	// The read_logs chat (plan F4) may read only these paths: a built-in default set,
	// the shipped -log-file, and any -log-allow / LOG_ALLOW entries. This is the agent's
	// own compiled floor; the platform validates the planned path too, so neither a
	// crafted question nor a compromised platform row can widen the read surface.
	allow := buildLogAllow(*logFile, firstNonEmpty(*logAllow, os.Getenv("LOG_ALLOW")))
	fmt.Printf("read_logs chat may read: %s\n", strings.Join(allow, ", "))
	fmt.Printf("agent %s polling %s every %s\n", cfg.AgentID, cfg.Server, poll.String())
	for {
		pollCommands(cfg, client, *enforce, *console, *blockContainer, allow)
		time.Sleep(*poll)
	}
}

// buildLogAllow assembles the read_logs allowlist: a sane default set, the shipped
// -log-file (so a host already tailing a log can also answer questions about it), and
// any operator-supplied extra entries. A trailing "/" makes an entry a directory prefix.
func buildLogAllow(logFile, extra string) []string {
	allow := []string{"/var/log/auth.log", "/var/log/syslog", "/var/log/app/"}
	if s := strings.TrimSpace(logFile); s != "" {
		allow = append(allow, s)
	}
	for _, e := range strings.Split(extra, ",") {
		if s := strings.TrimSpace(e); s != "" {
			allow = append(allow, s)
		}
	}
	return allow
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func pollCommands(cfg config, client *http.Client, enforce, console bool, blockContainer string, logAllow []string) {
	req, _ := http.NewRequest(http.MethodGet, cfg.Server+"/api/v1/agent/commands", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.AgentKey)
	req.Header.Set("X-Agent-Version", agentVersion)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return
	}
	var data struct {
		Commands []command `json:"commands"`
	}
	if err := json.Unmarshal(unwrap(raw), &data); err != nil {
		return
	}
	for _, cmd := range data.Commands {
		ok, reason := verifyCommand(cmd, cfg.PlatformPublicKey)
		if !ok {
			postResult(cfg, client, cmd.ID, "failed", map[string]any{"error": "refused: " + reason})
			continue
		}
		res := executeCommand(cmd, enforce, console, blockContainer, logAllow)
		postResult(cfg, client, cmd.ID, res.Status, res.Result)
	}
}

func postResult(cfg config, client *http.Client, id, status string, result map[string]any) {
	body, _ := json.Marshal(map[string]any{"status": status, "result": result})
	req, _ := http.NewRequest(http.MethodPost, cfg.Server+"/api/v1/agent/commands/"+id+"/result", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.AgentKey)
	req.Header.Set("X-Agent-Version", agentVersion)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// shipLogs tails a file and ships appended lines to the platform, which detects on
// them. A simple offset tail: start at the end, then read what is appended. Good
// enough for a PoC; rotation handling is a follow-up.
func shipLogs(cfg config, client *http.Client, path string) {
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		offset = fi.Size()
	}
	for {
		time.Sleep(3 * time.Second)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			continue
		}
		if fi.Size() < offset {
			offset = 0 // truncated/rotated
		}
		if fi.Size() == offset {
			_ = f.Close()
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			continue
		}
		buf, _ := io.ReadAll(io.LimitReader(f, 1<<20))
		offset += int64(len(buf))
		_ = f.Close()

		events := []map[string]string{}
		for _, line := range strings.Split(string(buf), "\n") {
			line = strings.TrimRight(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			events = append(events, map[string]string{"message": line, "timestamp": time.Now().UTC().Format(time.RFC3339)})
		}
		if len(events) == 0 {
			continue
		}
		body, _ := json.Marshal(map[string]any{"events": events})
		req, _ := http.NewRequest(http.MethodPost, cfg.Server+"/api/v1/agent/logs", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cfg.AgentKey)
		req.Header.Set("X-Agent-Version", agentVersion)
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}
}
