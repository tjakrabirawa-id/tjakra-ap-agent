package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// The executor runs the allowlisted actions and never a free-form shell command.
// Targets are validated to a strict character set and passed as argv (not through a
// shell), so a crafted target cannot inject. Destructive actions are a dry-run
// unless the agent was started with -enforce, so a test run never touches a live
// firewall or account by accident.

type execResult struct {
	Status string
	Result map[string]any
}

func executeCommand(cmd command, enforce, console bool, blockContainer string, logAllow []string) execResult {
	var params map[string]any
	_ = json.Unmarshal(cmd.Params, &params)
	target, _ := params["target"].(string)

	switch cmd.Action {
	case "block_ip":
		return runFirewall("block", target, enforce, blockContainer)
	case "revert_block":
		return runFirewall("revert", target, enforce, blockContainer)
	case "disable_user":
		return runDisableUser(target, enforce)
	case "isolate_host":
		return execResult{"done", map[string]any{"note": "host isolation is recorded but not enforced in this agent build"}}
	case "run_collector":
		return runCollector()
	case "run_probe":
		return runProbe(cmd.Params)
	case "run_command":
		return runCommand(cmd.Params, console)
	case "read_logs":
		return runReadLogs(cmd.Params, logAllow)
	}
	return execResult{"failed", map[string]any{"error": "unknown action"}}
}

// The narrowest block a single command may cover. A wider CIDR is refused so one bad
// target cannot DROP a whole network.
const (
	minPrefixV4 = 24
	minPrefixV6 = 64
)

// neverRange is a range a block target may neither be nor contain. It is held as a
// 16-byte prefix in the IPv6 address space with IPv4 mapped into ::ffff:0:0/96, so one
// overlap test covers both families and every IPv4-mapped IPv6 spelling of a range.
type neverRange struct {
	ip   net.IP
	ones int
	name string
}

var neverBlock = buildNeverBlock()

func buildNeverBlock() []neverRange {
	specs := []struct{ cidr, name string }{
		{"0.0.0.0/32", "unspecified"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"224.0.0.0/4", "multicast"},
		{"255.255.255.255/32", "broadcast"},
		{"::/128", "unspecified"},
		{"::1/128", "loopback"},
		{"fe80::/10", "link-local"},
		{"ff00::/8", "multicast"},
	}
	out := make([]neverRange, 0, len(specs))
	for _, s := range specs {
		_, n, err := net.ParseCIDR(s.cidr)
		if err != nil {
			panic(err)
		}
		ip, ones := widenNet(n)
		out = append(out, neverRange{ip, ones, s.name})
	}
	return out
}

// widenNet returns a network as a 16-byte prefix in the IPv6 address space, with an
// IPv4 network mapped into ::ffff:0:0/96.
func widenNet(n *net.IPNet) (net.IP, int) {
	ones, _ := n.Mask.Size()
	if len(n.IP) == net.IPv4len {
		ones += 96
	}
	return n.IP.To16(), ones
}

// prefixesOverlap reports whether two 16-byte prefixes share any address. Prefixes are
// either nested or disjoint, so comparing the shorter length of the two is enough.
func prefixesOverlap(a net.IP, aOnes int, b net.IP, bOnes int) bool {
	m := net.CIDRMask(min(aOnes, bOnes), 128)
	return a.Mask(m).Equal(b.Mask(m))
}

// validIPTarget reports whether t is a block target the agent will hand to iptables:
// one unicast address, or a CIDR no wider than /24 (IPv4) or /64 (IPv6). It refuses the
// unspecified, loopback, link-local, multicast and broadcast ranges, and any CIDR that
// contains one of them, including their IPv4-mapped IPv6 spellings. A CIDR prefix with
// a leading zero is refused because iptables reads it as octal. On refusal it returns
// the reason. The character set check stays first so nothing outside it ever reaches
// the parser or the argv.
func validIPTarget(t string) (ok bool, reason string) {
	if t == "" {
		return false, "empty"
	}
	if len(t) > 64 {
		return false, "longer than 64 characters"
	}
	for _, r := range t {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '.' || r == ':' || r == '/') {
			return false, "illegal character"
		}
	}

	var ip net.IP
	var ones int
	if i := strings.IndexByte(t, '/'); i >= 0 {
		// iptables reads the prefix in base 0, so a leading zero is octal: /024 installs /20.
		if p := t[i+1:]; len(p) > 1 && p[0] == '0' {
			return false, "prefix has a leading zero"
		}
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return false, "not a valid CIDR"
		}
		ip, ones = widenNet(n)
	} else {
		parsed := net.ParseIP(t)
		if parsed == nil {
			return false, "not an IP address"
		}
		ip, ones = parsed.To16(), 128
	}

	// An IPv4-mapped IPv6 address is judged as the IPv4 address it stands for.
	prefix, floor := ones, minPrefixV6
	if ip.To4() != nil {
		prefix, floor = ones-96, minPrefixV4
	}
	if prefix < floor {
		return false, fmt.Sprintf("prefix /%d is broader than the minimum /%d", prefix, floor)
	}

	for _, r := range neverBlock {
		if !prefixesOverlap(ip, ones, r.ip, r.ones) {
			continue
		}
		if ones == 128 {
			return false, r.name + " address"
		}
		return false, "range includes " + r.name + " addresses"
	}
	return true, ""
}

func validUsername(u string) bool {
	if u == "" || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func iptablesArgs(op, target string) []string {
	if op == "revert" {
		return []string{"-D", "INPUT", "-s", target, "-j", "DROP"}
	}
	return []string{"-I", "INPUT", "-s", target, "-j", "DROP"}
}

// runFirewall applies or reverts an iptables DROP for a source IP. When
// blockContainer is set (a host-run agent that must scope blocks to a target's
// network namespace), the rule runs inside that container's netns via nsenter, so a
// DROP lands only in the target and never touches the host netfilter. When it is
// empty the rule runs in the agent's own netns, correct on a host that is itself the
// isolation boundary. This is what lets the agent run on the host (full console
// reach) while a block stays scoped to the monitored container.
func runFirewall(op, target string, enforce bool, blockContainer string) execResult {
	// One check guards both ops: a signed revert of a refused target is refused too.
	if ok, reason := validIPTarget(target); !ok {
		return execResult{"failed", map[string]any{"error": "invalid target: " + reason}}
	}
	args := iptablesArgs(op, target)
	if runtime.GOOS != "linux" {
		return execResult{"done", map[string]any{"note": "recorded on a non-linux host, no firewall change", "op": op, "target": target}}
	}
	name, cmdArgs := firewallCommand(args, blockContainer)
	if !enforce {
		return execResult{"done", map[string]any{"note": "dry-run: start the agent with -enforce to apply", "op": op, "target": target, "wouldRun": append([]string{name}, cmdArgs...)}}
	}
	if blockContainer != "" {
		pid, err := containerPid(blockContainer)
		if err != nil {
			return execResult{"failed", map[string]any{"error": "could not resolve block container netns: " + err.Error(), "container": blockContainer}}
		}
		// Rebuild the args with the freshly resolved pid (it changes on restart).
		name, cmdArgs = "nsenter", append([]string{"-t", pid, "-n", "iptables"}, args...)
	}
	out, err := exec.Command(name, cmdArgs...).CombinedOutput()
	if err != nil {
		return execResult{"failed", map[string]any{"error": err.Error(), "output": string(out)}}
	}
	return execResult{"done", map[string]any{"op": op, "target": target, "container": blockContainer, "output": string(out)}}
}

// firewallCommand builds the command name and args for a dry-run preview. The real
// run re-resolves the container pid at apply time.
func firewallCommand(iptablesArgs []string, blockContainer string) (string, []string) {
	if blockContainer != "" {
		return "nsenter", append([]string{"-t", "<pid>", "-n", "iptables"}, iptablesArgs...)
	}
	return "iptables", iptablesArgs
}

// containerPid resolves a container's init pid, which is the handle for entering its
// network namespace. It is resolved per call because the pid changes when the
// container restarts.
func containerPid(name string) (string, error) {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", name).Output()
	if err != nil {
		return "", err
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return "", errors.New("container not running")
	}
	return pid, nil
}

func runDisableUser(user string, enforce bool) execResult {
	if !validUsername(user) {
		return execResult{"failed", map[string]any{"error": "invalid username"}}
	}
	if runtime.GOOS != "linux" {
		return execResult{"done", map[string]any{"note": "recorded on a non-linux host, no account change", "user": user}}
	}
	if !enforce {
		return execResult{"done", map[string]any{"note": "dry-run: start the agent with -enforce to apply", "wouldRun": []string{"usermod", "-L", user}}}
	}
	out, err := exec.Command("usermod", "-L", user).CombinedOutput()
	if err != nil {
		return execResult{"failed", map[string]any{"error": err.Error(), "output": string(out)}}
	}
	return execResult{"done", map[string]any{"user": user, "output": string(out)}}
}

func runCollector() execResult {
	host, _ := os.Hostname()
	return execResult{"done", map[string]any{"hostname": host, "os": runtime.GOOS, "arch": runtime.GOARCH}}
}

// runProbe fires a RedTeam technique's benign attack-signature requests at the
// agent's own resource so a simulation reaches a target the platform cannot (one
// bound to localhost for isolation). It is hard-restricted to a loopback or private
// target, so the platform can never turn an agent into a probe against an arbitrary
// host on the internet. The requests are plain GETs whose query string carries the
// signature the detection rules match in the access log; nothing is exploited.
func runProbe(rawParams json.RawMessage) execResult {
	var p struct {
		Target string   `json:"target"`
		Paths  []string `json:"paths"`
	}
	_ = json.Unmarshal(rawParams, &p)
	if p.Target == "" {
		p.Target = "http://127.0.0.1"
	}
	base, err := url.Parse(p.Target)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return execResult{"failed", map[string]any{"error": "probe target must be an http(s) URL"}}
	}
	if !isLocalProbeHost(base.Hostname()) {
		return execResult{"failed", map[string]any{"error": "probe target must be a loopback or private address"}}
	}
	if len(p.Paths) == 0 {
		return execResult{"failed", map[string]any{"error": "no probe paths given"}}
	}
	if len(p.Paths) > 20 {
		p.Paths = p.Paths[:20]
	}
	client := &http.Client{Timeout: 6 * time.Second}
	fired := 0
	for _, path := range p.Paths {
		target := strings.TrimRight(base.String(), "/") + "/" + strings.TrimPrefix(path, "/")
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "tjakra-satria-redteam/1.0 (agent probe)")
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			fired++
		}
	}
	return execResult{"done", map[string]any{"fired": fired, "target": base.String()}}
}

// runCommand is the remote console: it runs an operator-typed command through the
// OS shell and returns its combined output. It is the one action outside the
// allowlisted, deterministic model, so it is inert unless the agent was started with
// -console. The platform still signs it and admin-gates it; -console is the local
// operator's own consent that this host may be driven interactively. A non-zero exit
// is a normal result (status done, with exitCode), not a dispatch failure; only a
// command that could not start or timed out is failed. Output is capped and the run
// is bounded by a timeout so a runaway command cannot pin the agent.
func runCommand(rawParams json.RawMessage, console bool) execResult {
	if !console {
		return execResult{"failed", map[string]any{"error": "remote console is disabled on this agent (start it with -console to enable)"}}
	}
	var p struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(rawParams, &p)
	cmdStr := strings.TrimSpace(p.Command)
	if cmdStr == "" {
		return execResult{"failed", map[string]any{"error": "empty command"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ec *exec.Cmd
	if runtime.GOOS == "windows" {
		ec = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
	} else {
		ec = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	out, err := ec.CombinedOutput()
	const outCap = 64 * 1024
	truncated := false
	if len(out) > outCap {
		out = out[:outCap]
		truncated = true
	}
	result := map[string]any{"command": cmdStr, "output": string(out), "truncated": truncated}
	if ctx.Err() == context.DeadlineExceeded {
		result["error"] = "command timed out after 30s"
		return execResult{"failed", result}
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			result["exitCode"] = ee.ExitCode()
			return execResult{"done", result} // ran, exited non-zero: a normal shell result
		}
		result["error"] = err.Error()
		return execResult{"failed", result} // could not start
	}
	result["exitCode"] = 0
	return execResult{"done", result}
}

// runReadLogs answers the per-agent log chat (plan F4). It is READ-ONLY and bounded:
// it opens an ALLOWLISTED log path, optionally filters by a case-insensitive substring,
// returns only the last maxLines (capped) and at most 64 KB, within a 30s timeout, and
// NEVER touches a shell. It is a sibling switch case of run_command with no os/exec
// path, so a chat can structurally never reach the remote console. The path is matched
// against the compiled allowlist (an exact file, or a directory prefix ending in "/");
// anything else, or any ".." traversal, is refused. sinceMins is accepted for wire
// compatibility but this build bounds the read by maxLines, not by parsing timestamps.
func runReadLogs(rawParams json.RawMessage, logAllow []string) execResult {
	var p struct {
		Path      string `json:"path"`
		Grep      string `json:"grep"`
		SinceMins int    `json:"sinceMins"`
		MaxLines  int    `json:"maxLines"`
	}
	_ = json.Unmarshal(rawParams, &p)
	path := strings.TrimSpace(p.Path)
	if path == "" {
		return execResult{"failed", map[string]any{"error": "no log path given"}}
	}
	if !logPathAllowed(path, logAllow) {
		return execResult{"failed", map[string]any{"error": "log path is not allowlisted: " + path}}
	}
	maxLines := p.MaxLines
	if maxLines <= 0 || maxLines > 2000 {
		maxLines = 1000
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, err := os.Open(path)
	if err != nil {
		return execResult{"failed", map[string]any{"error": "could not open the log", "path": path}}
	}
	defer f.Close()

	needle := strings.ToLower(strings.TrimSpace(p.Grep))
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Ring buffer of the last maxLines matching lines: a streaming tail that never
	// holds the whole file, so a huge log cannot exhaust memory.
	ring := make([]string, 0, maxLines)
	matched := 0
	for sc.Scan() {
		if ctx.Err() != nil {
			break
		}
		line := sc.Text()
		if needle != "" && !strings.Contains(strings.ToLower(line), needle) {
			continue
		}
		matched++
		ring = append(ring, line)
		if len(ring) > maxLines {
			ring = ring[1:]
		}
	}
	out := strings.Join(ring, "\n")
	const outCap = 64 * 1024
	truncated := false
	if len(out) > outCap {
		// Keep the TAIL within the cap: the most recent lines are the useful ones.
		out = out[len(out)-outCap:]
		truncated = true
	}
	return execResult{"done", map[string]any{
		"path":      path,
		"lines":     len(ring),
		"matched":   matched,
		"output":    out,
		"truncated": truncated,
		"grep":      p.Grep,
	}}
}

// logPathAllowed reports whether path is admitted by the compiled allowlist. An entry
// ending in "/" is a directory prefix (the path must be strictly inside it); any other
// entry is an exact file match. A ".." anywhere is refused outright, so a traversal can
// never escape an allowed directory. Plain string matching (not filepath) is used
// because both the allowlist and the requested path are absolute paths in the target
// host's own convention.
func logPathAllowed(path string, allow []string) bool {
	if path == "" || strings.Contains(path, "..") {
		return false
	}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.HasSuffix(a, "/") {
			if strings.HasPrefix(path, a) && len(path) > len(a) {
				return true
			}
		} else if path == a {
			return true
		}
	}
	return false
}

// isLocalProbeHost admits only a loopback or RFC1918 private target, so a probe can
// never leave the host's own network. A bare "localhost" is allowed; any other
// hostname is refused rather than resolved, because a name could point anywhere.
func isLocalProbeHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
