package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogPathAllowed(t *testing.T) {
	allow := []string{"/var/log/auth.log", "/var/log/app/"}
	cases := []struct {
		path string
		want bool
	}{
		{"/var/log/auth.log", true},              // exact file
		{"/var/log/app/web.log", true},           // inside a dir prefix
		{"/var/log/app/sub/deep.log", true},      // deeper inside a dir prefix
		{"/var/log/syslog", false},               // not allowlisted
		{"/etc/shadow", false},                   // not allowlisted
		{"/var/log/app", false},                  // the dir itself, not strictly inside
		{"/var/log/auth.log.1", false},           // near-miss on an exact entry
		{"/var/log/app/../../etc/passwd", false}, // traversal is refused outright
		{"", false},                              // empty
	}
	for _, c := range cases {
		if got := logPathAllowed(c.path, allow); got != c.want {
			t.Fatalf("logPathAllowed(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestRunReadLogs(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	var b strings.Builder
	for i := 1; i <= 50; i++ {
		if i == 42 {
			b.WriteString("Failed password for root from 203.0.113.9\n")
			continue
		}
		b.WriteString("Accepted password for deploy line ")
		b.WriteByte(byte('0' + i%10))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	allow := []string{logPath}

	// A non-allowlisted path is refused, never opened.
	res := runReadLogs(json.RawMessage(`{"path":"/etc/shadow"}`), allow)
	if res.Status != "failed" {
		t.Fatalf("non-allowlisted path should fail, got %q", res.Status)
	}

	// A grep returns only matching lines.
	params, _ := json.Marshal(map[string]any{"path": logPath, "grep": "failed password", "maxLines": 100})
	res = runReadLogs(params, allow)
	if res.Status != "done" {
		t.Fatalf("expected done, got %q (%v)", res.Status, res.Result)
	}
	out, _ := res.Result["output"].(string)
	if !strings.Contains(out, "203.0.113.9") {
		t.Fatalf("grep should have matched the failed-password line, got %q", out)
	}
	if strings.Contains(out, "Accepted password") {
		t.Fatalf("grep should have excluded non-matching lines, got %q", out)
	}
	if m, _ := res.Result["matched"].(int); m != 1 {
		t.Fatalf("expected 1 matched line, got %v", res.Result["matched"])
	}

	// maxLines tails: with a tiny cap only the last N lines come back.
	params, _ = json.Marshal(map[string]any{"path": logPath, "maxLines": 3})
	res = runReadLogs(params, allow)
	out, _ = res.Result["output"].(string)
	if got := strings.Count(out, "\n"); got != 2 { // 3 lines -> 2 newlines
		t.Fatalf("maxLines=3 should tail 3 lines (2 newlines), got %d in %q", got, out)
	}
	if lines, _ := res.Result["lines"].(int); lines != 3 {
		t.Fatalf("expected lines=3, got %v", res.Result["lines"])
	}
}

func TestValidIPTarget(t *testing.T) {
	cases := []struct {
		target string
		ok     bool
		reason string // substring of the refusal reason; empty when ok
	}{
		// valid single unicast addresses, both families
		{"203.0.113.9", true, ""},
		{"8.8.8.8", true, ""},
		{"10.0.0.5", true, ""}, // private is allowed: an attacker can pivot from inside
		{"2001:db8::1", true, ""},
		{"2001:DB8::1", true, ""},
		{"::ffff:8.8.8.8", true, ""}, // mapped form of a plain unicast address

		// valid CIDRs at or above the minimum prefix
		{"203.0.113.0/24", true, ""},
		{"203.0.113.128/25", true, ""},
		{"203.0.113.9/32", true, ""},
		{"2001:db8:abcd:12::/64", true, ""},
		{"2001:db8::1/128", true, ""},

		// not an address at all, though built from the allowed characters
		{"ff", false, "not an IP address"},
		{"abc", false, "not an IP address"},
		{"deadbeef", false, "not an IP address"},
		{"1.2.3", false, "not an IP address"},
		{"256.1.1.1", false, "not an IP address"},
		{"010.0.0.1", false, "not an IP address"},  // leading zero reads as octal elsewhere
		{"2130706433", false, "not an IP address"}, // integer form of 127.0.0.1
		{"1.2.3.4:80", false, "not an IP address"},
		{":::", false, "not an IP address"},
		{"1.2.3.4/33", false, "not a valid CIDR"},
		{"1.2.3.4/", false, "not a valid CIDR"},
		{"/24", false, "not a valid CIDR"},
		{"1.2.3.4/24/8", false, "not a valid CIDR"},
		{"2001:db8::/129", false, "not a valid CIDR"},

		// iptables reads a prefix with a leading zero as octal, so /024 would install /20
		{"10.0.0.0/024", false, "leading zero"},
		{"1.2.3.4/032", false, "leading zero"},
		{"10.0.0.0/0024", false, "leading zero"},
		{"0.0.1.0/024", false, "leading zero"},
		{"255.255.255.192/032", false, "leading zero"},
		{"10.0.0.0/00", false, "leading zero"},
		{"10.0.0.0/08", false, "leading zero"},
		{"10.0.0.0/028", false, "leading zero"},
		{"2001:db8::/064", false, "leading zero"},
		{"2001:db8::/0128", false, "leading zero"},
		{"::ffff:10.0.0.0/0120", false, "leading zero"},

		// the character and length checks still hold
		{"", false, "empty"},
		{strings.Repeat("1", 65), false, "longer than 64 characters"},
		{"1.2.3.4;ls", false, "illegal character"},
		{"1.2.3.4 -j ACCEPT", false, "illegal character"},
		{"1.2.3.4\n", false, "illegal character"},
		{"-s", false, "illegal character"},

		// unspecified
		{"0.0.0.0", false, "unspecified address"},
		{"::", false, "unspecified address"},
		{"::ffff:0.0.0.0", false, "unspecified address"},
		{"0.0.0.0/24", false, "range includes unspecified addresses"},
		{"::/64", false, "range includes unspecified addresses"},

		// loopback
		{"127.0.0.1", false, "loopback address"},
		{"127.255.255.254", false, "loopback address"},
		{"127.0.0.1/32", false, "loopback address"},
		{"::1", false, "loopback address"},
		{"::1/128", false, "loopback address"},
		{"::ffff:127.0.0.1", false, "loopback address"},
		{"::ffff:7f00:1", false, "loopback address"},
		{"127.0.0.1/24", false, "range includes loopback addresses"},
		{"::ffff:127.0.0.0/120", false, "range includes loopback addresses"},

		// link-local
		{"169.254.0.1", false, "link-local address"},
		{"169.254.169.254", false, "link-local address"},
		{"fe80::1", false, "link-local address"},
		{"febf::1", false, "link-local address"},
		{"::ffff:169.254.169.254", false, "link-local address"},
		{"169.254.1.0/24", false, "range includes link-local addresses"},
		{"fe80::/64", false, "range includes link-local addresses"},

		// multicast
		{"224.0.0.1", false, "multicast address"},
		{"239.255.255.250", false, "multicast address"},
		{"ff02::1", false, "multicast address"},
		{"::ffff:224.0.0.1", false, "multicast address"},
		{"224.0.0.0/24", false, "range includes multicast addresses"},
		{"ff05::/64", false, "range includes multicast addresses"},

		// limited broadcast
		{"255.255.255.255", false, "broadcast address"},
		{"::ffff:255.255.255.255", false, "broadcast address"},
		{"255.255.255.0/24", false, "range includes broadcast addresses"},

		// broader than the minimum prefix
		{"0.0.0.0/0", false, "prefix /0 is broader than the minimum /24"},
		{"::/0", false, "prefix /0 is broader than the minimum /64"},
		{"10.0.0.0/8", false, "prefix /8 is broader than the minimum /24"},
		{"203.0.113.0/23", false, "prefix /23 is broader than the minimum /24"},
		{"128.0.0.0/1", false, "prefix /1 is broader than the minimum /24"},
		{"2001:db8::/32", false, "prefix /32 is broader than the minimum /64"},
		{"2001:db8::/63", false, "prefix /63 is broader than the minimum /64"},
		{"::ffff:0:0/96", false, "prefix /0 is broader than the minimum /24"}, // every IPv4 address, mapped
		{"::ffff:10.0.0.0/104", false, "prefix /8 is broader than the minimum /24"},

		// wide enough for IPv6 but covering the mapped IPv4 space, which holds loopback and the rest
		{"::fffe:0:0/95", false, "range includes unspecified addresses"},
	}
	for _, c := range cases {
		ok, reason := validIPTarget(c.target)
		if ok != c.ok {
			t.Fatalf("validIPTarget(%q) ok = %v (%q), want %v", c.target, ok, reason, c.ok)
		}
		if c.ok {
			if reason != "" {
				t.Fatalf("validIPTarget(%q) is ok but returned reason %q", c.target, reason)
			}
			continue
		}
		if !strings.Contains(reason, c.reason) {
			t.Fatalf("validIPTarget(%q) reason = %q, want it to contain %q", c.target, reason, c.reason)
		}
	}
}

// TestRunFirewallRefusesTarget proves a refused target stops at the check for both ops:
// the failed result carries the reason and nothing else, so the non-linux note and the
// dry-run preview (and the enforce path behind them) are never reached. Enforce is left
// off so a regression here cannot touch a real firewall.
func TestRunFirewallRefusesTarget(t *testing.T) {
	cases := []struct {
		target string
		reason string
	}{
		{"0.0.0.0/0", "prefix /0 is broader than the minimum /24"},
		{"::/0", "prefix /0 is broader than the minimum /64"},
		{"0.0.0.0", "unspecified address"},
		{"::", "unspecified address"},
		{"127.0.0.1", "loopback address"},
		{"::1", "loopback address"},
		{"::ffff:127.0.0.1", "loopback address"},
		{"169.254.169.254", "link-local address"},
		{"fe80::1", "link-local address"},
		{"224.0.0.1", "multicast address"},
		{"ff02::1", "multicast address"},
		{"255.255.255.255", "broadcast address"},
		{"224.0.0.0/24", "range includes multicast addresses"},
		{"10.0.0.0/024", "prefix has a leading zero"},
		{"ff", "not an IP address"},
		{"1.2.3.4;ls", "illegal character"},
		{"", "empty"},
	}
	for _, op := range []string{"block", "revert"} {
		for _, container := range []string{"", "some-container"} {
			for _, c := range cases {
				res := runFirewall(op, c.target, false, container)
				if res.Status != "failed" {
					t.Fatalf("%s %q (container %q): status = %q, want failed (%v)", op, c.target, container, res.Status, res.Result)
				}
				if want := "invalid target: " + c.reason; res.Result["error"] != want {
					t.Fatalf("%s %q (container %q): error = %v, want %q", op, c.target, container, res.Result["error"], want)
				}
				if len(res.Result) != 1 {
					t.Fatalf("%s %q (container %q): result carries more than the error, so a later path ran: %v", op, c.target, container, res.Result)
				}
			}
		}
	}
}

func TestRunFirewallAcceptsValidTarget(t *testing.T) {
	for _, op := range []string{"block", "revert"} {
		for _, target := range []string{"203.0.113.9", "203.0.113.0/24", "2001:db8::1"} {
			res := runFirewall(op, target, false, "")
			if res.Status != "done" {
				t.Fatalf("%s %q: status = %q, want done (%v)", op, target, res.Status, res.Result)
			}
			if res.Result["op"] != op || res.Result["target"] != target {
				t.Fatalf("%s %q: result should echo op and target, got %v", op, target, res.Result)
			}
		}
	}
}
