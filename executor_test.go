package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		{"feff::1", true, ""},        // just below ff00::/8 and above fe80::/10

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
		{"ff80::1", false, "multicast address"}, // the upper half of ff00::/8
		{"ffff::1", false, "multicast address"},
		{"::ffff:224.0.0.1", false, "multicast address"},
		{"224.0.0.0/24", false, "range includes multicast addresses"},
		{"ff05::/64", false, "range includes multicast addresses"},
		{"ff80::/64", false, "range includes multicast addresses"},
		{"ffff::/64", false, "range includes multicast addresses"},

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

// TestRunFirewallRefusesTarget proves a block of a refused target stops at the policy
// check: the failed result carries the reason and nothing else, so the non-linux note and
// the dry-run preview (and the enforce path behind them) are never reached. A revert is
// judged by syntax only, which TestRunFirewallRevertLiftsLegacyBlocks covers. Enforce is
// left off so a regression here cannot touch a real firewall.
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
	for _, container := range []string{"", "some-container"} {
		for _, c := range cases {
			res := runFirewall("block", c.target, false, container)
			if res.Status != "failed" {
				t.Fatalf("block %q (container %q): status = %q, want failed (%v)", c.target, container, res.Status, res.Result)
			}
			if want := "invalid target: " + c.reason; res.Result["error"] != want {
				t.Fatalf("block %q (container %q): error = %v, want %q", c.target, container, res.Result["error"], want)
			}
			if len(res.Result) != 1 {
				t.Fatalf("block %q (container %q): result carries more than the error, so a later path ran: %v", c.target, container, res.Result)
			}
		}
	}
}

// TestRunFirewallRevertLiftsLegacyBlocks proves a revert is judged by syntax only. A rule
// an older build installed for a target the policy now refuses must stay removable, or the
// DROP would outlive the block record. The same targets are still refused as a block.
func TestRunFirewallRevertLiftsLegacyBlocks(t *testing.T) {
	legacy := []string{
		"10.0.0.0/16", "10.0.0.0/8", "0.0.0.0/0", "0.0.0.0", "127.0.0.1", "169.254.0.1",
		"169.254.169.254", "224.0.0.1", "255.255.255.255", "::1", "::/0", "fe80::1", "ff02::1",
		"2001:db8::/32", "::ffff:127.0.0.1",
	}
	for _, container := range []string{"", "some-container"} {
		for _, target := range legacy {
			blocked := runFirewall("block", target, false, container)
			if blocked.Status != "failed" {
				t.Fatalf("block %q (container %q): status = %q, want failed", target, container, blocked.Status)
			}
			res := runFirewall("revert", target, false, container)
			if res.Status != "done" {
				t.Fatalf("revert %q (container %q): status = %q, want done (%v)", target, container, res.Status, res.Result)
			}
			if res.Result["op"] != "revert" || res.Result["target"] != target {
				t.Fatalf("revert %q (container %q): result should echo op and target, got %v", target, container, res.Result)
			}
		}
	}

	// The syntax step still guards the argv: nothing that is not an address gets through.
	malformed := []string{
		"", "ff", "not-an-ip", "1.2.3", "2130706433", "1.2.3.4:80", "1.2.3.4;ls", "-s",
		"10.0.0.0/33", "10.0.0.0/99", "10.0.0.0/", "2001:db8::/064", strings.Repeat("1", 65),
		// digits and dots that iptables would look up as a host name, or refuse as a mask
		"1.2.3.4/0ab", "1.2.3.4/0x1", "1.2.3/024", "1.2.3.4.5", "256.1.1.1", "08.0.0.1", "999.999.999.999",
		"1.2.3.4/099", "1.2.3.4/041", "1.2.3.4/0245", "1.2.3.4/1000", "cafe", "dead.beef", "1..3.4", ".1.2.3",
		"10.0.0.0/255.0.0.0", "::ffff:1.2.3.4/0128", "-1.2.3.4", "1.2.3.4/-1",
	}
	for _, target := range malformed {
		res := runFirewall("revert", target, false, "")
		if res.Status != "failed" {
			t.Fatalf("revert %q: status = %q, want failed (%v)", target, res.Status, res.Result)
		}
		if msg, _ := res.Result["error"].(string); !strings.HasPrefix(msg, "invalid target: ") {
			t.Fatalf("revert %q: error = %v, want an invalid target refusal", target, res.Result["error"])
		}
		if len(res.Result) != 1 {
			t.Fatalf("revert %q: result carries more than the error, so a later path ran: %v", target, res.Result)
		}
	}
}

// legacyOctalSpellings are targets the syntax step refuses but an older agent handed to
// iptables as they came, and iptables read them in base 0: /032 installed /26, /024
// installed /20, 010.0.0.1 is 8.0.0.1.
var legacyOctalSpellings = []string{
	"203.0.113.7/032", "10.1.2.3/024", "1.2.3.4/00", "10.0.0.0/010", "0.0.0.0/000", "010.0.0.1", "0177.0.0.1",
	"010.0.0.0/024", "203.0.113.7/0000032", "00.0.0.0/8",
}

// TestRunFirewallRevertLiftsOctalSpellings proves a revert of a rule an older build installed
// from a leading-zero spelling deletes with that exact spelling, since iptables reads it as
// octal and a rewritten /32 would not match the rule. A block of the same spelling is refused.
func TestRunFirewallRevertLiftsOctalSpellings(t *testing.T) {
	for _, container := range []string{"", "some-container"} {
		for _, target := range legacyOctalSpellings {
			res := runFirewall("revert", target, false, container)
			if res.Status != "done" {
				t.Fatalf("revert %q (container %q): status = %q, want done (%v)", target, container, res.Status, res.Result)
			}
			if res.Result["op"] != "revert" || res.Result["target"] != target {
				t.Fatalf("revert %q (container %q): result should echo op and target, got %v", target, container, res.Result)
			}
			if runtime.GOOS == "linux" {
				want := "iptables -D INPUT -s " + target + " -j DROP"
				if container != "" {
					want = "nsenter -t <pid> -n " + want
				}
				would, _ := res.Result["wouldRun"].([]string)
				if got := strings.Join(would, " "); got != want {
					t.Fatalf("revert %q (container %q): wouldRun %q, want %q", target, container, got, want)
				}
			}

			blocked := runFirewall("block", target, false, container)
			msg, _ := blocked.Result["error"].(string)
			if blocked.Status != "failed" || !strings.HasPrefix(msg, "invalid target: ") || len(blocked.Result) != 1 {
				t.Fatalf("block %q (container %q): status %q, result %v, want an invalid target refusal", target, container, blocked.Status, blocked.Result)
			}
		}
	}
}

// TestPlainDottedV4 pins the shape gate: exactly the spellings iptables reads as an IPv4
// address or network, and none it would look up as a host name.
func TestPlainDottedV4(t *testing.T) {
	yes := []string{
		"1.2.3.4", "0.0.0.0", "255.255.255.255", "010.0.0.1", "0377.0.0.0", "1.2.3.4/32", "1.2.3.4/0", "1.2.3.4/032",
		"1.2.3.4/040", "1.2.3.4/00", "1.2.3.4/0000032",
	}
	no := []string{
		"", "/", "1.2.3", "1.2.3.4.5", "1..3.4", ".1.2.3", "1.2.3.", "256.1.1.1", "1.2.3.256", "08.1.1.1", "1.2.3.09",
		"0400.0.0.0", "1.2.3.4/33", "1.2.3.4/041", "1.2.3.4/08", "1.2.3.4/", "1.2.3.4/-1", "1.2.3.4/0x1", "1.2.3.4/1.2",
		"1.2.3.4/24/8", "0x1.2.3.4", "1.2.3.4a", "cafe", "-1.2.3.4", " 1.2.3.4", "1.2.3.4\n", "2130706433", "::1",
		"::ffff:1.2.3.4", strings.Repeat("0", 60) + ".1.2.3", // four groups but 66 characters
	}
	for _, s := range yes {
		if !plainDottedV4(s) {
			t.Fatalf("plainDottedV4(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if plainDottedV4(s) {
			t.Fatalf("plainDottedV4(%q) = true, want false", s)
		}
	}
}

// TestParseIPTarget covers the syntax step alone. It accepts every well-formed address,
// including those the block policy refuses, and refuses everything that is not one.
func TestParseIPTarget(t *testing.T) {
	cases := []struct {
		target string
		reason string // substring of the refusal reason; empty when the syntax is fine
	}{
		{"203.0.113.9", ""},
		{"2001:db8::1", ""},
		{"203.0.113.0/24", ""},
		{"::ffff:8.8.8.8", ""},
		{"127.0.0.1", ""},
		{"0.0.0.0/0", ""},
		{"10.0.0.0/8", ""},
		{"::/0", ""},
		{"::ffff:127.0.0.1", ""},
		{"", "empty"},
		{strings.Repeat("1", 65), "longer than 64 characters"},
		{"1.2.3.4;ls", "illegal character"},
		{"1.2.3.4 -j ACCEPT", "illegal character"},
		{"ff", "not an IP address"},
		{"010.0.0.1", "not an IP address"},
		{"1.2.3.4:80", "not an IP address"},
		{"1.2.3.4/33", "not a valid CIDR"},
		{"1.2.3.4/24/8", "not a valid CIDR"},
		{"10.0.0.0/024", "leading zero"},
		{"2001:db8::/064", "leading zero"},
	}
	for _, c := range cases {
		ip, ones, reason := parseIPTarget(c.target)
		if c.reason == "" {
			if reason != "" || ip == nil {
				t.Fatalf("parseIPTarget(%q) = %v, %d, %q, want a parsed address", c.target, ip, ones, reason)
			}
			continue
		}
		if !strings.Contains(reason, c.reason) {
			t.Fatalf("parseIPTarget(%q) reason = %q, want it to contain %q", c.target, reason, c.reason)
		}
		if ip != nil {
			t.Fatalf("parseIPTarget(%q) refused but returned an address %v", c.target, ip)
		}
	}

	// The prefix comes back as a 16-byte length, with IPv4 mapped into ::ffff:0:0/96.
	if ip, ones, _ := parseIPTarget("203.0.113.0/24"); ones != 120 || !ip.Equal(net.ParseIP("203.0.113.0")) {
		t.Fatalf("parseIPTarget(203.0.113.0/24) = %v, %d, want 203.0.113.0, 120", ip, ones)
	}
	if ip, ones, _ := parseIPTarget("2001:db8::1"); ones != 128 || !ip.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("parseIPTarget(2001:db8::1) = %v, %d, want 2001:db8::1, 128", ip, ones)
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

// TestFirewallFamily pins which netfilter front end a target goes to and how it is
// spelled to it. An IPv6 target needs ip6tables. An IPv4-mapped IPv6 target stands for an
// IPv4 host, so it goes to iptables in dotted form: ip6tables accepts it and then matches
// nothing. The prefix is rewritten as a decimal so a leading zero is never read as octal.
func TestFirewallFamily(t *testing.T) {
	cases := []struct {
		target  string
		bin     string
		spelled string
	}{
		{"203.0.113.9", "iptables", "203.0.113.9"},
		{"203.0.113.0/24", "iptables", "203.0.113.0/24"},
		{"203.0.113.0/024", "iptables", "203.0.113.0/24"},
		{"0.0.0.0/0", "iptables", "0.0.0.0/0"},
		{"2001:db8::1", "ip6tables", "2001:db8::1"},
		{"2001:DB8:0:0::5", "ip6tables", "2001:db8::5"},
		{"2001:db8::1/128", "ip6tables", "2001:db8::1/128"},
		{"2001:db8::/64", "ip6tables", "2001:db8::/64"},
		{"2001:db8::/064", "ip6tables", "2001:db8::/64"},
		{"::1", "ip6tables", "::1"},
		{"::/0", "ip6tables", "::/0"},
		{"::ffff:203.0.113.9", "iptables", "203.0.113.9"},
		{"::ffff:cb00:7109", "iptables", "203.0.113.9"},
		{"::ffff:203.0.113.9/128", "iptables", "203.0.113.9/32"},
		{"::ffff:203.0.113.0/120", "iptables", "203.0.113.0/24"},
		{"::ffff:203.0.113.0/0120", "iptables", "203.0.113.0/24"},
		{"::ffff:127.0.0.1", "iptables", "127.0.0.1"},
		// a mapped host with a prefix shorter than 96 is an IPv6 network (::/64 here), not
		// an IPv4 range, so it must not be turned into a negative IPv4 prefix
		{"::ffff:203.0.113.9/64", "ip6tables", "::ffff:203.0.113.9/64"},
		// the boundary: /96 is exactly the mapped block (every IPv4 address), /95 is one bit wider
		{"::ffff:0:0/96", "iptables", "0.0.0.0/0"},
		{"::ffff:203.0.113.9/96", "iptables", "203.0.113.9/0"}, // host bits are left to iptables, as for any CIDR
		{"::ffff:203.0.113.9/95", "ip6tables", "::ffff:203.0.113.9/95"},
	}
	for _, c := range cases {
		bin, spelled := firewallFamily(c.target)
		if bin != c.bin || spelled != c.spelled {
			t.Fatalf("firewallFamily(%q) = %q, %q, want %q, %q", c.target, bin, spelled, c.bin, c.spelled)
		}
	}
}

// TestFirewallCommandUsesFamilyBinary proves the chosen binary is argv[0] on the direct
// path and follows "-n" on the nsenter path, and that the pid it is given lands after
// "-t", for a block and for a revert.
func TestFirewallCommandUsesFamilyBinary(t *testing.T) {
	cases := []struct {
		op        string
		target    string
		container string
		pid       string
		want      string
	}{
		{"block", "203.0.113.9", "", "<pid>", "iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "2001:db8::1", "", "<pid>", "ip6tables -I INPUT -s 2001:db8::1 -j DROP"},
		{"revert", "2001:db8::/64", "", "<pid>", "ip6tables -D INPUT -s 2001:db8::/64 -j DROP"},
		{"block", "::ffff:203.0.113.9", "", "<pid>", "iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "203.0.113.9", "some-container", "<pid>", "nsenter -t <pid> -n iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "2001:db8::1", "some-container", "<pid>", "nsenter -t <pid> -n ip6tables -I INPUT -s 2001:db8::1 -j DROP"},
		{"revert", "::ffff:203.0.113.0/120", "some-container", "<pid>", "nsenter -t <pid> -n iptables -D INPUT -s 203.0.113.0/24 -j DROP"},
		// a real pid, as the apply path passes it
		{"block", "203.0.113.9", "some-container", "4242", "nsenter -t 4242 -n iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "2001:db8::1", "some-container", "4242", "nsenter -t 4242 -n ip6tables -I INPUT -s 2001:db8::1 -j DROP"},
		{"revert", "2001:db8::/64", "some-container", "4242", "nsenter -t 4242 -n ip6tables -D INPUT -s 2001:db8::/64 -j DROP"},
		// no container: the pid is not used
		{"block", "203.0.113.9", "", "4242", "iptables -I INPUT -s 203.0.113.9 -j DROP"},
	}
	for _, c := range cases {
		bin, spelled := firewallFamily(c.target)
		name, args := firewallCommand(bin, iptablesArgs(c.op, spelled), c.container, c.pid)
		if got := strings.Join(append([]string{name}, args...), " "); got != c.want {
			t.Fatalf("%s %q (container %q, pid %q): command = %q, want %q", c.op, c.target, c.container, c.pid, got, c.want)
		}
	}
}

// TestRunFirewallDryRunUsesFamilyBinary checks that runFirewall itself hands the family
// binary to the command it builds. The preview is only built on Linux, so elsewhere the
// two pure tests above are what cover the choice.
func TestRunFirewallDryRunUsesFamilyBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the dry-run preview is only built on linux")
	}
	cases := []struct {
		op        string
		target    string
		container string
		want      string
	}{
		{"block", "203.0.113.9", "", "iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "2001:db8::1", "", "ip6tables -I INPUT -s 2001:db8::1 -j DROP"},
		{"revert", "2001:db8::/64", "", "ip6tables -D INPUT -s 2001:db8::/64 -j DROP"},
		{"block", "::ffff:203.0.113.9", "", "iptables -I INPUT -s 203.0.113.9 -j DROP"},
		{"block", "2001:db8::1", "some-container", "nsenter -t <pid> -n ip6tables -I INPUT -s 2001:db8::1 -j DROP"},
	}
	for _, c := range cases {
		res := runFirewall(c.op, c.target, false, c.container)
		would, _ := res.Result["wouldRun"].([]string)
		if got := strings.Join(would, " "); res.Status != "done" || got != c.want {
			t.Fatalf("%s %q (container %q): status %q, wouldRun %q, want %q", c.op, c.target, c.container, res.Status, got, c.want)
		}
		if res.Result["target"] != c.target {
			t.Fatalf("%s %q: result should echo the target as given, got %v", c.op, c.target, res.Result["target"])
		}
	}
}

// execFirewall runs a firewall action through executeCommand, the dispatch that chooses the
// block policy or the syntax-only revert. Enforce is off, so it never touches a firewall.
func execFirewall(action, target string) execResult {
	params, _ := json.Marshal(map[string]any{"target": target})
	return executeCommand(command{Action: action, Params: params}, false, false, "", nil)
}

// TestExecuteCommandBlockPolicy pins the action-to-check wiring. runFirewall takes the op as
// a string, so swapping the two calls in executeCommand would leave every runFirewall test
// green while block_ip accepted loopback and 0.0.0.0/0.
func TestExecuteCommandBlockPolicy(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "0.0.0.0/0", "10.0.0.0/024", "::1", "169.254.169.254"} {
		res := execFirewall("block_ip", target)
		if res.Status != "failed" {
			t.Fatalf("block_ip %q: status = %q, want failed (%v)", target, res.Status, res.Result)
		}
		if msg, _ := res.Result["error"].(string); !strings.HasPrefix(msg, "invalid target: ") {
			t.Fatalf("block_ip %q: error = %v, want an invalid target refusal", target, res.Result["error"])
		}
	}

	// A revert is judged by syntax only: a canonical target the policy refuses is still lifted.
	for _, target := range []string{"127.0.0.1", "0.0.0.0/0", "10.0.0.0/16", "::1", "169.254.169.254", "ff02::1"} {
		res := execFirewall("revert_block", target)
		if res.Status != "done" {
			t.Fatalf("revert_block %q: status = %q, want done (%v)", target, res.Status, res.Result)
		}
		if res.Result["op"] != "revert" || res.Result["target"] != target {
			t.Fatalf("revert_block %q: result should echo op and target, got %v", target, res.Result)
		}
	}

	// A valid target passes both actions, and each reports the op it ran.
	for action, op := range map[string]string{"block_ip": "block", "revert_block": "revert"} {
		res := execFirewall(action, "203.0.113.9")
		if res.Status != "done" || res.Result["op"] != op {
			t.Fatalf("%s 203.0.113.9: status %q, result %v, want done with op %q", action, res.Status, res.Result, op)
		}
	}

	// The syntax step still guards a revert.
	res := execFirewall("revert_block", "1.2.3.4;ls")
	if res.Status != "failed" || res.Result["error"] != "invalid target: illegal character" {
		t.Fatalf("revert_block 1.2.3.4;ls: status %q, result %v, want an illegal character refusal", res.Status, res.Result)
	}

	if res := execFirewall("no_such_action", "203.0.113.9"); res.Status != "failed" || res.Result["error"] != "unknown action" {
		t.Fatalf("unknown action: status %q, result %v, want failed", res.Status, res.Result)
	}
}

// TestRunFirewallRecordsOnNonLinux pins the note a non-linux host answers with.
func TestRunFirewallRecordsOnNonLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("a linux host builds the command")
	}
	res := runFirewall("block", "203.0.113.9", true, "some-container")
	if res.Status != "done" || res.Result["note"] != "recorded on a non-linux host, no firewall change" {
		t.Fatalf("status %q, result %v, want done with the non-linux note", res.Status, res.Result)
	}
	if _, ran := res.Result["wouldRun"]; ran {
		t.Fatalf("a non-linux host must not build a command, got %v", res.Result)
	}
}

// fakeFirewallTools puts stand-ins for docker, nsenter, iptables and ip6tables alone on PATH,
// so the enforce path runs for real without a firewall behind it. Each one appends its name
// and argv to the returned log; docker prints dockerOut, the pid `docker inspect` would.
func fakeFirewallTools(t *testing.T, dockerOut string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	for _, name := range []string{"docker", "nsenter", "iptables", "ip6tables"} {
		script := "#!/bin/sh\necho \"" + name + " $*\" >> '" + logPath + "'\n"
		if name == "docker" {
			script += "echo '" + dockerOut + "'\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return logPath
}

func readCalls(t *testing.T, logPath string) []string {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// TestRunFirewallEnforceRunsFamilyBinary drives the real apply path against stand-in tools
// and pins the argv it executes: the family binary, the freshly resolved pid, the container
// key in the result, and that a container that will not resolve runs nothing.
func TestRunFirewallEnforceRunsFamilyBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the apply path is only built on linux")
	}
	const inspect = "docker inspect -f {{.State.Pid}} victim"
	cases := []struct {
		op        string
		target    string
		container string
		want      []string
	}{
		{"block", "2001:db8::1", "victim", []string{inspect, "nsenter -t 4242 -n ip6tables -I INPUT -s 2001:db8::1 -j DROP"}},
		{"block", "203.0.113.9", "victim", []string{inspect, "nsenter -t 4242 -n iptables -I INPUT -s 203.0.113.9 -j DROP"}},
		{"revert", "::ffff:203.0.113.0/120", "victim", []string{inspect, "nsenter -t 4242 -n iptables -D INPUT -s 203.0.113.0/24 -j DROP"}},
		{"block", "2001:db8::1", "", []string{"ip6tables -I INPUT -s 2001:db8::1 -j DROP"}},
		{"revert", "203.0.113.9", "", []string{"iptables -D INPUT -s 203.0.113.9 -j DROP"}},
		// an older agent's octal spelling is deleted as it was installed, never rewritten
		{"revert", "203.0.113.7/032", "", []string{"iptables -D INPUT -s 203.0.113.7/032 -j DROP"}},
		{"revert", "010.0.0.1", "victim", []string{inspect, "nsenter -t 4242 -n iptables -D INPUT -s 010.0.0.1 -j DROP"}},
	}
	for _, c := range cases {
		logPath := fakeFirewallTools(t, "4242")
		res := runFirewall(c.op, c.target, true, c.container)
		if res.Status != "done" {
			t.Fatalf("%s %q (container %q): status = %q, want done (%v)", c.op, c.target, c.container, res.Status, res.Result)
		}
		if res.Result["container"] != c.container || res.Result["op"] != c.op || res.Result["target"] != c.target {
			t.Fatalf("%s %q (container %q): result should carry op, target and container, got %v", c.op, c.target, c.container, res.Result)
		}
		if got := readCalls(t, logPath); strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Fatalf("%s %q (container %q): ran %q, want %q", c.op, c.target, c.container, got, c.want)
		}
	}

	// A container that is not running has no netns to enter: nothing is executed.
	logPath := fakeFirewallTools(t, "0")
	res := runFirewall("block", "203.0.113.9", true, "victim")
	msg, _ := res.Result["error"].(string)
	if res.Status != "failed" || !strings.HasPrefix(msg, "could not resolve block container netns: ") || res.Result["container"] != "victim" {
		t.Fatalf("stopped container: status %q, result %v, want a failed netns resolution", res.Status, res.Result)
	}
	if got := readCalls(t, logPath); len(got) != 1 || got[0] != inspect {
		t.Fatalf("stopped container: ran %q, want only the inspect", got)
	}
}

// TestRunFirewallRevertRoundTripsAgainstIptables installs rules the way an older agent did
// (the raw target straight to iptables) and reverts them with the current code, then reads
// the chain back. It changes a real firewall, so it runs only when
// SATRIA_AGENT_IPTABLES_TEST=1, on linux with NET_ADMIN and an empty INPUT chain, for
// example a throwaway container from an image that has iptables, run with --network none
// and --cap-add NET_ADMIN, holding a test binary built by go test -c.
func TestRunFirewallRevertRoundTripsAgainstIptables(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SATRIA_AGENT_IPTABLES_TEST") != "1" {
		t.Skip("set SATRIA_AGENT_IPTABLES_TEST=1 on linux, in a throwaway network namespace, to run this")
	}
	chain := func() string {
		out, err := exec.Command("iptables", "-S", "INPUT").CombinedOutput()
		if err != nil {
			t.Skipf("iptables is not usable here: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := chain(); got != "-P INPUT ACCEPT" {
		t.Skipf("the INPUT chain is not empty, so this would touch someone's rules: %q", got)
	}
	t.Cleanup(func() { _ = exec.Command("iptables", "-F", "INPUT").Run() })

	targets := append([]string{"10.0.0.0/16", "0.0.0.0/0", "127.0.0.1"}, legacyOctalSpellings...)
	for _, target := range targets {
		if out, err := exec.Command("iptables", "-I", "INPUT", "-s", target, "-j", "DROP").CombinedOutput(); err != nil {
			t.Fatalf("install %q: %v: %s", target, err, out)
		}
		if got := chain(); !strings.Contains(got, "DROP") {
			t.Fatalf("install %q left no rule: %q", target, got)
		}
		if res := runFirewall("revert", target, true, ""); res.Status != "done" {
			t.Fatalf("revert %q: status = %q, want done (%v)", target, res.Status, res.Result)
		}
		if got := chain(); got != "-P INPUT ACCEPT" {
			t.Fatalf("revert %q left a rule behind: %q", target, got)
		}
	}
}
