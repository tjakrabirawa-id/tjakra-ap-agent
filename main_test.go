package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// agentVersion is sent as X-Agent-Version and shown on the console, so an operator can
// tell which hosts still run an old build. 1.2.0 is the first build with target
// validation: a version below it would make an upgraded agent look like an old one.
func TestAgentVersionIsAtLeastFirstValidatingBuild(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(agentVersion) {
		t.Fatalf("agentVersion = %q, want major.minor.patch", agentVersion)
	}
	parts := strings.Split(agentVersion, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	if major < 1 || (major == 1 && minor < 2) {
		t.Fatalf("agentVersion = %q, want at least 1.2.0, the first build with target validation", agentVersion)
	}
}
