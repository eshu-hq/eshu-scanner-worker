// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"os"
	"strings"
	"testing"
)

// TestCloneURLPolicyRefusesHostileOrigins is the F4 regression. These origins all
// passed and could receive the header. Each is refused before any git process.
func TestCloneURLPolicyRefusesHostileOrigins(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://evil.example/o/r",
		"https://evil.example:8443/o/r",
		"https://github.com:443/o/r",
		"https://github.com:8443/o/r",
		"https://github.com:/o/r",
		"https://169.254.169.254/latest/meta-data",
		"https://[fd00:ec2::254]/latest/meta-data",
		"https://[::1]/o/r",
		"https://127.0.0.1/o/r",
		"https://2130706433/o/r",
		"https://localhost/o/r",
		"https://github.com.evil.example/o/r",
		"https://github.com./o/r",
		"https://GITHUB.com/o/r",
		"https://user@github.com/o/r",
		"https://user:SENTINEL@github.com/o/r",
		"https://github.com@evil.example/o/r",
		"https://evil.example",
		"https://evil.example/",
		"https://github.com",
		"https://github.com/",
		"https://github.com/o",
		"https://github.com/o/",
		"https://github.com/../../x",
		"https://github.com/o/../r",
		"https://github.com/o/./r",
		"https://github.com/o//r",
		"https://github.com/%2e%2e/%2e%2e/x",
		"https://github.com/o/r%00",
		"https://github.com/O/R",
		"https://github.com/o/r.git",
		"https://github.com/o/r/",
		`https://github.com\@evil.example/o/r`,
		"http://github.com/o/r",
		"ssh://git@github.com/o/r",
		"file:///etc/passwd",
	} {
		target := validTarget()
		target.CloneURL = raw
		shim, log := gitShim(t, "")
		_, err := NewAnalyzer(Config{
			CollectorInstanceID: "i",
			Target:              target,
			Token:               ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID}),
			Options:             Options{GitPath: shim},
		})
		if err == nil {
			t.Errorf("clone url %q: error = nil, want refusal", raw)
			continue
		}
		if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "evil.example") {
			t.Errorf("clone url %q: error echoes the value: %v", raw, err)
		}
		if _, statErr := os.Stat(log); statErr == nil {
			t.Errorf("clone url %q: git ran", raw)
		}
	}
}

// TestCloneURLPolicyAcceptsCoreCanonicalRemotes mirrors what core's
// ValidCloneURL lets through on the default allowlist.
func TestCloneURLPolicyAcceptsCoreCanonicalRemotes(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"https://github.com/o/r", "https://github.com/eshu-hq/eshu-scanner-worker", "https://github.com/o/r.v2_x-y", "https://github.com/o/sub/r"} {
		target := validTarget()
		target.CloneURL = raw
		if _, err := NewAnalyzer(Config{CollectorInstanceID: "i", Target: target}); err != nil {
			t.Errorf("clone url %q: error = %v", raw, err)
		}
	}
}

// TestAllowedCloneHostsIsAnExplicitOperatorSetting proves the allowlist replaces
// the default, and that a target can never widen it.
func TestAllowedCloneHostsIsAnExplicitOperatorSetting(t *testing.T) {
	t.Parallel()

	build := func(raw string, hosts ...string) error {
		target := validTarget()
		target.CloneURL = raw
		_, err := NewAnalyzer(Config{CollectorInstanceID: "i", Target: target, Options: Options{AllowedCloneHosts: hosts}})
		return err
	}
	if err := build("https://git.corp.example/o/r", "git.corp.example"); err != nil {
		t.Fatalf("listed host: %v", err)
	}
	if err := build("https://github.com/o/r", "git.corp.example"); err == nil {
		t.Fatal("github.com passed a list that does not name it")
	}
	if err := build("https://git.corp.example:8443/o/r", "git.corp.example"); err == nil {
		t.Fatal("a port passed on a listed host")
	}
}

// TestValidateCloneHostsRefusesWhatCanNeverBeAHostName covers the setting itself:
// an IP literal or a port cannot be allowlisted, even by the operator.
func TestValidateCloneHostsRefusesWhatCanNeverBeAHostName(t *testing.T) {
	t.Parallel()

	if err := ValidateCloneHosts([]string{"github.com", "git.corp.example", "a-b.c1.example"}); err != nil {
		t.Fatalf("valid hosts: %v", err)
	}
	for _, hosts := range [][]string{
		nil,
		{},
		{""},
		{"localhost"},
		{"169.254.169.254"},
		{"127.0.0.1"},
		{"[::1]"},
		{"::1"},
		{"2130706433"},
		{"0x7f.0.0.1"},
		{"github.com:443"},
		{"https://github.com"},
		{"GitHub.com"},
		{"github.com."},
		{"user@github.com"},
		{"-a.example"},
		{"a-.example"},
		{"github.com", "SENTINEL"},
		{"a.example/x"},
		{"a b.example"},
	} {
		err := ValidateCloneHosts(hosts)
		if err == nil {
			t.Errorf("hosts %q: error = nil, want refusal", hosts)
		} else if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("hosts %q: error echoes the value: %v", hosts, err)
		}
	}
}
