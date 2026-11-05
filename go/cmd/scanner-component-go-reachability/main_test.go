// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	smokeScope = "go-reachability://repository:r_1a2b3c4d"
	smokeToken = "ghs_SMOKETOKEN0123456789abcdef"
	// smokeHost is the name the tests allowlist. httptest's TLS certificate covers
	// it, and every connection goes through a loopback proxy, so nothing leaves the
	// machine.
	smokeHost = "example.com"
)

// smokeCall is one binary invocation's inputs.
type smokeCall struct {
	token    map[string]any
	cloneURL string
	sha      string
	hosts    []string
	env      []string
}

func smokeTokenStanza() map[string]any {
	return map[string]any{"token": smokeToken, "scope_id": smokeScope}
}

// buildBinary builds the real binary once per test.
func buildBinary(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "scanner-component-go-reachability")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build error = %v\n%s", err, out)
	}
	return bin
}

// closedLoopbackAddress returns a loopback address nothing listens on.
func closedLoopbackAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return address
}

// requestFor builds the host's stdin document.
func requestFor(t *testing.T, call smokeCall) []byte {
	t.Helper()

	sha := call.sha
	if sha == "" {
		sha = strings.Repeat("a", 40)
	}
	config := map[string]any{
		"derive_from_go_modules": map[string]any{"enabled": true},
		"host_derived_target": map[string]any{
			"scope_id": smokeScope, "repository_id": "repository:r_1a2b3c4d",
			"source_commit_sha": sha, "clone_url": call.cloneURL,
		},
	}
	if call.token != nil {
		config["host_github_app_token"] = call.token
	}
	if call.hosts != nil {
		config["allowed_clone_hosts"] = call.hosts
	}
	payload, err := json.Marshal(map[string]any{
		"protocol_version": "collector-sdk/v1alpha3",
		"claim": map[string]any{
			"component_id": "eshu.scanner.go-reachability", "instance_id": "smoke", "collector_kind": "scanner_worker",
			"source_system": "scanner_worker", "scope": map[string]any{"id": smokeScope, "kind": "repository"},
			"source_run_id": "run-1", "generation_id": "gen-1", "work_item_id": "work-1", "fencing_token": "7",
			"attempt": 1, "deadline": time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano), "config_handle": "cfg",
		},
		"config": config,
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return payload
}

// baseEnv is the process environment without the variables a test sets on purpose.
func baseEnv(extra ...string) []string {
	env := slices.DeleteFunc(os.Environ(), func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TMPDIR":
			return true
		}
		return false
	})
	return append(env, extra...)
}

func serve(t *testing.T, bin string, call smokeCall) (map[string]any, string, string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(requestFor(t, call))
	cmd.Env = baseEnv(call.env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("binary exit = %v, stderr = %q", err, stderr.String())
	}
	var page map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v\n%s", err, stdout.String())
	}
	return page, stdout.String(), stderr.String()
}

// TestBinaryClassifiesClaimsOverStdio proves two no-network outcomes through a real
// subprocess: a missing credential is terminal before git runs, and an unreachable
// source is retryable. Neither stream carries the token or the URL.
func TestBinaryClassifiesClaimsOverStdio(t *testing.T) {
	bin := buildBinary(t)
	address := closedLoopbackAddress(t)
	cloneURL := "https://" + smokeHost + "/org/repo"
	env := []string{"HTTPS_PROXY=http://" + address, "TMPDIR=" + t.TempDir()}

	denied, _, deniedLog := serve(t, bin, smokeCall{cloneURL: cloneURL, hosts: []string{smokeHost}, env: env})
	if denied["state"] != "terminal" {
		t.Fatalf("state = %v, want terminal", denied["state"])
	}
	if !strings.Contains(deniedLog, `"failure_class":"auth_denied"`) {
		t.Fatalf("stderr = %q", deniedLog)
	}

	unreachable, _, unreachableLog := serve(t, bin, smokeCall{token: smokeTokenStanza(), cloneURL: cloneURL, hosts: []string{smokeHost}, env: env})
	if unreachable["state"] != "retryable" {
		t.Fatalf("state = %v, want retryable", unreachable["state"])
	}
	if !strings.Contains(unreachableLog, `"failure_class":"checkout_failed"`) {
		t.Fatalf("stderr = %q", unreachableLog)
	}
	for _, text := range []string{deniedLog, unreachableLog} {
		for _, leak := range []string{smokeToken, smokeHost, address, smokeScope} {
			if strings.Contains(text, leak) {
				t.Fatalf("stderr leaks %q: %q", leak, text)
			}
		}
	}
}

// TestBinaryRefusesAHostileOriginBeforeGitRuns is the F4 regression on the production
// path, with no test seam: the default allowlist and a real subprocess. A git on PATH
// that records its start proves no process ever saw the token.
func TestBinaryRefusesAHostileOriginBeforeGitRuns(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "git-ran")
	shim := "#!/bin/sh\necho ran > " + marker + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(shim), 0o700); err != nil { // #nosec G306 -- the shim must be executable
		t.Fatalf("WriteFile: %v", err)
	}
	env := []string{"PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH"), "TMPDIR=" + t.TempDir()}
	for _, cloneURL := range []string{
		"https://evil.example/o/r", "https://evil.example:8443/o/r", "https://169.254.169.254/o/r",
		"https://localhost/o/r", "https://github.com:8443/o/r", "https://github.com/../../x", "https://evil.example",
	} {
		page, _, log := serve(t, bin, smokeCall{token: smokeTokenStanza(), cloneURL: cloneURL, env: env})
		if page["state"] != "terminal" {
			t.Fatalf("%s: state = %v, want terminal", cloneURL, page["state"])
		}
		if !strings.Contains(log, `"failure_class":"component_bad_config"`) {
			t.Fatalf("%s: stderr = %q", cloneURL, log)
		}
		if strings.Contains(log, "evil.example") || strings.Contains(log, smokeToken) {
			t.Fatalf("%s: stderr echoes the target: %q", cloneURL, log)
		}
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: git ran", cloneURL)
		}
	}
}
