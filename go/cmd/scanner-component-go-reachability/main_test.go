// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	smokeScope = "go-reachability://repository:r_1a2b3c4d"
	smokeToken = "ghs_SMOKETOKEN0123456789abcdef"
)

// closedLoopbackAddress returns a loopback address nothing listens on, so the
// real binary's fetch fails without leaving the machine.
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

func serve(t *testing.T, bin string, token map[string]any, cloneURL string) (map[string]any, string) {
	t.Helper()

	config := map[string]any{
		"derive_from_go_modules": map[string]any{"enabled": true},
		"host_derived_target": map[string]any{
			"scope_id": smokeScope, "repository_id": "repository:r_1a2b3c4d",
			"source_commit_sha": strings.Repeat("a", 40), "clone_url": cloneURL,
		},
	}
	if token != nil {
		config["host_github_app_token"] = token
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = bytes.NewReader(payload)
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
	return page, stderr.String()
}

// TestBinaryClassifiesClaimsOverStdio builds the real binary and proves its two
// no-network outcomes through a real subprocess: a missing credential is terminal
// before git runs, and an unreachable source is retryable. Neither stream carries
// the token or the URL. The fact path needs the https transport or a test seam, so
// the component package covers it.
func TestBinaryClassifiesClaimsOverStdio(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "scanner-component-go-reachability")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build error = %v\n%s", err, out)
	}
	address := closedLoopbackAddress(t)
	cloneURL := "https://" + address + "/org/repo.git"

	denied, deniedLog := serve(t, bin, nil, cloneURL)
	if denied["state"] != "terminal" {
		t.Fatalf("state = %v, want terminal", denied["state"])
	}
	if !strings.Contains(deniedLog, `"failure_class":"auth_denied"`) {
		t.Fatalf("stderr = %q", deniedLog)
	}

	unreachable, unreachableLog := serve(t, bin, map[string]any{"token": smokeToken, "scope_id": smokeScope}, cloneURL)
	if unreachable["state"] != "retryable" {
		t.Fatalf("state = %v, want retryable", unreachable["state"])
	}
	if !strings.Contains(unreachableLog, `"failure_class":"checkout_failed"`) {
		t.Fatalf("stderr = %q", unreachableLog)
	}
	for _, text := range []string{deniedLog, unreachableLog} {
		for _, leak := range []string{smokeToken, address, smokeScope} {
			if strings.Contains(text, leak) {
				t.Fatalf("stderr leaks %q: %q", leak, text)
			}
		}
	}
}
