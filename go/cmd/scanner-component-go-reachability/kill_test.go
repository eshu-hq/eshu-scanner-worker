// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// processesHolding returns the pids whose environment holds needle, this test's own
// children only because the needle is unique to it.
func processesHolding(t *testing.T, needle string) []int {
	t.Helper()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("ReadDir(/proc): %v", err)
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		environ, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "environ")) // #nosec G304 -- /proc of a numeric pid
		if err == nil && strings.Contains(string(environ), needle) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// waitFor polls until done reports true or the budget ends.
func waitFor(budget time.Duration, done func() bool) bool {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if done() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return done()
}

// hangingProxy accepts connections and never answers, so a fetch stays blocked in
// git-remote-https, the helper that holds the token.
func hangingProxy(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return listener.Addr().String()
}

// TestHostSIGKILLLeavesNoTokenBearingProcess is the F6 regression: the host signals
// only the component, and git-remote-https then kept running with the token in its
// environment. The test waits until the helper really holds the header, kills the
// binary as the host does, and requires every holder gone. It then proves the next
// run sweeps the checkout the killed run left.
func TestHostSIGKILLLeavesNoTokenBearingProcess(t *testing.T) {
	bin := buildBinary(t)
	temp := t.TempDir()
	const token = "ghs_ORPHANSENTINEL0123456789abcdef"
	header := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	t.Cleanup(func() {
		for _, pid := range processesHolding(t, header) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	env := []string{"HTTPS_PROXY=http://" + hangingProxy(t), "TMPDIR=" + temp}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(requestFor(t, smokeCall{
		token:    map[string]any{"token": token, "scope_id": smokeScope},
		cloneURL: "https://" + smokeHost + "/org/repo", hosts: []string{smokeHost},
	}))
	cmd.Env = baseEnv(env...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	holdsHelper := func() bool {
		for _, pid := range processesHolding(t, header) {
			raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")) // #nosec G304 -- /proc of a numeric pid
			if err == nil && strings.Contains(string(raw), "remote-http") {
				return true
			}
		}
		return false
	}
	if !waitFor(30*time.Second, holdsHelper) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("git-remote-https never held the header; the check would prove nothing")
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	_ = cmd.Wait()
	if !waitFor(5*time.Second, func() bool { return len(processesHolding(t, header)) == 0 }) {
		t.Fatalf("processes still hold the token after the kill: %v", processesHolding(t, header))
	}

	pattern := filepath.Join(temp, "eshu-go-reachability", "claim-*")
	left, err := filepath.Glob(pattern)
	if err != nil || len(left) != 1 {
		t.Fatalf("killed run left %v, error = %v, want its one workspace", left, err)
	}
	serve(t, bin, smokeCall{
		token:    smokeTokenStanza(),
		cloneURL: "https://" + smokeHost + "/org/repo", hosts: []string{smokeHost},
		env: []string{"HTTPS_PROXY=http://" + closedLoopbackAddress(t), "TMPDIR=" + temp},
	})
	if left, err := filepath.Glob(pattern); err != nil || len(left) != 0 {
		t.Fatalf("next run left %v, error = %v", left, err)
	}
}

// TestHostSIGKILLStopsATokenlessGitCall proves the parent-death signal on the other
// git calls, which run with no guard. The git on PATH records its pid and blocks.
func TestHostSIGKILLStopsATokenlessGitCall(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	shim := "#!/bin/sh\necho $$ > " + pidFile + ".tmp\nmv " + pidFile + ".tmp " + pidFile + "\nexec sleep 300\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(shim), 0o700); err != nil { // #nosec G306 -- the shim must be executable
		t.Fatalf("WriteFile: %v", err)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(requestFor(t, smokeCall{token: smokeTokenStanza(), cloneURL: "https://github.com/o/r"}))
	cmd.Env = baseEnv("PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	var pid int
	if !waitFor(30*time.Second, func() bool {
		raw, err := os.ReadFile(pidFile) // #nosec G304 -- this test's own temp file
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		return err == nil
	}) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("git never started")
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}
	_ = cmd.Wait()
	alive := func() bool {
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) // #nosec G304 -- /proc of a numeric pid
		if err != nil {
			return false
		}
		// A dead process awaiting its reaper is state Z, after the command in parens.
		_, state, found := strings.Cut(string(raw), ") ")
		return found && !strings.HasPrefix(state, "Z")
	}
	if !waitFor(5*time.Second, func() bool { return !alive() }) {
		t.Fatalf("git pid %d outlived the component", pid)
	}
}
