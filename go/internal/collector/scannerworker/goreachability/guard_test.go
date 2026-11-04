// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

//go:build unix

package goreachability

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestMain lets this test binary stand in for the component as the guard, so the
// tests below exercise the real re-exec path.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == GitGuardCommand {
		os.Exit(RunGitGuard(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// guardOption wires the running test binary in as the guard.
func guardOption() []string { return []string{os.Args[0], GitGuardCommand} }

// TestGuardedFetchReachesTheSameFacts proves the guard changes nothing about the
// fetch: same exit handling, same output, the token still only in its environment.
func TestGuardedFetchReachesTheSameFacts(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, log := gitShim(t, "")
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) {
		c.Options.GitPath = shim
		c.Options.GitGuard = guardOption()
	}))
	if got := evidenceOf(result.Output); len(got) != 1 {
		t.Fatalf("evidence = %v", got)
	}
	assertNoToken(t, "guarded argv", strings.Join(argvLines(readLog(t, log)), "\n"))
}

func argvLines(log string) []string {
	var lines []string
	for line := range strings.SplitSeq(log, "\n") {
		if strings.HasPrefix(line, "ARGV ") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestGuardedFetchFailureKeepsItsClass proves git's exit code and stderr cross the
// guard, so a refusal is still auth_denied.
func TestGuardedFetchFailureKeepsItsClass(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, failOnArgument("fetch", "fatal: Authentication failed"))
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) {
		c.Options.GitPath = shim
		c.Options.GitGuard = guardOption()
	}).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassAuthDenied, false)
	wantReason(t, err, reasonTokenRejected)
}

// TestCancellingAGuardedFetchStopsTheGroup proves the deadline still reaches git
// through the guard.
func TestCancellingAGuardedFetchStopsTheGroup(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *" fetch "*) sleep 60;; esac`)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) {
		c.Options.GitPath = shim
		c.Options.GitGuard = guardOption()
	}).Analyze(ctx, testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("Analyze took %s, want the group killed before the wait delay", elapsed)
	}
}

// TestGuardRefusesToRunWithoutItsGroup proves running the guard by hand cannot
// signal the caller's process group. A test binary does not lead its group.
func TestGuardRefusesToRunWithoutItsGroup(t *testing.T) {
	t.Parallel()

	if code := RunGitGuard(nil, strings.NewReader(""), io.Discard, io.Discard); code != guardRefused {
		t.Fatalf("no arguments: code = %d", code)
	}
	if code := RunGitGuard([]string{"true"}, strings.NewReader(""), io.Discard, io.Discard); code != guardRefused {
		t.Fatalf("not a group leader: code = %d", code)
	}
}

// TestSuperviseGitReportsAndKills covers the supervisor in this process: exit codes
// pass through, a missing binary is reported, and end of file on the parent pipe
// fires the group kill while git still runs.
func TestSuperviseGitReportsAndKills(t *testing.T) {
	t.Parallel()

	never := func() {}
	blocked, release := io.Pipe()
	defer func() { _ = release.Close() }()
	var stdout bytes.Buffer
	if code := superviseGit([]string{"sh", "-c", "echo out; exit 3"}, blocked, &stdout, io.Discard, never); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if stdout.String() != "out\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if code := superviseGit([]string{"sh", "-c", "exit 0"}, blocked, io.Discard, io.Discard, never); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if code := superviseGit([]string{"/no/such/binary"}, blocked, io.Discard, io.Discard, never); code != guardCannotRunGit {
		t.Fatalf("exit code = %d, want %d", code, guardCannotRunGit)
	}
	killed := make(chan struct{})
	done := make(chan int, 1)
	reader, writer := io.Pipe()
	go func() {
		done <- superviseGit([]string{"sh", "-c", "sleep 2"}, reader, io.Discard, io.Discard, func() { close(killed) })
	}()
	_ = writer.Close()
	select {
	case <-killed:
	case <-time.After(10 * time.Second):
		t.Fatal("end of file on the parent pipe did not fire the group kill")
	}
	<-done
}
