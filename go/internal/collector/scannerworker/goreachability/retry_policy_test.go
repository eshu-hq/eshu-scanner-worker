// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// wantRetryAfter asserts the retry delay a failure asks the host for.
func wantRetryAfter(t *testing.T, err error, seconds int) {
	t.Helper()

	failure, ok := err.(scannerworker.AnalyzerFailure)
	if !ok {
		t.Fatalf("error = %#v, want AnalyzerFailure", err)
	}
	if got := failure.RetryAfterSeconds(); got != seconds {
		t.Fatalf("RetryAfterSeconds() = %d, want %d", got, seconds)
	}
}

// failingScannerBody replays a recorded stderr and exits 1 in every module.
func failingScannerBody(t *testing.T, fixture string) string {
	t.Helper()

	return "cat " + fixturePath(t, fixture) + " >&2; exit 1"
}

// TestRetryPolicyByClassAndAttempt is B5.4(1) and (3): per class and attempt,
// does the claim commit, with what class, and with what retry delay. The
// satellite never hardcodes the host's attempt budget, so attempt 10 behaves
// exactly like attempt 2 for the always-retryable classes; the host ends them.
// A proxy 404 is deterministic under the fleet policy, so it commits on the
// first attempt, and its status code wins over the dial line beside it.
func TestRetryPolicyByClassAndAttempt(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		fixture    string
		reason     string
		class      scannerworker.FailureClass
		retryable  bool
		retryAfter int
	}{
		"vulndb unavailable":     {"stderr_db_down.txt", warningVulnDBUnavailable, scannerworker.FailureClassVulnDBUnavailable, true, 300},
		"proxy unreachable":      {"stderr_proxy_down.txt", warningModuleDownloadFailed, scannerworker.FailureClassModuleDownloadFailed, true, 300},
		"proxy 404 is terminal":  {"stderr_private.txt", warningModuleDownloadFailed, scannerworker.FailureClassModuleDownloadFailed, false, 0},
		"inline dial tcp":        {"", warningModuleDownloadFailed, scannerworker.FailureClassModuleDownloadFailed, true, 300},
		"inline creating client": {"", warningVulnDBUnavailable, scannerworker.FailureClassVulnDBUnavailable, true, 300},
	} {
		for _, attempt := range []int{1, 2, 10} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				body := ""
				switch {
				case tc.fixture != "":
					body = failingScannerBody(t, tc.fixture)
				case name == "inline dial tcp":
					body = "printf '%s\n' '" + stderrDownloadFailure + "' >&2; exit 1"
				default:
					body = "printf '%s\n' '" + stderrVulnDBFailure + "' >&2; exit 1"
				}
				toolchain, _ := fakeScanner(t, body)
				input := stageInput(t, "go.mod")
				input.Claim.Attempt = attempt
				outcome, err := runStage(t, toolchain, input, nil)
				if tc.retryable {
					wantFailure(t, err, tc.class, true)
					wantReason(t, err, tc.reason)
					wantRetryAfter(t, err, tc.retryAfter)
					return
				}
				if err != nil {
					t.Fatalf("attempt %d: Run() error = %v, want a commit naming the module", attempt, err)
				}
				if len(outcome.Facts) != 0 || outcome.ModulesAnalyzed != 0 || len(outcome.Failed) != 1 {
					t.Fatalf("attempt %d: outcome = %+v", attempt, outcome)
				}
				if failed := outcome.Failed[0]; failed.Reason != tc.reason || failed.Class != tc.class || failed.RelativePath != "go.mod" {
					t.Fatalf("attempt %d: failed = %+v, want %s %s", attempt, failed, tc.reason, tc.class)
				}
			})
		}
	}
}

// TestGoneModuleIsTerminalLikeNotFound covers the 410 half of the B5.2 split.
func TestGoneModuleIsTerminalLikeNotFound(t *testing.T) {
	t.Parallel()

	body := `echo 'main.go:3:8: x@v1: reading https://proxy.golang.org/x/@v/v1.zip: 410 Gone' >&2; exit 1`
	toolchain, _ := fakeScanner(t, body)
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v, want a commit", err)
	}
	if len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningModuleDownloadFailed {
		t.Fatalf("failed = %+v", outcome.Failed)
	}
}

// TestTimeoutRetryDelayIsSixty is the timeout row of B5.2: retryable once at
// 60 seconds, then terminal for its module (the behavior proof is
// TestTimeoutKillsTheProcessGroupAndRetriesOnce).
func TestTimeoutRetryDelayIsSixty(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "exec /usr/bin/sleep 30")
	short := func(c *ScanConfig) { c.ModuleTimeout = 300 * time.Millisecond }
	_, err := runStage(t, toolchain, stageInput(t, "go.mod"), short)
	wantFailure(t, err, scannerworker.FailureClassTimeout, true)
	wantReason(t, err, warningAnalysisTimeout)
	wantRetryAfter(t, err, 60)
}

// TestFailFastStopsAtTheFirstRetryableModule is B5.4(2) and B5.3: nothing from
// a retryable run commits, so scanning the rest would only pay more package
// loads before the same outage. It holds on every attempt because vulndb is
// always retryable. A first-attempt timeout also fails fast.
func TestFailFastStopsAtTheFirstRetryableModule(t *testing.T) {
	t.Parallel()

	for _, attempt := range []int{1, 10} {
		toolchain, log := fakeScanner(t, `case "$PWD" in */bad) cat `+fixturePath(t, "stderr_db_down.txt")+` >&2; exit 1;; *) cat `+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")+`;; esac`)
		input := stageInput(t, "bad/go.mod", "good/go.mod")
		input.Claim.Attempt = attempt
		_, err := runStage(t, toolchain, input, nil)
		wantFailure(t, err, scannerworker.FailureClassVulnDBUnavailable, true)
		wantReason(t, err, warningVulnDBUnavailable)
		if got := strings.Count(readLog(t, log), "CALL "); got != 1 {
			t.Fatalf("attempt %d: scans = %d, want the stage to stop at the first", attempt, got)
		}
	}

	toolchain, log := fakeScanner(t, `case "$PWD" in */slow) exec /usr/bin/sleep 30;; *) cat `+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")+`;; esac`)
	_, err := runStage(t, toolchain, stageInput(t, "slow/go.mod", "good/go.mod"), func(c *ScanConfig) { c.ModuleTimeout = 300 * time.Millisecond })
	wantFailure(t, err, scannerworker.FailureClassTimeout, true)
	if got := strings.Count(readLog(t, log), "CALL "); got != 1 {
		t.Fatalf("first timeout: scans = %d, want 1", got)
	}
}

// TestTerminalFailureDoesNotFailFast proves a 404 keeps the loop going: the
// commit still carries every other module's facts.
func TestTerminalFailureDoesNotFailFast(t *testing.T) {
	t.Parallel()

	body := `case "$PWD" in */bad) cat ` + fixturePath(t, "stderr_private.txt") + ` >&2; exit 1;; *) cat ` + fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl") + `;; esac`
	toolchain, log := fakeScanner(t, body)
	outcome, err := runStage(t, toolchain, stageInput(t, "bad/go.mod", "good/go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := strings.Count(readLog(t, log), "CALL "); got != 2 {
		t.Fatalf("scans = %d, want both modules", got)
	}
	if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 1 || outcome.Failed[0].Reason != warningModuleDownloadFailed || len(outcome.Facts) != 4 {
		t.Fatalf("outcome = %d analyzed, %+v, %d facts", outcome.ModulesAnalyzed, outcome.Failed, len(outcome.Facts))
	}
}

// TestCompletionFiguresNameTheAttempt proves a committed run's stderr figures
// name its attempt, as the retryable record does (B5.3).
func TestCompletionFiguresNameTheAttempt(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/ok\n\nrequire m.test/a v1.0.0\n"})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := result.Completion.Figures["attempt"]; got != 1 {
		t.Fatalf("figures[attempt] = %d, want 1 (%v)", got, result.Completion.Figures)
	}
}

// TestUnreadableCacheRetriesAsSourceUnavailableAtSixty covers the last row of
// B5.2: openScanCache and the scratch directories are retryable at 60 seconds
// on every attempt.
func TestUnreadableCacheRetriesAsSourceUnavailableAtSixty(t *testing.T) {
	t.Parallel()

	blocker := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	toolchain, _ := fakeScanner(t, "exit 0")
	input := stageInput(t, "go.mod")
	input.Claim.Attempt = 7
	_, err := runStage(t, toolchain, input, func(c *ScanConfig) { c.CacheRoot = filepath.Join(blocker, "cache") })
	wantFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)
	wantRetryAfter(t, err, 60)
}
