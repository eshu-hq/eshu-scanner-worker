// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestFirstRunAttemptIsOneThroughClaimInput is B5.4(7): the satellite's whole
// retry policy keys on ClaimInput.Attempt, and the first run of a work item
// (host attempt_count 1) must arrive as exactly 1 through runner_build.
func TestFirstRunAttemptIsOneThroughClaimInput(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDGoReachability, goReachabilityScope, "scanner-worker:generation-test")
	if claim.Attempt != 1 {
		t.Fatalf("fixture claim Attempt = %d, want the first run to be 1", claim.Attempt)
	}
	input, err := claimInput(claim, Config{AcceptanceUnitID: goReachabilityRepository}, scannerworker.AnalyzerGoReachability, testClock())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	if input.Attempt != 1 {
		t.Fatalf("ClaimInput.Attempt = %d, want 1 for the first run", input.Attempt)
	}
	claim.Attempt = 2
	input, err = claimInput(claim, Config{AcceptanceUnitID: goReachabilityRepository}, scannerworker.AnalyzerGoReachability, testClock())
	if err != nil {
		t.Fatalf("claimInput(attempt 2) error = %v", err)
	}
	if input.Attempt != 2 {
		t.Fatalf("ClaimInput.Attempt = %d, want 2", input.Attempt)
	}
}

// TestRetryAfterSecondsForHonorsTheFailure proves the runner sends the delay
// a retryable failure carries (300s for the transient scan classes), keeps
// the 60s default for a failure that carries none, and sends nothing for a
// terminal failure.
func TestRetryAfterSecondsForHonorsTheFailure(t *testing.T) {
	t.Parallel()

	paced := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassVulnDBUnavailable, scannerworker.ResourceUsage{}, nil).(scannerworker.AnalyzerFailure).WithRetryAfterSeconds(300)
	if got := retryAfterSecondsFor(paced); got != 300 {
		t.Fatalf("retryAfterSecondsFor(300s failure) = %d, want 300", got)
	}
	plain := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassSourceUnavailable, scannerworker.ResourceUsage{}, nil)
	if got := retryAfterSecondsFor(plain); got != defaultRetryAfterSeconds {
		t.Fatalf("retryAfterSecondsFor(plain) = %d, want the %ds default", got, defaultRetryAfterSeconds)
	}
	terminal := scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassAnalysisFailed, scannerworker.ResourceUsage{}, nil)
	if got := retryAfterSecondsFor(terminal); got != 0 {
		t.Fatalf("retryAfterSecondsFor(terminal) = %d, want 0", got)
	}
}
