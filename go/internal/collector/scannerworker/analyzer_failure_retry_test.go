// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import "testing"

// TestAnalyzerFailureRetryAfterIsOptional proves a failure may carry the retry
// delay its class wants, without changing its class or disposition, and asks
// for none unless a call site set one: the runner then uses its default.
func TestAnalyzerFailureRetryAfterIsOptional(t *testing.T) {
	t.Parallel()

	plain, ok := NewRetryableAnalyzerFailure(FailureClassVulnDBUnavailable, ResourceUsage{}, nil).(AnalyzerFailure)
	if !ok {
		t.Fatal("failure is not an AnalyzerFailure")
	}
	if got := plain.RetryAfterSeconds(); got != 0 {
		t.Fatalf("RetryAfterSeconds() = %d, want 0 when unset", got)
	}
	paced := plain.WithRetryAfterSeconds(300)
	if got := paced.RetryAfterSeconds(); got != 300 {
		t.Fatalf("RetryAfterSeconds() = %d, want 300", got)
	}
	if !paced.Retryable() || paced.FailureClass() != FailureClassVulnDBUnavailable {
		t.Fatalf("WithRetryAfterSeconds changed the failure: %+v", paced)
	}
}
