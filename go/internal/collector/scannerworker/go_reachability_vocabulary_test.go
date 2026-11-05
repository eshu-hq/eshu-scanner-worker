// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// TestGoReachabilityAnalyzerUsesTheSourceAnalysisBudget pins the ruling's
// budget row: go_reachability runs in the scanner lane with exactly the
// AnalyzerSourceAnalysis limits (4 CPU, 4 GiB, 10 minutes, 2 GiB input, 250k
// files, 50k facts).
func TestGoReachabilityAnalyzerUsesTheSourceAnalysisBudget(t *testing.T) {
	t.Parallel()

	if string(AnalyzerGoReachability) != "go_reachability" {
		t.Fatalf("AnalyzerGoReachability = %q, want go_reachability", AnalyzerGoReachability)
	}
	lane, ok := AnalyzerLane(AnalyzerGoReachability)
	if !ok || lane != LaneScannerWorker {
		t.Fatalf("AnalyzerLane = %q, %v, want scanner_worker", lane, ok)
	}
	got, err := DefaultResourceLimits(AnalyzerGoReachability)
	if err != nil {
		t.Fatalf("DefaultResourceLimits() error = %v", err)
	}
	want := ResourceLimits{
		CPUMillis:     4000,
		MemoryBytes:   4 * gibibyte,
		Timeout:       10 * time.Minute,
		MaxInputBytes: 2 * gibibyte,
		MaxFiles:      250000,
		MaxFacts:      50000,
	}
	if got != want {
		t.Fatalf("limits = %+v, want %+v", got, want)
	}
}

// TestGoReachabilityFailureClassesAreBoundedVocabulary proves each class the
// ruling names validates, so a payload can carry it.
func TestGoReachabilityFailureClassesAreBoundedVocabulary(t *testing.T) {
	t.Parallel()

	for class, want := range map[FailureClass]string{
		FailureClassCheckoutFailed:       "checkout_failed",
		FailureClassAuthDenied:           "auth_denied",
		FailureClassToolchainUnsupported: "toolchain_unsupported",
		FailureClassAnalysisFailed:       "analysis_failed",
	} {
		if string(class) != want {
			t.Errorf("class = %q, want %q", class, want)
		}
		if err := class.validate(); err != nil {
			t.Errorf("%s.validate() error = %v", class, err)
		}
	}
}

// TestAnalyzerFailureReasonIsBoundedAndOptional proves a reason token rides
// the failure without changing its class or disposition, and is absent unless
// a call site set it.
func TestAnalyzerFailureReasonIsBoundedAndOptional(t *testing.T) {
	t.Parallel()

	plain := NewRetryableAnalyzerFailure(FailureClassCheckoutFailed, ResourceUsage{}, nil)
	failure, ok := plain.(AnalyzerFailure)
	if !ok {
		t.Fatalf("failure type = %T", plain)
	}
	if failure.Reason() != "" {
		t.Fatalf("Reason() = %q, want empty", failure.Reason())
	}
	reasoned := failure.WithReason("git_unavailable")
	if reasoned.Reason() != "git_unavailable" {
		t.Fatalf("Reason() = %q", reasoned.Reason())
	}
	if !reasoned.Retryable() || reasoned.FailureClass() != FailureClassCheckoutFailed {
		t.Fatalf("WithReason changed the failure: %+v", reasoned)
	}
}

// TestValidateFactOutputAdmitsGoReachabilityKinds proves both Go kinds pass
// the scanner allowlist at schema 1.0.0 and a wrong schema version does not.
func TestValidateFactOutputAdmitsGoReachabilityKinds(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	for _, kind := range []string{chain.VulnerabilityGoModuleEvidenceFactKind, chain.VulnerabilityGoCallReachabilityFactKind} {
		output := func(schema string) FactOutput {
			return FactOutput{TargetCount: 1, ResultCount: 1, Facts: []facts.Envelope{{
				FactID:           "fact-1",
				ScopeID:          input.Target.ScopeID,
				GenerationID:     input.GenerationID,
				FactKind:         kind,
				StableFactKey:    "key-1",
				SchemaVersion:    schema,
				CollectorKind:    "scanner_worker",
				FencingToken:     input.FencingToken,
				SourceConfidence: facts.SourceConfidenceReported,
				ObservedAt:       input.ObservedAt,
				Payload:          map[string]any{},
				SourceRef: facts.Ref{
					SourceSystem: "scanner_worker",
					ScopeID:      input.Target.ScopeID,
					GenerationID: input.GenerationID,
					FactKey:      "key-1",
				},
			}}}
		}
		if err := ValidateFactOutput(input, output(chain.VulnerabilityIntelligenceSchemaVersionV1)); err != nil {
			t.Errorf("%s at 1.0.0: error = %v", kind, err)
		}
		if err := ValidateFactOutput(input, output("9.9.9")); err == nil {
			t.Errorf("%s at 9.9.9: error = nil, want rejection", kind)
		}
	}
}
