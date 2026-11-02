// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/scope"
)

func TestAnalyzerProfilesRouteHeavyAnalyzersToScannerWorkers(t *testing.T) {
	t.Parallel()

	for _, analyzer := range []AnalyzerKind{
		AnalyzerSBOMGeneration,
		AnalyzerImageUnpacking,
		AnalyzerSourceAnalysis,
		AnalyzerOSPackageExtraction,
		AnalyzerSecretScan,
		AnalyzerLicenseScan,
		AnalyzerMisconfigurationScan,
	} {
		lane, ok := AnalyzerLane(analyzer)
		if !ok {
			t.Fatalf("AnalyzerLane(%q) ok = false, want true", analyzer)
		}
		if lane != LaneScannerWorker {
			t.Fatalf("AnalyzerLane(%q) = %q, want %q", analyzer, lane, LaneScannerWorker)
		}
	}

	for _, analyzer := range []AnalyzerKind{
		AnalyzerVulnerabilityMatching,
		AnalyzerCoverageReadiness,
		AnalyzerSecurityPriority,
	} {
		lane, ok := AnalyzerLane(analyzer)
		if !ok {
			t.Fatalf("AnalyzerLane(%q) ok = false, want true", analyzer)
		}
		if lane != LaneReducer {
			t.Fatalf("AnalyzerLane(%q) = %q, want %q", analyzer, lane, LaneReducer)
		}
	}
}

func TestValidateFactOutputRejectsSilentCleanOutput(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	output := FactOutput{TargetCount: 1}

	err := ValidateFactOutput(input, output)
	if err == nil {
		t.Fatal("ValidateFactOutput() error = nil, want silent clean output rejection")
	}
}

func TestValidateFactOutputRejectsReducerFacts(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	output := FactOutput{
		TargetCount: 1,
		ResultCount: 1,
		Facts: []facts.Envelope{{
			FactID:           "fact-reducer",
			ScopeID:          input.Target.ScopeID,
			GenerationID:     input.GenerationID,
			FactKind:         "reducer_supply_chain_impact_finding",
			StableFactKey:    "reducer-finding",
			SchemaVersion:    "1.0.0",
			CollectorKind:    string(scope.CollectorScannerWorker),
			FencingToken:     input.FencingToken,
			SourceConfidence: "reported",
			ObservedAt:       input.ObservedAt,
			Payload:          map[string]any{"status": "affected"},
		}},
	}

	err := ValidateFactOutput(input, output)
	if err == nil {
		t.Fatal("ValidateFactOutput() error = nil, want reducer fact rejection")
	}
	if got, want := err.Error(), "reducers own user-facing findings"; !strings.Contains(got, want) {
		t.Fatalf("ValidateFactOutput() error = %q, want substring %q", got, want)
	}
}

func TestValidateFactOutputAcceptsSourceFactsWithFencing(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	output := FactOutput{
		TargetCount: 1,
		ResultCount: 1,
		Facts: []facts.Envelope{{
			FactID:           "fact-analysis",
			ScopeID:          input.Target.ScopeID,
			GenerationID:     input.GenerationID,
			FactKind:         facts.ScannerWorkerAnalysisFactKind,
			StableFactKey:    "scanner-worker-analysis",
			SchemaVersion:    facts.ScannerWorkerSchemaVersionV1,
			CollectorKind:    string(scope.CollectorScannerWorker),
			FencingToken:     input.FencingToken,
			SourceConfidence: "reported",
			ObservedAt:       input.ObservedAt,
			Payload: map[string]any{
				"analyzer": string(input.Analyzer),
				"target":   string(input.Target.Kind),
			},
			SourceRef: facts.Ref{
				SourceSystem: string(scope.CollectorScannerWorker),
				ScopeID:      input.Target.ScopeID,
				GenerationID: input.GenerationID,
				FactKey:      "scanner-worker-analysis",
			},
		}},
	}

	if err := ValidateFactOutput(input, output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
}

func TestFailurePayloadDoesNotExposeRawTargetScope(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	payload, err := FailurePayloadFor(input, FailureDeadLetter, "memory_limit_exceeded", ResourceUsage{
		CPUSeconds:      7.5,
		PeakMemoryBytes: 3 << 30,
	})
	if err != nil {
		t.Fatalf("FailurePayloadFor() error = %v, want nil", err)
	}
	if payload.TargetLocatorHash != input.Target.LocatorHash {
		t.Fatalf("TargetLocatorHash = %q, want %q", payload.TargetLocatorHash, input.Target.LocatorHash)
	}
	if strings.Contains(payload.String(), input.Target.ScopeID) {
		t.Fatalf("FailurePayload leaked raw scope id %q in %q", input.Target.ScopeID, payload.String())
	}
	if payload.Retryable {
		t.Fatal("Retryable = true, want false for dead-letter payload")
	}
}

func TestFailurePayloadRejectsUnboundedFailureClass(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	_, err := FailurePayloadFor(input, FailureDeadLetter, "panic: /Users/private/repo", ResourceUsage{})
	if err == nil {
		t.Fatal("FailurePayloadFor() error = nil, want unbounded failure class rejection")
	}
	if got, want := err.Error(), "failure_class"; !strings.Contains(got, want) {
		t.Fatalf("FailurePayloadFor() error = %q, want substring %q", got, want)
	}
}

// testClaimInput builds the analyzer input the component runner derives from
// an SDK claim (see component.claimInput): repository target identity from
// TargetScopeForComponent and explicit resource limits.
func testClaimInput(t *testing.T) ClaimInput {
	t.Helper()

	now := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	const generationID = "scanner-worker:generation-1"
	target, err := TargetScopeForComponent("scanner-worker://repository/repo-private-name", "repository:repo-123", generationID, generationID)
	if err != nil {
		t.Fatalf("TargetScopeForComponent() error = %v, want nil", err)
	}
	input := ClaimInput{
		WorkItemID:     "scanner-worker:collector-scanner:work-1",
		ClaimID:        "claim-1",
		FencingToken:   7,
		OwnerID:        "scanner-worker-1",
		Analyzer:       AnalyzerSBOMGeneration,
		Target:         target,
		Limits:         testResourceLimits(),
		GenerationID:   generationID,
		Attempt:        2,
		ClaimedAt:      now,
		LeaseExpiresAt: now.Add(time.Minute),
		ObservedAt:     now,
	}
	if err := input.validate(); err != nil {
		t.Fatalf("validate() error = %v, want nil", err)
	}
	return input
}

func testResourceLimits() ResourceLimits {
	return ResourceLimits{
		CPUMillis:     2000,
		MemoryBytes:   1 << 30,
		Timeout:       10 * time.Minute,
		MaxInputBytes: 2 << 30,
		MaxFiles:      250000,
		MaxFacts:      50000,
	}
}
