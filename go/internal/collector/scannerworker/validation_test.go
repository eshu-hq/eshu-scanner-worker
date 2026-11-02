// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/scope"
)

// TestAnalyzerFailureCarriesBoundedClassOnly proves analyzer failures expose
// the class, disposition, and usage, and never the raw cause text.
func TestAnalyzerFailureCarriesBoundedClassOnly(t *testing.T) {
	t.Parallel()

	usage := ResourceUsage{CPUSeconds: 1.5, PeakMemoryBytes: 42}
	cause := errors.New("read /private/rootfs/etc/os-release")
	retry := NewRetryableAnalyzerFailure(FailureClassTargetUnavailable, usage, cause)
	terminal := NewTerminalAnalyzerFailure(FailureClassInputLimitExceeded, usage, cause)

	var failure AnalyzerFailure
	if !errors.As(retry, &failure) || !failure.Retryable() || failure.Disposition() != FailureRetryable ||
		failure.FailureClass() != FailureClassTargetUnavailable || failure.ResourceUsage() != usage {
		t.Fatalf("retryable failure = %+v, want retryable target_unavailable with usage", failure)
	}
	if !errors.As(terminal, &failure) || failure.Retryable() || failure.Disposition() != FailureDeadLetter {
		t.Fatalf("terminal failure = %+v, want dead_letter", failure)
	}
	for _, err := range []error{retry, terminal} {
		if strings.Contains(err.Error(), "/private/rootfs") {
			t.Fatalf("Error() = %q leaked the cause", err.Error())
		}
	}
}

// TestDefaultResourceLimitsProfiles proves every scanner-lane analyzer has a
// valid profile and reducer or unknown analyzers fail closed.
func TestDefaultResourceLimitsProfiles(t *testing.T) {
	t.Parallel()

	for _, kind := range []AnalyzerKind{
		AnalyzerSourceAnalysis, AnalyzerSecretScan, AnalyzerLicenseScan, AnalyzerMisconfigurationScan,
		AnalyzerSBOMGeneration, AnalyzerOSPackageExtraction, AnalyzerImageUnpacking,
	} {
		limits, err := DefaultResourceLimits(kind)
		if err != nil {
			t.Fatalf("DefaultResourceLimits(%q) error = %v", kind, err)
		}
		if err := limits.validate(); err != nil {
			t.Fatalf("DefaultResourceLimits(%q) invalid: %v", kind, err)
		}
		if limits.MaxFacts != 50000 {
			t.Fatalf("DefaultResourceLimits(%q).MaxFacts = %d, want 50000", kind, limits.MaxFacts)
		}
	}
	for _, kind := range []AnalyzerKind{AnalyzerVulnerabilityMatching, "no_such_analyzer"} {
		if _, err := DefaultResourceLimits(kind); err == nil {
			t.Fatalf("DefaultResourceLimits(%q) error = nil, want rejection", kind)
		}
	}
}

// TestClaimInputValidateRejectsEachDefect proves every claim input invariant
// fails closed.
func TestClaimInputValidateRejectsEachDefect(t *testing.T) {
	t.Parallel()

	mutations := map[string]func(*ClaimInput){
		"work item":       func(in *ClaimInput) { in.WorkItemID = " " },
		"claim":           func(in *ClaimInput) { in.ClaimID = "" },
		"fencing":         func(in *ClaimInput) { in.FencingToken = 0 },
		"owner":           func(in *ClaimInput) { in.OwnerID = "" },
		"analyzer blank":  func(in *ClaimInput) { in.Analyzer = "" },
		"analyzer":        func(in *ClaimInput) { in.Analyzer = "no_such_analyzer" },
		"reducer lane":    func(in *ClaimInput) { in.Analyzer = AnalyzerSecurityPriority },
		"cpu":             func(in *ClaimInput) { in.Limits.CPUMillis = 0 },
		"memory":          func(in *ClaimInput) { in.Limits.MemoryBytes = 0 },
		"timeout":         func(in *ClaimInput) { in.Limits.Timeout = 0 },
		"input bytes":     func(in *ClaimInput) { in.Limits.MaxInputBytes = 0 },
		"files":           func(in *ClaimInput) { in.Limits.MaxFiles = 0 },
		"facts":           func(in *ClaimInput) { in.Limits.MaxFacts = 0 },
		"generation":      func(in *ClaimInput) { in.GenerationID = "other" },
		"observed":        func(in *ClaimInput) { in.ObservedAt = time.Time{} },
		"locator blank":   func(in *ClaimInput) { in.Target.LocatorHash = "" },
		"locator prefix":  func(in *ClaimInput) { in.Target.LocatorHash = "md5:abc" },
		"locator length":  func(in *ClaimInput) { in.Target.LocatorHash = "sha256:abc" },
		"locator charset": func(in *ClaimInput) { in.Target.LocatorHash = "sha256:" + strings.Repeat("z", 64) },
	}
	for name, mutate := range mutations {
		input := testClaimInput(t)
		mutate(&input)
		if err := input.validate(); err == nil {
			t.Fatalf("%s: validate() error = nil, want rejection", name)
		}
	}
	if !isAllowedTargetKind(TargetArtifact) || isAllowedTargetKind("bucket") {
		t.Fatal("isAllowedTargetKind() accepted an unknown kind or rejected artifact")
	}
}

// TestValidateFactOutputRejectsEachDefect proves output and per-fact
// invariants fail closed before any page is emitted.
func TestValidateFactOutputRejectsEachDefect(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	good := func() facts.Envelope {
		return facts.Envelope{
			FactID: "fact-1", ScopeID: input.Target.ScopeID, GenerationID: input.GenerationID,
			FactKind: chain.VulnerabilityOSPackageFactKind, StableFactKey: "key-1",
			SchemaVersion: chain.VulnerabilityIntelligenceSchemaVersionV1, CollectorKind: "os_package_vulnerability",
			FencingToken: input.FencingToken, SourceConfidence: facts.SourceConfidenceReported, ObservedAt: input.ObservedAt,
			SourceRef: facts.Ref{
				SourceSystem: string(scope.CollectorScannerWorker), ScopeID: input.Target.ScopeID,
				GenerationID: input.GenerationID, FactKey: "key-1",
			},
		}
	}
	if err := ValidateFactOutput(input, FactOutput{TargetCount: 1, ResultCount: 1, Facts: []facts.Envelope{good()}}); err != nil {
		t.Fatalf("ValidateFactOutput(good) error = %v", err)
	}
	outputs := map[string]FactOutput{
		"targets":        {TargetCount: 0, Facts: []facts.Envelope{good()}},
		"negative count": {TargetCount: 1, ResultCount: -1, Facts: []facts.Envelope{good()}},
		"result above":   {TargetCount: 1, ResultCount: 2, Facts: []facts.Envelope{good()}},
	}
	for name, output := range outputs {
		if err := ValidateFactOutput(input, output); err == nil {
			t.Fatalf("%s: ValidateFactOutput() error = nil, want rejection", name)
		}
	}
	capped := input
	capped.Limits.MaxFacts = 1
	if err := ValidateFactOutput(capped, FactOutput{TargetCount: 1, Facts: []facts.Envelope{good(), good()}}); err == nil {
		t.Fatal("ValidateFactOutput(above max_facts) error = nil, want rejection")
	}
	if err := ValidateFactOutput(ClaimInput{}, FactOutput{TargetCount: 1, Facts: []facts.Envelope{good()}}); err == nil {
		t.Fatal("ValidateFactOutput(invalid input) error = nil, want rejection")
	}
	mutations := map[string]func(*facts.Envelope){
		"reducer kind":     func(f *facts.Envelope) { f.FactKind = "reducer.finding" },
		"unknown kind":     func(f *facts.Envelope) { f.FactKind = "git.commit" },
		"fact id":          func(f *facts.Envelope) { f.FactID = " " },
		"scope":            func(f *facts.Envelope) { f.ScopeID = "other" },
		"generation":       func(f *facts.Envelope) { f.GenerationID = "other" },
		"collector blank":  func(f *facts.Envelope) { f.CollectorKind = " " },
		"collector spaced": func(f *facts.Envelope) { f.CollectorKind = " os " },
		"fencing":          func(f *facts.Envelope) { f.FencingToken = 99 },
		"confidence":       func(f *facts.Envelope) { f.SourceConfidence = "guessed" },
		"derived":          func(f *facts.Envelope) { f.SourceConfidence = facts.SourceConfidenceDerived },
		"observed":         func(f *facts.Envelope) { f.ObservedAt = time.Time{} },
		"stable key":       func(f *facts.Envelope) { f.StableFactKey = "" },
		"schema":           func(f *facts.Envelope) { f.SchemaVersion = "9.9.9" },
		"system blank":     func(f *facts.Envelope) { f.SourceRef.SourceSystem = "" },
		"system spaced":    func(f *facts.Envelope) { f.SourceRef.SourceSystem = " scanner_worker " },
		"system foreign":   func(f *facts.Envelope) { f.SourceRef.SourceSystem = "git" },
		"ref scope blank":  func(f *facts.Envelope) { f.SourceRef.ScopeID = "" },
		"ref scope":        func(f *facts.Envelope) { f.SourceRef.ScopeID = "other" },
		"ref gen blank":    func(f *facts.Envelope) { f.SourceRef.GenerationID = "" },
		"ref gen":          func(f *facts.Envelope) { f.SourceRef.GenerationID = "other" },
		"ref key":          func(f *facts.Envelope) { f.SourceRef.FactKey = "" },
	}
	for name, mutate := range mutations {
		fact := good()
		mutate(&fact)
		if err := ValidateFactOutput(input, FactOutput{TargetCount: 1, Facts: []facts.Envelope{fact}}); err == nil {
			t.Fatalf("%s: ValidateFactOutput() error = nil, want rejection", name)
		}
	}
	sbom := good()
	sbom.FactKind = chain.SBOMDocumentFactKind
	sbom.SchemaVersion = chain.SBOMAttestationSchemaVersionV1
	if err := ValidateFactOutput(input, FactOutput{TargetCount: 1, Facts: []facts.Envelope{sbom}}); err != nil {
		t.Fatalf("ValidateFactOutput(sbom.document) error = %v, want SBOM source facts accepted", err)
	}
	if _, ok := sourceFactSchemaVersion("git.commit"); ok {
		t.Fatal("sourceFactSchemaVersion(git.commit) ok = true, want false")
	}
	for _, kind := range []string{facts.ScannerWorkerAnalysisFactKind, chain.SBOMDocumentFactKind} {
		if _, ok := sourceFactSchemaVersion(kind); !ok {
			t.Fatalf("sourceFactSchemaVersion(%q) ok = false, want a scanner source schema", kind)
		}
	}
}

// TestSplitFactOutputRejectsUnpageableInput proves empty output, a
// non-positive bound, and an unprojectable fact fail closed.
func TestSplitFactOutputRejectsUnpageableInput(t *testing.T) {
	t.Parallel()

	if _, err := SplitFactOutput(FactOutput{}, 1024); err == nil {
		t.Fatal("SplitFactOutput(empty) error = nil, want rejection")
	}
	one := FactOutput{TargetCount: 1, Facts: []facts.Envelope{{SourceConfidence: facts.SourceConfidenceReported}}}
	if _, err := SplitFactOutput(one, 0); err == nil {
		t.Fatal("SplitFactOutput(bound 0) error = nil, want rejection")
	}
	bad := FactOutput{TargetCount: 1, Facts: []facts.Envelope{{SourceConfidence: facts.SourceConfidenceUnknown}}}
	if _, err := SplitFactOutput(bad, 1024); err == nil {
		t.Fatal("SplitFactOutput(unprojectable) error = nil, want rejection")
	}
	unmarshalable := FactOutput{TargetCount: 1, Facts: []facts.Envelope{{
		SourceConfidence: facts.SourceConfidenceReported,
		Payload:          map[string]any{"bad": make(chan int)},
	}}}
	if _, err := SplitFactOutput(unmarshalable, 1024); err == nil {
		t.Fatal("SplitFactOutput(unmarshalable payload) error = nil, want rejection")
	}
}

// TestFailureVocabularyRejectsUnknownValues proves blank or unknown failure
// classes and dispositions fail closed.
func TestFailureVocabularyRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	if err := FailureClass("").validate(); err == nil {
		t.Fatal("blank failure class accepted")
	}
	if _, err := FailureDisposition("maybe").retryable(); err == nil {
		t.Fatal("unknown disposition accepted")
	}
	input := testClaimInput(t)
	if _, err := FailurePayloadFor(input, FailureRetryable, FailureClassTimeout, ResourceUsage{CPUSeconds: -1}); err == nil {
		t.Fatal("negative cpu accepted")
	}
	if _, err := FailurePayloadFor(input, FailureRetryable, FailureClassTimeout, ResourceUsage{PeakMemoryBytes: -1}); err == nil {
		t.Fatal("negative memory accepted")
	}
	if _, err := FailurePayloadFor(input, "maybe", FailureClassTimeout, ResourceUsage{}); err == nil {
		t.Fatal("unknown disposition accepted by payload")
	}
	if _, err := FailurePayloadFor(ClaimInput{}, FailureRetryable, FailureClassTimeout, ResourceUsage{}); err == nil {
		t.Fatal("invalid input accepted by payload")
	}
}
