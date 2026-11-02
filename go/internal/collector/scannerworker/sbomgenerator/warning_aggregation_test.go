// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"context"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

func TestAnalyzerAggregatesRepeatedComponentMissingIdentityWarnings(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	components := []Component{
		{PURL: "pkg:npm/kept@1.0.0", Name: "kept", Version: "1.0.0"},
	}
	for range 25 {
		components = append(components, Component{Type: "library"})
	}
	source := &stubSource{
		inventory: Inventory{
			SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
			Components:    components,
		},
	}
	analyzer := Analyzer{Source: source, Now: testClock}

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	warnings := warningFactsWithReason(result.Output.Facts, WarningReasonComponentMissingIdentity)
	if got, want := len(warnings), 1; got != want {
		t.Fatalf("component_missing_identity warnings = %d, want %d", got, want)
	}
	warning := warnings[0]
	if got, want := warning.Payload["occurrence_count"], 25; got != want {
		t.Fatalf("occurrence_count = %#v, want %#v", got, want)
	}
	samples, ok := warning.Payload["sample_component_indexes"].([]int)
	if !ok {
		t.Fatalf("sample_component_indexes = %T, want []int", warning.Payload["sample_component_indexes"])
	}
	if got, want := len(samples), 5; got != want {
		t.Fatalf("sample_component_indexes len = %d, want %d", got, want)
	}
	if got, want := samples[0], 1; got != want {
		t.Fatalf("first sample index = %d, want %d", got, want)
	}
	if summary, _ := warning.Payload["summary"].(string); !strings.Contains(summary, "25 components missing") {
		t.Fatalf("summary = %q, want aggregate count", summary)
	}
	counts := countFactKinds(result.Output.Facts)
	if got, want := counts[chain.SBOMComponentFactKind], 1; got != want {
		t.Fatalf("component facts = %d, want %d", got, want)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
}

func TestAnalyzerAllowsAggregatedMissingIdentityWarningsWithinFactLimit(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	input.Limits.MaxFacts = 3
	components := make([]Component, 0, 26)
	for range 25 {
		components = append(components, Component{Type: "library"})
	}
	components = append(components, Component{PURL: "pkg:npm/kept@1.0.0", Name: "kept", Version: "1.0.0"})
	source := &stubSource{
		inventory: Inventory{
			SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
			Components:    components,
		},
	}
	analyzer := Analyzer{Source: source, Now: testClock}

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil when aggregate output fits max_facts", err)
	}
	if got, want := len(result.Output.Facts), 3; got != want {
		t.Fatalf("facts len = %d, want %d", got, want)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
}

func TestAnalyzerAllowsSingleComponentAtExactFactLimit(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	input.Limits.MaxFacts = 2
	source := &stubSource{
		inventory: Inventory{
			SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
			Components: []Component{
				{PURL: "pkg:npm/kept@1.0.0", Name: "kept", Version: "1.0.0"},
			},
		},
	}
	analyzer := Analyzer{Source: source, Now: testClock}

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil when exact output fits max_facts", err)
	}
	if got, want := len(result.Output.Facts), 2; got != want {
		t.Fatalf("facts len = %d, want %d", got, want)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v, want nil", err)
	}
}

func warningFactsWithReason(envelopes []facts.Envelope, reason string) []facts.Envelope {
	out := make([]facts.Envelope, 0)
	for _, env := range envelopes {
		if env.FactKind != chain.SBOMWarningFactKind {
			continue
		}
		if got, _ := env.Payload["reason"].(string); got == reason {
			out = append(out, env)
		}
	}
	return out
}

func BenchmarkAnalyzerAggregatedMissingIdentityWarnings(b *testing.B) {
	input := benchmarkClaimInput(b)
	components := make([]Component, 0, 10001)
	components = append(components, Component{PURL: "pkg:npm/kept@1.0.0", Name: "kept", Version: "1.0.0"})
	for range 10000 {
		components = append(components, Component{Type: "library"})
	}
	source := &stubSource{
		inventory: Inventory{
			SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
			Components:    components,
		},
	}
	analyzer := Analyzer{Source: source, Now: testClock}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		result, err := analyzer.Analyze(context.Background(), input)
		if err != nil {
			b.Fatalf("Analyze() error = %v, want nil", err)
		}
		counts := countFactKinds(result.Output.Facts)
		if counts[chain.SBOMWarningFactKind] != 1 {
			b.Fatalf("warning facts = %d, want 1", counts[chain.SBOMWarningFactKind])
		}
	}
}

func benchmarkClaimInput(b *testing.B) scannerworker.ClaimInput {
	b.Helper()
	return sbomClaimInput("scanner-worker://repository/repo-private-name", "scanner-worker:collector-scanner:work-benchmark", "scanner-worker:generation-benchmark", "claim-benchmark", 1)
}
