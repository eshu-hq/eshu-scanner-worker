// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/packageidentity"
)

type fixedInventory struct {
	inventory Inventory
	err       error
}

func (s fixedInventory) Collect(context.Context, scannerworker.ClaimInput) (Inventory, error) {
	return s.inventory, s.err
}

func npmComponents(n int) []Component {
	components := make([]Component, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("pkg-%03d", i)
		components = append(components, Component{PURL: "pkg:npm/" + name + "@1.0.0", Name: name, Version: "1.0.0", Ecosystem: "npm"})
	}
	return components
}

func assertSBOMFailure(t *testing.T, err error, class scannerworker.FailureClass) {
	t.Helper()
	var failure scannerworker.AnalyzerFailure
	if !errors.As(err, &failure) || failure.FailureClass() != class {
		t.Fatalf("error = %v, want %s", err, class)
	}
}

// TestAnalyzerSourceAndClockEdges proves a missing source fails terminal, an
// existing analyzer failure from the source passes through unchanged, and a
// nil clock still stamps facts.
func TestAnalyzerSourceAndClockEdges(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	_, err := Analyzer{}.Analyze(context.Background(), input)
	assertSBOMFailure(t, err, scannerworker.FailureClassAnalyzerFailed)

	passthrough := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassTimeout, scannerworker.ResourceUsage{}, nil)
	_, err = Analyzer{Source: fixedInventory{err: passthrough}}.Analyze(context.Background(), input)
	assertSBOMFailure(t, err, scannerworker.FailureClassTimeout)

	result, err := Analyzer{Source: fixedInventory{inventory: Inventory{Components: npmComponents(1)}}}.Analyze(context.Background(), input)
	if err != nil || result.Output.Facts[0].ObservedAt.IsZero() {
		t.Fatalf("Analyze(nil clock) = %v, want stamped facts", err)
	}
}

// TestAnalyzerFactCeilings proves the precheck, the component-loop bound,
// and the final count each fail terminal before emitting above max_facts,
// and blank inventory warnings are dropped rather than emitted.
func TestAnalyzerFactCeilings(t *testing.T) {
	t.Parallel()

	analyze := func(inventory Inventory, maxFacts int) (scannerworker.AnalyzerResult, error) {
		input := testClaimInput(t)
		input.Limits.MaxFacts = maxFacts
		return Analyzer{Source: fixedInventory{inventory: inventory}, Now: testClock}.Analyze(context.Background(), input)
	}
	_, err := analyze(Inventory{}, 1)
	assertSBOMFailure(t, err, scannerworker.FailureClassFactLimitExceeded)
	_, err = analyze(Inventory{SubjectDigest: "sha256:" + strings.Repeat("a", 64), Components: npmComponents(5)}, 3)
	assertSBOMFailure(t, err, scannerworker.FailureClassFactLimitExceeded)

	result, err := analyze(Inventory{
		SubjectDigest: "sha256:" + strings.Repeat("a", 64),
		Components:    npmComponents(1),
		Warnings:      []Warning{{Reason: "  ", Summary: "dropped"}},
	}, 100)
	if err != nil || len(result.Output.Facts) != 2 {
		t.Fatalf("Analyze(blank warning) facts=%d err=%v, want document and component only", len(result.Output.Facts), err)
	}
}

// TestLockfileHelperEdges pins the bounded parse-error text, the registry
// default, Maven coordinate splitting, npm path helpers, Gradle and Poetry
// edge lines, and the sorted-unique helper.
func TestLockfileHelperEdges(t *testing.T) {
	t.Parallel()

	if boundedParseError(nil) != "malformed" || boundedParseError(errors.New("  ")) != "malformed" {
		t.Fatal("boundedParseError() did not default blank errors")
	}
	if got := boundedParseError(errors.New(strings.Repeat("x", 200))); len(got) != 120 {
		t.Fatalf("boundedParseError(long) length = %d, want 120", len(got))
	}
	if registryForEcosystem("swift") != "scanner-worker.local" {
		t.Fatal("registryForEcosystem(unknown) did not default")
	}
	if packageRawName(packageidentity.EcosystemMaven, "no-colon") != "no-colon" || mavenNamespace(packageidentity.EcosystemMaven, "no-colon") != "" {
		t.Fatal("maven helpers mishandled a coordinate without a group")
	}
	if npmDependencyType("node_modules/a/node_modules/b") != "transitive" || npmNameFromPackagePath("lib/a") != "" {
		t.Fatal("npm path helpers mishandled nested or non-node_modules paths")
	}
	if _, ok := newLockfileComponent(packageidentity.EcosystemNPM, "", "1.0.0", "p", "", ""); ok {
		t.Fatal("newLockfileComponent(blank name) ok = true")
	}
	gradle := parseGradleLockfileComponents("gradle.lockfile", []byte("# c\nempty=empty\nno-equals\nbad:coord=runtimeClasspath\norg.slf4j:slf4j-api:2.0.9=runtimeClasspath\n"))
	if len(gradle) != 1 || gradle[0].DependencyScope != "runtimeClasspath" {
		t.Fatalf("gradle components = %+v, want one runtimeClasspath component", gradle)
	}
	if !poetryRegistrySource("Legacy") || poetryRegistrySource("git") {
		t.Fatal("poetryRegistrySource() misclassified a source type")
	}
	if got := uniqueNonBlankSorted([]string{"c", " ", "a", "c", "b"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("uniqueNonBlankSorted() = %v, want a,b,c", got)
	}
}
