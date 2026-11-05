// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// typedWire validates one fact against the pinned schemas and returns the envelope
// a typed reader decodes. A typed read is the point of the factschema v0.1.0-rc.17
// pin: the reducer joins a warning and a verdict on these fields, not on raw JSON.
func typedWire(t *testing.T, fact facts.Envelope) factschema.Envelope {
	t.Helper()

	wire, err := factenvelope.SDKFactFromInternal(fact)
	if err != nil {
		t.Fatalf("SDKFactFromInternal: %v", err)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), sdkcollector.Result{Facts: []sdkcollector.Fact{wire}}); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	return factschema.Envelope{FactKind: wire.Kind, SchemaVersion: wire.SchemaVersion, Payload: wire.Payload}
}

// TestWarningDecodesTheTypedJoinKeys proves a typed reader gets the two keys the
// warning join uses, and that a whole-repository warning leaves the path absent.
func TestWarningDecodesTheTypedJoinKeys(t *testing.T) {
	t.Parallel()

	emit := emitContext{input: testInput(t), instanceID: "instance-1", repositoryID: testRepositoryID, commitSHA: "abc"}
	typed, err := factschema.DecodeScannerWorkerWarning(typedWire(t, emit.warningFact(warningGoModParseFailed, "tools/go.mod")))
	if err != nil {
		t.Fatalf("DecodeScannerWorkerWarning() error = %v", err)
	}
	if typed.RepositoryID == nil || *typed.RepositoryID != testRepositoryID {
		t.Fatalf("RepositoryID = %v", typed.RepositoryID)
	}
	if typed.RelativePath == nil || *typed.RelativePath != "tools/go.mod" {
		t.Fatalf("RelativePath = %v", typed.RelativePath)
	}
	whole, err := factschema.DecodeScannerWorkerWarning(typedWire(t, emit.warningFact(warningNoGoModules, "")))
	if err != nil {
		t.Fatalf("DecodeScannerWorkerWarning() error = %v", err)
	}
	if whole.RelativePath != nil {
		t.Fatalf("RelativePath = %q, want absent on a whole-repository warning", *whole.RelativePath)
	}
}

// TestReachabilityFactDecodesTheTypedProvenance proves a typed reader gets the fields
// that say how much a not_called answer is worth.
func TestReachabilityFactDecodesTheTypedProvenance(t *testing.T) {
	t.Parallel()

	input := StageInput{Claim: testInput(t), InstanceID: "instance-1", RepositoryID: testRepositoryID, SourceCommitSHA: "abc", SourceURI: "https://github.com/o/r"}
	config := &scanConfig{ScannerVersion: "v1.9.0", ScanLevel: "symbol", ScanMode: "source"}
	fact := input.reachabilityFact(Module{RelativePath: "go.mod", Dir: "."}, config, foldedFinding{osv: "GO-2021-0113", module: "example.test/dep", level: "not_called", traceCount: 0})
	typed, err := factschema.DecodeVulnerabilityGoCallReachability(typedWire(t, fact))
	if err != nil {
		t.Fatalf("DecodeVulnerabilityGoCallReachability() error = %v", err)
	}
	for name, got := range map[string]struct {
		field *string
		want  string
	}{
		"scan_level":        {typed.ScanLevel, "symbol"},
		"scan_mode":         {typed.ScanMode, "source"},
		"scanner_version":   {typed.ScannerVersion, "v1.9.0"},
		"source_commit_sha": {typed.SourceCommitSHA, "abc"},
		"deepest_module":    {typed.DeepestModule, "example.test/dep"},
	} {
		if got.field == nil || *got.field != got.want {
			t.Errorf("%s = %v, want %q", name, got.field, got.want)
		}
	}
	if typed.TraceCount == nil || *typed.TraceCount != 0 {
		t.Errorf("TraceCount = %v, want a present zero", typed.TraceCount)
	}
}
