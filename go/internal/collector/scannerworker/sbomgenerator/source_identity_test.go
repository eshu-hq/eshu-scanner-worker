// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package sbomgenerator

import (
	"context"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/scope"
)

// TestAnalyzerEmitsScopeURISourceIdentity pins the #9407 verdict: the SBOM
// inventory carries no URI, so every sbom fact projects the sanitized claim
// scope as source_ref.uri — the only URI-shaped, non-local identity in the
// claim path — with per-fact snapshot records. The SDK satellite contract
// requires uri and record_id on every fact.
func TestAnalyzerEmitsScopeURISourceIdentity(t *testing.T) {
	t.Parallel()

	input := testClaimInput(t)
	subject := "sha256:11111111111111111111111111111111111111111111111111111111111111aa"
	source := &stubSource{inventory: Inventory{
		SubjectDigest: subject,
		SpecVersion:   "1.6",
		SourceTool:    "eshu_scanner_sbom_generator 0.0.1",
		FileCount:     2,
		InputBytes:    512,
		Components: []Component{
			{PURL: "pkg:npm/foo@1.2.3", Name: "foo", Version: "1.2.3", Type: "library", BomRef: "comp-foo"},
			{PURL: "pkg:npm/bar@2.0.0", Name: "bar", Version: "2.0.0", Type: "library"},
		},
		Warnings: []Warning{{Reason: "lockfile_unsupported", Summary: "yarn v1 lockfile skipped"}},
	}}
	analyzer := Analyzer{Source: source, Now: testClock}

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	wantURI := "scanner-worker://repository/repo-private-name"
	byKind := map[string][]int{}
	for i, envelope := range result.Output.Facts {
		byKind[envelope.FactKind] = append(byKind[envelope.FactKind], i)
		if envelope.SourceRef.SourceURI != wantURI {
			t.Fatalf("%s facts[%d] SourceURI = %q, want claim scope %q",
				envelope.FactKind, i, envelope.SourceRef.SourceURI, wantURI)
		}
		if strings.TrimSpace(envelope.SourceRef.SourceRecordID) == "" {
			t.Fatalf("%s facts[%d] SourceRecordID is empty, want per-fact snapshot record",
				envelope.FactKind, i)
		}
		if envelope.SourceRef.SourceSystem != string(scope.CollectorScannerWorker) {
			t.Fatalf("%s facts[%d] SourceSystem = %q, want scanner_worker",
				envelope.FactKind, i, envelope.SourceRef.SourceSystem)
		}
	}
	doc := result.Output.Facts[byKind[chain.SBOMDocumentFactKind][0]]
	if doc.SourceRef.SourceRecordID != subject {
		t.Fatalf("document SourceRecordID = %q, want subject digest %q", doc.SourceRef.SourceRecordID, subject)
	}
	for _, i := range byKind[chain.SBOMComponentFactKind] {
		comp := result.Output.Facts[i]
		wantRecord, _ := comp.Payload["bom_ref"].(string)
		if wantRecord == "" {
			wantRecord, _ = comp.Payload["purl"].(string)
		}
		if comp.SourceRef.SourceRecordID != wantRecord {
			t.Fatalf("component %s SourceRecordID = %q, want bom_ref/purl %q",
				comp.Payload["name"], comp.SourceRef.SourceRecordID, wantRecord)
		}
	}
	if len(byKind[chain.SBOMWarningFactKind]) != 1 {
		t.Fatalf("warning facts = %d, want 1", len(byKind[chain.SBOMWarningFactKind]))
	}
}

// TestAnalyzerStripsCredentialsFromScopeURI proves a credentialed claim scope
// never reaches source_ref verbatim: the projected URI is sanitized with the
// shared scanner-side redaction.
func TestAnalyzerStripsCredentialsFromScopeURI(t *testing.T) {
	t.Parallel()

	input := testClaimInputWithScope(t, "scanner-worker://repository/repo?token=secret")
	source := &stubSource{inventory: Inventory{
		SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		FileCount:     1,
		InputBytes:    128,
		Components: []Component{
			{PURL: "pkg:npm/foo@1.2.3", Name: "foo", Version: "1.2.3"},
		},
	}}
	analyzer := Analyzer{Source: source, Now: testClock}

	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v, want nil", err)
	}
	for i, envelope := range result.Output.Facts {
		if strings.Contains(envelope.SourceRef.SourceURI, "token=secret") {
			t.Fatalf("facts[%d] SourceURI leaked credentials: %q", i, envelope.SourceRef.SourceURI)
		}
		if envelope.SourceRef.SourceURI != "scanner-worker://repository/repo" {
			t.Fatalf("facts[%d] SourceURI = %q, want sanitized scope", i, envelope.SourceRef.SourceURI)
		}
	}
}

// TestAnalyzerFailsClosedWhenScopeHasNoProjectableURI proves a claim scope
// that sanitizes to nothing (authority-shaped credential, no hierarchy to
// redact) dead-letters terminally instead of emitting uri-less facts the
// satellite contract would reject.
func TestAnalyzerFailsClosedWhenScopeHasNoProjectableURI(t *testing.T) {
	t.Parallel()

	input := testClaimInputWithScope(t, "svc:SECRET@host/x")
	source := &stubSource{inventory: Inventory{
		SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		FileCount:     1,
		InputBytes:    128,
		Components: []Component{
			{PURL: "pkg:npm/foo@1.2.3", Name: "foo", Version: "1.2.3"},
		},
	}}
	analyzer := Analyzer{Source: source, Now: testClock}

	_, err := analyzer.Analyze(context.Background(), input)
	if err == nil {
		t.Fatal("Analyze() error = nil, want terminal failure for unprojectable scope identity")
	}
	failure, ok := err.(scannerworker.AnalyzerFailure)
	if !ok {
		t.Fatalf("Analyze() error type = %T, want scannerworker.AnalyzerFailure", err)
	}
	if failure.FailureClass() != scannerworker.FailureClassUnsupportedTarget {
		t.Fatalf("FailureClass() = %q, want unsupported_target", failure.FailureClass())
	}
	if failure.Retryable() {
		t.Fatal("Retryable() = true, want terminal dead-letter: retry cannot mint source identity")
	}
}

// testClaimInputWithScope mirrors testClaimInput with a caller-chosen claim
// scope, for source-identity shapes the default fixture does not cover.
func testClaimInputWithScope(t *testing.T, scopeID string) scannerworker.ClaimInput {
	t.Helper()
	return sbomClaimInput(scopeID, "scanner-worker:collector-scanner:work-1", "scanner-worker:generation-1", "claim-1", 2)
}
