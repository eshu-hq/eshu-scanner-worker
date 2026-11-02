// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/sbomgenerator"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

const (
	paritySBOMScopeID          = "scanner-worker://repository/parity-repo"
	paritySBOMAcceptanceUnitID = "repository:parity-repo"
)

// paritySBOMSource returns the synthetic inventory the core parity driver
// captured (paritySBOMOutput at eshu aa95dbcdac^).
type paritySBOMSource struct{}

func (paritySBOMSource) Collect(context.Context, scannerworker.ClaimInput) (sbomgenerator.Inventory, error) {
	var components []sbomgenerator.Component
	for i := 0; i < 40; i++ {
		name := fmt.Sprintf("parity-pkg-%04d", i)
		components = append(components, sbomgenerator.Component{
			PURL: "pkg:npm/" + name + "@1.2.3", Name: name, Version: "1.2.3", Type: "library",
			BomRef: fmt.Sprintf("parity-bom-%04d", i), Ecosystem: "npm", EvidenceSource: "repository_lockfile",
			LockfilePath: "package-lock.json", DependencyScope: "dependencies", DependencyType: "runtime",
			ExtractionReason: "lockfile_parsed",
		})
	}
	return sbomgenerator.Inventory{
		SubjectDigest: "sha256:11111111111111111111111111111111111111111111111111111111111111aa",
		SpecVersion:   "1.6",
		SourceTool:    "eshu_scanner_sbom_generator 0.0.1",
		FileCount:     10,
		InputBytes:    1024,
		Components:    components,
	}, nil
}

func paritySBOMClaim() sdkcollector.Claim {
	claim := parityClaim()
	claim.ComponentID = IDSBOM
	claim.Scope.ID = paritySBOMScopeID
	return claim
}

// TestSBOMGoldenEnvelopeParity proves the ported SBOM analyzer reproduces the
// committed in-tree golden FactOutput byte for byte.
func TestSBOMGoldenEnvelopeParity(t *testing.T) {
	t.Parallel()

	golden := readParityGolden(t, "sbom")
	input, err := claimInput(paritySBOMClaim(), Config{AcceptanceUnitID: paritySBOMAcceptanceUnitID}, scannerworker.AnalyzerSBOMGeneration, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	result, err := sbomgenerator.Analyzer{Source: paritySBOMSource{}, Now: parityObservedAt}.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if err := scannerworker.ValidateFactOutput(input, result.Output); err != nil {
		t.Fatalf("ValidateFactOutput() error = %v", err)
	}
	got, err := json.MarshalIndent(result.Output.Facts, "", "  ")
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, golden) {
		t.Fatalf("sbom FactOutput differs from golden (%d bytes vs %d golden bytes)", len(got), len(golden))
	}
	t.Logf("sbom: facts=%d bytes=%d golden-parity=PASS", len(result.Output.Facts), len(got))
}

// TestSBOMRunnerPagesMatchGolden proves the SBOM runner's v1alpha3 pages
// equal, byte for byte, the pages built from the committed golden (only
// statuses[].source_latency_ms is zeroed).
func TestSBOMRunnerPagesMatchGolden(t *testing.T) {
	t.Parallel()

	var golden []facts.Envelope
	if err := json.Unmarshal(readParityGolden(t, "sbom"), &golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	wire := make([]sdkcollector.Fact, 0, len(golden))
	for i, envelope := range golden {
		fact, err := factenvelope.SDKFactFromInternal(envelope)
		if err != nil {
			t.Fatalf("SDKFactFromInternal(golden[%d]) error = %v", i, err)
		}
		wire = append(wire, fact)
	}
	wantPages, err := sdkcollector.SplitFacts(wire, parityPageBound)
	if err != nil || len(wantPages) < 2 {
		t.Fatalf("SplitFacts() pages=%d err=%v, want multi-page", len(wantPages), err)
	}
	config := map[string]any{
		"targets":            []any{map[string]any{"scope_id": paritySBOMScopeID, "root_path": t.TempDir()}},
		"acceptance_unit_id": paritySBOMAcceptanceUnitID,
		"page_bound_bytes":   parityPageBound,
	}
	var cursor *sdkcollector.PageContinuation
	for index := range wantPages {
		var stdout bytes.Buffer
		runner := Runner{
			ComponentID: IDSBOM,
			Stdin:       bytes.NewReader(testRequestWithContinuation(t, paritySBOMClaim(), config, cursor)),
			Stdout:      &stdout,
			Clock:       parityObservedAt,
			inventory:   paritySBOMSource{},
		}
		if err := runner.Run(context.Background()); err != nil {
			t.Fatalf("Run() page %d error = %v", index, err)
		}
		got := decodePage(t, stdout.Bytes())
		want := sdkcollector.Result{
			ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
			State:           sdkcollector.ResultComplete,
			Claim:           paritySBOMClaim(),
			Generation:      sdkcollector.Generation{ID: parityGenerationID, ObservedAt: parityObservedAt(), FreshnessHint: "snapshot"},
			Facts:           wantPages[index],
			Statuses:        []sdkcollector.Status{{Class: sdkcollector.StatusComplete, FactCount: len(wantPages[index])}},
			Page:            &sdkcollector.ResultPage{PageIndex: index, TotalFacts: len(wire)},
		}
		if index < len(wantPages)-1 {
			want.Page.Cursor = formatCursor(index+1, parityObservedAt())
			want.Page.More = true
		}
		for i := range got.Statuses {
			got.Statuses[i].SourceLatencyMS = 0
		}
		gotRaw, _ := json.Marshal(got)
		wantRaw, _ := json.Marshal(want)
		if !bytes.Equal(gotRaw, wantRaw) {
			t.Fatalf("page %d differs from golden page:\n got %s\nwant %s", index, gotRaw, wantRaw)
		}
		if got.Page != nil && got.Page.More {
			cursor = &sdkcollector.PageContinuation{Cursor: got.Page.Cursor}
		}
	}
	t.Logf("sbom: facts=%d pages=%d runner-page-parity=PASS", len(wire), len(wantPages))
}
