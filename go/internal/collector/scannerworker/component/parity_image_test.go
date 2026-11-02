// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/imageanalyzer"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

const (
	parityImageReference = "registry.example/parity:1.0"
	parityImageDigest    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func parityImageTargets(rootfs string) []imageanalyzer.TargetConfig {
	return []imageanalyzer.TargetConfig{{
		ScopeID:        parityScopeID,
		RootFSPath:     rootfs,
		SourceURI:      paritySourceURI,
		SourceRecordID: paritySourceRecordID,
		ImageReference: parityImageReference,
		ImageDigest:    parityImageDigest,
	}}
}

func parityImageClaim() sdkcollector.Claim {
	claim := parityClaim()
	claim.ComponentID = IDImage
	return claim
}

// TestImageGoldenEnvelopeParity proves the ported image analyzer reproduces
// the committed in-tree golden FactOutput byte for byte.
func TestImageGoldenEnvelopeParity(t *testing.T) {
	t.Parallel()

	golden := readParityGolden(t, "image")
	input, err := claimInput(parityImageClaim(), Config{AcceptanceUnitID: parityAcceptanceUnitID}, scannerworker.AnalyzerImageUnpacking, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := imageanalyzer.NewAnalyzer(imageanalyzer.AnalyzerConfig{
		CollectorInstanceID: parityInstanceID,
		Targets:             parityImageTargets(parityRootFS(t, 60)),
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), input)
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
		t.Fatalf("image FactOutput differs from golden (%d bytes vs %d golden bytes)", len(got), len(golden))
	}
	t.Logf("image: facts=%d bytes=%d golden-parity=PASS", len(result.Output.Facts), len(got))
}

// TestImageRunnerPagesMatchGolden proves the image runner's v1alpha3 pages
// equal, byte for byte, the pages built from the committed golden (only
// statuses[].source_latency_ms is zeroed, as for osruntime).
func TestImageRunnerPagesMatchGolden(t *testing.T) {
	t.Parallel()

	var golden []facts.Envelope
	if err := json.Unmarshal(readParityGolden(t, "image"), &golden); err != nil {
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

	rootfs := parityRootFS(t, 60)
	targets := make([]any, 0, 1)
	for _, target := range parityImageTargets(rootfs) {
		targets = append(targets, target)
	}
	config := map[string]any{"targets": targets, "acceptance_unit_id": parityAcceptanceUnitID, "page_bound_bytes": parityPageBound}
	var cursor *sdkcollector.PageContinuation
	for index := range wantPages {
		var stdout bytes.Buffer
		runner := Runner{
			ComponentID: IDImage,
			Stdin:       bytes.NewReader(testRequestWithContinuation(t, parityImageClaim(), config, cursor)),
			Stdout:      &stdout,
			Clock:       parityObservedAt,
		}
		if err := runner.Run(context.Background()); err != nil {
			t.Fatalf("Run() page %d error = %v", index, err)
		}
		got := decodePage(t, stdout.Bytes())
		want := sdkcollector.Result{
			ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
			State:           sdkcollector.ResultComplete,
			Claim:           parityImageClaim(),
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
	t.Logf("image: facts=%d pages=%d runner-page-parity=PASS", len(wire), len(wantPages))
}
