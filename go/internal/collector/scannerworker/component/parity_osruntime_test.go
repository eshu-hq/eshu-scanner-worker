// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// The parity inputs below rebuild the eshu pre-removal parity driver
// (extensionhost/analyzer_parity_test.go at eshu aa95dbcdac^) that captured
// testdata/scanner-parity/osruntime.json. See testdata/scanner-parity/PROVENANCE.md.
const (
	parityScopeID          = "image://registry.example/parity@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	parityAcceptanceUnitID = "image:sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	parityGenerationID     = "scanner-worker:generation-parity"
	parityInstanceID       = "scanner-parity"
	paritySourceURI        = "oci://registry.example/parity@sha256:deadbeef"
	paritySourceRecordID   = "sha256:deadbeef"
	// parityPageBound matches the core parity bound so the golden splits
	// into several pages and exercises the continuation path.
	parityPageBound = int64(8 * 1024)
)

func parityObservedAt() time.Time {
	return time.Date(2026, time.July, 8, 12, 0, 0, 0, time.UTC)
}

// parityRootFS writes the 60-package synthetic Alpine rootfs the core driver
// built (parityRootFS(t, 60)).
func parityRootFS(t *testing.T, packages int) string {
	t.Helper()

	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	write("etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\n")
	write("etc/apk/repositories", "https://dl-cdn.alpinelinux.org/alpine/v3.19/main\n")
	var db strings.Builder
	for i := 0; i < packages; i++ {
		fmt.Fprintf(&db, "P:parity-pkg-%04d\nV:3.1.4-r5\nA:x86_64\no:parity-pkg-%04d\n\n", i, i)
	}
	write("lib/apk/db/installed", db.String())
	return root
}

func parityClaim() sdkcollector.Claim {
	return sdkcollector.Claim{
		ComponentID:   IDOSRuntime,
		InstanceID:    parityInstanceID,
		CollectorKind: "scanner_worker",
		SourceSystem:  "scanner_worker",
		Scope:         sdkcollector.Scope{ID: parityScopeID, Kind: "repository"},
		SourceRunID:   parityGenerationID,
		GenerationID:  parityGenerationID,
		WorkItemID:    "scanner-worker:parity:work-1",
		FencingToken:  "13",
		Attempt:       1,
		Deadline:      parityObservedAt().Add(2 * time.Minute),
		ConfigHandle:  "cfg-parity",
	}
}

func parityTargets(rootfs string) []osruntime.TargetConfig {
	return []osruntime.TargetConfig{{
		ScopeID:        parityScopeID,
		RootFSPath:     rootfs,
		SourceURI:      paritySourceURI,
		SourceRecordID: paritySourceRecordID,
	}}
}

func readParityGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "scanner-parity", name+".json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	return raw
}

// TestOSRuntimeGoldenEnvelopeParity proves the ported osruntime analyzer
// reproduces the committed in-tree golden FactOutput byte for byte.
func TestOSRuntimeGoldenEnvelopeParity(t *testing.T) {
	t.Parallel()

	golden := readParityGolden(t, "osruntime")
	config := Config{AcceptanceUnitID: parityAcceptanceUnitID}
	input, err := claimInput(parityClaim(), config, scannerworker.AnalyzerOSPackageExtraction, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := osruntime.NewAnalyzer(osruntime.AnalyzerConfig{
		CollectorInstanceID: parityInstanceID,
		Targets:             parityTargets(parityRootFS(t, 60)),
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
		t.Fatalf("osruntime FactOutput differs from golden (%d bytes vs %d golden bytes)", len(got), len(golden))
	}
	t.Logf("osruntime: facts=%d bytes=%d golden-parity=PASS", len(result.Output.Facts), len(got))
}

// runParityPages drives the runner through every continuation call and
// returns each decoded stdout page.
func runParityPages(t *testing.T, rootfs string) []sdkcollector.Result {
	t.Helper()

	var targets []json.RawMessage
	for _, target := range parityTargets(rootfs) {
		raw, err := json.Marshal(target)
		if err != nil {
			t.Fatalf("marshal target: %v", err)
		}
		targets = append(targets, raw)
	}
	var pages []sdkcollector.Result
	cursor := ""
	for call := 0; call <= maxPagesPerClaim; call++ {
		req := map[string]any{
			"protocol_version": sdkcollector.ProtocolVersionV1Alpha3,
			"claim":            parityClaim(),
			"config": map[string]any{
				"targets":            targets,
				"acceptance_unit_id": parityAcceptanceUnitID,
				"page_bound_bytes":   parityPageBound,
			},
		}
		if cursor != "" {
			req["continuation"] = map[string]any{"cursor": cursor}
		}
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		var stdout bytes.Buffer
		runner := Runner{
			ComponentID: IDOSRuntime,
			Stdin:       bytes.NewReader(raw),
			Stdout:      &stdout,
			Clock:       parityObservedAt,
		}
		if err := runner.Run(context.Background()); err != nil {
			t.Fatalf("Run() call %d error = %v", call, err)
		}
		decoder := json.NewDecoder(&stdout)
		decoder.DisallowUnknownFields()
		var page sdkcollector.Result
		if err := decoder.Decode(&page); err != nil {
			t.Fatalf("decode page %d: %v", call, err)
		}
		pages = append(pages, page)
		if page.Page == nil || !page.Page.More {
			return pages
		}
		cursor = page.Page.Cursor
	}
	t.Fatalf("runner did not finish within %d calls", maxPagesPerClaim)
	return nil
}

// TestOSRuntimeRunnerPagesMatchGolden proves the v1alpha3 stdout pages the
// ported runner emits equal, byte for byte, the collector.Result pages built
// from the committed golden: same facts in the same order, same page split,
// same claim echo, generation, statuses, and page envelopes. Only
// statuses[].source_latency_ms is zeroed on both sides: it is the measured
// analysis latency, not fact truth.
func TestOSRuntimeRunnerPagesMatchGolden(t *testing.T) {
	t.Parallel()

	var golden []facts.Envelope
	if err := json.Unmarshal(readParityGolden(t, "osruntime"), &golden); err != nil {
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
	if err != nil {
		t.Fatalf("SplitFacts() error = %v", err)
	}
	if len(wantPages) < 2 {
		t.Fatalf("golden pages = %d, want multi-page output at bound %d", len(wantPages), parityPageBound)
	}

	gotPages := runParityPages(t, parityRootFS(t, 60))
	if len(gotPages) != len(wantPages) {
		t.Fatalf("runner pages = %d, want %d", len(gotPages), len(wantPages))
	}
	for index, got := range gotPages {
		want := sdkcollector.Result{
			ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
			State:           sdkcollector.ResultComplete,
			Claim:           parityClaim(),
			Generation: sdkcollector.Generation{
				ID:            parityGenerationID,
				ObservedAt:    parityObservedAt(),
				FreshnessHint: "snapshot",
			},
			Facts:    wantPages[index],
			Statuses: []sdkcollector.Status{{Class: sdkcollector.StatusComplete, FactCount: len(wantPages[index])}},
			Page:     &sdkcollector.ResultPage{PageIndex: index, TotalFacts: len(wire)},
		}
		if index < len(wantPages)-1 {
			want.Page.Cursor = formatCursor(index+1, parityObservedAt())
			want.Page.More = true
		}
		for i := range got.Statuses {
			got.Statuses[i].SourceLatencyMS = 0
		}
		gotRaw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal got page %d: %v", index, err)
		}
		wantRaw, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal want page %d: %v", index, err)
		}
		if !bytes.Equal(gotRaw, wantRaw) {
			t.Fatalf("page %d differs from golden page:\n got %s\nwant %s", index, gotRaw, wantRaw)
		}
	}
	t.Logf("osruntime: facts=%d pages=%d runner-page-parity=PASS", len(wire), len(gotPages))
}
