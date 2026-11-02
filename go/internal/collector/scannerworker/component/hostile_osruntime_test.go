// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// The full-range run re-analyzes 50,000 packages on each of 17 stateless
// calls: about 13 s plain and several minutes under the race detector, which
// adds nothing to this single-goroutine paging check. It runs in the test
// lane and stays out of the race and coverage lane.

//go:build !race

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
)

// hostileFactCount is the #9380 hostile full-range size: the analyzer's
// MaxFacts ceiling, so the claim is as large as the contract allows.
const hostileFactCount = 50000

// TestOSRuntimeHostileFullRangePaging is the committed #9380 re-run for the
// osruntime component: 50,000 facts paged at the real stdout-derived bound
// (4,128,768 bytes). Every stdout document fits the host stdout limit, every
// page's facts fit the page bound, the page sequence is contiguous, and the
// reassembled facts equal one direct analysis byte for byte.
//
// The snapshot time is pinned so every stateless call sees the same input.
// With the wall-clock LocalRootFSProvider the split can drift between calls;
// that defect is tracked in eshu-hq/eshu-scanner-worker#33.
func TestOSRuntimeHostileFullRangePaging(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount)
	pinned := pinnedSnapshotProvider{at: parityCaptureTime(t)}
	bound, err := pageBound(0)
	if err != nil {
		t.Fatalf("pageBound() error = %v", err)
	}
	if bound != 4128768 {
		t.Fatalf("default page bound = %d, want 4128768", bound)
	}

	claim := parityClaim()
	config := map[string]any{
		"targets":            []any{map[string]any{"scope_id": parityScopeID, "rootfs_path": root, "source_uri": paritySourceURI, "source_record_id": paritySourceRecordID}},
		"acceptance_unit_id": parityAcceptanceUnitID,
	}
	var reassembled []sdkcollector.Fact
	var cursor *sdkcollector.PageContinuation
	for index := 0; ; index++ {
		if index >= maxPagesPerClaim {
			t.Fatalf("paging exceeded %d pages", maxPagesPerClaim)
		}
		var stdout bytes.Buffer
		runner := Runner{
			ComponentID: IDOSRuntime,
			Stdin:       bytes.NewReader(testRequestWithContinuation(t, claim, config, cursor)),
			Stdout:      &stdout,
			Clock:       parityObservedAt,
			snapshots:   pinned,
		}
		if err := runner.Run(context.Background()); err != nil {
			t.Fatalf("Run() page %d error = %v", index, err)
		}
		if int64(stdout.Len()) > DefaultStdoutLimitBytes {
			t.Fatalf("page %d stdout = %d bytes, above host limit %d", index, stdout.Len(), DefaultStdoutLimitBytes)
		}
		page := decodePage(t, stdout.Bytes())
		if page.State != sdkcollector.ResultComplete || page.Page == nil || page.Page.PageIndex != index || page.Page.TotalFacts != hostileFactCount {
			t.Fatalf("page %d state=%q envelope=%+v, want complete contiguous page of %d", index, page.State, page.Page, hostileFactCount)
		}
		var pageBytes int64
		for _, fact := range page.Facts {
			size, err := sdkcollector.FactWireBytes(fact)
			if err != nil {
				t.Fatalf("FactWireBytes() error = %v", err)
			}
			pageBytes += int64(size)
		}
		if pageBytes > bound {
			t.Fatalf("page %d facts = %d bytes, above bound %d", index, pageBytes, bound)
		}
		reassembled = append(reassembled, page.Facts...)
		if !page.Page.More {
			t.Logf("hostile osruntime: facts=%d pages=%d bound=%d", len(reassembled), index+1, bound)
			break
		}
		cursor = &sdkcollector.PageContinuation{Cursor: page.Page.Cursor}
	}

	direct := directPinnedOSRuntimeFacts(t, root, pinned)
	if len(reassembled) != len(direct) {
		t.Fatalf("reassembled %d facts, want %d", len(reassembled), len(direct))
	}
	gotRaw, err := json.Marshal(reassembled)
	if err != nil {
		t.Fatalf("marshal reassembled: %v", err)
	}
	wantRaw, err := json.Marshal(direct)
	if err != nil {
		t.Fatalf("marshal direct: %v", err)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatal("reassembled facts differ from the direct analysis")
	}
}

// directPinnedOSRuntimeFacts runs one direct analysis with the same pinned
// snapshot and projects it to SDK wire facts.
func directPinnedOSRuntimeFacts(t *testing.T, root string, provider osruntime.SnapshotProvider) []sdkcollector.Fact {
	t.Helper()

	input, err := claimInput(parityClaim(), Config{AcceptanceUnitID: parityAcceptanceUnitID}, scannerworker.AnalyzerOSPackageExtraction, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := osruntime.NewAnalyzer(osruntime.AnalyzerConfig{
		CollectorInstanceID: parityInstanceID,
		Targets:             parityTargets(root),
		Provider:            provider,
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	facts := make([]sdkcollector.Fact, 0, len(result.Output.Facts))
	for _, envelope := range result.Output.Facts {
		fact, err := factenvelope.SDKFactFromInternal(envelope)
		if err != nil {
			t.Fatalf("SDKFactFromInternal() error = %v", err)
		}
		facts = append(facts, fact)
	}
	return facts
}
