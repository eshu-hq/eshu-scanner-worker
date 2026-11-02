// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Like the #9380 full-range runs this re-analyzes 50,000 facts on every
// stateless call, so it stays out of the race and coverage lane.

//go:build !race

package component

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/imageanalyzer"
)

// TestOSRuntimeMultiPageClaimSurvivesDriftingWallClock drives a 50,000
// fact osruntime claim across its pages while every call sees a different
// wall clock, through the real LocalRootFSProvider. Reassembly must neither
// lose nor duplicate a fact, and every fact must carry one observation time.
func TestOSRuntimeMultiPageClaimSurvivesDriftingWallClock(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount)
	config := map[string]any{
		"targets":            []any{map[string]any{"scope_id": parityScopeID, "rootfs_path": root, "source_uri": paritySourceURI, "source_record_id": paritySourceRecordID}},
		"acceptance_unit_id": parityAcceptanceUnitID,
	}
	want := directOSRuntimeFacts(t, root)
	assertDriftingClockPaging(t, IDOSRuntime, parityClaim(), config, want)
}

// TestImageRootFSMultiPageClaimSurvivesDriftingWallClock is the same
// check for the image component's rootfs evidence path, which reads through
// the same snapshot provider: 49,999 packages plus the analysis fact.
func TestImageRootFSMultiPageClaimSurvivesDriftingWallClock(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount-1)
	targets := parityImageTargets(root)
	config := map[string]any{"targets": []any{targets[0]}, "acceptance_unit_id": parityAcceptanceUnitID}
	input, err := claimInput(parityImageClaim(), Config{AcceptanceUnitID: parityAcceptanceUnitID}, scannerworker.AnalyzerImageUnpacking, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := imageanalyzer.NewAnalyzer(imageanalyzer.AnalyzerConfig{
		CollectorInstanceID: parityInstanceID,
		Targets:             targets,
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertDriftingClockPaging(t, IDImage, parityImageClaim(), config, projectEnvelopes(t, result.Output.Facts))
}

// assertDriftingClockPaging runs the component across all pages with a
// wall clock that differs on every call, then checks the reassembled stream against the direct analysis's fact
// identities and for one shared observation time.
func assertDriftingClockPaging(t *testing.T, componentID string, claim sdkcollector.Claim, config map[string]any, want []sdkcollector.Fact) {
	t.Helper()

	// Each stateless call sees a different wall clock, as a live host does.
	// The times differ only in trailing zeros of the RFC 3339 nanosecond
	// form, which changes fact byte sizes. Only page 0's clock may reach the
	// facts; later pages must take the time from the cursor.
	times := []time.Time{
		time.Date(2026, time.July, 8, 12, 0, 0, 123456789, time.UTC),
		time.Date(2026, time.July, 8, 12, 0, 1, 120000000, time.UTC),
	}
	var calls atomic.Int64
	got := hostileRun(t, componentID, claim, config, func(stdin []byte, stdout *bytes.Buffer) Runner {
		at := times[int(calls.Add(1)-1)%len(times)]
		return Runner{ComponentID: componentID, Stdin: bytes.NewReader(stdin), Stdout: stdout, Clock: func() time.Time { return at }}
	}, hostileFactCount)

	if len(got) != len(want) {
		t.Errorf("reassembled %d facts, want %d: pages split differently across calls", len(got), len(want))
	}
	wantKeys := make(map[string]struct{}, len(want))
	for _, fact := range want {
		wantKeys[fact.Kind+"\x00"+fact.StableKey] = struct{}{}
	}
	seen := make(map[string]struct{}, len(got))
	duplicates := 0
	observed := make(map[time.Time]int)
	for _, fact := range got {
		key := fact.Kind + "\x00" + fact.StableKey
		if _, ok := seen[key]; ok {
			duplicates++
		}
		seen[key] = struct{}{}
		observed[fact.ObservedAt]++
	}
	lost := 0
	for key := range wantKeys {
		if _, ok := seen[key]; !ok {
			lost++
		}
	}
	if lost != 0 || duplicates != 0 {
		t.Errorf("reassembly lost %d facts and duplicated %d across pages", lost, duplicates)
	}
	if len(observed) != 1 || observed[times[0]] != len(got) {
		t.Errorf("facts carry observed_at values %v, want every fact at the page 0 claim observation time %s", observed, times[0].Format(time.RFC3339Nano))
	}
}
