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

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/imageanalyzer"
)

// driftingSnapshotProvider wraps the real rootfs provider and stamps each
// Snapshot call with the next time in a cycle, as the wall clock does for the
// stateless per-page calls of one claim. The cycle differs only in trailing
// zeros of the RFC 3339 nanosecond form, which is enough to change fact byte
// sizes and so move the page split (eshu-hq/eshu-scanner-worker#33).
type driftingSnapshotProvider struct {
	calls *atomic.Int64
	times []time.Time
}

func (p driftingSnapshotProvider) Snapshot(
	ctx context.Context,
	target osruntime.TargetConfig,
	limits scannerworker.ResourceLimits,
) (osruntime.Snapshot, scannerworker.ResourceUsage, error) {
	snapshot, usage, err := osruntime.LocalRootFSProvider{}.Snapshot(ctx, target, limits)
	call := p.calls.Add(1) - 1
	snapshot.ObservedAt = p.times[int(call)%len(p.times)]
	return snapshot, usage, err
}

// TestOSRuntimeMultiPageClaimSurvivesDriftingSnapshotClock drives a 50,000
// fact osruntime claim across its pages while every call sees a different
// wall-clock snapshot time. Reassembly must neither lose nor duplicate a
// fact, and every fact must carry one observation time.
func TestOSRuntimeMultiPageClaimSurvivesDriftingSnapshotClock(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount)
	config := map[string]any{
		"targets":            []any{map[string]any{"scope_id": parityScopeID, "rootfs_path": root, "source_uri": paritySourceURI, "source_record_id": paritySourceRecordID}},
		"acceptance_unit_id": parityAcceptanceUnitID,
	}
	want := directPinnedOSRuntimeFacts(t, root, pinnedSnapshotProvider{at: parityCaptureTime(t)})
	assertDriftingClockPaging(t, IDOSRuntime, parityClaim(), config, want)
}

// TestImageRootFSMultiPageClaimSurvivesDriftingSnapshotClock is the same
// check for the image component's rootfs evidence path, which reads through
// the same snapshot provider: 49,999 packages plus the analysis fact.
func TestImageRootFSMultiPageClaimSurvivesDriftingSnapshotClock(t *testing.T) {
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
		Provider:            pinnedSnapshotProvider{at: parityImageCaptureTime(t)},
		Now:                 parityObservedAt,
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
// snapshot provider that returns a different wall-clock time on every call,
// then checks the reassembled stream against the direct analysis's fact
// identities and for one shared observation time.
func assertDriftingClockPaging(t *testing.T, componentID string, claim sdkcollector.Claim, config map[string]any, want []sdkcollector.Fact) {
	t.Helper()

	provider := driftingSnapshotProvider{
		calls: new(atomic.Int64),
		times: []time.Time{
			time.Date(2026, time.October, 31, 16, 8, 20, 123456789, time.UTC),
			time.Date(2026, time.October, 31, 16, 8, 20, 120000000, time.UTC),
		},
	}
	got := hostileRun(t, componentID, claim, config, func(stdin []byte, stdout *bytes.Buffer) Runner {
		return Runner{ComponentID: componentID, Stdin: bytes.NewReader(stdin), Stdout: stdout, Clock: parityObservedAt, snapshots: provider}
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
	if len(observed) != 1 {
		t.Errorf("facts carry %d distinct observed_at values, want 1 for one claim", len(observed))
	}
}
