// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestLayerReadsUnderHugeInputBudgets proves the guard reads normally when the
// derived budget saturates. room+1 used to overflow and slice with a negative
// bound for any MaxInputBytes above MaxInt64/8.
func TestLayerReadsUnderHugeInputBudgets(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{"etc/os-release": alpineRelease, "lib/apk/db/installed": alpineDB})
	for _, maxInput := range []int64{math.MaxInt64 / 8, math.MaxInt64/8 + 1, 1 << 60, math.MaxInt64} {
		reader := newLayerSnapshotReader(inflateLimits(maxInput))
		if err := reader.readLayer(context.Background(), layer); err != nil {
			t.Fatalf("MaxInputBytes=%d readLayer() error = %v, want accepted", maxInput, err)
		}
		if reader.inflatedBytes == 0 {
			t.Fatalf("MaxInputBytes=%d inflatedBytes = 0, want the layer read through the guard", maxInput)
		}
	}
}

// countdownContext reports cancellation after a fixed number of Err calls, so
// a test can land the cancellation inside an evidence read without a timer.
type countdownContext struct {
	context.Context
	calls atomic.Int64
	after int64
}

func (c *countdownContext) Err() error {
	if c.calls.Add(1) > c.after {
		return context.Canceled
	}
	return nil
}

// TestLayerFailuresInsideEvidenceReadKeepTheirClass proves a budget overrun or
// a cancellation that lands while an evidence file is being read keeps its
// class. io.ReadAll turns any read error into retryable target_unavailable
// unless readLayer prefers the guard's error.
func TestLayerFailuresInsideEvidenceReadKeepTheirClass(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{
		"etc/os-release": alpineRelease + string(make([]byte, 20000)),
	})
	var sawBudget bool
	for maxInput := int64(2200); maxInput <= 2800; maxInput += 8 {
		reader := newLayerSnapshotReader(inflateLimits(maxInput))
		err := reader.readLayer(context.Background(), layer)
		if errors.Is(err, errTargetUnavailable) || errors.Is(err, errUnsupportedTarget) {
			t.Fatalf("MaxInputBytes=%d error = %v, want input limit or success, never a read-failure class", maxInput, err)
		}
		sawBudget = sawBudget || errors.Is(err, errInputLimitExceeded)
	}
	if !sawBudget {
		t.Fatal("no budget overran inside the evidence read, so the sweep proved nothing")
	}

	var sawCancel bool
	for after := int64(0); after < 12; after++ {
		ctx := &countdownContext{Context: context.Background(), after: after}
		reader := newLayerSnapshotReader(inflateLimits(1 << 30))
		err := reader.readLayer(ctx, layer)
		if errors.Is(err, errTargetUnavailable) || errors.Is(err, errUnsupportedTarget) {
			t.Fatalf("cancel after %d checks error = %v, want source unavailable or success", after, err)
		}
		sawCancel = sawCancel || errors.Is(err, errSourceUnavailable)
	}
	if !sawCancel {
		t.Fatal("no cancellation landed, so the sweep proved nothing")
	}
}

// TestAnalyzeReportsInflateBudgetFiguresThroughTheWrap proves the figures
// survive the production wrap, not only the raw readLayer error.
func TestAnalyzeReportsInflateBudgetFiguresThroughTheWrap(t *testing.T) {
	t.Parallel()

	layer := writeZeroEntryLayer(t, 64*mebibyte)
	input := testImageClaimInput(t)
	input.Limits.MaxInputBytes = 2 * mebibyte
	analyzer := newTestAnalyzer(t, TargetConfig{ScopeID: input.Target.ScopeID, LayerPaths: []string{layer}})
	_, err := analyzer.Analyze(context.Background(), input)
	assertImageFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
	var failure scannerworker.AnalyzerFailure
	if !errors.As(err, &failure) {
		t.Fatalf("Analyze() error = %T, want AnalyzerFailure", err)
	}
	detail, ok := failure.InputLimit()
	if !ok || detail.BudgetBytes != 16*mebibyte || detail.InflatedBytes <= detail.BudgetBytes || detail.CompressedBytes <= 0 {
		t.Fatalf("InputLimit() = %+v, %t, want the 16 MiB budget overrun with a compressed size", detail, ok)
	}
}

// TestLayerEmptyGzipMemberFloodHonorsDeadline reproduces the review finding:
// gzip skips empty members inside one Read, so a flood of 20-byte members ran
// past the deadline without ever reaching the guard.
func TestLayerEmptyGzipMemberFloodHonorsDeadline(t *testing.T) {
	t.Parallel()

	var member bytes.Buffer
	gzipWriter := gzip.NewWriter(&member)
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "flood.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 3_000_000; i++ {
		if _, err := file.Write(member.Bytes()); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	reader := newLayerSnapshotReader(inflateLimits(1 << 30))
	start := time.Now()
	err = reader.readLayer(ctx, path)
	if !errors.Is(err, errSourceUnavailable) {
		t.Fatalf("readLayer() error = %v after %s, want source unavailable once the deadline passes", err, time.Since(start))
	}
}
