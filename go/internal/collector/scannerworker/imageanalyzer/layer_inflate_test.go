// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// zeroEntryBytes is the single-entry size from the #35 reproduction: a
	// 512 MiB run of zeros that gzip packs into roughly 522 KB.
	zeroEntryBytes = int64(512) << 20
	mebibyte       = int64(1) << 20
)

// writeZeroEntryLayer writes a gzip layer holding one zero-filled entry of
// size bytes, streamed so the raw bytes are never held in memory.
func writeZeroEntryLayer(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "layer.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		t.Fatalf("NewWriterLevel: %v", err)
	}
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "var/cache/zero", Typeflag: tar.TypeReg, Mode: 0o644, Size: size}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := io.CopyN(tarWriter, zeroReader{}, size); err != nil {
		t.Fatalf("CopyN: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	return path
}

func inflateLimits(maxInput int64) scannerworker.ResourceLimits {
	return scannerworker.ResourceLimits{MaxInputBytes: maxInput, MaxFiles: 1000}
}

// TestLayerInflateBudgetStopsLargeSkippedEntry reproduces #35: one 512 MiB
// zero entry in a ~522 KB layer inflated in full because skipped entry data
// was never charged to any budget.
func TestLayerInflateBudgetStopsLargeSkippedEntry(t *testing.T) {
	t.Parallel()

	layer := writeZeroEntryLayer(t, zeroEntryBytes)
	if info, err := os.Stat(layer); err != nil || info.Size() > 4*mebibyte {
		t.Fatalf("layer size = %v, %v, want a high-ratio layer under 4 MiB", info, err)
	}
	budget := 64 * mebibyte
	reader := newLayerSnapshotReader(inflateLimits(budget))
	err := reader.readLayer(context.Background(), layer)
	if !errors.Is(err, errInputLimitExceeded) {
		t.Fatalf("readLayer() error = %v, want input limit", err)
	}
	if reader.inflatedBytes > budget {
		t.Fatalf("inflatedBytes = %d, want at most the %d budget", reader.inflatedBytes, budget)
	}
	assertImageFailure(t, analyzerFailure(err, reader.usage()), scannerworker.FailureClassInputLimitExceeded, false)
}

// TestLayerCancellationStopsInsideLongEntry reproduces the deadline half of
// #35: ctx was checked only between entries, so a deadline expiring inside a
// long entry was ignored until the entry finished inflating.
func TestLayerCancellationStopsInsideLongEntry(t *testing.T) {
	t.Parallel()

	layer := writeZeroEntryLayer(t, zeroEntryBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	reader := newLayerSnapshotReader(inflateLimits(4 * 1024 * mebibyte))
	err := reader.readLayer(ctx, layer)
	if !errors.Is(err, errSourceUnavailable) {
		t.Fatalf("readLayer() error = %v, want source unavailable after the deadline", err)
	}
	if reader.inflatedBytes >= zeroEntryBytes {
		t.Fatalf("inflatedBytes = %d, want the entry cut short of %d", reader.inflatedBytes, zeroEntryBytes)
	}
	assertImageFailure(t, analyzerFailure(err, reader.usage()), scannerworker.FailureClassSourceUnavailable, true)
}

// TestLayerInflateBudgetBoundary proves the budget is exact: the byte count
// the tar reader consumed passes, one byte less fails, and the budget is
// shared across the layers of one target.
func TestLayerInflateBudgetBoundary(t *testing.T) {
	t.Parallel()

	layer := writeLayer(t, map[string]string{"etc/os-release": alpineRelease, "tmp/pad": string(make([]byte, 8192))})
	probe := newLayerSnapshotReader(inflateLimits(1 << 30))
	if err := probe.readLayer(context.Background(), layer); err != nil {
		t.Fatalf("probe readLayer() error = %v", err)
	}
	consumed := probe.inflatedBytes
	if consumed < 8192 {
		t.Fatalf("probe inflatedBytes = %d, want the layer's decompressed bytes", consumed)
	}

	exact := newLayerSnapshotReader(inflateLimits(consumed))
	if err := exact.readLayer(context.Background(), layer); err != nil {
		t.Fatalf("budget == consumed error = %v, want accepted", err)
	}
	short := newLayerSnapshotReader(inflateLimits(consumed - 1))
	if err := short.readLayer(context.Background(), layer); !errors.Is(err, errInputLimitExceeded) {
		t.Fatalf("budget == consumed-1 error = %v, want input limit", err)
	}

	shared := newLayerSnapshotReader(inflateLimits(consumed + consumed/2))
	if err := shared.readLayer(context.Background(), layer); err != nil {
		t.Fatalf("first layer error = %v, want accepted", err)
	}
	if err := shared.readLayer(context.Background(), layer); !errors.Is(err, errInputLimitExceeded) {
		t.Fatalf("second layer error = %v, want the shared budget exhausted", err)
	}
}

// TestLayerPlainTarSkipsInflateBudget documents that an uncompressed layer
// inflates nothing: its bytes are charged once as layer size.
func TestLayerPlainTarSkipsInflateBudget(t *testing.T) {
	t.Parallel()

	layer := writePlainTar(t, []tarEntry{{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease}})
	reader := newLayerSnapshotReader(inflateLimits(1 << 20))
	if err := reader.readLayer(context.Background(), layer); err != nil {
		t.Fatalf("readLayer() error = %v", err)
	}
	if reader.inflatedBytes != 0 {
		t.Fatalf("inflatedBytes = %d, want 0 for an uncompressed layer", reader.inflatedBytes)
	}
}
