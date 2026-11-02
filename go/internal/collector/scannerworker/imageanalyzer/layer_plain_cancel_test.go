// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePlainEvidenceLayer writes an uncompressed layer whose package database
// entry is size bytes of zeros, streamed to disk.
func writePlainEvidenceLayer(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plain.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	writer := tar.NewWriter(file)
	if err := writer.WriteHeader(&tar.Header{Name: dpkgStatusPath, Typeflag: tar.TypeReg, Mode: 0o644, Size: size}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := io.CopyN(writer, zeroReader{}, size); err != nil {
		t.Fatalf("CopyN: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close: %v", err)
	}
	return path
}

// readWithin runs readLayer and fails the test when it has not returned within
// the bound, so a missing cancellation check fails instead of hanging.
func readWithin(t *testing.T, ctx context.Context, reader *layerSnapshotReader, layer string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- reader.readLayer(ctx, layer) }()
	select {
	case err := <-done:
		return err
	case <-time.After(60 * time.Second):
		t.Fatal("readLayer() did not return within 60s of the cancellation")
		return nil
	}
}

// TestPlainLayerEvidenceReadHonorsCancellation proves an uncompressed layer
// checks the context on every read of an evidence body. The body is bounded by
// the remaining byte budget (4 GiB on the image default) and io.ReadAll buffers
// it, so without a per-read check a cancelled claim waits for the whole read.
func TestPlainLayerEvidenceReadHonorsCancellation(t *testing.T) {
	t.Parallel()

	layer := writePlainEvidenceLayer(t, 64*mebibyte)
	ctx := &countdownContext{Context: context.Background(), after: 8}
	reader := newLayerSnapshotReader(inflateLimits(1 << 30))
	err := readWithin(t, ctx, reader, layer)
	if !errors.Is(err, errSourceUnavailable) {
		t.Fatalf("readLayer() error = %v, want source unavailable once the context cancels", err)
	}
	if checks := ctx.calls.Load(); checks > 20 {
		t.Fatalf("context was checked %d times, want the read stopped within a few checks of the 8th", checks)
	}
}

// TestPlainLayerRecordChainHonorsCancellation proves the same for the records
// tar.Reader folds into the next header, including a chain that ends the
// archive with no header after it.
func TestPlainLayerRecordChainHonorsCancellation(t *testing.T) {
	t.Parallel()

	record := metaPrefix(t, &tar.Header{Name: "n" + string(bytes.Repeat([]byte("n"), 149)), Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU})
	for name, trailer := range map[string]bool{"with trailer": true, "no trailer": false} {
		layer := writeRawLayer(t, bytes.Repeat(record, headerOnlyEntries), trailer, false)
		ctx := &countdownContext{Context: context.Background(), after: 50}
		limits := inflateLimits(1 << 40)
		limits.MaxFiles = 1 << 40
		reader := newLayerSnapshotReader(limits)
		err := readWithin(t, ctx, reader, layer)
		if !errors.Is(err, errSourceUnavailable) {
			t.Fatalf("%s: readLayer() error = %v, want source unavailable once the context cancels", name, err)
		}
	}
}

// TestPlainLayerChecksContextBeforeChargingTrailing proves a context that is
// already cancelled when the archive ends is reported, not charged.
func TestPlainLayerChecksContextBeforeChargingTrailing(t *testing.T) {
	t.Parallel()

	// Err is called four times before the check under test: at the top of
	// readLayer, in ctxReader while the gzip probe reads the header, and in
	// the two trackedFile reads of the end-of-archive blocks. after: 4 lets
	// those pass and cancels on the fifth call, the check before
	// chargeTrailing. A smaller value cancels inside a read and never reaches
	// it.
	layer := writeRawLayer(t, nil, true, false)
	ctx := &countdownContext{Context: context.Background(), after: 4}
	reader := newLayerSnapshotReader(inflateLimits(1 << 30))
	if err := readWithin(t, ctx, reader, layer); !errors.Is(err, errSourceUnavailable) {
		t.Fatalf("readLayer() error = %v, want source unavailable for a context cancelled at the end of the archive", err)
	}
}
