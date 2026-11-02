// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"errors"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestTrailingBlocksTable pins the end-of-archive arithmetic: the stream
// bytes past the last header and its body, minus the two-block marker, in
// whole blocks, never negative.
func TestTrailingBlocksTable(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		pos, last, prevBody int64
		want                int64
	}{
		"only the marker":            {pos: 1024, want: 0},
		"marker plus one block":      {pos: 1024 + tarBlockBytes, want: 1},
		"marker plus three blocks":   {pos: 1024 + 3*tarBlockBytes, want: 3},
		"after a body":               {pos: 700 + 1024 + 2*tarBlockBytes, last: 700, want: 2},
		"previous body is excluded":  {pos: 4096 + 1024, last: 0, prevBody: 4096, want: 0},
		"less than the marker":       {pos: 100, want: 0},
		"nothing consumed":           {pos: 0, want: 0},
		"short of the previous body": {pos: 300, last: 0, prevBody: 4096, want: 0},
		"partial block is dropped":   {pos: 1024 + tarBlockBytes + 100, want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			meter := metaMeter{pos: func() int64 { return tc.pos }, last: tc.last, prevBody: tc.prevBody}
			if got := meter.trailingBlocks(); got != tc.want {
				t.Fatalf("trailingBlocks() = %d, want %d", got, tc.want)
			}
		})
	}
	var zero metaMeter
	if got := zero.trailingBlocks(); got != 0 {
		t.Fatalf("trailingBlocks(zero meter) = %d, want 0", got)
	}
}

// TestChargeTrailingTable pins the charge itself: the cost lands on filesSeen,
// the limit is exact, and the cost carries across layers of one target.
func TestChargeTrailingTable(t *testing.T) {
	t.Parallel()

	meter := func(blocks int64) metaMeter {
		return metaMeter{pos: func() int64 { return 1024 + blocks*tarBlockBytes }}
	}
	for name, tc := range map[string]struct {
		blocks, filesSeen, maxFiles int64
		wantErr                     bool
		wantSeen                    int64
	}{
		"fits with room":      {blocks: 3, filesSeen: 1, maxFiles: 10, wantSeen: 4},
		"fits exactly":        {blocks: 3, filesSeen: 2, maxFiles: 5, wantSeen: 5},
		"one over":            {blocks: 3, filesSeen: 3, maxFiles: 5, wantErr: true, wantSeen: 3},
		"free marker":         {blocks: 0, filesSeen: 5, maxFiles: 5, wantSeen: 5},
		"charges onto a seen": {blocks: 2, filesSeen: 7, maxFiles: 9, wantSeen: 9},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reader := &layerSnapshotReader{meter: meter(tc.blocks), filesSeen: tc.filesSeen, maxFiles: tc.maxFiles}
			err := reader.chargeTrailing()
			if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, errFileLimitExceeded)) {
				t.Fatalf("chargeTrailing() error = %v, want error=%t as a file limit", err, tc.wantErr)
			}
			if reader.filesSeen != tc.wantSeen {
				t.Fatalf("filesSeen = %d, want %d", reader.filesSeen, tc.wantSeen)
			}
		})
	}
}

// TestTrailingChargeAccumulatesAcrossLayers runs two layers that each end in a
// record chain through the production reader: the budget is exact at the sum
// of both chains and one under it fails.
func TestTrailingChargeAccumulatesAcrossLayers(t *testing.T) {
	t.Parallel()

	const records = 6
	record := metaPrefix(t, &tar.Header{Name: strings.Repeat("n", 150), Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatGNU})
	perLayer := int64(records * len(record) / tarBlockBytes)
	layers := []string{
		writeRawLayer(t, repeatBytes(record, records), true, false),
		writeRawLayer(t, repeatBytes(record, records), true, true),
	}
	run := func(maxFiles int64) error {
		_, _, err := readLayerSnapshot(t.Context(), TargetConfig{LayerPaths: layers},
			scannerworker.ResourceLimits{MaxInputBytes: 1 << 30, MaxFiles: maxFiles})
		return err
	}
	if err := run(2 * perLayer); errors.Is(err, errFileLimitExceeded) {
		t.Fatalf("MaxFiles=%d (the sum of both chains) error = %v, want no file limit", 2*perLayer, err)
	}
	if err := run(2*perLayer - 1); !errors.Is(err, errFileLimitExceeded) {
		t.Fatalf("MaxFiles=%d (one under the sum) error = %v, want a file limit", 2*perLayer-1, err)
	}
	if err := run(perLayer - 1); !errors.Is(err, errFileLimitExceeded) {
		t.Fatalf("MaxFiles=%d (one under a single chain) error = %v, want a file limit", perLayer-1, err)
	}
}

func repeatBytes(b []byte, n int) []byte {
	out := make([]byte, 0, len(b)*n)
	for i := 0; i < n; i++ {
		out = append(out, b...)
	}
	return out
}
