// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"math"
	"testing"
)

// TestMetaMeterCountsBlocksBetweenHeaders proves the meter reports only the
// record blocks between a previous body and the next header.
func TestMetaMeterCountsBlocksBetweenHeaders(t *testing.T) {
	t.Parallel()

	var pos int64
	meter := newMetaMeter(func() int64 { return pos }, 100)
	// First header: two record blocks plus the header block.
	pos = 3 * tarBlockBytes
	if meter.limit == 0 {
		t.Fatal("newMetaMeter armed no limit, want one for the first Next")
	}
	if got := meter.blocks(&tar.Header{Size: 700}); got != 2 {
		t.Fatalf("blocks(first) = %d, want 2", got)
	}
	if meter.limit != 0 {
		t.Fatalf("limit after a header = %d, want it cleared until settle re-arms", meter.limit)
	}
	// Second header: the 700-byte body pads to 1024, then only the header.
	pos += 1024 + tarBlockBytes
	if got := meter.blocks(&tar.Header{}); got != 0 {
		t.Fatalf("blocks(second) = %d, want 0", got)
	}
	// A position that moved less than the body (sparse shortfall) is clamped.
	if got := meter.blocks(&tar.Header{}); got != 0 {
		t.Fatalf("blocks(no movement) = %d, want 0", got)
	}
	var zero metaMeter
	if got := zero.blocks(&tar.Header{}); got != 0 {
		t.Fatalf("blocks(zero meter) = %d, want 0", got)
	}
	zero.arm(5)
	if zero.limit != 0 {
		t.Fatalf("arm(zero meter) set limit %d, want none", zero.limit)
	}
}

// TestMetaMeterArmsAndSaturatesLimit proves the stream limit tracks the file
// units left and saturates instead of overflowing.
func TestMetaMeterArmsAndSaturatesLimit(t *testing.T) {
	t.Parallel()

	meter := newMetaMeter(func() int64 { return 1000 }, 3)
	if want := int64(1000 + tarBlockBytes*5); meter.limit != want {
		t.Fatalf("limit(3 units) = %d, want %d", meter.limit, want)
	}
	meter.arm(-4)
	if want := int64(1000 + tarBlockBytes*2); meter.limit != want {
		t.Fatalf("limit(negative units) = %d, want %d", meter.limit, want)
	}
	meter.arm(math.MaxInt64)
	if meter.limit != math.MaxInt64 {
		t.Fatalf("limit(MaxInt64 units) = %d, want saturation", meter.limit)
	}
	meter.prevBody = math.MaxInt64
	meter.arm(1)
	if meter.limit != math.MaxInt64 {
		t.Fatalf("limit(huge body) = %d, want saturation instead of overflow", meter.limit)
	}
}

// TestMetaMeterPaddedBodyAndSparse covers the size helper and sparse
// detection through both the type flag and PAX records.
func TestMetaMeterPaddedBodyAndSparse(t *testing.T) {
	t.Parallel()

	for size, want := range map[int64]int64{-1: 0, 0: 0, 1: 512, 512: 512, 513: 1024, math.MaxInt64: math.MaxInt64} {
		if got := paddedBody(size); got != want {
			t.Fatalf("paddedBody(%d) = %d, want %d", size, got, want)
		}
	}
	if !isSparse(&tar.Header{Typeflag: tar.TypeGNUSparse}) {
		t.Fatal("isSparse(GNU sparse type) = false")
	}
	if !isSparse(&tar.Header{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"GNU.sparse.map": "0,1"}}) {
		t.Fatal("isSparse(PAX sparse record) = false")
	}
	if isSparse(&tar.Header{Typeflag: tar.TypeReg, PAXRecords: map[string]string{"comment": "x"}}) {
		t.Fatal("isSparse(plain PAX) = true")
	}
}
