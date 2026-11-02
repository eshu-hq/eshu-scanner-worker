// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// layerInflateBudgetMultiplier sizes the decompressed-byte budget as a
// multiple of MaxInputBytes. Legitimate gzip layers inflate about 2.5x to 3x;
// a decompression bomb inflates about 1000x. 8x sits above every realistic
// whole image (32 GiB on the 4 GiB image default) and two orders of magnitude
// below the bomb signature. It is a package constant, not a limit field, so
// no config surface carries it.
const layerInflateBudgetMultiplier = 8

// inflateBudget returns the decompressed-byte budget for maxInputBytes,
// saturating at math.MaxInt64 instead of overflowing.
func inflateBudget(maxInputBytes int64) int64 {
	if maxInputBytes > math.MaxInt64/layerInflateBudgetMultiplier {
		return math.MaxInt64
	}
	return maxInputBytes * layerInflateBudgetMultiplier
}

// inflateBudgetError is the decompressed-byte budget overrun. It keeps the
// figures typed so analyzerFailure can hand them to the component without
// parsing text; Error renders the same struct, so the two cannot drift.
type inflateBudgetError struct {
	Detail scannerworker.InputLimitDetail
}

func (e inflateBudgetError) Error() string {
	return fmt.Sprintf(
		"%s: layer decompressed byte budget exceeded inflated_bytes=%d budget_bytes=%d compressed_bytes=%d",
		errInputLimitExceeded, e.Detail.InflatedBytes, e.Detail.BudgetBytes, e.Detail.CompressedBytes,
	)
}

// Unwrap lets errors.Is match errInputLimitExceeded, so the failure class
// mapping is unchanged.
func (e inflateBudgetError) Unwrap() error { return errInputLimitExceeded }

// inflateGuard wraps the decompressed layer stream. It charges every byte the
// tar reader pulls from the gzip stream, including entry data the reader
// skips, against the target-wide decompressed-byte budget, and it checks the
// context on every read so a deadline is honored inside a long entry.
//
// The first failure is sticky: tar and io.ReadAll wrap or replace read errors,
// so readLayer consults err to report the real cause.
type inflateGuard struct {
	ctx    context.Context
	src    io.Reader
	budget *layerSnapshotReader
	err    error
}

func (g *inflateGuard) Read(p []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	if err := g.ctx.Err(); err != nil {
		g.err = fmt.Errorf("%w: context canceled", errSourceUnavailable)
		return 0, g.err
	}
	room := g.budget.maxInflated - g.budget.inflatedBytes
	if room < 0 {
		room = 0
	}
	// Ask for one byte past the room so an over-budget stream is detected
	// without ever counting bytes beyond the budget.
	// The comparison runs first so room+1 is never evaluated near MaxInt64.
	if room < int64(len(p))-1 {
		p = p[:room+1]
	}
	n, err := g.src.Read(p)
	if err != nil && errors.Is(err, errSourceUnavailable) {
		g.err = err
		return n, err
	}
	if int64(n) > room {
		// Byte counts are privacy-safe. The read is clamped to room+1, so
		// InflatedBytes is always BudgetBytes+1 here; the signal for an
		// operator is BudgetBytes over CompressedBytes (a bomb is far above
		// 8x, a large image is not).
		g.err = inflateBudgetError{Detail: scannerworker.InputLimitDetail{
			InflatedBytes:   g.budget.inflatedBytes + int64(n),
			BudgetBytes:     g.budget.maxInflated,
			CompressedBytes: g.budget.compressedBytes,
		}}
		return 0, g.err
	}
	g.budget.inflatedBytes += int64(n)
	if limit := g.budget.meter.limit; limit > 0 && g.budget.inflatedBytes > limit {
		g.err = fmt.Errorf("%w: layer file budget exceeded", errFileLimitExceeded)
		return 0, g.err
	}
	return n, err
}

// ctxReader checks the context on every read of the compressed layer file.
// gzip skips empty members inside one Read without producing output, so the
// guard above it never runs during such a flood; this reader sits below gzip
// and does.
type ctxReader struct {
	ctx context.Context
	src io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: context canceled", errSourceUnavailable)
	}
	return c.src.Read(p)
}
