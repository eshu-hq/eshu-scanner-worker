// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"context"
	"fmt"
	"io"
)

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
	if int64(len(p)) > room+1 {
		p = p[:room+1]
	}
	n, err := g.src.Read(p)
	if int64(n) > room {
		g.err = fmt.Errorf("%w: layer decompressed byte budget exceeded", errInputLimitExceeded)
		return 0, g.err
	}
	g.budget.inflatedBytes += int64(n)
	return n, err
}
