// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"io"
	"math"
	"strings"
)

const tarBlockBytes = 512

// layerCounter counts the bytes the tar reader pulls from a decompressed
// stream. An uncompressed layer reports its file offset instead, so tar keeps
// skipping entry data by seek.
type layerCounter struct {
	src io.Reader
	n   int64
}

func (c *layerCounter) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.n += int64(n)
	return n, err
}

// metaMeter measures the PAX and GNU long-name records tar.Reader folds into
// the next header. Next returns only the real header, so the records are
// invisible to handleEntry; the stream position shows them. Between two
// returned headers the reader consumes the previous entry's padded body, the
// new header block, and the records. What is left is the record bytes.
type metaMeter struct {
	pos      func() int64
	last     int64
	prevBody int64
}

func newMetaMeter(pos func() int64) metaMeter {
	return metaMeter{pos: pos, last: pos()}
}

// blocks returns how many 512-byte record blocks preceded header h. A zero
// meter, or a sparse file whose body is shorter than its Size, returns 0.
func (m *metaMeter) blocks(h *tar.Header) int64 {
	if m.pos == nil {
		return 0
	}
	cur := m.pos()
	meta := cur - m.last - m.prevBody - tarBlockBytes
	m.last = cur
	m.prevBody = paddedBody(h.Size)
	if meta < 0 {
		return 0
	}
	return meta / tarBlockBytes
}

// settle runs after handleEntry. A sparse entry declares its logical size in
// Header.Size but carries fewer bytes on the wire, so subtracting the padded
// Size would let it absorb later records. Drain the body and measure from the
// real position instead; the padding left over is under one block.
func (m *metaMeter) settle(h *tar.Header, body io.Reader) {
	if m.pos == nil || !isSparse(h) {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	m.last = m.pos()
	m.prevBody = 0
}

func isSparse(h *tar.Header) bool {
	if h.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for key := range h.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return true
		}
	}
	return false
}

func paddedBody(size int64) int64 {
	if size <= 0 {
		return 0
	}
	blocks := size / tarBlockBytes
	if size%tarBlockBytes != 0 {
		blocks++
	}
	if blocks > math.MaxInt64/tarBlockBytes {
		return math.MaxInt64
	}
	return blocks * tarBlockBytes
}
