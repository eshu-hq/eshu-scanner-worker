// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"math"
	"os"
	"strings"
)

const tarBlockBytes = 512

// trackedFile follows the read offset of an uncompressed layer without a
// system call per query. tar.Reader skips entry data by seeking when its
// source is an io.Seeker, so the wrapper keeps that path and records each
// result.
type trackedFile struct {
	file *os.File
	pos  int64
}

func (f *trackedFile) Read(p []byte) (int, error) {
	n, err := f.file.Read(p)
	f.pos += int64(n)
	return n, err
}

func (f *trackedFile) Seek(offset int64, whence int) (int64, error) {
	pos, err := f.file.Seek(offset, whence)
	if err == nil {
		f.pos = pos
	}
	return pos, err
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
	// limit is the stream position past which the next header cannot arrive
	// inside the file budget: the previous body, then one block per
	// remaining unit plus the header block. Zero means no limit.
	limit int64
}

func newMetaMeter(pos func() int64, remaining int64) metaMeter {
	m := metaMeter{pos: pos, last: pos()}
	m.arm(remaining)
	return m
}

// arm sets limit for the next Next call, given the file-budget units left. A
// chain of records longer than that cannot fit the budget, so the decompressed
// stream stops it while it streams instead of after it has all been read.
func (m *metaMeter) arm(remaining int64) {
	if m.pos == nil {
		return
	}
	if remaining < 0 {
		remaining = 0
	}
	if m.prevBody > math.MaxInt64-m.last {
		m.limit = math.MaxInt64
		return
	}
	room := m.last + m.prevBody
	if remaining > (math.MaxInt64-room)/tarBlockBytes-2 {
		m.limit = math.MaxInt64
		return
	}
	m.limit = room + tarBlockBytes*(remaining+2)
}

// blocks returns how many 512-byte record blocks preceded header h. A zero
// meter returns 0.
func (m *metaMeter) blocks(h *tar.Header) int64 {
	if m.pos == nil {
		return 0
	}
	// The header is in; the stream limit guarded only the span that found
	// it. readLayer arms the next one after the entry, so the body read in between
	// is free.
	m.limit = 0
	cur := m.pos()
	meta := cur - m.last - m.prevBody - tarBlockBytes
	m.last = cur
	m.prevBody = wireBody(h)
	if meta < 0 {
		return 0
	}
	return meta / tarBlockBytes
}

// trailingBlocks returns the record blocks the stream consumed after the last
// returned header, once tar.Reader reports the end of the archive with no
// header after them. The end-of-archive marker is up to two zero blocks and
// costs nothing.
func (m *metaMeter) trailingBlocks() int64 {
	if m.pos == nil {
		return 0
	}
	blocks := (m.pos()-m.last-m.prevBody)/tarBlockBytes - 2
	if blocks < 0 {
		return 0
	}
	return blocks
}

// isSparse reports whether h is a sparse entry in either GNU format. Its body
// is a logical stream: draining it generates zeros for the declared size at no
// cost to any byte budget, and its wire size cannot be read from Header.Size.
// The OCI image-spec says sparse files SHOULD NOT be used in a layer because
// tar implementations support them inconsistently (layer.md), so the reader
// rejects them.
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

// wireBody returns the padded body bytes tar.Reader consumes after h. Go
// leaves Header.Size at the declared value for header-only types though it
// reads no body for them, so those count as zero.
func wireBody(h *tar.Header) int64 {
	switch h.Typeflag {
	case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
		return 0
	}
	return paddedBody(h.Size)
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
