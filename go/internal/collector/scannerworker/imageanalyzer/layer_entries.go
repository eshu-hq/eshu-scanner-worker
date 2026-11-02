// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
)

const (
	whiteoutPrefix = ".wh."
	opaqueWhiteout = ".wh..wh..opq"

	// maxLayerEntryNameBytes caps one tar entry name; Linux PATH_MAX is 4096.
	maxLayerEntryNameBytes = 4096
)

// chargeTrailing charges record blocks that ended the archive without a
// header after them. They are invisible to handleEntry, so a chain of them at
// the end of a layer would otherwise cost nothing.
func (r *layerSnapshotReader) chargeTrailing() error {
	cost := r.meter.trailingBlocks()
	if r.filesSeen+cost > r.maxFiles {
		return fmt.Errorf("%w: layer file budget exceeded", errFileLimitExceeded)
	}
	r.filesSeen += cost
	return nil
}

func (r *layerSnapshotReader) handleEntry(header *tar.Header, body io.Reader) error {
	// Every entry costs budget before any branching, so header-only entries
	// (whiteouts, links, directories, unsafe names) cannot bypass MaxFiles.
	// PAX and GNU long-name records fold into this header inside tar.Reader;
	// each 512-byte block they occupy costs one more unit.
	cost := 1 + r.meter.blocks(header)
	if r.filesSeen+cost > r.maxFiles {
		return fmt.Errorf("%w: layer file budget exceeded", errFileLimitExceeded)
	}
	r.filesSeen += cost
	if isSparse(header) {
		return fmt.Errorf("%w: sparse layer entry", errUnsupportedTarget)
	}
	if len(header.Name) > maxLayerEntryNameBytes {
		return fmt.Errorf("%w: layer entry name too long", errInputLimitExceeded)
	}
	name := cleanLayerName(header.Name)
	if name == "" {
		return nil
	}
	if base := filepath.Base(name); strings.HasPrefix(base, whiteoutPrefix) {
		r.applyWhiteout(name)
		return nil
	}
	if header.Typeflag != tar.TypeReg {
		return nil
	}
	if !isPackageEvidencePath(name) {
		return nil
	}
	if isRPMDatabasePath(name) && header.Size > ospackagevulnerability.RPMDatabaseByteLimit {
		r.files[name] = nil
		r.oversizedRPM[name] = true
		return nil
	}
	if header.Size > r.remainingBytes {
		return fmt.Errorf("%w: layer metadata byte budget exceeded", errInputLimitExceeded)
	}
	content, err := io.ReadAll(io.LimitReader(body, header.Size+1))
	if err != nil {
		return fmt.Errorf("%w: read layer metadata", errTargetUnavailable)
	}
	if int64(len(content)) != header.Size {
		return fmt.Errorf("%w: truncated layer metadata", errTargetUnavailable)
	}
	r.remainingBytes -= int64(len(content))
	if int64(len(content)) > r.peakBytes {
		r.peakBytes = int64(len(content))
	}
	r.files[name] = content
	delete(r.oversizedRPM, name)
	return nil
}

func (r *layerSnapshotReader) applyWhiteout(name string) {
	dir := filepath.Dir(name)
	base := filepath.Base(name)
	if base == opaqueWhiteout {
		cleanDir := filepath.ToSlash(filepath.Clean(dir))
		for existing := range r.files {
			if filepath.Dir(existing) == cleanDir {
				delete(r.files, existing)
				delete(r.oversizedRPM, existing)
			}
		}
		return
	}
	target := filepath.ToSlash(filepath.Join(dir, strings.TrimPrefix(base, whiteoutPrefix)))
	delete(r.files, target)
	delete(r.oversizedRPM, target)
}

func cleanLayerName(name string) string {
	cleaned := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(strings.TrimSpace(name), "/")))
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return ""
	}
	return cleaned
}
