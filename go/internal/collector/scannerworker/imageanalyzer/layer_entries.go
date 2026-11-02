// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"fmt"
	"io"
	"path"
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
	if header.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	name := cleanLayerName(header.Name)
	if name == "" {
		return nil
	}
	if base := path.Base(name); strings.HasPrefix(base, whiteoutPrefix) {
		r.applyWhiteout(name)
		return nil
	}
	if header.Typeflag == tar.TypeDir {
		// A directory over a directory only replaces attributes; over a
		// file it replaces the file. Children from lower layers stay.
		r.removeEvidence(name, true, false, r.layer+1)
		return nil
	}
	// Any other entry replaces whatever was at its path, children included.
	r.removeEvidence(name, true, true, r.layer+1)
	if header.Typeflag != tar.TypeReg || !isPackageEvidencePath(name) {
		return nil
	}
	if isRPMDatabasePath(name) && header.Size > ospackagevulnerability.RPMDatabaseByteLimit {
		r.files[name] = nil
		r.oversizedRPM[name] = true
		r.pathLayer[name] = r.layer
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
	r.pathLayer[name] = r.layer
	return nil
}

// applyWhiteout applies an OCI whiteout entry (image-spec layer.md,
// "Whiteouts" and "Opaque Whiteout"). It reaches only paths from lower
// layers, so a file in the same layer survives whatever the tar order.
func (r *layerSnapshotReader) applyWhiteout(name string) {
	dir := path.Dir(name)
	base := path.Base(name)
	if base == opaqueWhiteout {
		// Hide every descendant of the marker's directory; "." is the root.
		prefix := dir
		if prefix == "." {
			prefix = ""
		}
		r.removeEvidence(prefix, false, true, r.layer)
		return
	}
	target := strings.TrimPrefix(base, whiteoutPrefix)
	if target == "" || strings.HasPrefix(target, whiteoutPrefix) {
		// A bare ".wh." and AUFS ".wh..wh.*" metadata name no real path:
		// no filesystem can hold a name that begins with ".wh.".
		return
	}
	r.removeEvidence(path.Join(dir, target), true, true, r.layer)
}

// removeEvidence drops tracked package evidence at prefix (when self is set)
// and below it (when descendants is set) that came from a layer older than
// beforeLayer. An empty prefix with descendants set means every path. Only
// package evidence paths are tracked, so the walk is a few map entries.
func (r *layerSnapshotReader) removeEvidence(prefix string, self, descendants bool, beforeLayer int) {
	if len(r.pathLayer) == 0 {
		return
	}
	under := prefix + "/"
	for tracked, layer := range r.pathLayer {
		if layer >= beforeLayer {
			continue
		}
		match := self && tracked == prefix
		if !match && descendants {
			match = prefix == "" || strings.HasPrefix(tracked, under)
		}
		if match {
			delete(r.files, tracked)
			delete(r.oversizedRPM, tracked)
			delete(r.pathLayer, tracked)
		}
	}
}

// cleanLayerName returns the slash-separated, root-relative form of a tar
// entry name, or "" when the name escapes the root. It does not trim
// whitespace: a name with a space is a different path.
func cleanLayerName(name string) string {
	cleaned := path.Clean(strings.TrimLeft(name, "/"))
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return ""
	}
	return cleaned
}
