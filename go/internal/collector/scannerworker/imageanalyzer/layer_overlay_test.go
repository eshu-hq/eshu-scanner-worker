// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package imageanalyzer

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// These tests pin the OCI image-spec layer semantics the reader must follow
// (https://github.com/opencontainers/image-spec/blob/v1.1.0/layer.md):
// "Whiteouts" (whiteouts apply only to lower layers and hide descendants),
// "Opaque Whiteout" (hides all children, sub-directories and descendants),
// and "Changeset over existing files" (an entry at an existing path replaces
// it, whatever its type).

const (
	debianRelease = "ID=debian\nVERSION_ID=12\n"
	debianStatus  = "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.11-1~deb12u2\n\n"
)

func alpineLower(t *testing.T) string {
	t.Helper()
	return writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: "lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
	})
}

func debianLower(t *testing.T) string {
	t.Helper()
	return writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: debianRelease},
		{name: "var/lib/dpkg/status", typeflag: tar.TypeReg, body: debianStatus},
	})
}

func assertPackages(t *testing.T, layers []string, want int, reason string) {
	t.Helper()
	result, err := analyzeLayers(t, testImageDigest, layers...)
	if want == 0 {
		assertUnsupportedWarning(t, result, err, reason)
		return
	}
	if err != nil || result.Output.ResultCount != want {
		t.Fatalf("packages = %d, %v, want %d", result.Output.ResultCount, err, want)
	}
}

// TestLayerNonRegularEntryReplacesLowerFile covers "Changeset over existing
// files": a symlink, hard link, or directory entry at a path removes the
// lower regular file there.
func TestLayerNonRegularEntryReplacesLowerFile(t *testing.T) {
	t.Parallel()

	lower := alpineLower(t)
	for name, entry := range map[string]tarEntry{
		"symlink":   {name: "lib/apk/db/installed", typeflag: tar.TypeSymlink},
		"directory": {name: "lib/apk/db/installed/", typeflag: tar.TypeDir},
		"fifo":      {name: "lib/apk/db/installed", typeflag: tar.TypeFifo},
	} {
		upper := writePlainTar(t, []tarEntry{entry})
		t.Run(name, func(t *testing.T) {
			assertPackages(t, []string{lower, upper}, 0, extractionUnsupported)
		})
	}
}

// TestLayerEntryReplacesLowerAncestorDirectory proves a non-directory entry
// at an ancestor path removes every lower descendant.
func TestLayerEntryReplacesLowerAncestorDirectory(t *testing.T) {
	t.Parallel()

	lower := alpineLower(t)
	for name, entry := range map[string]tarEntry{
		"symlink over lib/apk": {name: "lib/apk", typeflag: tar.TypeSymlink},
		"regular over lib":     {name: "lib", typeflag: tar.TypeReg, body: "now a file"},
	} {
		upper := writePlainTar(t, []tarEntry{entry})
		t.Run(name, func(t *testing.T) {
			assertPackages(t, []string{lower, upper}, 0, extractionUnsupported)
		})
	}
}

// TestLayerDirectoryEntryKeepsLowerChildren covers the directory-over-
// directory case: attributes are replaced and children stay.
func TestLayerDirectoryEntryKeepsLowerChildren(t *testing.T) {
	t.Parallel()

	upper := writePlainTar(t, []tarEntry{
		{name: "lib/", typeflag: tar.TypeDir},
		{name: "lib/apk/db/", typeflag: tar.TypeDir},
	})
	assertPackages(t, []string{alpineLower(t), upper}, 1, "")
}

// TestLayerOpaqueMarkerHidesAllDescendants covers "Opaque Whiteout": the
// marker hides sub-directories and all descendants, not only direct children.
func TestLayerOpaqueMarkerHidesAllDescendants(t *testing.T) {
	t.Parallel()

	for name, marker := range map[string]string{
		"parent":      "lib/apk/db/.wh..wh..opq",
		"grandparent": "lib/apk/.wh..wh..opq",
		"root":        "lib/.wh..wh..opq",
		"image root":  ".wh..wh..opq",
	} {
		upper := writePlainTar(t, []tarEntry{{name: marker, typeflag: tar.TypeReg}})
		t.Run(name, func(t *testing.T) {
			assertPackages(t, []string{alpineLower(t), upper}, 0, extractionUnsupported)
		})
	}
}

// TestLayerFileWhiteoutHidesDirectoryTree covers "Whiteouts": a whiteout for
// a directory removes the directory and everything below it.
func TestLayerFileWhiteoutHidesDirectoryTree(t *testing.T) {
	t.Parallel()

	for name, marker := range map[string]string{
		"dpkg dir": "var/lib/.wh.dpkg",
		"var dir":  "var/.wh.lib",
		"file":     "var/lib/dpkg/.wh.status",
	} {
		upper := writePlainTar(t, []tarEntry{{name: marker, typeflag: tar.TypeReg}})
		t.Run(name, func(t *testing.T) {
			assertPackages(t, []string{debianLower(t), upper}, 0, extractionUnsupported)
		})
	}
}

// TestLayerWhiteoutAppliesOnlyToLowerLayers covers "Whiteouts ... MUST only
// apply to resources in lower/parent layers": files in the same layer survive
// a whiteout whatever the tar order, and a later layer can restore the path.
func TestLayerWhiteoutAppliesOnlyToLowerLayers(t *testing.T) {
	t.Parallel()

	files := []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: "lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
	}
	for name, marker := range map[string]string{
		"opaque":        "lib/apk/db/.wh..wh..opq",
		"opaque parent": "lib/.wh..wh..opq",
		"file whiteout": "lib/apk/db/.wh.installed",
		"dir whiteout":  "lib/apk/.wh.db",
	} {
		before := append([]tarEntry{{name: marker, typeflag: tar.TypeReg}}, files...)
		after := append(append([]tarEntry{}, files...), tarEntry{name: marker, typeflag: tar.TypeReg})
		t.Run(name, func(t *testing.T) {
			assertPackages(t, []string{writePlainTar(t, before)}, 1, "")
			assertPackages(t, []string{writePlainTar(t, after)}, 1, "")
		})
	}

	hide := writePlainTar(t, []tarEntry{{name: "lib/apk/db/.wh.installed", typeflag: tar.TypeReg}})
	restore := writePlainTar(t, []tarEntry{{name: "lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB}})
	assertPackages(t, []string{alpineLower(t), hide, restore}, 1, "")

	// The lower layer's file is still hidden when the same upper layer also
	// carries unrelated files.
	mixed := writePlainTar(t, []tarEntry{
		{name: "lib/apk/db/.wh.installed", typeflag: tar.TypeReg},
		{name: "usr/share/doc/readme", typeflag: tar.TypeReg, body: "x"},
	})
	assertPackages(t, []string{alpineLower(t), mixed}, 0, extractionUnsupported)
}

// TestLayerIgnoresInertWhiteoutNames proves names that cannot hide a real
// path (a bare ".wh." and AUFS ".wh..wh." metadata) leave lower files alone.
func TestLayerIgnoresInertWhiteoutNames(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"lib/apk/db/.wh.", "lib/apk/db/.wh..wh.plnk", "lib/apk/db/.wh..wh.aufs"} {
		upper := writePlainTar(t, []tarEntry{{name: name, typeflag: tar.TypeReg}})
		assertPackages(t, []string{alpineLower(t), upper}, 1, "")
	}
}

// TestLayerEntryNamesAreNotTrimmed proves a name with a leading space is a
// different path, while leading slashes and "./" normalize to the real one.
func TestLayerEntryNamesAreNotTrimmed(t *testing.T) {
	t.Parallel()

	trimmed := writePlainTar(t, []tarEntry{
		{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
		{name: " lib/apk/db/installed", typeflag: tar.TypeReg, body: alpineDB},
		{name: "lib/apk/db/installed ", typeflag: tar.TypeReg, body: alpineDB},
	})
	assertPackages(t, []string{trimmed}, 0, extractionUnsupported)

	for _, name := range []string{"/lib/apk/db/installed", "//lib/apk/db/installed", "./lib/apk/db/installed"} {
		layer := writePlainTar(t, []tarEntry{
			{name: "etc/os-release", typeflag: tar.TypeReg, body: alpineRelease},
			{name: name, typeflag: tar.TypeReg, body: alpineDB},
		})
		assertPackages(t, []string{layer}, 1, "")
	}

	// A spaced whiteout name must not hide the real path either.
	spaced := writePlainTar(t, []tarEntry{{name: "lib/apk/db/.wh. installed", typeflag: tar.TypeReg}})
	assertPackages(t, []string{alpineLower(t), spaced}, 1, "")
}

// TestLayerGlobalPAXHeaderIsInert proves a PAX global header never replaces a
// package path, whatever name it carries. tar.Writer refuses to encode a
// named global header, so the test rewrites a regular header in place.
func TestLayerGlobalPAXHeaderIsInert(t *testing.T) {
	t.Parallel()

	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	if err := writer.WriteHeader(&tar.Header{Name: "lib/apk/db/installed", Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	block := raw.Bytes()[:512]
	block[156] = tar.TypeXGlobalHeader
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:], fmt.Sprintf("%06o\x00 ", sum))
	path := filepath.Join(t.TempDir(), "layer.tar")
	if err := os.WriteFile(path, raw.Bytes(), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	assertPackages(t, []string{alpineLower(t), path}, 1, "")
}
