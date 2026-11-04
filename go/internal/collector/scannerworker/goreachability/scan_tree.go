// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// goFileSniffBytes bounds how much of one Go file is read for its imports, which
// come first in a file.
const goFileSniffBytes = 256 * 1024

// What a module directory holds, for a scan that matched no packages.
const (
	goFilesNone = iota
	goFilesPresent
	goFilesNeedCgo
)

var cgoImport = []byte("import \"C\"")

// goFilesIn classifies a module's own non-test Go files, skipping what ./... skips: a
// nested module, vendor, testdata, and a directory named with a leading dot or
// underscore. It follows no link, so a link cannot read outside the checkout. A file
// it cannot read counts as present, so an unreadable tree never passes as empty.
func goFilesIn(root string) int {
	found := goFilesNone
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			found = max(found, goFilesPresent)
			return nil
		}
		if entry.IsDir() {
			return skipForPackages(root, path, entry.Name())
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		found = max(found, goFilesPresent)
		if importsCgo(path) {
			found = goFilesNeedCgo
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// skipForPackages applies the go command's pattern rule to one directory.
func skipForPackages(root, path, name string) error {
	if path == root {
		return nil
	}
	if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return filepath.SkipDir
	}
	if _, err := os.Lstat(filepath.Join(path, goModName)); err == nil {
		return filepath.SkipDir
	}
	return nil
}

// importsCgo reports whether a file's head imports "C".
func importsCgo(path string) bool {
	file, err := os.Open(path) // #nosec G304 -- a regular file the walk found in this claim's private checkout
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	head, err := io.ReadAll(io.LimitReader(file, goFileSniffBytes))
	if err != nil {
		return false
	}
	return bytes.Contains(head, cgoImport)
}
