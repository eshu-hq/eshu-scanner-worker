// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
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

// graphListFormat prints, for each non-standard package in the module's graph, its
// directory and the Go files the build excluded. The standard library is left out
// because it always holds cgo files it can build without.
const graphListFormat = `{{if not .Standard}}{{if .IgnoredGoFiles}}{{.Dir}}|{{join .IgnoredGoFiles ","}}{{"\n"}}{{end}}{{end}}`

// graphNeedsCgo explains a scan that failed with a plain type error. With cgo off, a
// dependency whose files all import "C" builds to nothing, and its importers report
// undefined symbols, with no text that names cgo: a real run on eshu-hq/eshu printed
// only "undefined: tree_sitter.Node". So this asks the go command which of the graph's
// excluded files import "C". go list runs no compiler and no repository code. It is
// only ever a better name for a failure, and on any error the failure keeps its name.
func (s *ScanStage) graphNeedsCgo(ctx context.Context, dir string, env []string) bool {
	cmd := exec.CommandContext(ctx, filepath.Join(s.config.Toolchain.GoRoot, "bin", "go"), "list", "-e", "-deps", "-f", graphListFormat, "./...") // #nosec G204 -- the seeded go with fixed arguments
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = gitWaitDelay
	configureProcessGroup(cmd, true)
	output := &boundedBuffer{limit: scanStderrLimit * 16}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return false
	}
	for line := range strings.Lines(output.String()) {
		packageDir, files, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok {
			continue
		}
		for name := range strings.SplitSeq(files, ",") {
			path := filepath.Join(packageDir, name)
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && importsCgo(path) {
				return true
			}
		}
	}
	return false
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
