// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"context"
	"errors"
	"go/build"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		if needsCgo(path) {
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
// excluded files only cgo kept out. go list runs no compiler and no repository code. It is
// only ever a better name for a failure, and on any error the failure keeps its name.
func (s *ScanStage) graphNeedsCgo(ctx context.Context, dir string, env []string) bool {
	excluded, err := s.graphCgoExcluded(ctx, dir, env)
	return err == nil && excluded
}

// graphCgoExcluded is the one probe behind both cgo rules: it reports whether
// at least one file in a non-standard package of the module's graph is in
// IgnoredGoFiles under the scan environment (CGO_ENABLED=0) yet accepted once
// cgo is on — excluded only by cgo. It runs under the caller's context, so the
// module budget and the claim lease bound it exactly as they bound the scan.
// A probe error is returned, never read as "no file excluded": on the clean
// path the caller fails the module closed rather than emit not_called from a
// graph it could not prove whole.
func (s *ScanStage) graphCgoExcluded(ctx context.Context, dir string, env []string) (bool, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(s.config.Toolchain.GoRoot, "bin", "go"), "list", "-e", "-deps", "-f", graphListFormat, "./...") // #nosec G204 -- the seeded go with fixed arguments
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = gitWaitDelay
	configureProcessGroup(cmd, true)
	output := &boundedBuffer{limit: scanStderrLimit * 16}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return false, err
	}
	for line := range strings.Lines(output.String()) {
		packageDir, files, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok {
			continue
		}
		for name := range strings.SplitSeq(files, ",") {
			path := filepath.Join(packageDir, name)
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && needsCgo(path) {
				return true, nil
			}
		}
	}
	return false, nil
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

// replacesStayInCheckout follows every link in each local replace target. A target that
// does not exist stays allowed: the go command fails on it, so nothing outside is read.
// Any other error refuses, because the path could not be proven inside.
func replacesStayInCheckout(checkout string, replaces []string) bool {
	root, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		return false
	}
	for _, target := range replaces {
		resolved, err := filepath.EvalSymlinks(filepath.Join(checkout, filepath.FromSlash(target)))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !pathInside(root, resolved) {
			return false
		}
	}
	return true
}

// pathInside reports whether a resolved path is the root or under it.
func pathInside(root, resolved string) bool {
	relative, err := filepath.Rel(root, resolved)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// errLinkOutsideCheckout stops a link walk at the first escaping link.
var errLinkOutsideCheckout = errors.New("a link resolves outside the checkout")

// linksStayInCheckout walks the module directory and every local replace root
// without following links, and resolves every symlink it finds: measured, the
// go command reads a linked .go file and a linked package directory from
// outside the module, so a link that leaves the checkout would put code that
// is not in this commit into the scan. A link that stays inside the checkout
// names this same commit and is allowed; a dangling link is allowed, as a
// missing replace target is, because the go command fails on it and reads
// nothing. A nested module's subtree is skipped: it is checked when it is
// scanned, and as a replace root when another module names it. The .git
// directory is not commit content and the go command never reads it, so it is
// skipped too. Any other walk or resolve error refuses, because the tree
// could not be proven inside.
func linksStayInCheckout(checkout string, module Module) bool {
	root, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		return false
	}
	roots := []string{filepath.Join(checkout, filepath.FromSlash(module.Dir))}
	for _, target := range module.LocalReplaces {
		roots = append(roots, filepath.Join(checkout, filepath.FromSlash(target)))
	}
	seen := make(map[string]bool, len(roots))
	for _, raw := range roots {
		resolved, err := filepath.EvalSymlinks(raw)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !pathInside(root, resolved) {
			return false
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		info, err := os.Stat(resolved)
		if err != nil {
			return false
		}
		if !info.IsDir() {
			continue
		}
		if err := walkLinksInside(root, resolved); err != nil {
			return false
		}
	}
	return true
}

// walkLinksInside resolves every symlink under one resolved root.
func walkLinksInside(checkoutRoot, root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(path)
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if !pathInside(checkoutRoot, resolved) {
				return errLinkOutsideCheckout
			}
			return nil
		}
		if entry.IsDir() && path != root {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(path, goModName)); err == nil {
				return filepath.SkipDir
			}
		}
		return nil
	})
}

// needsCgo reports whether cgo is the only thing that kept a file out of the
// scanned graph: go/build accepts it for the pinned GOOS/GOARCH once cgo is
// on, and with cgo off it is excluded — either because it imports "C"
// (MatchFile reads only name and build constraints, so the import is checked
// here) or because its constraints name the cgo tag. A `//go:build ignore`
// file or another platform's file can import "C" too, and golang.org/x/sys/unix
// ships several, so without the first arm nearly any graph would count; a
// plain file is accepted with cgo off too, so without the second it would
// count as well.
func needsCgo(path string) bool {
	withCgo := scanBuildContext(true)
	match, err := withCgo.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil || !match {
		return false
	}
	if importsCgo(path) {
		return true
	}
	withoutCgo := scanBuildContext(false)
	matchOff, err := withoutCgo.MatchFile(filepath.Dir(path), filepath.Base(path))
	return err == nil && !matchOff
}

// scanBuildContext is the build context of the scan configuration, with cgo
// set as asked: a copy of build.Default pinned to this toolchain's GOOS and
// GOARCH (the binary and the seeded toolchain ship for the same image), with
// no build tags. CgoEnabled is set here, never read from the component's own
// environment, which the refusing startup check keeps unset in production.
// No tags beyond the defaults keeps the probe honest about custom-tag files:
// they are a stated caveat of the scan configuration, never a cgo exclusion.
func scanBuildContext(cgoEnabled bool) build.Context {
	context := build.Default
	context.GOOS, context.GOARCH, context.CgoEnabled = runtime.GOOS, runtime.GOARCH, cgoEnabled
	context.BuildTags = nil
	context.OpenFile = func(path string) (io.ReadCloser, error) {
		file, err := os.Open(path) // #nosec G304 -- a regular file the walk found in this claim's private checkout or module cache
		if err != nil {
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{io.LimitReader(file, goFileSniffBytes), file}, nil
	}
	return context
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
