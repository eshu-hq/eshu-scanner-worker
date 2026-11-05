// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// goModName is the only file this analyzer reads.
	goModName = "go.mod"
	// maxGoModBytes bounds one go.mod read. A real file is kilobytes; a larger one
	// is reported as a warning rather than read.
	maxGoModBytes = 4 * 1024 * 1024
	// maxGoModTotalBytes bounds what one claim reads across every go.mod, far above
	// a real repository. Over it the claim fails input_limit_exceeded.
	maxGoModTotalBytes = 64 * 1024 * 1024
	// maxGoModFiles bounds the go.mod files one claim handles, far above a real
	// repository. Over it the claim fails file_limit_exceeded.
	maxGoModFiles = 4096
	// maxTreeEntryBytes bounds one ls-tree record. No checkout can hold a path this
	// long, so a longer one is a hostile tree.
	maxTreeEntryBytes = 64 * 1024

	gitModeSymlink = "120000"
	gitModeGitlink = "160000"
)

// goModState says what reading one go.mod entry may do.
type goModState int

const (
	// goModReadable is a regular blob with a safe path, within the read bound.
	goModReadable goModState = iota
	// goModOversized is above the read bound and is never read.
	goModOversized
	// goModNotRegular is a symlink or a gitlink. The go command follows a link, so
	// the entry is a module this analyzer cannot attest, and it is never read.
	goModNotRegular
	// goModInvalidPath has a path that must not reach a fact as identity, or a path
	// a hand-built tree names twice, which would give two facts one stable key.
	goModInvalidPath
)

// goModEntry is one go.mod the verified tree holds.
type goModEntry struct {
	// rawPath is the path as the tree holds it. It never reaches a fact.
	rawPath string
	// relativePath is the path for facts. An invalid path carries its injective
	// escape, so two hostile names can never share a key.
	relativePath string
	object       string
	size         int64
	state        goModState
}

// treeManifest is what the verified tree holds, measured before any worktree byte
// exists.
type treeManifest struct {
	goMods []goModEntry
}

// shouldSkipDir names the directories whose go.mod files are not this
// repository's modules.
func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "vendor", "testdata", "node_modules":
		return true
	default:
		return false
	}
}

// readManifest streams the verified tree and holds it to the claim's budgets. It
// counts every entry and every blob byte, excluded directories included, so an
// overrun is terminal before one worktree byte is written. git reads a blob's size
// from its object header, so a compressed bomb costs nothing to measure.
func (g gitRunner) readManifest(ctx context.Context, dir string, target TargetConfig, limits scannerworker.ResourceLimits) (treeManifest, error) {
	var manifest treeManifest
	output, err := g.stream(ctx, target.origin, func(stdout io.Reader) error {
		parsed, parseErr := parseTree(stdout, limits)
		manifest = parsed
		return parseErr
	}, "-C", dir, "ls-tree", "-r", "-l", "-z", "--full-tree", target.SourceCommitSHA)
	if err != nil {
		var failure scannerworker.AnalyzerFailure
		if errors.As(err, &failure) {
			return treeManifest{}, err
		}
		return treeManifest{}, classifyGitFailure(err, output, reasonCheckoutFailed)
	}
	return manifest, nil
}

// parseTree reads `git ls-tree -r -l -z` records and applies the budgets as it goes.
func parseTree(stream io.Reader, limits scannerworker.ResourceLimits) (treeManifest, error) {
	var (
		manifest  treeManifest
		fileCount int64
		bytesRead int64
		goModRead int64
	)
	reader := bufio.NewReaderSize(stream, maxTreeEntryBytes)
	for {
		record, err := reader.ReadSlice(0)
		if errors.Is(err, io.EOF) && len(record) == 0 {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return treeManifest{}, inputLimitFailure()
		}
		if err != nil {
			return treeManifest{}, checkoutFailure(reasonCheckoutFailed)
		}
		mode, object, size, rawPath, ok := parseTreeRecord(record[:len(record)-1])
		if !ok {
			return treeManifest{}, checkoutFailure(reasonCheckoutFailed)
		}
		fileCount++
		if fileCount > limits.MaxFiles {
			return treeManifest{}, fileLimitFailure()
		}
		bytesRead += size
		if bytesRead > limits.MaxInputBytes {
			return treeManifest{}, inputLimitFailure()
		}
		if !isModuleFile(rawPath) {
			continue
		}
		entry := classifyGoMod(mode, object, size, rawPath)
		if entry.state == goModReadable {
			goModRead += size
		}
		if goModRead > maxGoModTotalBytes {
			return treeManifest{}, inputLimitFailure()
		}
		manifest.goMods = append(manifest.goMods, entry)
		if len(manifest.goMods) > maxGoModFiles {
			return treeManifest{}, fileLimitFailure()
		}
	}
	slices.SortFunc(manifest.goMods, func(a, b goModEntry) int {
		return cmp.Or(cmp.Compare(a.relativePath, b.relativePath), cmp.Compare(a.rawPath, b.rawPath))
	})
	manifest.goMods = refuseRepeatedPaths(manifest.goMods)
	return manifest, nil
}

// refuseRepeatedPaths leaves one invalid entry for a path a hand-built tree repeats.
// Neither blob can speak for the path, and git itself could check out only one.
func refuseRepeatedPaths(sorted []goModEntry) []goModEntry {
	kept := sorted[:0]
	for _, entry := range sorted {
		if len(kept) > 0 && kept[len(kept)-1].rawPath == entry.rawPath {
			kept[len(kept)-1].state = goModInvalidPath
			kept[len(kept)-1].relativePath = escapePath(entry.rawPath)
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// parseTreeRecord splits "<mode> <type> <object> <size>\t<path>". The size column
// is space padded, and is "-" for an entry with no blob.
func parseTreeRecord(record []byte) (mode, object string, size int64, rawPath string, ok bool) {
	head, pathBytes, found := bytes.Cut(record, []byte{'\t'})
	if !found {
		return "", "", 0, "", false
	}
	fields := strings.Fields(string(head))
	if len(fields) != 4 {
		return "", "", 0, "", false
	}
	if fields[3] != "-" {
		parsed, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || parsed < 0 {
			return "", "", 0, "", false
		}
		size = parsed
	}
	return fields[0], fields[2], size, string(pathBytes), true
}

// isModuleFile reports a go.mod outside the excluded directories, at any depth.
func isModuleFile(rawPath string) bool {
	if path.Base(rawPath) != goModName {
		return false
	}
	for _, segment := range strings.Split(path.Dir(rawPath), "/") {
		if shouldSkipDir(segment) {
			return false
		}
	}
	return true
}

// classifyGoMod decides what may happen to one go.mod entry. A bad path wins, since
// that entry's path cannot reach a fact whatever its mode.
func classifyGoMod(mode, object string, size int64, rawPath string) goModEntry {
	entry := goModEntry{rawPath: rawPath, relativePath: rawPath, object: object, size: size}
	switch {
	case !isSafeRelativePath(rawPath):
		entry.relativePath = escapePath(rawPath)
		entry.state = goModInvalidPath
	case mode == gitModeSymlink || mode == gitModeGitlink:
		entry.state = goModNotRegular
	case size > maxGoModBytes:
		entry.state = goModOversized
	default:
		entry.state = goModReadable
	}
	return entry
}

// isSafeRelativePath accepts a relative path a fact may carry as identity: valid
// UTF-8 with no control character and no empty or dot segment.
func isSafeRelativePath(rawPath string) bool {
	if !isSafeText(rawPath) {
		return false
	}
	for _, segment := range strings.Split(rawPath, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// isSafeText reports text a fact may carry: Postgres TEXT cannot hold NUL, JSON
// repair would rewrite invalid UTF-8, and a control character can forge a log line.
func isSafeText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	return !strings.ContainsFunc(text, unicode.IsControl)
}

// escapePath percent-encodes the bytes a fact cannot carry, and "%" itself, so the
// result is valid text and two different raw paths never escape to the same value.
func escapePath(rawPath string) string {
	var escaped strings.Builder
	for rest := rawPath; rest != ""; {
		r, size := utf8.DecodeRuneInString(rest)
		switch {
		case r == utf8.RuneError && size == 1, unicode.IsControl(r), r == '%':
			for _, b := range []byte(rest[:size]) {
				fmt.Fprintf(&escaped, "%%%02X", b)
			}
		default:
			escaped.WriteString(rest[:size])
		}
		rest = rest[size:]
	}
	return escaped.String()
}

// readBlob reads one go.mod object. The manifest's size bounds it. Reading the
// object, not a worktree file, means no filter, symlink, or path can intervene.
func (g gitRunner) readBlob(ctx context.Context, dir string, target TargetConfig, entry goModEntry) ([]byte, error) {
	body, output, err := g.capture(ctx, maxGoModBytes+1, target.origin, HostToken{}, "-C", dir, "cat-file", "blob", entry.object)
	if err != nil {
		return nil, classifyGitFailure(err, output, reasonCheckoutFailed)
	}
	if int64(len(body)) != entry.size {
		return nil, checkoutFailure(reasonCheckoutFailed)
	}
	return body, nil
}
