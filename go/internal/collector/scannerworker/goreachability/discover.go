// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// goModName is the only file this walk reads.
const goModName = "go.mod"

// maxGoModBytes bounds one go.mod read. A real file is kilobytes; a larger one
// is reported as a warning rather than read.
const maxGoModBytes = 4 * 1024 * 1024

// goModFile is one discovered go.mod. Oversized files carry no body.
type goModFile struct {
	relativePath string
	body         []byte
	oversized    bool
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

// discoverGoMods walks the checkout in lexical order under the claim's file and
// byte budgets, which count every regular file outside the skipped directories.
// Symlinks are never followed, so a link cannot read outside the checkout.
func discoverGoMods(ctx context.Context, root string, limits scannerworker.ResourceLimits) ([]goModFile, error) {
	var (
		found      []goModFile
		fileCount  int64
		inputBytes int64
	)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return checkoutFailure(reasonCheckoutFailed)
		}
		if ctx.Err() != nil {
			return checkoutFailure(reasonCheckoutFailed)
		}
		if entry.IsDir() {
			if path != root && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		fileCount++
		if fileCount > limits.MaxFiles {
			return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassFileLimitExceeded, scannerworker.ResourceUsage{}, nil)
		}
		info, err := entry.Info()
		if err != nil {
			return checkoutFailure(reasonCheckoutFailed)
		}
		inputBytes += info.Size()
		if inputBytes > limits.MaxInputBytes {
			return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassInputLimitExceeded, scannerworker.ResourceUsage{}, nil)
		}
		if entry.Name() != goModName {
			return nil
		}
		file := goModFile{relativePath: filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator)))}
		file.body, err = readBounded(path)
		if errors.Is(err, errGoModTooLarge) {
			file.oversized = true
		} else if err != nil {
			return checkoutFailure(reasonCheckoutFailed)
		}
		found = append(found, file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

var errGoModTooLarge = errors.New("go.mod above the read bound")

// readBounded reads at most maxGoModBytes from a file the walk saw as regular.
func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- path comes from walking this analyzer's own private checkout directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	body, err := io.ReadAll(io.LimitReader(file, maxGoModBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxGoModBytes {
		return nil, errGoModTooLarge
	}
	return body, nil
}
