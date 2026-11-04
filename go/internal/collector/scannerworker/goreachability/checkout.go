// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

const (
	// Bounded reasons narrowing a checkout_failed or auth_denied class on the
	// stderr record.
	reasonGitUnavailable = "git_unavailable"
	reasonFetchFailed    = "fetch_failed"
	reasonCheckoutFailed = "checkout_failed"
	reasonCommitMismatch = "commit_mismatch"
	reasonSourceRefused  = "source_refused"
	reasonTokenRejected  = "token_rejected"

	// sha256ObjectNameLength names a commit in a sha-256 repository, which git
	// must initialize in that object format to fetch from.
	sha256ObjectNameLength = 64
	// fetchWatchInterval is how often a running fetch has its .git measured. A
	// pack has no client-side size limit, so this is the only bound on the write.
	fetchWatchInterval = time.Second
)

// fetchCommit fetches exactly one commit into dir under the byte budget and
// verifies that the fetched object is that commit. It writes no worktree. The
// token reaches only the fetch process, through its environment.
func (g gitRunner) fetchCommit(ctx context.Context, dir string, target TargetConfig, token HostToken, maxBytes int64) error {
	initArgs := []string{"init", "--quiet", "--template="}
	if len(target.SourceCommitSHA) == sha256ObjectNameLength {
		initArgs = append(initArgs, "--object-format=sha256")
	}
	for _, args := range [][]string{append(initArgs, dir), {"-C", dir, "remote", "add", "origin", target.CloneURL}} {
		if _, output, err := g.run(ctx, target.origin, HostToken{}, args...); err != nil {
			return classifyGitFailure(err, output, reasonFetchFailed)
		}
	}
	if err := g.watchedFetch(ctx, dir, target, token, maxBytes); err != nil {
		return err
	}
	return g.verifyCommit(ctx, dir, target, "FETCH_HEAD^{commit}")
}

// watchedFetch runs the fetch while measuring .git, and cancels it the moment the
// directory passes the byte budget. A final measure catches a fetch that finished
// between two polls.
func (g gitRunner) watchedFetch(ctx context.Context, dir string, target TargetConfig, token HostToken, maxBytes int64) error {
	gitDir := filepath.Join(dir, ".git")
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var overBudget atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(fetchWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				if directorySize(gitDir) > maxBytes {
					overBudget.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	_, output, err := g.run(watchCtx, target.origin, token, "-C", dir, "fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules", "origin", target.SourceCommitSHA)
	cancel()
	<-done
	if overBudget.Load() {
		return inputLimitFailure()
	}
	if err != nil {
		return classifyGitFailure(err, output, reasonFetchFailed)
	}
	if directorySize(gitDir) > maxBytes {
		return inputLimitFailure()
	}
	return nil
}

// materialize writes the verified commit's whole tree for stage B. The manifest
// has already held that tree to the budgets.
func (g gitRunner) materialize(ctx context.Context, dir string, target TargetConfig) error {
	if _, output, err := g.run(ctx, target.origin, HostToken{}, "-C", dir, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", target.SourceCommitSHA); err != nil {
		return classifyGitFailure(err, output, reasonCheckoutFailed)
	}
	return g.verifyCommit(ctx, dir, target, "HEAD")
}

// verifyCommit proves a revision is the claimed commit.
func (g gitRunner) verifyCommit(ctx context.Context, dir string, target TargetConfig, revision string) error {
	head, output, err := g.run(ctx, target.origin, HostToken{}, "-C", dir, "rev-parse", "--verify", "--end-of-options", revision)
	if err != nil {
		return classifyGitFailure(err, output, reasonCheckoutFailed)
	}
	if strings.TrimSpace(head) != target.SourceCommitSHA {
		return checkoutFailure(reasonCommitMismatch)
	}
	return nil
}

// directorySize sums the files under dir. git renames temporary files as it
// works, so a file that vanishes mid-walk is simply not counted.
func directorySize(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil //nolint:nilerr // a vanished entry is not a measuring failure
		}
		if info, infoErr := entry.Info(); infoErr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// classifyGitFailure maps one failed git call to a bounded failure. The cause
// and output are dropped here: they can name the remote.
func classifyGitFailure(err error, output, reason string) error {
	var missing *exec.Error
	if errors.As(err, &missing) || errors.Is(err, os.ErrNotExist) {
		return checkoutFailure(reasonGitUnavailable)
	}
	if reason == reasonFetchFailed {
		if refused, tokenRejected := sourceRefused(output); refused {
			return authFailure(tokenRejected)
		}
	}
	return checkoutFailure(reason)
}

// sourceRefused recognizes a source that refused the credential. git runs with
// LC_ALL=C, so its text is stable. GitHub answers 404 for a private repository
// the token cannot see, so a missing repository counts as a refusal rather than
// a transient to retry.
func sourceRefused(output string) (refused, tokenRejected bool) {
	lower := strings.ToLower(output)
	for _, marker := range []string{"authentication failed", "could not read username", "could not read password", "terminal prompts disabled", "returned error: 401"} {
		if strings.Contains(lower, marker) {
			return true, true
		}
	}
	for _, marker := range []string{"returned error: 403", "returned error: 404", "repository not found"} {
		if strings.Contains(lower, marker) {
			return true, false
		}
	}
	if strings.Contains(lower, "repository '") && strings.Contains(lower, "not found") {
		return true, false
	}
	return false, false
}

func checkoutFailure(reason string) error {
	failure := scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassCheckoutFailed, scannerworker.ResourceUsage{}, nil)
	return asFailure(failure).WithReason(reason)
}

func authFailure(tokenRejected bool) error {
	reason := reasonSourceRefused
	if tokenRejected {
		reason = reasonTokenRejected
	}
	failure := scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassAuthDenied, scannerworker.ResourceUsage{}, nil)
	return asFailure(failure).WithReason(reason)
}

func inputLimitFailure() error {
	return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassInputLimitExceeded, scannerworker.ResourceUsage{}, nil)
}

func fileLimitFailure() error {
	return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassFileLimitExceeded, scannerworker.ResourceUsage{}, nil)
}

func factLimitFailure() error {
	return scannerworker.NewTerminalAnalyzerFailure(scannerworker.FailureClassFactLimitExceeded, scannerworker.ResourceUsage{}, nil)
}

// asFailure unwraps the constructors' error type. They always return
// scannerworker.AnalyzerFailure.
func asFailure(err error) scannerworker.AnalyzerFailure {
	var failure scannerworker.AnalyzerFailure
	errors.As(err, &failure)
	return failure
}
