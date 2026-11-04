// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestEachGitStepFailureIsClassified fails one git step at a time through the
// shim and proves the bounded reason names the step. A checkout runs only for a
// stage, so that row wires one.
func TestEachGitStepFailureIsClassified(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	for subcommand, reason := range map[string]string{
		"init":      reasonFetchFailed,
		"remote":    reasonFetchFailed,
		"fetch":     reasonFetchFailed,
		"rev-parse": reasonCheckoutFailed,
		"ls-tree":   reasonCheckoutFailed,
		"cat-file":  reasonCheckoutFailed,
		"checkout":  reasonCheckoutFailed,
	} {
		t.Run(subcommand, func(t *testing.T) {
			t.Parallel()

			shim, _ := gitShim(t, failOnArgument(subcommand, ""))
			analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) {
				c.Options.GitPath = shim
				c.Options.Stage = &recordingStage{t: t}
			})
			_, err := analyzer.Analyze(context.Background(), testInput(t))
			wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
			wantReason(t, err, reason)
		})
	}
}

// failOnArgument is a shim body that fails a call holding this exact argument.
// It compares whole arguments because temp paths carry the test name, which can
// hold the subcommand's own text.
func failOnArgument(argument, stderr string) string {
	return `for a in "$@"; do if [ "$a" = "` + argument + `" ]; then echo "` + stderr + `" >&2; exit 1; fi; done`
}

// TestCheckoutRefusalTextIsOnlyReadOnTheFetch proves a local failure whose text
// happens to read like a refusal stays a retryable checkout failure.
func TestCheckoutRefusalTextIsOnlyReadOnTheFetch(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, failOnArgument("ls-tree", "Authentication failed"))
	analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim })
	_, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
}

// TestSourceRefusedRecognizesGitsWording pins the classifier against git's text
// for each way a source refuses, and against ordinary transient text.
func TestSourceRefusedRecognizesGitsWording(t *testing.T) {
	t.Parallel()

	for output, want := range map[string][2]bool{
		"fatal: Authentication failed for 'https://h/o/r.git/'":                       {true, true},
		"fatal: could not read Username for 'https://h': terminal prompts disabled":   {true, true},
		"fatal: could not read Password for 'https://h': No such device":              {true, true},
		"fatal: unable to access 'https://h/': The requested URL returned error: 401": {true, true},
		"fatal: unable to access 'https://h/': The requested URL returned error: 403": {true, false},
		"fatal: unable to access 'https://h/': The requested URL returned error: 404": {true, false},
		"remote: Repository not found.":                                               {true, false},
		"fatal: repository 'https://h/o/r.git/' not found":                            {true, false},
		"fatal: unable to access 'https://h/': The requested URL returned error: 503": {false, false},
		"fatal: remote error: upload-pack: not our ref aaaa":                          {false, false},
		"fatal: unable to access 'https://h/': Could not resolve host: h":             {false, false},
		"": {false, false},
	} {
		refused, tokenRejected := sourceRefused(output)
		if refused != want[0] || tokenRejected != want[1] {
			t.Errorf("sourceRefused(%q) = %v, %v, want %v", output, refused, tokenRejected, want)
		}
	}
}

// TestTimeoutKillsGitAndItsChildren proves a spent deadline stops the whole
// process group promptly. The sleep is a child of the shim standing in for git; killing
// only the shim would hold the output pipes until WaitDelay.
func TestTimeoutKillsGitAndItsChildren(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *fetch*) sleep 60;; esac`)
	analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := analyzer.Analyze(ctx, testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	if elapsed := time.Since(start); elapsed >= gitWaitDelay {
		t.Fatalf("Analyze returned after %s, want the process group killed before the %s wait delay", elapsed, gitWaitDelay)
	}
}

// TestUnusableTempRootIsRetryable proves a missing checkout volume is a
// retryable checkout failure.
func TestUnusableTempRootIsRetryable(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.TempRoot = filepath.Join(t.TempDir(), "missing") })
	_, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
}

// TestBoundedBufferKeepsTheHeadAndNeverBlocks proves a long stream is truncated
// and still reports every byte written, so git never stalls on a full pipe.
func TestBoundedBufferKeepsTheHeadAndNeverBlocks(t *testing.T) {
	t.Parallel()

	buffer := &boundedBuffer{limit: 4}
	for range 2 {
		written, err := buffer.Write([]byte("abc"))
		if err != nil || written != 3 {
			t.Fatalf("Write = %d, %v", written, err)
		}
	}
	if got := buffer.String(); got != "abca" {
		t.Fatalf("String = %q", got)
	}
}

// TestFactLimitCoversWarningsAddedAfterTheStage proves stage facts count toward
// the fact budget.
func TestFactLimitCoversWarningsAddedAfterTheStage(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	input := testInput(t)
	input.Limits.MaxFacts = 1
	stage := &recordingStage{t: t, outcome: StageOutcome{
		ModulesAnalyzed: 1,
		Failed:          []ModuleFailure{{RelativePath: "go.mod", Reason: "analysis_failed", Class: scannerworker.FailureClassAnalysisFailed}},
	}}
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassFactLimitExceeded, false)
}

// TestAStageWithNoEligibleModuleIsNotCalled proves a repository whose every
// module is above the pin never starts stage B and stays partial.
func TestAStageWithNoEligibleModuleIsNotCalled(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/a\n\ngo 1.99\n\nrequire m.test/b v1.0.0\n"})
	stage := &recordingStage{t: t, err: errors.New("stage must not run")}
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if c := result.Completion; !c.Partial || c.TrustedDeletion {
		t.Fatalf("completion = %+v", c)
	}
}

// TestProductionDefaultsNeedNoOptions proves the defaults: https alone, git on
// PATH, the running toolchain, and this build's version.
func TestProductionDefaultsNeedNoOptions(t *testing.T) {
	t.Parallel()

	analyzer, err := NewAnalyzer(Config{CollectorInstanceID: "i", Target: validTarget()})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	if analyzer.git.path != "git" || strings.Join(analyzer.git.schemes, ",") != "https" {
		t.Fatalf("git = %+v", analyzer.git)
	}
	if !strings.HasPrefix(analyzer.toolchain, "go1.") || strings.Contains(analyzer.toolchain, " ") || analyzer.version == "" {
		t.Fatalf("toolchain = %q version = %q", analyzer.toolchain, analyzer.version)
	}
	if got := analyzer.target.origin; got != "https://github.com" {
		t.Fatalf("origin = %q", got)
	}
}
