// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// symlinkRepo builds a repository whose sub/go.mod is a link to an outside file.
func symlinkRepo(t *testing.T) (string, string) {
	t.Helper()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/ok\n\nrequire m.test/a v1.0.0\n"})
	root := strings.TrimPrefix(url, "file://")
	outside := filepath.Join(t.TempDir(), "outside.mod")
	if err := os.WriteFile(outside, []byte("module m.test/leak\n\nrequire m.test/leaked v1.0.0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o750); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sub", "go.mod")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--message", "link")
	_ = shas
	return url, fixtureGit(t, root, "rev-parse", "HEAD")
}

// TestWithoutStageBAModuleResultIsNeverComplete pins the ruling for the Stage A
// release: no govulncheck ran, so nothing attests reachability or deletion.
func TestWithoutStageBAModuleResultIsNeverComplete(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	c := result.Completion
	if c == nil || !c.Partial || c.TrustedDeletion || c.FailureClass != "" || c.WarningCount != 0 {
		t.Fatalf("completion = %+v, want partial, untrusted, no failure class, no warning", c)
	}
	if c.Figures["modules_total"] != 1 || c.Figures["modules_analyzed"] != 0 || c.Figures["requirements_total"] != 1 || c.Figures["warnings_total"] != 0 {
		t.Fatalf("figures = %v", c.Figures)
	}
}

// TestStageSeamReceivesEligibleModulesAndDecidesTheAttestation is the seam
// contract for #48.
func TestStageSeamReceivesEligibleModulesAndDecidesTheAttestation(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{
		"go.mod":     "module m.test/root\n\ngo 1.24\n\nrequire m.test/a v1.0.0\n",
		"sub/go.mod": "module m.test/sub\n\ngo 1.24\n\nrequire m.test/b v1.0.0\n",
	})
	stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 2}, inspect: func(input StageInput) {
		cmd := exec.Command("git", "-C", input.CheckoutDir, "rev-list", "--count", "HEAD")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("rev-list: %v", err)
			return
		}
		if count, err := strconv.Atoi(strings.TrimSpace(string(out))); err != nil || count != 1 {
			t.Errorf("history depth = %q, want a one-commit shallow fetch", out)
		}
	}}
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if got := stage.input.RepositoryID; got != testRepositoryID {
		t.Fatalf("stage repository = %q", got)
	}
	if stage.input.SourceCommitSHA != shas[0] || stage.input.SourceURI != url {
		t.Fatalf("stage input = %+v", stage.input)
	}
	var paths []string
	for _, module := range stage.input.Modules {
		paths = append(paths, module.RelativePath+"="+module.Dir+"="+module.ModulePath)
	}
	if !slices.Equal(paths, []string{"go.mod=.=m.test/root", "sub/go.mod=sub=m.test/sub"}) {
		t.Fatalf("stage modules = %v", paths)
	}
	c := result.Completion
	if c.Partial || !c.TrustedDeletion || c.Figures["modules_analyzed"] != 2 {
		t.Fatalf("completion = %+v, want complete and trusted once every module was analyzed", c)
	}
}

// TestStageExcludesToolchainUnsupportedModulesAndNeverAttests proves a module
// above the pin is never handed to stage B and blocks the attestation.
func TestStageExcludesToolchainUnsupportedModulesAndNeverAttests(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{
		"go.mod":     "module m.test/root\n\ngo 1.24\n\nrequire m.test/a v1.0.0\n",
		"new/go.mod": "module m.test/new\n\ngo 1.99\n\nrequire m.test/b v1.0.0\n",
	})
	stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1}}
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if len(stage.input.Modules) != 1 || stage.input.Modules[0].RelativePath != "go.mod" {
		t.Fatalf("stage modules = %+v", stage.input.Modules)
	}
	if c := result.Completion; !c.Partial || c.TrustedDeletion {
		t.Fatalf("completion = %+v", c)
	}
}

// TestStageShortOrFailedRunsNeverAttest covers a stage that analyzed fewer
// modules than it was given and one that reported a failed module.
func TestStageShortOrFailedRunsNeverAttest(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	for name, outcome := range map[string]StageOutcome{
		"short":  {ModulesAnalyzed: 0},
		"failed": {ModulesAnalyzed: 1, Failed: []ModuleFailure{{RelativePath: "go.mod", Reason: "analysis_failed", Class: scannerworker.FailureClassAnalysisFailed}}},
	} {
		stage := &recordingStage{t: t, outcome: outcome}
		result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
		if c := result.Completion; !c.Partial || c.TrustedDeletion {
			t.Errorf("%s: completion = %+v, want partial and untrusted", name, c)
		}
		if name == "failed" {
			if got := warningsOf(result.Output); !slices.Equal(got, []string{"analysis_failed go.mod"}) {
				t.Errorf("failed: warnings = %v", got)
			}
			if result.Completion.FailureClass != scannerworker.FailureClassAnalysisFailed {
				t.Errorf("failed: class = %q", result.Completion.FailureClass)
			}
		}
	}
}

// TestStageErrorFailsTheClaim proves a whole-claim stage failure passes through
// with its own class.
func TestStageErrorFailsTheClaim(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	stage := &recordingStage{t: t, err: scannerworker.NewRetryableAnalyzerFailure(scannerworker.FailureClassSourceUnavailable, scannerworker.ResourceUsage{}, errors.New("db"))}
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassSourceUnavailable, true)
}

// TestFreshnessHintFollowsTheRulingTuple proves the hint is stable for one
// tuple and moves when any member moves.
func TestFreshnessHintFollowsTheRulingTuple(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1}, map[string]string{"go.mod": goModV1, "x": "y"})
	hint := func(sha string, mutate func(*Config)) string {
		return analyze(t, fixtureAnalyzer(t, url, sha, mutate)).Completion.FreshnessHint
	}
	base := hint(shas[0], nil)
	if !strings.HasPrefix(base, "sha256:") || len(base) != len("sha256:")+64 {
		t.Fatalf("hint = %q, want sha256:<64 hex>", base)
	}
	if again := hint(shas[0], nil); again != base {
		t.Fatalf("hint moved for one tuple: %q vs %q", again, base)
	}
	for name, got := range map[string]string{
		"commit":    hint(shas[1], nil),
		"scanner":   hint(shas[0], func(c *Config) { c.Options.ScannerVersion = "other" }),
		"toolchain": hint(shas[0], func(c *Config) { c.Options.Toolchain = "go1.26.11" }),
		"vulndb": hint(shas[0], func(c *Config) {
			c.Options.Stage = &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1, VulnDBLastModified: "2026-11-02T00:00:00Z"}}
		}),
	} {
		if got == base {
			t.Errorf("%s: hint did not move", name)
		}
	}
}

// TestPinnedToolchainDropsExperimentSuffix proves the default pin reads a real
// runtime version string.
func TestPinnedToolchainDropsExperimentSuffix(t *testing.T) {
	t.Parallel()

	if got := pinnedToolchain("go1.26.10 X:nocoverageredesign"); got != "go1.26.10" {
		t.Fatalf("pinnedToolchain = %q", got)
	}
}
