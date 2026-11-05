// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// TestReplaceLeavingTheCheckoutIsRefused is the B4 regression: a local replace outside
// the tree put a function from another directory into a fact claiming this commit.
func TestReplaceLeavingTheCheckoutIsRefused(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		path, target string
		outside      bool
	}{
		"parent":          {"go.mod", "../outside", true},
		"absolute":        {"go.mod", "/etc", true},
		"nested too far":  {"a/b/go.mod", "../../../outside", true},
		"cleaned out":     {"go.mod", "./lib/../../outside", true},
		"inside":          {"go.mod", "./lib", false},
		"nested inside":   {"a/b/go.mod", "../../lib", false},
		"cleaned inside":  {"a/go.mod", "../a/../lib", false},
		"the module root": {"a/go.mod", "..", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gomod := "module m.test/app\n\nrequire m.test/x v1.0.0\n\nreplace m.test/x => " + tc.target + "\n"
			url, shas := fixtureRepo(t, map[string]string{tc.path: gomod})
			stage := &recordingStage{t: t}
			if !tc.outside {
				stage.outcome = StageOutcome{ModulesAnalyzed: 1}
			}
			result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
			if got := evidenceOf(result.Output); len(got) != 1 {
				t.Fatalf("evidence = %v, want the go.mod evidence kept", got)
			}
			warnings := warningsOf(result.Output)
			if !tc.outside {
				if len(warnings) != 0 || len(stage.input.Modules) != 1 || result.Completion.Partial {
					t.Fatalf("warnings = %v modules = %+v completion = %+v, want a clean scan", warnings, stage.input.Modules, result.Completion)
				}
				return
			}
			if !slices.Equal(warnings, []string{"replace_outside_checkout " + tc.path}) {
				t.Fatalf("warnings = %v", warnings)
			}
			if c := result.Completion; len(stage.input.Modules) != 0 || !c.Partial || !c.TrustedDeletion || c.FailureClass != scannerworker.FailureClassAnalysisFailed {
				t.Fatalf("modules = %+v completion = %+v", stage.input.Modules, c)
			}
		})
	}
}

// TestReplaceThroughALinkIsResolvedBeforeTheScan covers what the go.mod text cannot
// show: a path that stays inside lexically and leaves through a link in the tree.
func TestReplaceThroughALinkIsResolvedBeforeTheScan(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()
	for name, tc := range map[string]struct {
		target string
		ran    bool
	}{
		"link leaves":     {outside, false},
		"link stays":      {"lib", true},
		"dangling":        {"missing", true},
		"chained outward": {"inner", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			files := map[string]string{"go.mod": "module m.test/app\n\nrequire m.test/x v1.0.0\n\nreplace m.test/x => ./link\n", "lib/keep.txt": "a directory the link can name"}
			links := map[string]string{"link": tc.target}
			if name == "chained outward" {
				links["inner"] = outside
			}
			url, sha := linkedRepo(t, files, links)
			toolchain, log := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
			stage := realStage(t, toolchain, filepath.Join(t.TempDir(), "cache"))
			result := analyze(t, fixtureAnalyzer(t, url, sha, func(c *Config) { c.Options.Stage = stage }))
			warnings := warningsOf(result.Output)
			if tc.ran {
				if _, err := os.Stat(log); err != nil {
					t.Fatalf("the scanner did not run: %v, warnings = %v", err, warnings)
				}
				if slices.Contains(warnings, "replace_outside_checkout go.mod") {
					t.Fatalf("warnings = %v", warnings)
				}
				return
			}
			assertNeverRan(t, log)
			if !slices.Equal(warnings, []string{"replace_outside_checkout go.mod"}) {
				t.Fatalf("warnings = %v", warnings)
			}
		})
	}
}

// TestWindowsReplacePathNeverReachesTheScan pins what the strict parser does with a
// backslash path on this platform, so the replace check does not have to.
func TestWindowsReplacePathNeverReachesTheScan(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/app\n\nrequire m.test/x v1.0.0\n\nreplace m.test/x => ..\\outside\n"})
	stage := &recordingStage{t: t, err: errors.New("the stage must not run")}
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_parse_failed go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
}

// TestLocalReplacesAreDeduplicated keeps the link check cheap on a hostile file that
// repeats one target tens of thousands of times.
func TestLocalReplacesAreDeduplicated(t *testing.T) {
	t.Parallel()

	module, err := parseGoMod("a/go.mod", []byte(heavyGoMod("q", 256*1024)))
	if err != nil {
		t.Fatalf("parseGoMod() error = %v", err)
	}
	if !slices.Equal(module.localReplaces, []string{"x"}) {
		t.Fatalf("localReplaces = %v", module.localReplaces)
	}
	if module.replaceOutside {
		t.Fatal("replaceOutside = true for a path inside the checkout")
	}
}
