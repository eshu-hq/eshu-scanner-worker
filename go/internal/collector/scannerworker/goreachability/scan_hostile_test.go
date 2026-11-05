// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// linkedRepo commits files plus symlinks, which fixtureRepo cannot write.
func linkedRepo(t *testing.T, files, links map[string]string) (string, string) {
	t.Helper()

	url, _ := fixtureRepo(t, files)
	root := strings.TrimPrefix(url, "file://")
	for name, target := range links {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--message", "links")
	return url, fixtureGit(t, root, "rev-parse", "HEAD")
}

// realStage builds a ScanStage over a stand-in scanner and a cache the test owns.
func realStage(t *testing.T, toolchain Toolchain, cacheRoot string) *ScanStage {
	t.Helper()

	stage, err := NewScanStage(ScanConfig{Toolchain: toolchain, CacheRoot: cacheRoot, Lookup: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatalf("NewScanStage() error = %v", err)
	}
	return stage
}

// assertNeverRan fails if the stand-in scanner wrote its call log.
func assertNeverRan(t *testing.T, log string) {
	t.Helper()

	if _, err := os.Stat(log); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the scanner ran: %s", readLog(t, log))
	}
}

// TestLinkedGoSumCannotWriteOutsideItsCheckout is the B1 regression. GOFLAGS=-mod=mod
// makes the go command write go.sum through a link, so a repository could plant a file
// anywhere the uid can write, and at the shared module cache it broke the next
// repository's scan. The stand-in does what the go command did: it writes go.sum, then
// creates the cache directory a real download needs.
func TestLinkedGoSumCannotWriteOutsideItsCheckout(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]func(cacheRoot, outside string) string{
		"planted outside": func(_, outside string) string { return filepath.Join(outside, "planted-by-repo") },
		"shared cache": func(cacheRoot, _ string) string {
			return filepath.Join(cacheRoot, "mod", "cache", "download", "rsc.io")
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cacheRoot := filepath.Join(t.TempDir(), "cache")
			if err := os.MkdirAll(filepath.Join(cacheRoot, "mod", "cache", "download"), 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			planted := target(cacheRoot, t.TempDir())
			fixture := fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl")
			toolchain, _ := fakeScanner(t, `printf 'm v1 h1:x\n' > go.sum; mkdir -p "$GOMODCACHE/cache/download/rsc.io" || exit 1; cat `+fixture)
			stage := realStage(t, toolchain, cacheRoot)

			url, sha := linkedRepo(t, map[string]string{"go.mod": goModV1}, map[string]string{"go.sum": planted})
			result := analyze(t, fixtureAnalyzer(t, url, sha, func(c *Config) { c.Options.Stage = stage }))
			if _, err := os.Lstat(planted); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the link wrote outside the checkout: %s, %v", planted, err)
			}
			victimURL, victimShas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
			victim := analyze(t, fixtureAnalyzer(t, victimURL, victimShas[0], func(c *Config) { c.Options.Stage = stage }))
			if got := warningsOf(victim.Output); len(got) != 0 {
				t.Errorf("the next repository was affected: warnings = %v", got)
			}
			if v := victim.Completion; v.Partial || v.Figures["modules_analyzed"] != 1 {
				t.Errorf("victim completion = %+v", v)
			}

			if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_sum_not_regular go.mod"}) {
				t.Fatalf("warnings = %v", got)
			}
			if got := evidenceOf(result.Output); len(got) != 1 {
				t.Fatalf("evidence = %v, want the go.mod evidence kept", got)
			}
			c := result.Completion
			if !c.Partial || !c.TrustedDeletion || c.Figures["modules_total"] != 1 || c.Figures["modules_analyzed"] != 0 {
				t.Fatalf("completion = %+v", c)
			}
		})
	}
}

// TestLinkedGoSumNeverStartsTheScan proves the refusal comes before the child: nothing
// the go command does can follow a link if it never runs.
func TestLinkedGoSumNeverStartsTheScan(t *testing.T) {
	t.Parallel()

	toolchain, log := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	stage := realStage(t, toolchain, filepath.Join(t.TempDir(), "cache"))
	url, sha := linkedRepo(t, map[string]string{"go.mod": goModV1}, map[string]string{"go.sum": "/does/not/exist"})
	analyze(t, fixtureAnalyzer(t, url, sha, func(c *Config) { c.Options.Stage = stage }))
	assertNeverRan(t, log)
}

// TestLinkedGoSumCostsOnlyItsModule proves the sibling module still scans.
func TestLinkedGoSumCostsOnlyItsModule(t *testing.T) {
	t.Parallel()

	url, sha := linkedRepo(t, map[string]string{"go.mod": goModV1, "sub/go.mod": "module m.test/sub\n\nrequire m.test/b v1.0.0\n"}, map[string]string{"sub/go.sum": "../go.sum.real"})
	stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1}}
	result := analyze(t, fixtureAnalyzer(t, url, sha, func(c *Config) { c.Options.Stage = stage }))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_sum_not_regular sub/go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
	if len(stage.input.Modules) != 1 || stage.input.Modules[0].RelativePath != "go.mod" {
		t.Fatalf("stage modules = %+v", stage.input.Modules)
	}
}

// treeRecord writes one `git ls-tree -r -l -z` record.
func treeRecord(mode, kind, size, path string) string {
	return fmt.Sprintf("%s %s %s %7s\t%s\x00", mode, kind, strings.Repeat("a", 40), size, path)
}

// TestParseTreeMarksOnlyANonRegularGoSumBesideItsModule covers a link and a gitlink,
// and proves a regular go.sum, an orphan link, and an excluded directory stay out.
func TestParseTreeMarksOnlyANonRegularGoSumBesideItsModule(t *testing.T) {
	t.Parallel()

	stream := treeRecord("100644", "blob", "10", "go.mod") + treeRecord("120000", "blob", "4", "go.sum") +
		treeRecord("100644", "blob", "10", "gitlink/go.mod") + treeRecord("160000", "commit", "-", "gitlink/go.sum") +
		treeRecord("100644", "blob", "10", "plain/go.mod") + treeRecord("100644", "blob", "10", "plain/go.sum") +
		treeRecord("120000", "blob", "4", "orphan/go.sum") +
		treeRecord("100644", "blob", "10", "vendor/x/go.mod") + treeRecord("120000", "blob", "4", "vendor/x/go.sum")
	manifest, err := parseTree(strings.NewReader(stream), testInput(t).Limits)
	if err != nil {
		t.Fatalf("parseTree() error = %v", err)
	}
	got := map[string]bool{}
	for _, entry := range manifest.goMods {
		got[entry.relativePath] = entry.sumNotRegular
	}
	want := map[string]bool{"go.mod": true, "gitlink/go.mod": true, "plain/go.mod": false}
	if len(got) != len(want) {
		t.Fatalf("modules = %v", got)
	}
	for path, flag := range want {
		if got[path] != flag {
			t.Errorf("%s: sumNotRegular = %t, want %t", path, got[path], flag)
		}
	}
}

// TestParseTreeBoundsTheLinkedGoSumsItHolds proves a tree of links cannot grow the
// held set past the same bound as the go.mod list.
func TestParseTreeBoundsTheLinkedGoSumsItHolds(t *testing.T) {
	t.Parallel()

	var stream strings.Builder
	for i := range maxGoModFiles + 1 {
		stream.WriteString(treeRecord("120000", "blob", "4", fmt.Sprintf("d%d/go.sum", i)))
	}
	_, err := parseTree(strings.NewReader(stream.String()), testInput(t).Limits)
	wantFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
}

// TestParseTreeLeavesLinkedGoSumsInExcludedDirectoriesAlone proves vendored links cost
// nothing: no module there is scanned, so they must not spend the bound.
func TestParseTreeLeavesLinkedGoSumsInExcludedDirectoriesAlone(t *testing.T) {
	t.Parallel()

	var stream strings.Builder
	for i := range maxGoModFiles + 1 {
		stream.WriteString(treeRecord("120000", "blob", "4", fmt.Sprintf("vendor/d%d/go.sum", i)))
	}
	if _, err := parseTree(strings.NewReader(stream.String()), testInput(t).Limits); err != nil {
		t.Fatalf("parseTree() error = %v", err)
	}
}
