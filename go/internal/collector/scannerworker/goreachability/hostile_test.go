// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// heavyGoMod is a go.mod near the read bound holding one require and one replace
// per line pair, the shape that made replace matching quadratic.
func heavyGoMod(prefix string, limit int) string {
	var body strings.Builder
	body.WriteString("module m.test/" + prefix + "\n\n")
	for i := 0; body.Len() < limit-80; i++ {
		fmt.Fprintf(&body, "require m.test/%s%d v1.0.0\nreplace m.test/%s%d => ../x\n", prefix, i, prefix, i)
	}
	return body.String()
}

// peakHeapDuring samples the live heap while run executes and returns its peak
// in bytes. Top-level tests that do not call t.Parallel run alone, so the sample
// measures this analysis.
func peakHeapDuring(run func()) uint64 {
	var peak atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var stats runtime.MemStats
		for {
			runtime.ReadMemStats(&stats)
			if stats.HeapAlloc > peak.Load() {
				peak.Store(stats.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	run()
	close(stop)
	<-done
	return peak.Load()
}

// TestHostileModuleSetStaysUnderTheMemoryBudget is the F1 regression. Sixteen
// files near the read bound passed every input budget and held 5,224 MiB of heap
// against the 4,096 MiB budget, because the fact budget ran after every file
// parsed. It must now stop at the first file that overruns the budget.
func TestHostileModuleSetStaysUnderTheMemoryBudget(t *testing.T) {
	files := map[string]string{}
	for i := range 16 {
		files[fmt.Sprintf("m%d/go.mod", i)] = heavyGoMod(fmt.Sprintf("p%d", i), maxGoModBytes)
	}
	url, shas := fixtureRepo(t, files)
	var err error
	peak := peakHeapDuring(func() {
		_, err = fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), testInput(t))
	})
	wantFailure(t, err, scannerworker.FailureClassFactLimitExceeded, false)
	t.Logf("peak heap = %d MiB", peak>>20)
	if ceiling := uint64(1 << 30); peak > ceiling {
		t.Fatalf("peak heap = %d MiB, want under %d MiB", peak>>20, ceiling>>20)
	}
}

// TestLargestLegalModuleSetStaysUnderTheMemoryBudget is the case the early stop does
// not reach: sixteen files at the read bound whose facts stay inside the budget, so
// every file parses and every fact is held. It must finish, under the same ceiling.
func TestLargestLegalModuleSetStaysUnderTheMemoryBudget(t *testing.T) {
	const requiresPerFile = 3000
	files := map[string]string{}
	for i := range 16 {
		var body strings.Builder
		fmt.Fprintf(&body, "module m.test/f%d\n\n", i)
		for j := range requiresPerFile {
			fmt.Fprintf(&body, "require m.test/f%d/r%d v1.0.0\n", i, j)
		}
		for body.Len() < maxGoModBytes-80 {
			fmt.Fprintf(&body, "// padding %d\n", body.Len())
		}
		files[fmt.Sprintf("m%d/go.mod", i)] = body.String()
	}
	url, shas := fixtureRepo(t, files)
	var (
		result scannerworker.AnalyzerResult
		err    error
	)
	peak := peakHeapDuring(func() {
		result, err = fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), testInput(t))
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if got := len(result.Output.Facts); got != 16*requiresPerFile {
		t.Fatalf("facts = %d", got)
	}
	t.Logf("peak heap = %d MiB", peak>>20)
	if ceiling := uint64(1 << 30); peak > ceiling {
		t.Fatalf("peak heap = %d MiB, want under %d MiB", peak>>20, ceiling>>20)
	}
}

// BenchmarkParseGoModAtTheReadBound measures the worst file the bound admits.
func BenchmarkParseGoModAtTheReadBound(b *testing.B) {
	body := []byte(heavyGoMod("b", maxGoModBytes))
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, err := parseGoMod("go.mod", body); err != nil {
			b.Fatal(err)
		}
	}
}

// TestReplaceMatchingIsLinear is the quadratic regression: one file with 82,236
// requires and replaces took 24 seconds to parse. The bound is about 100 times
// the linear cost, so it holds on a loaded machine and fails on a scan per require.
func TestReplaceMatchingIsLinear(t *testing.T) {
	t.Parallel()

	body := []byte(heavyGoMod("q", maxGoModBytes))
	start := time.Now()
	module, err := parseGoMod("go.mod", body)
	if err != nil {
		t.Fatalf("parseGoMod() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 12*time.Second {
		t.Fatalf("parseGoMod took %s for %d requires, want linear replace matching", elapsed, len(module.requirements))
	}
	if len(module.requirements) < 50_000 || module.requirements[0].replacementPath != "../x" {
		t.Fatalf("requirements = %d, first = %+v", len(module.requirements), module.requirements[0])
	}
}

// TestBudgetCountsTheWholeTreeBeforeAnyWorktreeByte is the F2 regression: a large
// blob under an excluded directory passed a small budget. The budget now reads
// the verified tree, so the overrun is terminal with no file written.
func TestBudgetCountsTheWholeTreeBeforeAnyWorktreeByte(t *testing.T) {
	t.Parallel()

	for _, dir := range []string{"", "vendor/", "testdata/", "node_modules/", "sub/vendor/"} {
		t.Run("dir="+dir, func(t *testing.T) {
			t.Parallel()

			url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1, dir + "bomb.bin": strings.Repeat("\x00", 8<<20)})
			shim, log := gitShim(t, "")
			input := testInput(t)
			input.Limits.MaxInputBytes = 1 << 20
			_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), input)
			wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
			for call := range strings.SplitSeq(readLog(t, log), "ARGV ") {
				argv, _, _ := strings.Cut(call, "\n")
				if strings.Contains(argv, " checkout ") {
					t.Fatalf("checkout ran before the budget refused the tree: %s", argv)
				}
			}
		})
	}
}

// TestFileBudgetCountsExcludedDirectories proves the file budget has no hole.
func TestFileBudgetCountsExcludedDirectories(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1, "vendor/a": "a", "vendor/b": "b", "testdata/c": "c"})
	input := testInput(t)
	input.Limits.MaxFiles = 3
	_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
}

// TestNonRegularGoModIsPartialAndNamed is the F3 regression: a go.mod that is a
// symlink returned no_go_modules and complete, though the go command follows the link
// and the module still builds. It now counts as a module named by a warning.
func TestNonRegularGoModIsPartialAndNamed(t *testing.T) {
	t.Parallel()

	for name, link := range map[string]string{"inside": "gomod.real", "outside": "/etc/passwd", "dangling": "missing"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
			if err := os.WriteFile(filepath.Join(root, "gomod.real"), []byte(goModV1), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if err := os.Symlink(link, filepath.Join(root, "go.mod")); err != nil {
				t.Fatalf("Symlink: %v", err)
			}
			fixtureGit(t, root, "add", "--all")
			fixtureGit(t, root, "commit", "--quiet", "--message", "fixture")
			result := analyze(t, fixtureAnalyzer(t, "file://"+root, fixtureGit(t, root, "rev-parse", "HEAD"), nil))
			if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_not_regular go.mod"}) {
				t.Fatalf("warnings = %v, want the typed warning and never no_go_modules", got)
			}
			c := result.Completion
			if !c.Partial || !c.TrustedDeletion || c.Figures["modules_total"] != 1 || c.FailureClass != scannerworker.FailureClassAnalysisFailed {
				t.Fatalf("completion = %+v", c)
			}
			if got := evidenceOf(result.Output); len(got) != 0 {
				t.Fatalf("evidence = %v, want none: the link is never read", got)
			}
		})
	}
}

// TestHostileStringsNeverReachFacts is the F7 regression. A go.mod path that is
// not a valid import path is skipped with a typed warning and the module leaves
// stage B, while its valid requires stay as evidence.
func TestHostileStringsNeverReachFacts(t *testing.T) {
	t.Parallel()

	for name, require := range map[string]string{
		"nul":       `"a\x00b.test/x"`,
		"escape":    `"a\x1b[31mb.test/x"`,
		"traversal": "../../etc/passwd",
		"newline":   `"a.test/x\ny"`,
		"utf8":      `"a.test/\xff"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			gomod := "module m.test/app\n\nrequire (\n\t" + require + " v1.0.0\n\tm.test/good v1.0.0\n)\n"
			url, shas := fixtureRepo(t, map[string]string{"go.mod": gomod})
			stage := &recordingStage{t: t}
			result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
			if got := evidenceOf(result.Output); !slices.Equal(got, []string{"go.mod m.test/good v1.0.0"}) {
				t.Fatalf("evidence = %v", got)
			}
			if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_invalid_path go.mod"}) {
				t.Fatalf("warnings = %v", got)
			}
			c := result.Completion
			if !c.Partial || !c.TrustedDeletion || c.FailureClass != scannerworker.FailureClassAnalysisFailed {
				t.Fatalf("completion = %+v", c)
			}
			if len(stage.input.Modules) != 0 {
				t.Fatalf("stage modules = %+v, want the module held back", stage.input.Modules)
			}
			for _, fact := range result.Output.Facts {
				if strings.ContainsAny(fact.SourceRef.SourceRecordID, "\x00\x1b\n") || !isSafeText(fact.SourceRef.SourceRecordID) {
					t.Fatalf("record id = %q", fact.SourceRef.SourceRecordID)
				}
			}
		})
	}
}

// TestRealImportPathsWithoutADotAreKept guards the accuracy side of F7: a private
// module with no dot in its first element, a major suffix, and a tilde are real
// requires. module.CheckPath would have dropped the first.
func TestRealImportPathsWithoutADotAreKept(t *testing.T) {
	t.Parallel()

	gomod := "module corp/app\n\nrequire (\n\tcorp/internal/lib v1.0.0\n\tgopkg.in/yaml.v3 v3.0.1\n\tm.test/a~b/v2 v2.0.0\n)\n\nreplace corp/internal/lib => ../lib\n"
	url, shas := fixtureRepo(t, map[string]string{"go.mod": gomod})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := warningsOf(result.Output); len(got) != 0 {
		t.Fatalf("warnings = %v, want none", got)
	}
	if got := evidenceOf(result.Output); len(got) != 3 {
		t.Fatalf("evidence = %v", got)
	}
}

// TestInvalidRootModulePathCostsTheWholeFile covers a hostile module line.
func TestInvalidRootModulePathCostsTheWholeFile(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module \"a\\x00b\"\n\nrequire m.test/x v1.0.0\n"})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := evidenceOf(result.Output); len(got) != 0 {
		t.Fatalf("evidence = %v", got)
	}
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_invalid_path go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
}

// TestHostileReplacementTextIsRefused covers the replace side of a require.
func TestHostileReplacementTextIsRefused(t *testing.T) {
	t.Parallel()

	gomod := "module m.test/app\n\nrequire m.test/x v1.0.0\n\nreplace m.test/x => \"../a\\x1bb\"\n"
	url, shas := fixtureRepo(t, map[string]string{"go.mod": gomod})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := evidenceOf(result.Output); len(got) != 0 {
		t.Fatalf("evidence = %v", got)
	}
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_invalid_path go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
}

// TestInvalidUTF8DirectoriesDoNotCollide is the F7 key regression: two directories
// differing only in invalid bytes both encoded to one key, so one module's evidence
// vanished. Each now gets its own warning, keyed by an injective escape.
func TestInvalidUTF8DirectoriesDoNotCollide(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
	for _, dir := range []string{"a\xff", "a\xfe", "a%FF", "b\nc"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Skipf("this filesystem refuses the name %q: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte(goModV1), 0o600); err != nil {
			t.Skipf("this filesystem refuses the name %q: %v", dir, err)
		}
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--message", "fixture")
	result := analyze(t, fixtureAnalyzer(t, "file://"+root, fixtureGit(t, root, "rev-parse", "HEAD"), nil))
	want := []string{"go_mod_invalid_path a%FE/go.mod", "go_mod_invalid_path a%FF/go.mod", "go_mod_invalid_path b%0Ac/go.mod"}
	if got := warningsOf(result.Output); !slices.Equal(got, want) {
		t.Fatalf("warnings = %v, want %v", got, want)
	}
	// The valid sibling a%FF keeps its evidence under its real path, and it cannot
	// collide with the escaped warning for a\xff, whose kind and key differ.
	if got := evidenceOf(result.Output); !slices.Equal(got, []string{"a%FF/go.mod example.test/dep v1.0.0"}) {
		t.Fatalf("evidence = %v", got)
	}
	keys := map[string]bool{}
	for _, fact := range result.Output.Facts {
		if keys[fact.StableFactKey] {
			t.Fatalf("stable keys collide: %q", fact.StableFactKey)
		}
		keys[fact.StableFactKey] = true
	}
	if c := result.Completion; !c.Partial || !c.TrustedDeletion || c.Figures["modules_total"] != 4 {
		t.Fatalf("completion = %+v", c)
	}
}

// craftedTreeRepo commits a tree git add refuses to write, with one go.mod blob
// under the given directory name, and returns the URL and commit.
func craftedTreeRepo(t *testing.T, dirName string) (string, string) {
	t.Helper()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
	path := filepath.Join(root, "blob")
	if err := os.WriteFile(path, []byte(goModV1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	blob := fixtureGit(t, root, "hash-object", "-w", "blob")
	inner := fixtureGitInput(t, root, "100644 blob "+blob+"\tgo.mod\n", "mktree")
	outer := fixtureGitInput(t, root, "040000 tree "+inner+"\t"+dirName+"\n", "mktree")
	commit := fixtureGit(t, root, "commit-tree", outer, "-m", "fixture")
	fixtureGit(t, root, "update-ref", "refs/heads/main", commit)
	return "file://" + root, commit
}

// TestCraftedTreePathsAreClassifiedWithoutTouchingDisk covers tree names git add
// refuses to record. ".." is a traversal and stays a warning; ".git" is excluded.
func TestCraftedTreePathsAreClassifiedWithoutTouchingDisk(t *testing.T) {
	t.Parallel()

	url, sha := craftedTreeRepo(t, "..")
	result := analyze(t, fixtureAnalyzer(t, url, sha, nil))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_invalid_path ../go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
	if got := evidenceOf(result.Output); len(got) != 0 {
		t.Fatalf("evidence = %v", got)
	}

	url, sha = craftedTreeRepo(t, ".git")
	result = analyze(t, fixtureAnalyzer(t, url, sha, nil))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"no_go_modules "}) {
		t.Fatalf("warnings = %v, want the .git tree excluded", got)
	}
}

// TestDuplicateTreeEntriesCannotShareAKey covers a hand-built tree naming go.mod
// twice with different content. Two facts would share a stable key and the host would
// keep one silently, so the path is unusable and one warning names it.
func TestDuplicateTreeEntriesCannotShareAKey(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
	first := fixtureGitInput(t, root, goModV1, "hash-object", "-w", "--stdin")
	second := fixtureGitInput(t, root, goModV2, "hash-object", "-w", "--stdin")
	tree := fixtureGitInput(t, root, "100644 blob "+first+"\tgo.mod\n100644 blob "+second+"\tgo.mod\n", "mktree")
	commit := fixtureGit(t, root, "commit-tree", tree, "-m", "fixture")
	fixtureGit(t, root, "update-ref", "refs/heads/main", commit)
	result := analyze(t, fixtureAnalyzer(t, "file://"+root, commit, nil))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"go_mod_invalid_path go.mod"}) {
		t.Fatalf("warnings = %v", got)
	}
	if got := evidenceOf(result.Output); len(got) != 0 {
		t.Fatalf("evidence = %v", got)
	}
	if c := result.Completion; !c.Partial || !c.TrustedDeletion || c.Figures["modules_total"] != 1 {
		t.Fatalf("completion = %+v", c)
	}
}

// TestInvalidPathsAreCountedInTheFigures proves the invalid-path count reaches
// the completion figures, so the attestation cannot silently drop the warnings.
func TestInvalidPathsAreCountedInTheFigures(t *testing.T) {
	t.Parallel()

	url, sha := craftedTreeRepo(t, "..")
	result := analyze(t, fixtureAnalyzer(t, url, sha, nil))
	if got := result.Completion.Figures["invalid_paths"]; got != 1 {
		t.Fatalf("invalid_paths = %d, want 1", got)
	}
	if got := result.Completion.Figures["modules_total"]; got != 1 {
		t.Fatalf("modules_total = %d, want 1", got)
	}
}

// TestInvalidPathWarningsCannotCollide covers a valid directory literally named like
// another's escape, with a bad require. Each warning needs its own key.
func TestInvalidPathWarningsCannotCollide(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main")
	bad := "module m.test/a\n\nrequire ../x v1.0.0\n"
	for _, dir := range []string{"a\xff", "a%FF"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
			t.Skipf("this filesystem refuses the name %q: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte(bad), 0o600); err != nil {
			t.Skipf("this filesystem refuses the name %q: %v", dir, err)
		}
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--message", "fixture")
	result := analyze(t, fixtureAnalyzer(t, "file://"+root, fixtureGit(t, root, "rev-parse", "HEAD"), nil))
	want := []string{"go_mod_invalid_path a%25FF/go.mod", "go_mod_invalid_path a%FF/go.mod"}
	if got := warningsOf(result.Output); !slices.Equal(got, want) {
		t.Fatalf("warnings = %v, want %v", got, want)
	}
}

// TestTheCredentialIsNeverInTheCheckoutEnvironmentOfOtherCalls keeps the
// env-only claim honest for the two calls added by the budget work.
func TestTheCredentialIsNeverInTheCheckoutEnvironmentOfOtherCalls(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, log := gitShim(t, "")
	analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }))
	header := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + testToken))
	seen := map[string]bool{}
	for _, call := range strings.Split(readLog(t, log), "ARGV ")[1:] {
		argv, env, _ := strings.Cut(call, "\n")
		fields := strings.Fields(argv)
		seen[strings.Join(fields[min(2, len(fields)-1):min(3, len(fields))], "")] = true
		if strings.Contains(env, header) != strings.Contains(argv, " fetch ") {
			t.Fatalf("credential placement is wrong for: %s", argv)
		}
	}
	for _, want := range []string{"fetch", "ls-tree", "cat-file"} {
		if !seen[want] {
			t.Fatalf("calls = %v, want %q", seen, want)
		}
	}
}
