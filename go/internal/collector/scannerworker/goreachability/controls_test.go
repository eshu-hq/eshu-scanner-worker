// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// callEnvironment returns the logged call whose arguments hold subcommand, split
// into its argv and its git config entries as key=value.
func callEnvironment(t *testing.T, log, subcommand string) (string, map[string]string) {
	t.Helper()

	for _, call := range strings.Split(readLog(t, log), "ARGV ")[1:] {
		argv, env, _ := strings.Cut(call, "\n")
		if !slices.Contains(strings.Fields(argv), subcommand) {
			continue
		}
		keys := regexp.MustCompile(`(?m)^ENV GIT_CONFIG_KEY_(\d+)=(.*)$`).FindAllStringSubmatch(env, -1)
		config := make(map[string]string, len(keys))
		for _, key := range keys {
			value := regexp.MustCompile(`(?m)^ENV GIT_CONFIG_VALUE_` + key[1] + `=(.*)$`).FindStringSubmatch(env)
			if value == nil {
				t.Fatalf("no value for config key %s", key[2])
			}
			config[key[2]] = value[1]
		}
		return argv, config
	}
	t.Fatalf("no git call with %q in %s", subcommand, readLog(t, log))
	return "", nil
}

// TestStatedGitControlsAreOnTheFetch pins each control SECURITY.md states to what
// git actually receives. Removing any one setting fails here.
func TestStatedGitControlsAreOnTheFetch(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, log := gitShim(t, "")
	analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }))

	argv, config := callEnvironment(t, log, "fetch")
	for key, want := range map[string]string{
		"core.hooksPath":       os.DevNull,
		"credential.helper":    "",
		"http.followRedirects": "false",
		"http.lowSpeedLimit":   "1000",
		"http.lowSpeedTime":    "60",
		"gc.auto":              "0",
		"maintenance.auto":     "false",
	} {
		if got, ok := config[key]; !ok || got != want {
			t.Errorf("config %s = %q (present %v), want %q", key, got, ok, want)
		}
	}
	for _, flag := range []string{"--no-recurse-submodules", "--no-tags", "--quiet"} {
		if !slices.Contains(strings.Fields(argv), flag) {
			t.Errorf("fetch argv %q lacks %s", argv, flag)
		}
	}
	if !strings.Contains(argv, "--depth 1") {
		t.Errorf("fetch argv %q is not shallow", argv)
	}
	initArgv, _ := callEnvironment(t, log, "init")
	if !slices.Contains(strings.Fields(initArgv), "--template=") {
		t.Errorf("init argv %q has a template", initArgv)
	}
}

// TestNoHooksDirectoryExists proves the --template= argument behaviorally: the
// default template would write sample hooks, and a stage sees none.
func TestNoHooksDirectoryExists(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	checked := false
	stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1}, inspect: func(input StageInput) {
		checked = true
		entries, err := os.ReadDir(filepath.Join(input.CheckoutDir, ".git", "hooks"))
		if err == nil && len(entries) > 0 {
			t.Errorf("hooks directory holds %d entries", len(entries))
		}
	}}
	analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if !checked {
		t.Fatal("the stage did not run; the check proved nothing")
	}
}

// TestWaitDelayBoundsAChildHoldingThePipes proves a process outside git's group that
// keeps stdout open cannot hold the claim. Without WaitDelay, Wait blocks until the
// stray exits, so the call would take the shim's full sleep.
func TestWaitDelayBoundsAChildHoldingThePipes(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *rev-parse*) setsid sleep 25 & exit 0;; esac`)
	start := time.Now()
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("Analyze took %s, want the wait delay to stop it", elapsed)
	}
}

// TestShouldSkipDirNamesExactlyTheExcludedDirectories pins the table, including
// that a similar name is not excluded.
func TestShouldSkipDirNamesExactlyTheExcludedDirectories(t *testing.T) {
	t.Parallel()

	for _, name := range []string{".git", "vendor", "testdata", "node_modules"} {
		if !shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = false", name)
		}
	}
	for _, name := range []string{"", ".", ".github", "vendored", "Testdata", "node_module"} {
		if shouldSkipDir(name) {
			t.Errorf("shouldSkipDir(%q) = true", name)
		}
	}
}

// TestFileBudgetBoundary covers at the limit and one past it.
func TestFileBudgetBoundary(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1, "a": "a", "b": "b"})
	input := testInput(t)
	input.Limits.MaxFiles = 3
	if _, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	input.Limits.MaxFiles = 2
	_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
}

// TestByteBudgetBoundary covers at the limit and one past it. The tree total is the
// sum of its blobs. A .git this small passes the watcher in both cases.
func TestByteBudgetBoundary(t *testing.T) {
	t.Parallel()

	blob := strings.Repeat("x", 512*1024)
	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1, "a": blob})
	total := int64(len(goModV1) + len(blob))
	input := testInput(t)
	input.Limits.MaxInputBytes = total
	if _, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	input.Limits.MaxInputBytes = total - 1
	_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
}

// TestFactBudgetBoundary covers at the limit and one past it.
func TestFactBudgetBoundary(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/a\n\nrequire (\n\tm.test/b v1.0.0\n\tm.test/c v1.0.0\n)\n"})
	input := testInput(t)
	input.Limits.MaxFacts = 2
	if _, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	input.Limits.MaxFacts = 1
	_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassFactLimitExceeded, false)
}

// TestGoModReadBoundBoundary covers a file exactly at the bound, which is read, and
// one byte past it, which is a warning.
func TestGoModReadBoundBoundary(t *testing.T) {
	t.Parallel()

	const header = "module m.test/a\n\nrequire m.test/b v1.0.0\n\n// "
	exact := header + strings.Repeat("x", maxGoModBytes-len(header)-1) + "\n"
	if len(exact) != maxGoModBytes {
		t.Fatalf("fixture is %d bytes", len(exact))
	}
	url, shas := fixtureRepo(t, map[string]string{"go.mod": exact}, map[string]string{"go.mod": header + strings.Repeat("x", maxGoModBytes-len(header)) + "\n"})
	if got := evidenceOf(analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output); !slices.Equal(got, []string{"go.mod m.test/b v1.0.0"}) {
		t.Fatalf("at the bound: evidence = %v", got)
	}
	over := analyze(t, fixtureAnalyzer(t, url, shas[1], nil)).Output
	if got := warningsOf(over); !slices.Equal(got, []string{"go_mod_too_large go.mod"}) {
		t.Fatalf("past the bound: warnings = %v", got)
	}
}

// catFileCalls counts the go.mod objects a run read.
func catFileCalls(t *testing.T, log string) int {
	t.Helper()

	return strings.Count(readLog(t, log), " cat-file blob ")
}

// TestFactBudgetStopsTheReadAtTheFirstOverrun is the early-stop half of F1: the
// later files are never read, so their memory is never spent.
func TestFactBudgetStopsTheReadAtTheFirstOverrun(t *testing.T) {
	t.Parallel()

	files := map[string]string{}
	for i := range 5 {
		files[fmt.Sprintf("m%d/go.mod", i)] = "module m.test/a\n\nrequire (\n\tm.test/b v1.0.0\n\tm.test/c v1.0.0\n)\n"
	}
	url, shas := fixtureRepo(t, files)
	shim, log := gitShim(t, "")
	input := testInput(t)
	input.Limits.MaxFacts = 3
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassFactLimitExceeded, false)
	if got := catFileCalls(t, log); got != 2 {
		t.Fatalf("read %d go.mod files, want the second to overrun and stop the read", got)
	}
}

// TestGoModTotalBudgetIsCheckedBeforeAnyRead proves the claim-wide read bound.
func TestGoModTotalBudgetIsCheckedBeforeAnyRead(t *testing.T) {
	t.Parallel()

	const fileBytes = maxGoModBytes
	files := map[string]string{}
	for i := range maxGoModTotalBytes/fileBytes + 1 {
		files[fmt.Sprintf("m%d/go.mod", i)] = "module m.test/a\n\n// " + strings.Repeat(fmt.Sprintf("%d", i%10), fileBytes-30) + "\n"
	}
	url, shas := fixtureRepo(t, files)
	shim, log := gitShim(t, "")
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
	if got := catFileCalls(t, log); got != 0 {
		t.Fatalf("read %d go.mod files before refusing the set", got)
	}
}

// TestGoModCountBudgetBoundary proves the go.mod count bound against the manifest
// parser, at the bound and one past it.
func TestGoModCountBudgetBoundary(t *testing.T) {
	t.Parallel()

	limits := testInput(t).Limits
	var tree strings.Builder
	for i := range maxGoModFiles {
		fmt.Fprintf(&tree, "100644 blob %s %7d\tm%d/go.mod\x00", strings.Repeat("a", 40), 10, i)
	}
	manifest, err := parseTree(strings.NewReader(tree.String()), limits)
	if err != nil || len(manifest.goMods) != maxGoModFiles {
		t.Fatalf("at the bound: %d files, error = %v", len(manifest.goMods), err)
	}
	fmt.Fprintf(&tree, "100644 blob %s %7d\tlast/go.mod\x00", strings.Repeat("a", 40), 10)
	_, err = parseTree(strings.NewReader(tree.String()), limits)
	wantFailure(t, err, scannerworker.FailureClassFileLimitExceeded, false)
}

// TestParseTreeRefusesAHostileOrBrokenStream covers what a hand-built tree or a
// broken git could send. A record past the bound cannot exist on any checkout.
func TestParseTreeRefusesAHostileOrBrokenStream(t *testing.T) {
	t.Parallel()

	limits := testInput(t).Limits
	sha := strings.Repeat("a", 40)
	_, err := parseTree(strings.NewReader("100644 blob "+sha+" 1\t"+strings.Repeat("p", maxTreeEntryBytes)+"\x00"), limits)
	wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
	for name, stream := range map[string]string{
		"no tab":        "100644 blob " + sha + " 1 go.mod\x00",
		"short head":    "100644 blob 1\tgo.mod\x00",
		"bad size":      "100644 blob " + sha + " x\tgo.mod\x00",
		"negative size": "100644 blob " + sha + " -1\tgo.mod\x00",
		"truncated":     "100644 blob " + sha + " 1\tgo.mod",
	} {
		_, err := parseTree(strings.NewReader(stream), limits)
		wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
		if t.Failed() {
			t.Fatalf("stream %q", name)
		}
	}
	manifest, err := parseTree(strings.NewReader("160000 commit "+sha+"       -\tsub/go.mod\x00100755 blob "+sha+"      10\tx/go.mod\x00"), limits)
	if err != nil || len(manifest.goMods) != 2 || manifest.goMods[0].state != goModNotRegular || manifest.goMods[1].state != goModReadable {
		t.Fatalf("manifest = %+v, error = %v", manifest, err)
	}
}

// TestFetchWatcherStopsAPackOverTheBudget is the disk half of F2: a pack has no
// client-side limit, so the watcher measures .git while the fetch runs and fails the
// claim terminal. The shim stands in for a server sending a large pack forever.
func TestFetchWatcherStopsAPackOverTheBudget(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *" fetch "*) dir="$2"; head -c 4096 /dev/zero > "$dir/.git/objects/pack/tmp_pack_x"; sleep 60;; esac`)
	input := testInput(t)
	input.Limits.MaxInputBytes = 1024
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(ctx, input)
	wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("Analyze took %s, want the watcher to cancel the fetch", elapsed)
	}
}

// TestFinishedPackOverTheBudgetIsRefused proves the final measure: a fetch can end
// between two polls.
func TestFinishedPackOverTheBudgetIsRefused(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *" fetch "*) dir="$2"; "`+realGitPath(t)+`" "$@"; code=$?; head -c 4096 /dev/zero > "$dir/.git/objects/pack/tmp_pack_x"; exit $code;; esac`)
	input := testInput(t)
	input.Limits.MaxInputBytes = 2048
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), input)
	wantFailure(t, err, scannerworker.FailureClassInputLimitExceeded, false)
}

func realGitPath(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("LookPath(git): %v", err)
	}
	return path
}

// TestBlobSizeDisagreementFailsTheClaim proves the size check on a read: the
// manifest and the object store must agree.
func TestBlobSizeDisagreementFailsTheClaim(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *cat-file*) echo short; exit 0;; esac`)
	_, err := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }).Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
}

// TestEscapePathIsInjectiveAndSafe pins the escape that keys a hostile path.
func TestEscapePathIsInjectiveAndSafe(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for _, raw := range []string{"a\xff", "a\xfe", "a%FF", "a%25", "a\x00", "a\x7f", "a\n", "é", "a"} {
		escaped := escapePath(raw)
		if !isSafeText(escaped) {
			t.Errorf("escapePath(%q) = %q is not safe", raw, escaped)
		}
		if other, taken := seen[escaped]; taken {
			t.Errorf("escapePath(%q) and escapePath(%q) both = %q", raw, other, escaped)
		}
		seen[escaped] = raw
	}
	if got := escapePath("é/a"); got != "é/a" {
		t.Errorf("valid UTF-8 changed: %q", got)
	}
}
