// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

const (
	goModV1 = "module example.test/app\n\ngo 1.24\n\nrequire example.test/dep v1.0.0\n"
	goModV2 = "module example.test/app\n\ngo 1.24\n\nrequire example.test/dep v2.0.0+incompatible\n"
)

// TestAnalyzeReadsExactlyTheClaimedCommit claims the older of two commits and
// proves the facts come from it, not from the branch tip.
func TestAnalyzeReadsExactlyTheClaimedCommit(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1}, map[string]string{"go.mod": goModV2})
	for i, want := range []string{"go.mod example.test/dep v1.0.0", "go.mod example.test/dep v2.0.0+incompatible"} {
		result := analyze(t, fixtureAnalyzer(t, url, shas[i], nil))
		if got := evidenceOf(result.Output); !slices.Equal(got, []string{want}) {
			t.Fatalf("commit %d: evidence = %v, want %q", i, got, want)
		}
		if got := factFor(t, result.Output, "example.test/dep").Payload["source_commit_sha"]; got != shas[i] {
			t.Fatalf("commit %d: source_commit_sha = %v, want %s", i, got, shas[i])
		}
	}
}

// TestAnalyzeFailsWhenCheckoutIsNotTheClaimedCommit proves the commit check:
// a git that reports a different HEAD yields no facts, whatever the tree holds.
func TestAnalyzeFailsWhenCheckoutIsNotTheClaimedCommit(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, _ := gitShim(t, `case "$*" in *rev-parse*) echo 0000000000000000000000000000000000000000; exit 0;; esac`)
	analyzer := fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim })
	result, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	wantReason(t, err, reasonCommitMismatch)
	if len(result.Output.Facts) != 0 {
		t.Fatalf("facts = %d, want none", len(result.Output.Facts))
	}
}

// TestReadModulesStopsOnACancelledContext proves the per-file context check: a
// cancelled context fails the read before any entry is touched, even one that
// needs no git call. The live-context control proves the fixture otherwise
// reads.
func TestReadModulesStopsOnACancelledContext(t *testing.T) {
	t.Parallel()

	analyzer := &Analyzer{toolchain: testToolchain}
	emit := emitContext{input: testInput(t), instanceID: "instance-1", repositoryID: testRepositoryID, commitSHA: strings.Repeat("a", 40)}
	manifest := treeManifest{goMods: []goModEntry{{rawPath: "big/go.mod", relativePath: "big/go.mod", state: goModOversized}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := analyzer.readModules(ctx, gitRunner{}, t.TempDir(), emit, manifest)
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	wantReason(t, err, reasonCheckoutFailed)

	read, err := analyzer.readModules(context.Background(), gitRunner{}, t.TempDir(), emit, manifest)
	if err != nil {
		t.Fatalf("live context: %v", err)
	}
	if read.unread != 1 || len(read.warnings) != 1 {
		t.Fatalf("live context: read = %+v, want the oversized warning", read)
	}
}

// TestAnalyzeIdentityComesFromTheClaim proves a checkout cannot choose its
// repository identity: the go.mod module path and remote never reach
// repository_id.
func TestAnalyzeIdentityComesFromTheClaim(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module evil.example/spoof\n\nrequire example.test/dep v1.0.0\n"})
	fact := factFor(t, analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output, "example.test/dep")
	if fact.Payload["repository_id"] != testRepositoryID {
		t.Fatalf("repository_id = %v, want %s", fact.Payload["repository_id"], testRepositoryID)
	}
	if fact.ScopeID != testScopeID || fact.SourceRef.ScopeID != testScopeID {
		t.Fatalf("scope = %q / %q, want %q", fact.ScopeID, fact.SourceRef.ScopeID, testScopeID)
	}
	if fact.Payload["root_module_path"] != "evil.example/spoof" {
		t.Fatalf("root_module_path = %v, want the declared text kept as evidence", fact.Payload["root_module_path"])
	}
}

// TestDiscoverySkipsExcludedDirectories proves every go.mod is found at any
// depth except under the four excluded directory names, at any depth.
func TestDiscoverySkipsExcludedDirectories(t *testing.T) {
	t.Parallel()

	mod := func(name string) string {
		return "module example.test/" + name + "\n\nrequire example.test/" + name + "dep v1.0.0\n"
	}
	url, shas := fixtureRepo(t, map[string]string{
		"go.mod":                     mod("root"),
		"nested/deep/go.mod":         mod("nested"),
		"_examples/go.mod":           mod("examples"),
		"vendor/x/go.mod":            mod("vendor"),
		"testdata/go.mod":            mod("testdata"),
		"node_modules/y/go.mod":      mod("node"),
		"nested/testdata/z/go.mod":   mod("nestedtestdata"),
		"nested/vendor/go.mod":       mod("nestedvendor"),
		"nested/vendored/go.mod":     mod("vendored"),
		"nested/notgo.mod":           "not a module",
		"nested/go.mod.bak/readme":   "not a module",
		"nested/deep/README.md":      "docs",
		"cmd/node_modules/q/go.mod":  mod("cmdnode"),
		"tools/.gitkeep":             "",
		"tools/subdir/keep/.gitkeep": "",
	})
	got := evidenceOf(analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output)
	want := []string{
		"_examples/go.mod example.test/examplesdep v1.0.0",
		"go.mod example.test/rootdep v1.0.0",
		"nested/deep/go.mod example.test/nesteddep v1.0.0",
		"nested/vendored/go.mod example.test/vendoreddep v1.0.0",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("evidence = %v\nwant %v", got, want)
	}
}

// TestRequirementPayloadCarriesReplaceLineAndIndirect is the replace-handling
// table: all-version, version-specific match and miss, local path, and the
// version-specific form winning over an earlier all-version one.
func TestRequirementPayloadCarriesReplaceLineAndIndirect(t *testing.T) {
	t.Parallel()

	gomod := `module example.test/app

go 1.24

require (
	example.test/all v1.0.0
	example.test/hit v1.1.0
	example.test/miss v1.2.0
	example.test/local v1.3.0
	example.test/both v1.4.0
	example.test/none v1.5.0 // indirect
)

replace example.test/all => example.test/all-fork v9.0.0

replace example.test/hit v1.1.0 => example.test/hit-fork v9.1.0

replace example.test/miss v1.0.0 => example.test/miss-fork v9.2.0

replace example.test/local => ../sibling

replace example.test/both => example.test/both-any v9.3.0

replace example.test/both v1.4.0 => example.test/both-exact v9.4.0
`
	url, shas := fixtureRepo(t, map[string]string{"go.mod": gomod})
	output := analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output
	for module, want := range map[string]struct {
		path, version, from string
		line                int
		indirect            bool
	}{
		"example.test/all":   {"example.test/all-fork", "v9.0.0", "", 6, false},
		"example.test/hit":   {"example.test/hit-fork", "v9.1.0", "v1.1.0", 7, false},
		"example.test/miss":  {"", "", "", 8, false},
		"example.test/local": {"../sibling", "", "", 9, false},
		"example.test/both":  {"example.test/both-exact", "v9.4.0", "v1.4.0", 10, false},
		"example.test/none":  {"", "", "", 11, true},
	} {
		payload := factFor(t, output, module).Payload
		str := func(key string) string {
			value, _ := payload[key].(string)
			return value
		}
		if str("replacement_path") != want.path || str("replacement_version") != want.version || str("replace_from_version") != want.from {
			t.Errorf("%s: replace = %q %q from %q, want %q %q from %q", module, str("replacement_path"), str("replacement_version"), str("replace_from_version"), want.path, want.version, want.from)
		}
		if payload["line_number"] != want.line {
			t.Errorf("%s: line_number = %v, want %d", module, payload["line_number"], want.line)
		}
		if payload["indirect"] != want.indirect {
			t.Errorf("%s: indirect = %v, want %v", module, payload["indirect"], want.indirect)
		}
	}
}

// TestStableKeyFollowsTheRulingTuple proves the key moves with each tuple
// member, does not move with the commit or generation, and that an exact
// duplicate require collapses while a second version stays.
func TestStableKeyFollowsTheRulingTuple(t *testing.T) {
	t.Parallel()

	gomod := "module m.test/a\n\nrequire (\n\tm.test/dep v1.0.0\n\tm.test/dep v1.0.0\n\tm.test/dep v1.1.0\n)\n"
	url, shas := fixtureRepo(t, map[string]string{"go.mod": gomod, "sub/go.mod": gomod}, map[string]string{"go.mod": gomod, "sub/go.mod": gomod, "x.txt": "later"})
	keys := func(sha string) []string {
		var out []string
		for _, fact := range analyze(t, fixtureAnalyzer(t, url, sha, nil)).Output.Facts {
			out = append(out, fact.StableFactKey)
		}
		return out
	}
	first := keys(shas[0])
	if len(first) != 4 {
		t.Fatalf("facts = %d, want 4 (two paths, two versions each; the exact duplicate collapses)", len(first))
	}
	unique := slices.Clone(first)
	slices.Sort(unique)
	if len(slices.Compact(unique)) != 4 {
		t.Fatalf("stable keys collide: %v", first)
	}
	if !slices.Equal(first, keys(shas[1])) {
		t.Fatal("stable keys moved with the commit, want idempotent keys across commits")
	}
}

// TestToolchainDirectiveAboveThePinIsTerminalForTheGeneration covers go and
// toolchain directives: the module evidence stays, one warning names the
// module, and the result is partial and still attests deletion.
func TestToolchainDirectiveAboveThePinIsTerminalForTheGeneration(t *testing.T) {
	t.Parallel()

	for name, directive := range map[string]string{
		"go directive":        "go 1.99\n",
		"toolchain directive": "go 1.24\n\ntoolchain go1.99.1\n",
		"next patch":          "go 1.26.11\n",
		"trailing comment":    "go 1.99 // newer than the pin\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			url, shas := fixtureRepo(t, map[string]string{
				"go.mod":     "module m.test/ok\n\ngo 1.24\n\nrequire m.test/a v1.0.0\n",
				"new/go.mod": "module m.test/new\n\n" + directive + "\nrequire m.test/b v1.0.0\n",
			})
			result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
			if got := evidenceOf(result.Output); !slices.Equal(got, []string{"go.mod m.test/a v1.0.0", "new/go.mod m.test/b v1.0.0"}) {
				t.Fatalf("evidence = %v, want both modules", got)
			}
			if got := warningsOf(result.Output); !slices.Equal(got, []string{"toolchain_unsupported new/go.mod"}) {
				t.Fatalf("warnings = %v", got)
			}
			c := result.Completion
			if !c.Partial || !c.TrustedDeletion || c.FailureClass != scannerworker.FailureClassToolchainUnsupported || c.WarningCount != 1 {
				t.Fatalf("completion = %+v", c)
			}
		})
	}
}

// TestToolchainDirectiveAtOrBelowThePinIsAccepted covers the boundary and the
// forms that name no version above the pin.
func TestToolchainDirectiveAtOrBelowThePinIsAccepted(t *testing.T) {
	t.Parallel()

	for _, directive := range []string{"go 1.26.10\n", "go 1.26\n", "go 1.24\n\ntoolchain go1.26.10\n", "go 1.24\n\ntoolchain default\n", "// go 1.99\n", "go 1.24 // toolchain go1.99\n"} {
		url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/ok\n\n" + directive + "\nrequire m.test/a v1.0.0\n"})
		if got := warningsOf(analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output); len(got) != 0 {
			t.Errorf("directive %q: warnings = %v, want none", directive, got)
		}
	}
}

// TestMalformedGoModWarnsWithoutItsText keeps the other modules, names the bad
// file, and never copies the file's text into the fact.
func TestMalformedGoModWarnsWithoutItsText(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{
		"go.mod":     "module m.test/ok\n\nrequire m.test/a v1.0.0\n",
		"bad/go.mod": "module m.test/bad\n\nSENTINELDIRECTIVE secret-looking-text\n",
		"new/go.mod": "module m.test/new\n\ngo 1.99\n\nUNKNOWNDIRECTIVE x\n",
	})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	want := []string{"go_mod_parse_failed bad/go.mod", "go_mod_parse_failed new/go.mod", "toolchain_unsupported new/go.mod"}
	if got := warningsOf(result.Output); !slices.Equal(got, want) {
		t.Fatalf("warnings = %v, want %v", got, want)
	}
	if got := evidenceOf(result.Output); !slices.Equal(got, []string{"go.mod m.test/a v1.0.0"}) {
		t.Fatalf("evidence = %v", got)
	}
	if c := result.Completion; !c.Partial || !c.TrustedDeletion || c.FailureClass != scannerworker.FailureClassToolchainUnsupported {
		t.Fatalf("completion = %+v, want toolchain_unsupported to win", c)
	}
	for _, fact := range result.Output.Facts {
		for _, value := range fact.Payload {
			if text, ok := value.(string); ok && strings.Contains(text, "secret-looking-text") {
				t.Fatalf("fact copied go.mod text: %+v", fact.Payload)
			}
		}
	}
}

// TestRepositoryWithNoGoModIsCompleteAndAttestsDeletion proves a clean checkout
// with no module is an explicit, trusted result: the warning avoids silent
// clean output, and the attestation lets stale evidence retract.
func TestRepositoryWithNoGoModIsCompleteAndAttestsDeletion(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"README.md": "no modules", "vendor/go.mod": "module m.test/v\n"})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"no_go_modules "}) {
		t.Fatalf("warnings = %v", got)
	}
	if c := result.Completion; c.Partial || !c.TrustedDeletion || c.WarningCount != 1 {
		t.Fatalf("completion = %+v, want complete and trusted", c)
	}
}

// TestModuleWithoutRequirementsStillEmitsAFact proves a go.mod with no require
// lines cannot produce silent clean output.
func TestModuleWithoutRequirementsStillEmitsAFact(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/empty\n\ngo 1.24\n"})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := warningsOf(result.Output); !slices.Equal(got, []string{"no_module_requirements "}) {
		t.Fatalf("warnings = %v", got)
	}
}

// TestFactsCarryTheDeclaredEnvelope pins the envelope fields the runner and
// the host validate.
func TestFactsCarryTheDeclaredEnvelope(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	fact := factFor(t, analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output, "example.test/dep")
	if fact.FactKind != chain.VulnerabilityGoModuleEvidenceFactKind || fact.SchemaVersion != "1.0.0" || fact.CollectorKind != "scanner_worker" {
		t.Fatalf("kind/schema/collector = %s %s %s", fact.FactKind, fact.SchemaVersion, fact.CollectorKind)
	}
	if fact.SourceConfidence != "reported" || fact.SourceRef.SourceSystem != "scanner_worker" || fact.SourceRef.FactKey != fact.StableFactKey {
		t.Fatalf("envelope = %+v", fact)
	}
	if fact.FencingToken != 7 || fact.GenerationID != "gen-1" || fact.ObservedAt != testInput(t).ObservedAt {
		t.Fatalf("claim identity = %+v", fact)
	}
	if fact.SourceRef.SourceURI != url {
		t.Fatalf("source uri = %q, want %q", fact.SourceRef.SourceURI, url)
	}
}

// TestFactOrderIsStableAcrossRuns proves stateless re-invocations see the same
// fact order, which the page cursor depends on.
func TestFactOrderIsStableAcrossRuns(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{
		"b/go.mod": "module m.test/b\n\nrequire m.test/z v1.0.0\n",
		"a/go.mod": "module m.test/a\n\nrequire (\n\tm.test/y v1.0.0\n\tm.test/x v1.0.0\n)\n",
	})
	run := func() []string {
		var out []string
		for _, fact := range analyze(t, fixtureAnalyzer(t, url, shas[0], nil)).Output.Facts {
			out = append(out, fact.StableFactKey)
		}
		return out
	}
	if first, second := run(), run(); !slices.Equal(first, second) {
		t.Fatalf("fact order moved:\n%v\n%v", first, second)
	}
}
