// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// TestParseDerivedTargetReadsTheHostKey covers the object, tolerance of future
// fields, and every malformed form. An error never echoes the value.
func TestParseDerivedTargetReadsTheHostKey(t *testing.T) {
	t.Parallel()

	valid := func() map[string]any {
		return map[string]any{
			"scope_id": testScopeID, "repository_id": testRepositoryID,
			"source_commit_sha": strings.Repeat("a", 40), "clone_url": "https://github.com/o/r",
			"target_kind": "repository",
		}
	}
	got, err := ParseDerivedTarget(valid())
	if err != nil {
		t.Fatalf("ParseDerivedTarget() error = %v", err)
	}
	if got.ScopeID != testScopeID || got.RepositoryID != testRepositoryID || got.SourceCommitSHA != strings.Repeat("a", 40) || got.CloneURL != "https://github.com/o/r" {
		t.Fatalf("target = %+v", got)
	}
	for _, raw := range []any{nil, "SENTINEL", 7, []any{"SENTINEL"}, map[string]any{}} {
		if _, err := ParseDerivedTarget(raw); err == nil {
			t.Errorf("ParseDerivedTarget(%v) error = nil", raw)
		} else if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("error echoes the value: %v", err)
		}
	}
	for _, key := range []string{"scope_id", "repository_id", "source_commit_sha", "clone_url"} {
		for _, value := range []any{nil, 7, "", "  "} {
			raw := valid()
			raw[key] = value
			if _, err := ParseDerivedTarget(raw); err == nil {
				t.Errorf("%s = %v: error = nil", key, value)
			}
		}
		raw := valid()
		delete(raw, key)
		if _, err := ParseDerivedTarget(raw); err == nil {
			t.Errorf("%s missing: error = nil", key)
		}
	}
}

// TestAnalyzeFetchesASHA256Repository proves core's other accepted commit shape:
// a 64-hex object name needs a sha-256 repository to fetch into.
func TestAnalyzeFetchesASHA256Repository(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet", "--initial-branch=main", "--object-format=sha256")
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(goModV1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fixtureGit(t, root, "add", "--all")
	fixtureGit(t, root, "commit", "--quiet", "--message", "fixture")
	sha := fixtureGit(t, root, "rev-parse", "HEAD")
	if len(sha) != 64 {
		t.Fatalf("fixture commit = %q, want a sha-256 name", sha)
	}
	result := analyze(t, fixtureAnalyzer(t, "file://"+root, sha, nil))
	if got := evidenceOf(result.Output); !slices.Equal(got, []string{"go.mod example.test/dep v1.0.0"}) {
		t.Fatalf("evidence = %v", got)
	}
}

// TestStageBFetchIsShallow proves the fetch brings one commit even when the
// claimed commit has history. The one-commit fixture cannot show this.
func TestStageBFetchIsShallow(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1}, map[string]string{"go.mod": goModV2})
	count := ""
	stage := &recordingStage{t: t, outcome: StageOutcome{ModulesAnalyzed: 1}, inspect: func(input StageInput) {
		count = fixtureGit(t, input.CheckoutDir, "rev-list", "--count", "HEAD")
	}}
	analyze(t, fixtureAnalyzer(t, url, shas[1], func(c *Config) { c.Options.Stage = stage }))
	if count != "1" {
		t.Fatalf("history depth = %q, want a one-commit shallow fetch", count)
	}
}

// TestCredentialHeaderIsScopedToTheOrigin proves the git config key names the
// clone URL's origin, so the header cannot go to any other URL git contacts.
func TestCredentialHeaderIsScopedToTheOrigin(t *testing.T) {
	t.Parallel()

	var header string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	shim, log := gitShim(t, "")
	analyzer := fixtureAnalyzer(t, server.URL+"/org/repo.git", strings.Repeat("a", 40), func(c *Config) {
		c.Options.AllowedSchemes = []string{"http"}
		c.Options.GitPath = shim
	})
	_, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassAuthDenied, false)
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken)); header != want {
		t.Fatalf("Authorization = %q", header)
	}
	if text := readLog(t, log); !strings.Contains(text, "=http."+server.URL+"/.extraHeader\n") {
		t.Fatalf("no git config key scoped to %s:\n%s", server.URL, text)
	}
}

// TestStageCanCarryANotCalledFactWithDeepestModule proves the seam stage B needs.
// The reducer drops a reachability row with no deepest_module, so a not_called
// fact must carry it, with osv_id and repository_id and an empty trace.
func TestStageCanCarryANotCalledFactWithDeepestModule(t *testing.T) {
	t.Parallel()

	fileURL, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	url, _ := serveFixture(t, strings.TrimPrefix(fileURL, "file://"))
	stage := &builderStage{}
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) {
		c.Options.AllowedSchemes = []string{"http"}
		c.Options.Stage = stage
	}))
	if c := result.Completion; c.Partial || !c.TrustedDeletion {
		t.Fatalf("completion = %+v", c)
	}
	var found *facts.Envelope
	for i, envelope := range result.Output.Facts {
		if envelope.FactKind == chain.VulnerabilityGoCallReachabilityFactKind {
			found = &result.Output.Facts[i]
		}
	}
	if found == nil {
		t.Fatalf("stage fact missing from output: %+v", result.Output.Facts)
	}
	if found.ScopeID != testScopeID || found.GenerationID != "gen-1" || found.FencingToken != 7 || found.SourceRef.SourceURI != url {
		t.Fatalf("stage fact claim identity = %+v", found)
	}
	wire, err := factenvelope.SDKFactFromInternal(*found)
	if err != nil {
		t.Fatalf("SDKFactFromInternal: %v", err)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), sdkcollector.Result{Facts: []sdkcollector.Fact{wire}}); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	typed, err := factschema.DecodeVulnerabilityGoCallReachability(factschema.Envelope{FactKind: wire.Kind, SchemaVersion: wire.SchemaVersion, Payload: wire.Payload})
	if err != nil {
		t.Fatalf("DecodeVulnerabilityGoCallReachability() error = %v", err)
	}
	if typed.DeepestModule == nil || *typed.DeepestModule != "example.test/dep" || typed.ReachabilityLevel == nil || *typed.ReachabilityLevel != "not_called" || len(typed.Trace) != 0 {
		t.Fatalf("typed = %+v", typed)
	}
}

// builderStage builds its fact through StageInput.Envelope, as stage B will.
type builderStage struct{}

func (builderStage) Run(_ context.Context, input StageInput) (StageOutcome, error) {
	return StageOutcome{
		ModulesAnalyzed: len(input.Modules),
		Facts: []facts.Envelope{input.Envelope(chain.VulnerabilityGoCallReachabilityFactKind, "key-1", "record-1", map[string]any{
			"repository_id":      input.RepositoryID,
			"osv_id":             "GO-2022-1059",
			"deepest_module":     "example.test/dep",
			"reachability_level": "not_called",
			"trace":              []any{},
		})},
	}, nil
}
