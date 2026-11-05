// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
	"gopkg.in/yaml.v3"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

const (
	goReachabilityRepository = "repository:r_1a2b3c4d"
	goReachabilityScope      = "go-reachability://" + goReachabilityRepository
	goReachabilityToken      = "ghs_RUNNERTOKEN0123456789abcdef"
)

// goReachabilityRepo builds one repository per file map, one commit each, and
// returns the file URL and the last commit id.
func goReachabilityRepo(t *testing.T, commits ...map[string]string) (string, string) {
	t.Helper()

	root := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		cmd.Env = []string{
			"PATH=" + os.Getenv("PATH"), "HOME=" + root, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=f", "GIT_AUTHOR_EMAIL=f@example.invalid", "GIT_COMMITTER_NAME=f", "GIT_COMMITTER_EMAIL=f@example.invalid",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet", "--initial-branch=main")
	for _, files := range commits {
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
		run("add", "--all")
		run("commit", "--quiet", "--message", "fixture")
	}
	return serveRepository(t, root), run("rev-parse", "HEAD")
}

// serveRepository serves a fixture over loopback smart HTTP through the real git
// http-backend, and refuses any request without the expected credential. The SDK
// rejects a file source_ref.uri, so the host-accepted path needs a URL like this.
func serveRepository(t *testing.T, root string) string {
	t.Helper()

	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Root: "/",
		Dir:  root,
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Dir(root), "GIT_HTTP_EXPORT_ALL=1", "HOME=" + root,
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		},
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+goReachabilityToken))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/" + filepath.Base(root)
}

func goModFile(body string) map[string]string { return map[string]string{"go.mod": body} }

func goReachabilityConfig(cloneURL, sha string, token map[string]any) map[string]any {
	config := map[string]any{
		"derive_from_go_modules": map[string]any{"enabled": true, "scan_interval": "6h"},
		"host_derived_target": map[string]any{
			"scope_id": goReachabilityScope, "repository_id": goReachabilityRepository,
			"source_commit_sha": sha, "clone_url": cloneURL,
		},
	}
	if token != nil {
		config["host_github_app_token"] = token
	}
	return config
}

func goReachabilityTokenStanza() map[string]any {
	return map[string]any{"token": goReachabilityToken, "scope_id": goReachabilityScope}
}

// runGoReachability drives the real Runner with the file transport a production
// runner refuses.
func runGoReachability(t *testing.T, config map[string]any, continuation *sdkcollector.PageContinuation) (sdkcollector.Result, string) {
	t.Helper()

	claim := testClaim(IDGoReachability, goReachabilityScope, "gen-go-1")
	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: IDGoReachability,
		Stdin:       bytes.NewReader(testRequestWithContinuation(t, claim, config, continuation)),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       testClock,
		goReachability: goreachability.Options{
			AllowedSchemes: []string{"http"},
			ScannerVersion: "test-version",
			TempRoot:       t.TempDir(),
		},
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, stderr = %q", err, stderr.String())
	}
	return decodePage(t, stdout.Bytes()), stderr.String()
}

func goReachabilityValidator(t *testing.T) sdkcollector.Validator {
	t.Helper()

	manifest, err := ManifestFor(scannerworker.AnalyzerGoReachability)
	if err != nil {
		t.Fatalf("ManifestFor: %v", err)
	}
	contract := sdkcollector.Contract{ProtocolVersion: protocolVersion}
	for _, family := range manifest.Spec.EmittedFacts {
		contract.Facts = append(contract.Facts, sdkcollector.FactDeclaration{
			Kind: family.Kind, SchemaVersions: family.SchemaVersions,
			SourceConfidence: []sdkcollector.SourceConfidence{sdkcollector.SourceConfidenceReported},
		})
	}
	return sdkcollector.NewValidator(contract)
}

// TestGoReachabilityRunnerEmitsAcceptedPartialResult is the end-to-end Stage A
// path through the stdio runner: the host validator accepts it, the facts match
// the published schema, the state is partial and attests deletion, the hint is
// the tuple hash, and stderr holds one line of counts with nothing identifying.
func TestGoReachabilityRunnerEmitsAcceptedPartialResult(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module example.test/app\n\ngo 1.24\n\nrequire example.test/dep v1.0.0\n"))
	page, stderr := runGoReachability(t, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), nil)

	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), page); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	if page.State != sdkcollector.ResultPartial || len(page.Facts) != 1 {
		t.Fatalf("state = %q facts = %d, want partial with one fact", page.State, len(page.Facts))
	}
	if !page.Generation.TrustedDeletion {
		t.Fatal("TrustedDeletion = false, want true: every committed generation is a full snapshot")
	}
	if !strings.HasPrefix(page.Generation.FreshnessHint, "sha256:") {
		t.Fatalf("FreshnessHint = %q", page.Generation.FreshnessHint)
	}
	if len(page.Statuses) != 1 || page.Statuses[0].Class != sdkcollector.StatusWarning || !page.Statuses[0].Partial || page.Statuses[0].FactCount != 1 {
		t.Fatalf("statuses = %+v", page.Statuses)
	}
	if page.Facts[0].Payload["repository_id"] != goReachabilityRepository {
		t.Fatalf("repository_id = %v", page.Facts[0].Payload["repository_id"])
	}

	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if len(lines) != 1 {
		t.Fatalf("stderr lines = %d, want one per claim:\n%s", len(lines), stderr)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("stderr is not JSON: %v", err)
	}
	for key, want := range map[string]float64{"modules_total": 1, "modules_analyzed": 0, "requirements_total": 1, "warnings_total": 0} {
		if record[key] != want {
			t.Errorf("stderr %s = %v, want %v", key, record[key], want)
		}
	}
	if _, ok := record["latency_ms"]; !ok {
		t.Error("stderr lacks latency_ms")
	}
	for _, leak := range []string{goReachabilityToken, cloneURL, strings.TrimPrefix(cloneURL, "http://"), sha, goReachabilityRepository, "go.mod", "example.test"} {
		if strings.Contains(stderr, leak) {
			t.Errorf("stderr leaks %q:\n%s", leak, stderr)
		}
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(raw), goReachabilityToken) {
		t.Fatal("result carries the token")
	}
}

// TestGoReachabilityTokenFailureIsTerminal maps a missing credential onto a
// terminal auth_denied the host accepts.
func TestGoReachabilityTokenFailureIsTerminal(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n"))
	page, stderr := runGoReachability(t, goReachabilityConfig(cloneURL, sha, nil), nil)
	if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "auth_denied" || len(page.Facts) != 0 {
		t.Fatalf("page = %+v", page)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if !strings.Contains(stderr, `"failure_class":"auth_denied"`) || !strings.Contains(stderr, "latency_ms") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestGoReachabilityCheckoutFailureIsRetryable proves the retry delay and the
// bounded reason, with no URL on stderr.
func TestGoReachabilityCheckoutFailureIsRetryable(t *testing.T) {
	t.Parallel()

	cloneURL, _ := goReachabilityRepo(t, goModFile("module m.test/a\n"))
	page, stderr := runGoReachability(t, goReachabilityConfig(cloneURL, strings.Repeat("a", 40), goReachabilityTokenStanza()), nil)
	if page.State != sdkcollector.ResultRetryable || page.Statuses[0].FailureClass != "checkout_failed" || page.Statuses[0].RetryAfterSeconds == 0 {
		t.Fatalf("page = %+v", page)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if !strings.Contains(stderr, `"failure_reason":"fetch_failed"`) {
		t.Fatalf("stderr lacks the reason: %q", stderr)
	}
	if strings.Contains(stderr, strings.TrimPrefix(cloneURL, "http://")) {
		t.Fatalf("stderr leaks the URL: %q", stderr)
	}
}

// TestGoReachabilityToolchainResultCarriesTheClass proves the partial status
// names toolchain_unsupported and counts the warning.
func TestGoReachabilityToolchainResultCarriesTheClass(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n\ngo 1.99\n\nrequire m.test/b v1.0.0\n"))
	page, _ := runGoReachability(t, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), nil)
	if page.State != sdkcollector.ResultPartial || len(page.Facts) != 2 {
		t.Fatalf("state = %q facts = %d, want partial with evidence and a warning", page.State, len(page.Facts))
	}
	status := page.Statuses[0]
	if status.FailureClass != "toolchain_unsupported" || status.WarningCount != 1 || !status.Partial {
		t.Fatalf("status = %+v", status)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestGoReachabilityNoModulesAttestsDeletion proves the complete path: a
// repository with no go.mod reports complete, trusted, with one warning fact.
func TestGoReachabilityNoModulesAttestsDeletion(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, map[string]string{"README.md": "no modules"})
	page, _ := runGoReachability(t, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), nil)
	if page.State != sdkcollector.ResultComplete || !page.Generation.TrustedDeletion || len(page.Facts) != 1 {
		t.Fatalf("page = %+v", page)
	}
	if status := page.Statuses[0]; status.Class != sdkcollector.StatusComplete || status.Partial || status.WarningCount != 1 {
		t.Fatalf("status = %+v", status)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
}

// TestGoReachabilityPagesPinOneGeneration splits a large go.mod across pages and
// proves the generation fields the host pins stay equal, every page validates,
// the warning is counted once, and no fact is lost.
func TestGoReachabilityPagesPinOneGeneration(t *testing.T) {
	t.Parallel()

	var gomod strings.Builder
	gomod.WriteString("module m.test/big\n\ngo 1.99\n\nrequire (\n")
	for i := range 60 {
		gomod.WriteString("\tm.test/dep-")
		gomod.WriteByte(byte('a' + i%26))
		gomod.WriteByte(byte('a' + (i/26)%26))
		gomod.WriteString(" v1.0.0\n")
	}
	gomod.WriteString(")\n")
	cloneURL, sha := goReachabilityRepo(t, goModFile(gomod.String()))
	config := goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza())
	config["page_bound_bytes"] = int64(4096)

	validator := goReachabilityValidator(t)
	first, _ := runGoReachability(t, config, nil)
	pages := []sdkcollector.Result{first}
	for pages[len(pages)-1].Page.More {
		next, _ := runGoReachability(t, config, &sdkcollector.PageContinuation{Cursor: pages[len(pages)-1].Page.Cursor})
		pages = append(pages, next)
		if len(pages) > 64 {
			t.Fatal("paging did not terminate")
		}
	}
	if len(pages) < 2 {
		t.Fatalf("pages = %d, want the bound to split the result", len(pages))
	}
	seen := map[string]struct{}{}
	warnings := 0
	for i, page := range pages {
		if _, err := validator.ValidateResult(page); err != nil {
			t.Fatalf("page %d: ValidateResult() error = %v", i, err)
		}
		if page.State != first.State {
			t.Fatalf("page %d state = %q, want %q", i, page.State, first.State)
		}
		if page.Generation != first.Generation {
			t.Fatalf("page %d generation = %+v, want %+v", i, page.Generation, first.Generation)
		}
		if !page.Statuses[0].Partial {
			t.Fatalf("page %d status = %+v", i, page.Statuses[0])
		}
		warnings += page.Statuses[0].WarningCount
		for _, fact := range page.Facts {
			seen[fact.StableKey] = struct{}{}
		}
	}
	if len(seen) != first.Page.TotalFacts || warnings != 1 {
		t.Fatalf("unique facts = %d, declared = %d, warnings = %d, want the warning counted once", len(seen), first.Page.TotalFacts, warnings)
	}
}

// TestProductionRunnerRefusesNonHTTPSTransports proves the real default: without
// the test seam a file URL is a bad config before git runs.
func TestProductionRunnerRefusesNonHTTPSTransports(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDGoReachability, goReachabilityScope, "gen-go-1")
	config := goReachabilityConfig("file:///unused", strings.Repeat("a", 40), goReachabilityTokenStanza())
	runTerminal(t, IDGoReachability, testRequest(t, claim, config), "component_bad_config")
}

// TestOtherComponentsStillRefuseACredential keeps the earlier contract: the
// token key is valid for go_reachability alone.
func TestOtherComponentsStillRefuseACredential(t *testing.T) {
	t.Parallel()

	claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
	config := osruntimeConfig(parityRootFS(t, 2), 0)
	config["host_github_app_token"] = goReachabilityTokenStanza()
	runTerminal(t, IDOSRuntime, testRequest(t, claim, config), "component_bad_config")
}

// TestGoReachabilityToleratesFutureTokenFields follows the #9182 ruling: the
// stanza is an object so the host can add fields without breaking a satellite.
func TestGoReachabilityToleratesFutureTokenFields(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n\nrequire m.test/b v1.0.0\n"))
	stanza := goReachabilityTokenStanza()
	stanza["expires_at"] = "2026-11-04T13:00:00Z"
	page, _ := runGoReachability(t, goReachabilityConfig(cloneURL, sha, stanza), nil)
	if page.State != sdkcollector.ResultPartial {
		t.Fatalf("state = %q", page.State)
	}
}

// TestGoReachabilityManifestMatchesGolden pins the bytes, with the core-pending
// provenance recorded in testdata/manifests/PROVENANCE.md.
func TestGoReachabilityManifestMatchesGolden(t *testing.T) {
	t.Parallel()

	golden, err := os.ReadFile(filepath.Join("testdata", "manifests", "go_reachability.manifest.yaml"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want conformance.Manifest
	if err := yaml.Unmarshal(golden, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	manifest, err := ManifestFor(scannerworker.AnalyzerGoReachability)
	if err != nil {
		t.Fatalf("ManifestFor() error = %v", err)
	}
	manifest.Spec.Artifacts[0].Image = want.Spec.Artifacts[0].Image
	got, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("manifest differs from golden:\n%s\nwant:\n%s", got, golden)
	}
	if got := manifest.Spec.Telemetry.MetricsPrefix; strings.Contains(got, "-") {
		t.Fatalf("metrics prefix %q is not a valid Prometheus name", got)
	}
}

// TestSeedAcceptsTheGoReachabilityImage proves the seed contract for the new
// image name and its refusal of another component's image.
func TestSeedAcceptsTheGoReachabilityImage(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("c", 64)
	dest := filepath.Join(t.TempDir(), "runtime")
	ref := "ghcr.io/eshu-hq/scanner-go-reachability@sha256:" + digest
	if err := Seed(IDGoReachability, []string{"--dest", dest, "--image-ref", ref}); err != nil {
		t.Fatalf("Seed() error = %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dest, "manifest.yaml"))
	if err != nil || !strings.Contains(string(raw), ref) {
		t.Fatalf("seeded manifest = %q, %v", raw, err)
	}
	if err := Seed(IDGoReachability, []string{"--dest", dest, "--image-ref", "ghcr.io/eshu-hq/scanner-sbom@sha256:" + digest}); err == nil {
		t.Fatal("Seed() with another component's image: error = nil")
	}
}
