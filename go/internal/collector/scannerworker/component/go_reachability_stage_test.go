// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// seededScanner lays out a seeded toolchain whose scanner is a stand-in replaying a
// recorded govulncheck run, so the whole production path runs with no network.
func seededScanner(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "go", "bin"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go", "VERSION"), []byte(goreachability.PinnedToolchainVersion()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	for name, script := range map[string]string{"go/bin/go": "#!/bin/sh\n", "govulncheck": "#!/bin/sh\nPATH=/usr/bin:/bin\n" + body + "\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { // #nosec G306 -- the stand-ins must be executable
			t.Fatalf("WriteFile: %v", err)
		}
	}
	return dir
}

// runStageB drives the Runner with the default stage built from a seeded tree.
func runStageB(t *testing.T, toolchainDir string, config map[string]any, lookup func(string) (string, bool)) (sdkcollector.Result, string) {
	t.Helper()

	claim := goReachabilityClaim()
	claim.Deadline = time.Now().Add(10 * time.Minute)
	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: IDGoReachability,
		Stdin:       bytes.NewReader(testRequest(t, claim, config)),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       testClock,
		goReachability: goreachability.Options{
			AllowedSchemes: []string{"http"},
			ScannerVersion: "test-version",
			TempRoot:       t.TempDir(),
			ToolchainDir:   toolchainDir,
			Lookup:         lookup,
		},
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v, stderr = %q", err, stderr.String())
	}
	return decodePage(t, stdout.Bytes()), stderr.String()
}

func noOperatorEnv(string) (string, bool) { return "", false }

func recordedRun(t *testing.T) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "goreachability", "testdata", "govulncheck", "xtext_v0_3_5_symbol_source.jsonl"))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return path
}

const stageBGoMod = "module example.com/gvcexp\n\ngo 1.24\n\nrequire golang.org/x/text v0.3.5\n"

// TestStageBCleanRunIsCompleteTrustedAndConforms runs checkout, module evidence,
// the scan, and the fold through the production wiring: a clean symbol run is
// complete and trusted, and every fact passes the published schemas, the host
// validator, and the typed decoder the reducer uses.
func TestStageBCleanRunIsCompleteTrustedAndConforms(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile(stageBGoMod))
	toolchain := seededScanner(t, "cat "+recordedRun(t))
	page, stderr := runStageB(t, toolchain, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), noOperatorEnv)
	if page.State != sdkcollector.ResultComplete || !page.Generation.TrustedDeletion {
		t.Fatalf("state = %q trusted = %v, want complete and trusted", page.State, page.Generation.TrustedDeletion)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), roundTripResult(t, page)); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	levels := map[string]string{}
	for _, fact := range roundTripResult(t, page).Facts {
		if fact.Kind != "vulnerability.go_call_reachability" {
			continue
		}
		typed, err := factschema.DecodeVulnerabilityGoCallReachability(factschema.Envelope{FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload})
		if err != nil {
			t.Fatalf("DecodeVulnerabilityGoCallReachability() error = %v", err)
		}
		if typed.RepositoryID != goReachabilityRepository || typed.DeepestModule == nil || *typed.DeepestModule != "golang.org/x/text" || typed.ReachabilityLevel == nil {
			t.Fatalf("typed = %+v", typed)
		}
		levels[typed.OSVID] = *typed.ReachabilityLevel
		if *typed.ReachabilityLevel == "symbol" {
			if len(typed.Trace) != 2 || *typed.Trace[0].Function != "main" || *typed.Trace[1].Function != "Parse" || *typed.Trace[1].Position != "language/parse.go:33:6" {
				t.Fatalf("trace = %+v", typed.Trace)
			}
		}
	}
	want := map[string]string{"GO-2021-0113": "symbol", "GO-2022-1059": "not_called", "GO-2026-5970": "not_called", "GO-2026-6629": "not_called"}
	for osv, level := range want {
		if levels[osv] != level {
			t.Errorf("%s = %q, want %q", osv, levels[osv], level)
		}
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &record); err != nil {
		t.Fatalf("stderr is not one JSON line: %v\n%s", err, stderr)
	}
	for key, value := range map[string]any{
		"modules_total": 1.0, "modules_analyzed": 1.0, "findings_symbol": 1.0, "findings_not_called": 3.0,
		"scanner_version": goreachability.GovulncheckVersion, "toolchain": goreachability.PinnedToolchainVersion(),
		"vulndb_last_modified": "2026-11-02T22:01:43Z", "modcache_pruned": 0.0,
	} {
		if record[key] != value {
			t.Errorf("stderr %s = %v, want %v", key, record[key], value)
		}
	}
	if dropped, _ := record["findings_stdlib_dropped"].(float64); dropped == 0 {
		t.Errorf("stderr findings_stdlib_dropped = %v", record["findings_stdlib_dropped"])
	}
	for _, leak := range []string{goReachabilityToken, cloneURL, sha, goReachabilityRepository, "go.mod"} {
		if strings.Contains(stderr, leak) {
			t.Errorf("stderr leaks %q", leak)
		}
	}
}

// TestStageBFailedModuleIsPartialWithNoReachability proves a failed scan keeps the
// module evidence, writes the joinable warning, writes no reachability, and never
// attests deletion.
func TestStageBFailedModuleIsPartialWithNoReachability(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile(stageBGoMod))
	toolchain := seededScanner(t, `echo "package x: build constraints exclude all Go files in /x" >&2; exit 1`)
	page, stderr := runStageB(t, toolchain, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()), noOperatorEnv)
	if page.State != sdkcollector.ResultPartial || !page.Generation.TrustedDeletion {
		t.Fatalf("state = %q trusted = %v", page.State, page.Generation.TrustedDeletion)
	}
	if _, err := goReachabilityValidator(t).ValidateResult(page); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	counts := map[string]int{}
	for _, fact := range roundTripResult(t, page).Facts {
		counts[fact.Kind]++
		if fact.Kind != "scanner_worker.warning" {
			continue
		}
		typed, err := factschema.DecodeScannerWorkerWarning(factschema.Envelope{FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload})
		if err != nil {
			t.Fatalf("DecodeScannerWorkerWarning() error = %v", err)
		}
		if typed.Analyzer != "go_reachability" || typed.Reason != "cgo_required" || typed.WarningClass != "scanner_worker_warning" || typed.TargetKind != "repository" {
			t.Fatalf("typed = %+v", typed)
		}
		if fact.Payload["repository_id"] != goReachabilityRepository || fact.Payload["relative_path"] != "go.mod" {
			t.Fatalf("join keys = %+v", fact.Payload)
		}
	}
	if counts["vulnerability.go_module_evidence"] != 1 || counts["scanner_worker.warning"] != 1 || counts["vulnerability.go_call_reachability"] != 0 || counts["vulnerability.warning"] != 0 {
		t.Fatalf("counts = %v", counts)
	}
	if err := conformance.ValidatePayloadSchemas(fixturepack.Schemas(), roundTripResult(t, page)); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	if status := page.Statuses[0]; !status.Partial || status.FailureClass != "analysis_failed" || status.WarningCount != 1 {
		t.Fatalf("status = %+v", status)
	}
	if !strings.Contains(stderr, `"modules_analyzed":0`) {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestMissingToolchainIsTerminalWithItsReason is the production default: a real
// claim with no seeded tree fails terminal before git runs and names the reason
// for the operator.
func TestMissingToolchainIsTerminalWithItsReason(t *testing.T) {
	t.Parallel()

	config := goReachabilityConfig("https://github.com/o/r", strings.Repeat("a", 40), goReachabilityTokenStanza())
	page, stderr := runStageB(t, filepath.Join(t.TempDir(), "absent"), config, noOperatorEnv)
	if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "component_bad_config" {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(stderr, `"failure_reason":"toolchain_missing"`) {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestRefusedOperatorVariableIsTerminalWithItsReason proves a policy variable in
// the activation fails the claim rather than being ignored.
func TestRefusedOperatorVariableIsTerminalWithItsReason(t *testing.T) {
	t.Parallel()

	config := goReachabilityConfig("https://github.com/o/r", strings.Repeat("a", 40), goReachabilityTokenStanza())
	lookup := func(name string) (string, bool) { return "-tags=x", name == "GOFLAGS" }
	page, stderr := runStageB(t, seededScanner(t, ""), config, lookup)
	if page.State != sdkcollector.ResultTerminal || page.Statuses[0].FailureClass != "component_bad_config" {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(stderr, `"failure_reason":"env_refused"`) || strings.Contains(stderr, "-tags") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// TestStageBTimeoutRetriesOnFirstAttempt maps a stage timeout onto a retryable
// claim the host accepts.
func TestStageBTimeoutRetriesOnFirstAttempt(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile(stageBGoMod))
	claim := goReachabilityClaim()
	claim.Deadline = time.Now().Add(31 * time.Second)
	toolchain := seededScanner(t, "sleep 60 & wait")
	var stdout, stderr bytes.Buffer
	runner := Runner{
		ComponentID: IDGoReachability,
		Stdin:       bytes.NewReader(testRequest(t, claim, goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza()))),
		Stdout:      &stdout,
		Stderr:      &stderr,
		Clock:       testClock,
		goReachability: goreachability.Options{
			AllowedSchemes: []string{"http"},
			TempRoot:       t.TempDir(),
			ToolchainDir:   toolchain,
			Lookup:         noOperatorEnv,
		},
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	page := decodePage(t, stdout.Bytes())
	if page.State != sdkcollector.ResultRetryable || page.Statuses[0].FailureClass != "timeout" || page.Statuses[0].RetryAfterSeconds == 0 || len(page.Facts) != 0 {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(stderr.String(), `"failure_reason":"analysis_timeout"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"attempt":1`) {
		t.Fatalf("stderr does not name the attempt: %q", stderr.String())
	}
	if page.Statuses[0].RetryAfterSeconds != 60 {
		t.Fatalf("retry_after_seconds = %d, want the timeout class's 60", page.Statuses[0].RetryAfterSeconds)
	}
}

// roundTripResult sends a page across JSON, as the host receives it.
func roundTripResult(t *testing.T, page sdkcollector.Result) sdkcollector.Result {
	t.Helper()

	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded sdkcollector.Result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return decoded
}
