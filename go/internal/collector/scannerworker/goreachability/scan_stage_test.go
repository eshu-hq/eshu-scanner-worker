// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// fakeScanner writes a stand-in for govulncheck. Its body picks the module by the
// working directory's name, and it records each call's arguments, directory, and
// environment. No test here reaches the network.
func fakeScanner(t *testing.T, body string) (Toolchain, string) {
	t.Helper()

	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "govulncheck")
	// The child's PATH holds only the toolchain, so the stand-in records with
	// absolute paths, then widens PATH for its body.
	source := "#!/bin/sh\n{ printf 'CALL %s\\n' \"$*\"; printf 'DIR %s\\n' \"$PWD\"; /usr/bin/env | /usr/bin/sed 's/^/ENV /'; } >> " + log + "\nPATH=/usr/bin:/bin\nexport PATH\n" + body + "\n"
	writeExecutable(t, script, source)
	toolchain := Toolchain{GoRoot: filepath.Join(dir, "goroot"), Govulncheck: script}
	// The cgo probe runs the toolchain's go command, so every fake toolchain
	// carries a stand-in that logs as GO and lists nothing. writeFakeGo
	// replaces it where a test needs the probe to see a graph.
	writeFakeGo(t, toolchain, "#!/bin/sh\n{ printf 'GO %s\\n' \"$*\"; } >> "+log+"\n")
	return toolchain, log
}

// fixturePath is a committed recorded run, absolute so a stand-in can cat it.
func fixturePath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("testdata", "govulncheck", name))
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return path
}

// runStage runs a real ScanStage against module directories under a temp checkout.
func runStage(t *testing.T, toolchain Toolchain, input StageInput, mutate func(*ScanConfig)) (StageOutcome, error) {
	t.Helper()

	config := ScanConfig{
		Toolchain: toolchain,
		CacheRoot: filepath.Join(t.TempDir(), "cache"),
		Lookup:    func(string) (string, bool) { return "", false },
	}
	if mutate != nil {
		mutate(&config)
	}
	stage, err := NewScanStage(config)
	if err != nil {
		t.Fatalf("NewScanStage() error = %v", err)
	}
	return stage.Run(context.Background(), input)
}

// stageInput lays out one checkout directory per module path.
func stageInput(t *testing.T, relativePaths ...string) StageInput {
	t.Helper()

	scratch := t.TempDir()
	checkout := filepath.Join(scratch, "checkout")
	input := StageInput{
		Claim:           testInput(t),
		InstanceID:      "instance-1",
		RepositoryID:    testRepositoryID,
		SourceCommitSHA: strings.Repeat("a", 40),
		SourceURI:       "https://github.com/o/r",
		CheckoutDir:     checkout,
		ScratchDir:      scratch,
	}
	for _, relativePath := range relativePaths {
		dir := filepath.Dir(relativePath)
		if err := os.MkdirAll(filepath.Join(checkout, dir), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		input.Modules = append(input.Modules, Module{RelativePath: relativePath, Dir: filepath.ToSlash(dir), ModulePath: "m.test/" + relativePath})
	}
	return input
}

func reachabilityByOSV(outcome StageOutcome) map[string]facts.Envelope {
	out := make(map[string]facts.Envelope, len(outcome.Facts))
	for _, fact := range outcome.Facts {
		out[fact.Payload["osv_id"].(string)] = fact
	}
	return out
}

// TestStageEmitsOneFactPerPairFromARecordedRun drives the recorded symbol run
// through the real child path: the payload for each outcome the contract names,
// the dropped standard-library findings, and the stderr figures.
func TestStageEmitsOneFactPerPairFromARecordedRun(t *testing.T) {
	t.Parallel()

	toolchain, _ := fakeScanner(t, "cat "+fixturePath(t, "xtext_v0_3_5_symbol_source.jsonl"))
	outcome, err := runStage(t, toolchain, stageInput(t, "go.mod"), nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if outcome.ModulesAnalyzed != 1 || len(outcome.Failed) != 0 || len(outcome.Facts) != 4 {
		t.Fatalf("outcome = %d analyzed, %v failed, %d facts", outcome.ModulesAnalyzed, outcome.Failed, len(outcome.Facts))
	}
	byOSV := reachabilityByOSV(outcome)

	called := byOSV["GO-2021-0113"].Payload
	if called["reachability_level"] != "symbol" || called["deepest_module"] != "golang.org/x/text" || called["deepest_package"] != "golang.org/x/text/language" || called["deepest_symbol"] != "Parse" {
		t.Fatalf("called = %+v", called)
	}
	trace, ok := called["trace"].([]any)
	if !ok || len(trace) != 2 {
		t.Fatalf("trace = %#v", called["trace"])
	}
	entry, vulnerable := trace[0].(map[string]any), trace[1].(map[string]any)
	if entry["function"] != "main" || vulnerable["function"] != "Parse" {
		t.Fatalf("trace order = %+v, want entry point first", trace)
	}
	if vulnerable["position"] != "language/parse.go:33:6" || entry["position"] != "main.go:10:28" {
		t.Fatalf("positions = %v, %v", vulnerable["position"], entry["position"])
	}
	if called["trace_count"] != 1 {
		t.Fatalf("trace_count = %v", called["trace_count"])
	}

	imported := byOSV["GO-2022-1059"].Payload
	if imported["reachability_level"] != "not_called" || imported["deepest_module"] != "golang.org/x/text" || imported["deepest_package"] != "golang.org/x/text/language" {
		t.Fatalf("imported = %+v", imported)
	}
	if got, ok := imported["trace"].([]any); !ok || len(got) != 0 {
		t.Fatalf("not_called trace = %#v, want empty", imported["trace"])
	}
	if _, present := imported["deepest_symbol"]; present {
		t.Fatalf("not_called carries a symbol: %+v", imported)
	}
	moduleOnly := byOSV["GO-2026-5970"].Payload
	if moduleOnly["reachability_level"] != "not_called" || moduleOnly["deepest_module"] != "golang.org/x/text" {
		t.Fatalf("moduleOnly = %+v", moduleOnly)
	}
	if _, present := moduleOnly["deepest_package"]; present {
		t.Fatalf("module-depth finding carries a package: %+v", moduleOnly)
	}
	for osv, fact := range byOSV {
		payload := fact.Payload
		if payload["repository_id"] != testRepositoryID || payload["relative_path"] != "go.mod" || payload["scan_level"] != "symbol" || payload["scan_mode"] != "source" || payload["scanner_version"] != GovulncheckVersion || payload["source_commit_sha"] != strings.Repeat("a", 40) {
			t.Fatalf("%s provenance = %+v", osv, payload)
		}
		if fact.FactKind != chain.VulnerabilityGoCallReachabilityFactKind || fact.ScopeID != testScopeID || fact.GenerationID != "gen-1" {
			t.Fatalf("%s envelope = %+v", osv, fact)
		}
	}
	if outcome.Figures["findings_symbol"] != 1 || outcome.Figures["findings_not_called"] != 3 {
		t.Fatalf("figures = %v", outcome.Figures)
	}
	if outcome.Figures["findings_stdlib_dropped"] == 0 {
		t.Fatalf("figures = %v, want the dropped stdlib findings counted", outcome.Figures)
	}
	if outcome.VulnDBLastModified != "2026-11-02T22:01:43Z" || outcome.Labels["vulndb_last_modified"] != outcome.VulnDBLastModified || outcome.Labels["scanner_version"] != GovulncheckVersion {
		t.Fatalf("labels = %v", outcome.Labels)
	}
}

// TestStageRunsTheExactCommandAndEnvironment asserts the child's whole environment
// and command line. PWD, OLDPWD, SHLVL, and _ are the stand-in shell's own. The
// token and every inherited variable must be absent.
func TestStageRunsTheExactCommandAndEnvironment(t *testing.T) {
	toolchain, log := fakeScanner(t, `echo '{"config":{"scan_level":"symbol","scan_mode":"source","scanner_version":"`+GovulncheckVersion+`"}}'`)
	for name, value := range map[string]string{
		"GITHUB_TOKEN": testToken, "ESHU_POSTGRES_DSN": "postgres://secret", "GOFLAGS_INHERITED": "x",
		"GIT_TRACE": "1", "HTTP_PROXY": "http://inherited", "GOPROXY_INHERITED": "x",
	} {
		t.Setenv(name, value)
	}
	input := stageInput(t, "sub/go.mod")
	config := ScanConfig{Toolchain: toolchain, CacheRoot: filepath.Join(t.TempDir(), "cache")}
	config.Lookup = func(string) (string, bool) { return "", false }
	stage, err := NewScanStage(config)
	if err != nil {
		t.Fatalf("NewScanStage() error = %v", err)
	}
	if _, err := stage.Run(context.Background(), input); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	var got, calls, dirs []string
	for line := range strings.Lines(readLog(t, log)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ENV "):
			entry := strings.TrimPrefix(line, "ENV ")
			if name, _, _ := strings.Cut(entry, "="); !slices.Contains([]string{"PWD", "OLDPWD", "SHLVL", "_"}, name) {
				got = append(got, entry)
			}
		case strings.HasPrefix(line, "CALL "):
			calls = append(calls, strings.TrimPrefix(line, "CALL "))
		case strings.HasPrefix(line, "DIR "):
			dirs = append(dirs, strings.TrimPrefix(line, "DIR "))
		}
	}
	want := []string{
		"CGO_ENABLED=0",
		"GOCACHE=" + filepath.Join(config.CacheRoot, "build"),
		"GOENV=off",
		"GOFLAGS=-mod=mod",
		"GOMODCACHE=" + filepath.Join(config.CacheRoot, "mod"),
		"GOPROXY=https://proxy.golang.org",
		"GOROOT=" + toolchain.GoRoot,
		"GOSUMDB=sum.golang.org",
		"GOTELEMETRY=off",
		"GOTOOLCHAIN=local",
		"GOVCS=*:off",
		"GOWORK=off",
		"HOME=" + filepath.Join(input.ScratchDir, "scan-home"),
		"PATH=" + filepath.Join(toolchain.GoRoot, "bin"),
		"TMPDIR=" + filepath.Join(input.ScratchDir, "scan-tmp"),
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("child env:\n got %q\nwant %q", got, want)
	}
	if len(calls) != 1 || calls[0] != "-json -mode source ./..." {
		t.Fatalf("command = %q", calls)
	}
	wantDir, err := filepath.EvalSymlinks(filepath.Join(input.CheckoutDir, "sub"))
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if len(dirs) != 1 || dirs[0] != wantDir {
		t.Fatalf("dir = %q, want %q", dirs, wantDir)
	}
}

// TestOperatorOverridesAreAllowlisted proves the six overrides reach the child,
// GOVULNDB as a flag, and that a policy variable or a direct proxy is refused.
func TestOperatorOverridesAreAllowlisted(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		"GOPROXY": "https://mirror.example", "GOSUMDB": "off.example", "GOVULNDB": "https://vulndb.example",
		"HTTPS_PROXY": "http://proxy.example", "NO_PROXY": "internal.example", "SSL_CERT_FILE": "/etc/ca.pem",
	}
	lookup := func(name string) (string, bool) { value, ok := values[name]; return value, ok }
	overrides, err := readScanOverrides(lookup)
	if err != nil {
		t.Fatalf("readScanOverrides() error = %v", err)
	}
	env := scanEnvironment(Toolchain{GoRoot: "/g"}, "/m", "/b", "/s", overrides)
	for _, entry := range []string{"GOPROXY=https://mirror.example", "GOSUMDB=off.example", "HTTPS_PROXY=http://proxy.example", "NO_PROXY=internal.example", "SSL_CERT_FILE=/etc/ca.pem"} {
		if !slices.Contains(env, entry) {
			t.Errorf("env lacks %q: %q", entry, env)
		}
	}
	if got := strings.Join(scanArguments(overrides), " "); got != "-json -mode source -db https://vulndb.example ./..." {
		t.Fatalf("arguments = %q", got)
	}
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOVULNDB=") {
			t.Fatalf("env carries %q", entry)
		}
	}
	for _, name := range []string{"GOFLAGS", "GOTOOLCHAIN", "GOPRIVATE", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "CGO_ENABLED", "GOWORK", "GOVCS", "GOROOT"} {
		_, err := readScanOverrides(func(looked string) (string, bool) { return "SENTINEL", looked == name })
		if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("%s: error = %v, want a refusal naming the variable", name, err)
		}
	}
	for _, proxy := range []string{"direct", "https://m.example,direct", "off", "https://m.example|direct"} {
		if _, err := readScanOverrides(func(looked string) (string, bool) { return proxy, looked == "GOPROXY" }); err == nil {
			t.Errorf("GOPROXY=%s: error = nil", proxy)
		}
	}
}
