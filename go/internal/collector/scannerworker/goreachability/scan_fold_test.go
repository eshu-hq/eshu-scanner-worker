// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "govulncheck", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func parseFixture(t *testing.T, name string) scanStream {
	t.Helper()

	stream, err := parseScanStream(bytes.NewReader(readFixture(t, name)))
	if err != nil {
		t.Fatalf("parseScanStream(%s) error = %v", name, err)
	}
	return stream
}

func foldedByOSV(t *testing.T, stream scanStream) map[string]foldedFinding {
	t.Helper()

	folded, _, err := foldFindings(stream.config.ScanLevel, stream.findings)
	if err != nil {
		t.Fatalf("foldFindings() error = %v", err)
	}
	out := make(map[string]foldedFinding, len(folded))
	for _, finding := range folded {
		out[finding.osv] = finding
	}
	return out
}

// TestParseStreamReadsTheRealSchema reads the recorded symbol run: the config,
// every finding, and a position that arrives as an object. The SBOM and osv
// messages are other message types it must pass over.
func TestParseStreamReadsTheRealSchema(t *testing.T) {
	t.Parallel()

	stream := parseFixture(t, "xtext_v0_3_5_symbol_source.jsonl")
	config := stream.config
	if config == nil || config.ScanLevel != "symbol" || config.ScanMode != "source" || config.ScannerVersion != "v1.9.0" || config.DBLastModified != "2026-11-02T22:01:43Z" {
		t.Fatalf("config = %+v", config)
	}
	if len(stream.findings) != 27 {
		t.Fatalf("findings = %d, want all 27 recorded", len(stream.findings))
	}
	found := false
	for _, finding := range stream.findings {
		if frame := finding.Trace[0]; frame.Function == "Parse" {
			found = true
			if frame.Position == nil || frame.Position.Filename != "language/parse.go" || frame.Position.Line != 33 || frame.Position.Column != 6 {
				t.Fatalf("position = %+v", frame.Position)
			}
		}
	}
	if !found {
		t.Fatal("no symbol-level finding parsed; the position object was dropped")
	}
}

// TestParseStreamToleratesUnknownMessageTypes proves a future message type is
// passed over, including one whose body would not fit any known struct.
func TestParseStreamToleratesUnknownMessageTypes(t *testing.T) {
	t.Parallel()

	stream, err := parseScanStream(strings.NewReader(`{"config":{"scan_level":"symbol","scan_mode":"source"}}
{"future":{"finding":"not an object"}}
{"future2":[1,2,3]}
{"SBOM":{"go_version":"go1.26.10"}}
{"finding":{"osv":"GO-1","trace":[{"module":"m.test/a"}]}}
`))
	if err != nil {
		t.Fatalf("parseScanStream() error = %v", err)
	}
	if stream.config == nil || len(stream.findings) != 1 {
		t.Fatalf("stream = %+v", stream)
	}
}

// TestParseStreamRefusesWhatItCannotTrust covers truncation and a finding with
// no usable identity, which must fail rather than vanish.
func TestParseStreamRefusesWhatItCannotTrust(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"truncated":        `{"config":{"scan_level":"symbol"}}` + "\n" + `{"finding":{"osv":"GO-1","tra`,
		"not json":         "govulncheck: loading packages\n",
		"string position":  `{"finding":{"osv":"GO-1","trace":[{"module":"m","function":"F","position":"a.go:1:1"}]}}`,
		"no trace":         `{"finding":{"osv":"GO-1","trace":[]}}`,
		"no osv":           `{"finding":{"osv":"","trace":[{"module":"m"}]}}`,
		"no module":        `{"finding":{"osv":"GO-1","trace":[{"package":"p"}]}}`,
		"second config":    `{"config":{"scan_level":"symbol"}}` + "\n" + `{"config":{"scan_level":"module"}}`,
		"null first frame": `{"finding":{"osv":"GO-1","trace":[null]}}`,
	} {
		if _, err := parseScanStream(strings.NewReader(input)); err == nil {
			t.Errorf("%s: error = nil, want refusal", name)
		}
	}
}

// TestParseStreamStopsAtTheByteCap proves the stream cap fails rather than
// buffering without bound.
func TestParseStreamStopsAtTheByteCap(t *testing.T) {
	t.Parallel()

	line := `{"progress":{"message":"` + strings.Repeat("x", 1024) + `"}}` + "\n"
	_, err := parseBoundedScanStream(strings.NewReader(strings.Repeat(line, 8)), 4096)
	if !errors.Is(err, errScanStreamTooLarge) {
		t.Fatalf("error = %v, want errScanStreamTooLarge", err)
	}
}

// TestFoldKeepsTheDeepestFindingPerAdvisoryAndModule is the correction C4 pins:
// a called advisory arrives first at module level, then package, then function,
// and folding must not stop at the first message.
func TestFoldKeepsTheDeepestFindingPerAdvisoryAndModule(t *testing.T) {
	t.Parallel()

	byOSV := foldedByOSV(t, parseFixture(t, "xtext_v0_3_5_symbol_source.jsonl"))
	called, ok := byOSV["GO-2021-0113"]
	if !ok || called.level != levelSymbol {
		t.Fatalf("GO-2021-0113 = %+v, want symbol", called)
	}
	if called.module != "golang.org/x/text" || called.deepestPackage != "golang.org/x/text/language" || called.deepestSymbol != "Parse" {
		t.Fatalf("deepest = %+v", called)
	}
	if got := byOSV["GO-2022-1059"]; got.level != levelNotCalled || got.deepestPackage != "golang.org/x/text/language" || got.deepestSymbol != "" || len(got.trace) != 0 {
		t.Fatalf("GO-2022-1059 = %+v, want package-depth not_called with no trace", got)
	}
	if got := byOSV["GO-2026-5970"]; got.level != levelNotCalled || got.deepestPackage != "" || got.module != "golang.org/x/text" || len(got.trace) != 0 {
		t.Fatalf("GO-2026-5970 = %+v, want module-depth not_called keeping deepest_module", got)
	}
}

// TestFoldLevelTableFollowsTheContract walks every row of the SDK producer table
// and one row for each producer error.
func TestFoldLevelTableFollowsTheContract(t *testing.T) {
	t.Parallel()

	moduleOnly := scanFinding{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/a"}}}
	packageOnly := scanFinding{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/a", Package: "m.test/a/p"}}}
	function := scanFinding{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/a", Package: "m.test/a/p", Function: "F"}}}
	for _, tc := range []struct {
		scan     string
		findings []scanFinding
		want     string
	}{
		{"symbol", []scanFinding{moduleOnly, packageOnly, function}, levelSymbol},
		{"symbol", []scanFinding{function, moduleOnly}, levelSymbol},
		{"symbol", []scanFinding{moduleOnly, packageOnly}, levelNotCalled},
		{"symbol", []scanFinding{moduleOnly}, levelNotCalled},
		{"package", []scanFinding{moduleOnly, packageOnly}, levelImport},
		{"package", []scanFinding{moduleOnly}, levelModule},
		{"module", []scanFinding{moduleOnly}, levelModule},
	} {
		folded, _, err := foldFindings(tc.scan, tc.findings)
		if err != nil || len(folded) != 1 || folded[0].level != tc.want {
			t.Errorf("scan %s: folded = %+v, err = %v, want level %s", tc.scan, folded, err, tc.want)
		}
	}
	if _, _, err := foldFindings("", []scanFinding{moduleOnly}); err == nil {
		t.Error("blank scan level: error = nil")
	}
	if _, _, err := foldFindings("module", []scanFinding{packageOnly}); err == nil {
		t.Error("package depth from a module scan: error = nil, want a producer error, not a guess")
	}
	if _, _, err := foldFindings("package", []scanFinding{function}); err == nil {
		t.Error("function depth from a package scan: error = nil, want a producer error, not a guess")
	}
}

// TestFoldReversesTheTraceAndPicksTheShortest proves Eshu's wire order, the
// deterministic choice, and that trace_count counts every call trace.
func TestFoldReversesTheTraceAndPicksTheShortest(t *testing.T) {
	t.Parallel()

	frame := func(pkg, fn string) *scanFrame {
		return &scanFrame{Module: "m.test/a", Package: pkg, Function: fn, Version: "v1.0.0"}
	}
	long := scanFinding{OSV: "GO-1", Trace: []*scanFrame{frame("m.test/a/v", "Bad"), frame("m.test/a/x", "Mid"), frame("main", "main")}}
	zebra := scanFinding{OSV: "GO-1", Trace: []*scanFrame{frame("m.test/a/v", "Bad"), frame("main", "zebra")}}
	apple := scanFinding{OSV: "GO-1", Trace: []*scanFrame{frame("m.test/a/v", "Bad"), frame("main", "apple")}}
	for _, order := range [][]scanFinding{{long, zebra, apple}, {apple, zebra, long}, {zebra, long, apple}} {
		folded, _, err := foldFindings("symbol", order)
		if err != nil || len(folded) != 1 {
			t.Fatalf("folded = %+v, %v", folded, err)
		}
		got := folded[0]
		if len(got.trace) != 2 || got.trace[0].Function != "apple" || got.trace[1].Function != "Bad" {
			t.Fatalf("trace = %+v, want the shortest, lexically first, entry point first", got.trace)
		}
		if got.traceCount != 3 {
			t.Fatalf("trace_count = %d, want 3", got.traceCount)
		}
		if got.deepestSymbol != "Bad" || got.deepestPackage != "m.test/a/v" {
			t.Fatalf("deepest = %+v, want the vulnerable frame", got)
		}
	}
	// The fold must not reorder the caller's slice in place.
	if long.Trace[0].Function != "Bad" {
		t.Fatalf("fold mutated its input: %+v", long.Trace[0])
	}
}

// TestFoldKeepsOnePerPairAndDropsStdlib proves two modules under one advisory
// stay separate, and standard-library findings are counted and dropped because
// no go.mod evidence can anchor them.
func TestFoldKeepsOnePerPairAndDropsStdlib(t *testing.T) {
	t.Parallel()

	folded, stdlib, err := foldFindings("symbol", []scanFinding{
		{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/a"}}},
		{OSV: "GO-1", Trace: []*scanFrame{{Module: "m.test/b"}}},
		{OSV: "GO-2", Trace: []*scanFrame{{Module: "stdlib", Package: "net/http", Function: "Get"}}},
		{OSV: "GO-2", Trace: []*scanFrame{{Module: "stdlib"}}},
		{OSV: "GO-3", Trace: []*scanFrame{{Module: "stdlib"}}},
	})
	if err != nil {
		t.Fatalf("foldFindings() error = %v", err)
	}
	if len(folded) != 2 || folded[0].module != "m.test/a" || folded[1].module != "m.test/b" {
		t.Fatalf("folded = %+v", folded)
	}
	if stdlib != 2 {
		t.Fatalf("stdlib = %d, want the 2 distinct advisory pairs", stdlib)
	}
}

// TestRecordedRunsFoldLikeGovulnchecksOwnRules is the parity test. Its oracle is
// independent of the parser: it reads each committed file as untyped JSON and
// applies govulncheck's own rule (internal/scan/template.go: called when
// Trace[0].Function is set), then compares every non-stdlib pair.
func TestRecordedRunsFoldLikeGovulnchecksOwnRules(t *testing.T) {
	t.Parallel()

	for _, name := range parityFixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want, scanLevel := paritySummary(t, readFixture(t, name))
			if len(want) == 0 {
				t.Fatal("oracle found no pair; the fixture proves nothing")
			}
			folded, _, err := foldFindings(scanLevel, parseFixture(t, name).findings)
			if err != nil {
				t.Fatalf("foldFindings() error = %v", err)
			}
			if len(folded) != len(want) {
				t.Fatalf("folded %d pairs, want %d: %+v", len(folded), len(want), folded)
			}
			for _, finding := range folded {
				if got, expected := finding.level, want[finding.osv+" "+finding.module]; got != expected {
					t.Errorf("%s %s = %s, want %s", finding.osv, finding.module, got, expected)
				}
			}
		})
	}
}

// parityFixtures lists every committed recorded run with findings.
var parityFixtures = []string{
	"xtext_v0_3_5_symbol_source.jsonl",
	"xtext_v0_3_5_package_source.jsonl",
}

// paritySummary folds a recorded file without using the production types.
func paritySummary(t *testing.T, raw []byte) (map[string]string, string) {
	t.Helper()

	depth := map[string]int{}
	scanLevel := ""
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var message map[string]map[string]any
		if err := decoder.Decode(&message); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			continue
		}
		if config, ok := message["config"]; ok {
			scanLevel, _ = config["scan_level"].(string)
		}
		finding, ok := message["finding"]
		if !ok {
			continue
		}
		first, _ := finding["trace"].([]any)[0].(map[string]any)
		module, _ := first["module"].(string)
		if module == "stdlib" {
			continue
		}
		rank := 0
		if first["package"] != nil {
			rank = 1
		}
		if first["function"] != nil {
			rank = 2
		}
		key := finding["osv"].(string) + " " + module
		depth[key] = max(depth[key], rank)
	}
	want := make(map[string]string, len(depth))
	for key, rank := range depth {
		switch {
		case scanLevel == "symbol" && rank == 2:
			want[key] = "symbol"
		case scanLevel == "symbol":
			want[key] = "not_called"
		case scanLevel == "package" && rank == 1:
			want[key] = "import"
		default:
			want[key] = "module"
		}
	}
	return want, scanLevel
}
