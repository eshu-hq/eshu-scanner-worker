// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// The full-range runs re-analyze 50,000 facts on every stateless call (17 to
// 25 calls per analyzer): seconds each plain and several minutes under the
// race detector, which adds nothing to these single-goroutine paging checks.
// They run in the test lane and stay out of the race and coverage lane.

//go:build !race

package component

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/imageanalyzer"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/sbomgenerator"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
)

// hostileFactCount is the #9380 hostile full-range size: the analyzer's
// MaxFacts ceiling, so the claim is as large as the contract allows.
const hostileFactCount = 50000

// hostileRun drives one component through every page at the real
// stdout-derived bound and returns the reassembled facts. It fails if any
// stdout document exceeds the host limit, any page's facts exceed the bound,
// or the page sequence is not contiguous with the declared total.
func hostileRun(t *testing.T, componentID string, claim sdkcollector.Claim, config map[string]any, runner func(stdin []byte, stdout *bytes.Buffer) Runner, wantTotal int) []sdkcollector.Fact {
	t.Helper()

	bound, err := pageBound(0)
	if err != nil {
		t.Fatalf("pageBound() error = %v", err)
	}
	if bound != 4128768 {
		t.Fatalf("default page bound = %d, want 4128768", bound)
	}
	var reassembled []sdkcollector.Fact
	var cursor *sdkcollector.PageContinuation
	for index := 0; ; index++ {
		if index >= maxPagesPerClaim {
			t.Fatalf("%s: paging exceeded %d pages", componentID, maxPagesPerClaim)
		}
		var stdout bytes.Buffer
		r := runner(testRequestWithContinuation(t, claim, config, cursor), &stdout)
		if err := r.Run(context.Background()); err != nil {
			t.Fatalf("%s: Run() page %d error = %v", componentID, index, err)
		}
		if int64(stdout.Len()) > DefaultStdoutLimitBytes {
			t.Fatalf("%s: page %d stdout = %d bytes, above host limit %d", componentID, index, stdout.Len(), DefaultStdoutLimitBytes)
		}
		page := decodePage(t, stdout.Bytes())
		if page.State != sdkcollector.ResultComplete || page.Page == nil || page.Page.PageIndex != index || page.Page.TotalFacts != wantTotal {
			t.Fatalf("%s: page %d state=%q envelope=%+v, want complete contiguous page of %d", componentID, index, page.State, page.Page, wantTotal)
		}
		var pageBytes int64
		for _, fact := range page.Facts {
			size, err := sdkcollector.FactWireBytes(fact)
			if err != nil {
				t.Fatalf("FactWireBytes() error = %v", err)
			}
			pageBytes += int64(size)
		}
		if pageBytes > bound {
			t.Fatalf("%s: page %d facts = %d bytes, above bound %d", componentID, index, pageBytes, bound)
		}
		reassembled = append(reassembled, page.Facts...)
		if !page.Page.More {
			t.Logf("hostile %s: facts=%d pages=%d bound=%d", componentID, len(reassembled), index+1, bound)
			return reassembled
		}
		cursor = &sdkcollector.PageContinuation{Cursor: page.Page.Cursor}
	}
}

func assertSameFacts(t *testing.T, name string, got, want []sdkcollector.Fact) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: reassembled %d facts, want %d", name, len(got), len(want))
	}
	gotRaw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal reassembled: %v", err)
	}
	wantRaw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal direct: %v", err)
	}
	if !bytes.Equal(gotRaw, wantRaw) {
		t.Fatalf("%s: reassembled facts differ from the direct analysis", name)
	}
}

func projectEnvelopes(t *testing.T, envelopes []facts.Envelope) []sdkcollector.Fact {
	t.Helper()
	out := make([]sdkcollector.Fact, 0, len(envelopes))
	for _, envelope := range envelopes {
		fact, err := factenvelope.SDKFactFromInternal(envelope)
		if err != nil {
			t.Fatalf("SDKFactFromInternal() error = %v", err)
		}
		out = append(out, fact)
	}
	return out
}

// TestOSRuntimeHostileFullRangePaging is the committed #9380 re-run for the
// osruntime component: 50,000 facts at the real 4,128,768-byte bound,
// reassembled equal to one direct analysis byte for byte.
//
// It reads through the real LocalRootFSProvider with no pin: every fact
// carries the claim observation time, so the split cannot drift between the
// stateless per-page calls (eshu-hq/eshu-scanner-worker#33).
func TestOSRuntimeHostileFullRangePaging(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount)
	config := map[string]any{
		"targets":            []any{map[string]any{"scope_id": parityScopeID, "rootfs_path": root, "source_uri": paritySourceURI, "source_record_id": paritySourceRecordID}},
		"acceptance_unit_id": parityAcceptanceUnitID,
	}
	got := hostileRun(t, IDOSRuntime, parityClaim(), config, func(stdin []byte, stdout *bytes.Buffer) Runner {
		return Runner{ComponentID: IDOSRuntime, Stdin: bytes.NewReader(stdin), Stdout: stdout, Clock: parityObservedAt}
	}, hostileFactCount)
	assertSameFacts(t, "osruntime", got, directOSRuntimeFacts(t, root))
}

// TestImageHostileFullRangePaging is the #9380 re-run for the image
// component: 49,999 packages plus the analysis fact make 50,000 facts.
func TestImageHostileFullRangePaging(t *testing.T) {
	t.Parallel()

	root := parityRootFS(t, hostileFactCount-1)
	targets := parityImageTargets(root)
	config := map[string]any{"targets": []any{targets[0]}, "acceptance_unit_id": parityAcceptanceUnitID}
	got := hostileRun(t, IDImage, parityImageClaim(), config, func(stdin []byte, stdout *bytes.Buffer) Runner {
		return Runner{ComponentID: IDImage, Stdin: bytes.NewReader(stdin), Stdout: stdout, Clock: parityObservedAt}
	}, hostileFactCount)

	input, err := claimInput(parityImageClaim(), Config{AcceptanceUnitID: parityAcceptanceUnitID}, scannerworker.AnalyzerImageUnpacking, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := imageanalyzer.NewAnalyzer(imageanalyzer.AnalyzerConfig{CollectorInstanceID: parityInstanceID, Targets: targets})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertSameFacts(t, "image", got, projectEnvelopes(t, result.Output.Facts))
}

// hostileSBOMSource returns a synthetic inventory of n npm components.
type hostileSBOMSource struct{ n int }

func (s hostileSBOMSource) Collect(context.Context, scannerworker.ClaimInput) (sbomgenerator.Inventory, error) {
	inventory := sbomgenerator.Inventory{SubjectDigest: "sha256:" + strings.Repeat("1", 64), SpecVersion: "1.6", FileCount: 1, InputBytes: 1}
	for i := 0; i < s.n; i++ {
		name := fmt.Sprintf("hostile-pkg-%05d", i)
		inventory.Components = append(inventory.Components, sbomgenerator.Component{
			PURL: "pkg:npm/" + name + "@1.2.3", Name: name, Version: "1.2.3", Type: "library", Ecosystem: "npm",
			EvidenceSource: "repository_lockfile", LockfilePath: "package-lock.json", DependencyScope: "dependencies",
			DependencyType: "runtime", ExtractionReason: "lockfile_parsed",
		})
	}
	return inventory, nil
}

// TestSBOMHostileFullRangePaging is the #9380 re-run for the SBOM
// component: one document fact plus 49,999 component facts.
func TestSBOMHostileFullRangePaging(t *testing.T) {
	t.Parallel()

	source := hostileSBOMSource{n: hostileFactCount - 1}
	config := map[string]any{"targets": []any{map[string]any{"scope_id": paritySBOMScopeID, "root_path": t.TempDir()}}, "acceptance_unit_id": paritySBOMAcceptanceUnitID}
	got := hostileRun(t, IDSBOM, paritySBOMClaim(), config, func(stdin []byte, stdout *bytes.Buffer) Runner {
		return Runner{ComponentID: IDSBOM, Stdin: bytes.NewReader(stdin), Stdout: stdout, Clock: parityObservedAt, inventory: source}
	}, hostileFactCount)

	input, err := claimInput(paritySBOMClaim(), Config{AcceptanceUnitID: paritySBOMAcceptanceUnitID}, scannerworker.AnalyzerSBOMGeneration, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	result, err := sbomgenerator.Analyzer{Source: source, Now: parityObservedAt}.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	assertSameFacts(t, "sbom", got, projectEnvelopes(t, result.Output.Facts))
}

// directOSRuntimeFacts runs one direct analysis with the default provider and
// projects it to SDK wire facts.
func directOSRuntimeFacts(t *testing.T, root string) []sdkcollector.Fact {
	t.Helper()

	input, err := claimInput(parityClaim(), Config{AcceptanceUnitID: parityAcceptanceUnitID}, scannerworker.AnalyzerOSPackageExtraction, parityObservedAt())
	if err != nil {
		t.Fatalf("claimInput() error = %v", err)
	}
	analyzer, err := osruntime.NewAnalyzer(osruntime.AnalyzerConfig{
		CollectorInstanceID: parityInstanceID,
		Targets:             parityTargets(root),
	})
	if err != nil {
		t.Fatalf("NewAnalyzer() error = %v", err)
	}
	result, err := analyzer.Analyze(context.Background(), input)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	facts := make([]sdkcollector.Fact, 0, len(result.Output.Facts))
	for _, envelope := range result.Output.Facts {
		fact, err := factenvelope.SDKFactFromInternal(envelope)
		if err != nil {
			t.Fatalf("SDKFactFromInternal() error = %v", err)
		}
		facts = append(facts, fact)
	}
	return facts
}
