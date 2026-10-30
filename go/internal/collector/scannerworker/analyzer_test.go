// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package scannerworker

import (
	"testing"
)

// TestAnalyzerLaneAssignsScannerWorkerToAnalyzerProfiles pins the
// scanner-vs-reducer lane map that the migration carries from Eshu core
// (Refs eshu-hq/eshu#8878). The reducer-owned profiles must never resolve
// to the scanner-worker lane.
func TestAnalyzerLaneAssignsScannerWorkerToAnalyzerProfiles(t *testing.T) {
	t.Parallel()

	scannerAnalyzers := []AnalyzerKind{
		AnalyzerSBOMGeneration,
		AnalyzerImageUnpacking,
		AnalyzerSourceAnalysis,
		AnalyzerOSPackageExtraction,
		AnalyzerSecretScan,
		AnalyzerLicenseScan,
		AnalyzerMisconfigurationScan,
	}
	for _, analyzer := range scannerAnalyzers {
		lane, ok := AnalyzerLane(analyzer)
		if !ok {
			t.Errorf("AnalyzerLane(%q) not found, want scanner_worker lane", analyzer)
			continue
		}
		if lane != LaneScannerWorker {
			t.Errorf("AnalyzerLane(%q) = %q, want %q", analyzer, lane, LaneScannerWorker)
		}
	}

	reducerAnalyzers := []AnalyzerKind{
		AnalyzerVulnerabilityMatching,
		AnalyzerCoverageReadiness,
		AnalyzerSecurityPriority,
	}
	for _, analyzer := range reducerAnalyzers {
		lane, ok := AnalyzerLane(analyzer)
		if !ok {
			t.Errorf("AnalyzerLane(%q) not found, want reducer lane", analyzer)
			continue
		}
		if lane != LaneReducer {
			t.Errorf("AnalyzerLane(%q) = %q, want %q", analyzer, lane, LaneReducer)
		}
	}
}

// TestAnalyzerLaneRejectsUnknownAnalyzer keeps the lane map closed: an
// unlisted profile must not silently resolve to either lane.
func TestAnalyzerLaneRejectsUnknownAnalyzer(t *testing.T) {
	t.Parallel()

	if lane, ok := AnalyzerLane("definitely_not_an_analyzer"); ok {
		t.Fatalf("AnalyzerLane(unknown) = (%q, true), want (_, false)", lane)
	}
}
