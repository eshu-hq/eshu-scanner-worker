// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/scope"
)

// evidenceSource labels this producer on the payload, matching the value core's
// go.mod evidence used.
const evidenceSource = "go_module_manifest"

// Warning reasons. Each is a bounded token: the warning names the module by
// relative path and never copies file text.
const (
	warningToolchainUnsupported = "toolchain_unsupported"
	warningGoModParseFailed     = "go_mod_parse_failed"
	warningGoModTooLarge        = "go_mod_too_large"
	warningGoModNotRegular      = "go_mod_not_regular"
	warningGoModInvalidPath     = "go_mod_invalid_path"
	warningGoSumNotRegular      = "go_sum_not_regular"
	warningNoGoModules          = "no_go_modules"
	warningNoRequirements       = "no_module_requirements"
	warningCgoRequired          = "cgo_required"
	warningAnalysisTimeout      = "analysis_timeout"
	warningAnalysisFailed       = "analysis_failed"
	warningModuleBudgetExceeded = "module_budget_exceeded"
	warningModuleDownloadFailed = "module_download_failed"
	warningVulnDBUnavailable    = "vulndb_unavailable"
)

// warningDetails is fixed text per reason, so no file content reaches a fact.
var warningDetails = map[string]string{
	warningToolchainUnsupported: "a go or toolchain requirement is above the pinned toolchain; this module is not analyzed for reachability",
	warningGoModParseFailed:     "go.mod did not parse; no module evidence for this file",
	warningGoModTooLarge:        "go.mod is above the read bound; no module evidence for this file",
	warningGoModNotRegular:      "go.mod is a symlink or a submodule link; it is not read, and there is no module evidence for this file",
	warningGoModInvalidPath:     "go.mod or a path it declares is not valid as identity; that text is not recorded, and this module is not analyzed for reachability",
	warningGoSumNotRegular:      "go.sum is a symlink or a submodule link, which a scan would write through; this module is not analyzed for reachability",
	warningNoGoModules:          "no go.mod at this commit outside excluded directories",
	warningNoRequirements:       "no go.mod at this commit declares a requirement",
	warningCgoRequired:          "a package needs cgo, which this scan disables; this module is not analyzed for reachability",
	warningAnalysisTimeout:      "the scan of this module did not finish in its budget; this module is not analyzed for reachability",
	warningAnalysisFailed:       "the scan of this module did not finish; this module is not analyzed for reachability",
	warningModuleDownloadFailed: "a required module did not download; this module is not analyzed for reachability",
	warningVulnDBUnavailable:    "the vulnerability database was not reachable; this module is not analyzed for reachability",
	warningModuleBudgetExceeded: "this repository has more modules than one claim scans; some are not analyzed for reachability",
}

// Scanner vocabulary for the scanner_worker.warning status fields, shared with
// the image analyzer. A reason that only reports an empty repository is a finished
// scan; every other reason left something unscanned.
const (
	warningAnalyzer           = "go_reachability"
	warningClassConstant      = "scanner_worker_warning"
	analysisStatusCompleted   = "completed"
	analysisStatusNotScanned  = "not_scanned"
	coverageStatusScanned     = "scanned"
	coverageStatusUnsupported = "unsupported"
)

// emitContext is the claim-owned identity every fact of one analysis carries.
type emitContext struct {
	input        scannerworker.ClaimInput
	instanceID   string
	repositoryID string
	commitSHA    string
	sourceURI    string
}

// evidenceFact builds one vulnerability.go_module_evidence fact. Identity comes
// from the claim. The stable key is the ruled tuple, so a retry or a new commit
// with the same require line keeps the same key.
func (c emitContext) evidenceFact(module goModule, item requirement) facts.Envelope {
	key := facts.StableID(chain.VulnerabilityGoModuleEvidenceFactKind, map[string]any{
		"repository_id":    c.repositoryID,
		"relative_path":    module.relativePath,
		"module_path":      item.modulePath,
		"required_version": item.requiredVersion,
	})
	payload := map[string]any{
		"collector_instance_id": c.instanceID,
		"source":                evidenceSource,
		"repository_id":         c.repositoryID,
		"source_commit_sha":     c.commitSHA,
		"relative_path":         module.relativePath,
		"module_path":           item.modulePath,
		"required_version":      item.requiredVersion,
		"indirect":              item.indirect,
		"line_number":           item.lineNumber,
	}
	putNonEmpty(payload, map[string]string{
		"root_module_path":     module.modulePath,
		"root_go_version":      module.goVersion,
		"root_toolchain":       module.toolchain,
		"replacement_path":     item.replacementPath,
		"replacement_version":  item.replacementVersion,
		"replace_from_version": item.replaceFromVersion,
	})
	record := module.relativePath + "#" + item.modulePath + "@" + item.requiredVersion
	return c.envelope(chain.VulnerabilityGoModuleEvidenceFactKind, key, record, payload)
}

// warningFact builds one scanner_worker.warning fact, the kind readiness reads. The
// class goes in reason; warning_class stays the constant every producer of this kind
// writes. A blank relative path covers the whole repository, so the key is left out.
// The key names the go.mod file, not a dependency, because a scan is keyed by the file.
//
// factschema types repository_id and relative_path as the warning join keys. A path
// the escape rewrote is not byte-equal to evidence rows, so it does not join: that
// module then has no reachability evidence, and never reads not_called.
func (c emitContext) warningFact(reason, relativePath string) facts.Envelope {
	key := facts.StableID(facts.ScannerWorkerWarningFactKind, map[string]any{
		"analyzer":      warningAnalyzer,
		"repository_id": c.repositoryID,
		"relative_path": relativePath,
		"reason":        reason,
	})
	analysisStatus, coverageStatus := analysisStatusNotScanned, coverageStatusUnsupported
	if reason == warningNoGoModules || reason == warningNoRequirements {
		analysisStatus, coverageStatus = analysisStatusCompleted, coverageStatusScanned
	}
	payload := map[string]any{
		"collector_instance_id": c.instanceID,
		"analyzer":              warningAnalyzer,
		"target_kind":           string(c.input.Target.Kind),
		"target_locator_hash":   c.input.Target.LocatorHash,
		"reason":                reason,
		"warning_class":         warningClassConstant,
		"analysis_status":       analysisStatus,
		"coverage_status":       coverageStatus,
		"repository_id":         c.repositoryID,
		"source_commit_sha":     c.commitSHA,
		"detail":                warningDetails[reason],
	}
	putNonEmpty(payload, map[string]string{"relative_path": relativePath})
	envelope := c.envelope(facts.ScannerWorkerWarningFactKind, key, reason+"#"+relativePath, payload)
	envelope.SchemaVersion = facts.ScannerWorkerSchemaVersionV1
	return envelope
}

func (c emitContext) envelope(kind, stableKey, recordID string, payload map[string]any) facts.Envelope {
	return facts.Envelope{
		FactID: facts.StableID("GoReachabilityFact", map[string]any{
			"fact_kind":       kind,
			"generation_id":   c.input.GenerationID,
			"scope_id":        c.input.Target.ScopeID,
			"stable_fact_key": stableKey,
		}),
		ScopeID:          c.input.Target.ScopeID,
		GenerationID:     c.input.GenerationID,
		FactKind:         kind,
		StableFactKey:    stableKey,
		SchemaVersion:    chain.VulnerabilityIntelligenceSchemaVersionV1,
		CollectorKind:    string(scope.CollectorScannerWorker),
		FencingToken:     c.input.FencingToken,
		SourceConfidence: facts.SourceConfidenceReported,
		ObservedAt:       c.input.ObservedAt.UTC(),
		Payload:          payload,
		SourceRef: facts.Ref{
			SourceSystem:   string(scope.CollectorScannerWorker),
			ScopeID:        c.input.Target.ScopeID,
			GenerationID:   c.input.GenerationID,
			FactKey:        stableKey,
			SourceURI:      c.sourceURI,
			SourceRecordID: recordID,
		},
	}
}

// putNonEmpty leaves absent optional fields absent rather than blank, so a typed
// reader can tell "no replace" from an empty replacement.
func putNonEmpty(payload map[string]any, values map[string]string) {
	for key, value := range values {
		if value != "" {
			payload[key] = value
		}
	}
}

// sanitizeSourceURI projects the clone URL through the one sanitizer every
// scanner envelope uses.
func sanitizeSourceURI(raw string) string {
	return ospackagevulnerability.SanitizeURL(raw)
}
