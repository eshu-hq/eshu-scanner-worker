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
	warningNoGoModules          = "no_go_modules"
	warningNoRequirements       = "no_module_requirements"
)

// warningDetails is fixed text per reason, so no file content reaches a fact.
var warningDetails = map[string]string{
	warningToolchainUnsupported: "a go or toolchain directive is above the pinned toolchain; this module is not analyzed for reachability",
	warningGoModParseFailed:     "go.mod did not parse; no module evidence for this file",
	warningGoModTooLarge:        "go.mod is above the read bound; no module evidence for this file",
	warningNoGoModules:          "no go.mod at this commit outside excluded directories",
	warningNoRequirements:       "no go.mod at this commit declares a requirement",
}

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

// warningFact builds one vulnerability.warning fact for a reason and optional
// module path.
func (c emitContext) warningFact(reason string, class scannerworker.FailureClass, relativePath, detail string) facts.Envelope {
	key := facts.StableID(chain.VulnerabilityWarningFactKind, map[string]any{
		"repository_id": c.repositoryID,
		"reason":        reason,
		"relative_path": relativePath,
	})
	payload := map[string]any{
		"collector_instance_id": c.instanceID,
		"collector_kind":        string(scope.CollectorScannerWorker),
		"repository_id":         c.repositoryID,
		"source_commit_sha":     c.commitSHA,
		"reason":                reason,
		"relative_path":         relativePath,
		"detail":                detail,
	}
	putNonEmpty(payload, map[string]string{"failure_class": string(class)})
	return c.envelope(chain.VulnerabilityWarningFactKind, key, reason+"#"+relativePath, payload)
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
