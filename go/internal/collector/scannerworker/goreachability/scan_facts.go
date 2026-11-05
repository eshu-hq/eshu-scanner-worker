// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

// reachabilityFact builds one vulnerability.go_call_reachability fact. Identity
// comes from the claim and the key names no trace position, so a retry or a
// reordered stream keeps one fact per (repository, advisory, module, go.mod).
//
// scan_level through trace_count are the provenance factschema types, which say how
// much a not_called answer is worth. relative_path is not in that schema; it is an
// extra key the schema admits, and it is what keeps one fact per go.mod.
func (s StageInput) reachabilityFact(module Module, config *scanConfig, finding foldedFinding) facts.Envelope {
	key := facts.StableID(chain.VulnerabilityGoCallReachabilityFactKind, map[string]any{
		"repository_id":  s.RepositoryID,
		"osv_id":         finding.osv,
		"deepest_module": finding.module,
		"relative_path":  module.RelativePath,
	})
	trace := make([]any, 0, len(finding.trace))
	for _, frame := range finding.trace {
		trace = append(trace, framePayload(frame, s.CheckoutDir))
	}
	payload := map[string]any{
		"collector_instance_id": s.InstanceID,
		"repository_id":         s.RepositoryID,
		"osv_id":                finding.osv,
		"relative_path":         module.RelativePath,
		"deepest_module":        finding.module,
		"reachability_level":    finding.level,
		"scan_level":            config.ScanLevel,
		"scan_mode":             config.ScanMode,
		"scanner_version":       config.ScannerVersion,
		"source_commit_sha":     s.SourceCommitSHA,
		"trace_count":           finding.traceCount,
		"trace":                 trace,
	}
	putNonEmpty(payload, map[string]string{
		"deepest_package": finding.deepestPackage,
		"deepest_symbol":  finding.deepestSymbol,
	})
	record := module.RelativePath + "#" + finding.osv + "#" + finding.module
	return s.Envelope(chain.VulnerabilityGoCallReachabilityFactKind, key, record, payload)
}

// framePayload renders one frame in the wire shape, with the position as the
// string the contract names.
func framePayload(frame scanFrame, checkoutDir string) map[string]any {
	payload := map[string]any{}
	putNonEmpty(payload, map[string]string{
		"module":   frame.Module,
		"version":  frame.Version,
		"package":  frame.Package,
		"function": frame.Function,
		"receiver": frame.Receiver,
		"position": renderPosition(frame.Position, checkoutDir),
	})
	return payload
}

// renderPosition writes filename:line:column and drops the offset. A real run
// reports paths relative to the module, and this keeps that true for any other
// form: a fact never carries a pod path.
func renderPosition(position *scanPosition, checkoutDir string) string {
	if position == nil || position.Filename == "" {
		return ""
	}
	name := filepath.ToSlash(position.Filename)
	if filepath.IsAbs(position.Filename) {
		if relative, ok := strings.CutPrefix(name, filepath.ToSlash(checkoutDir)+"/"); ok {
			name = relative
		} else {
			name = filepath.Base(name)
		}
	}
	return fmt.Sprintf("%s:%d:%d", name, position.Line, position.Column)
}
