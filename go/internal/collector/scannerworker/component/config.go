// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// maxRequestBytes bounds one stdin request document. A request carries the
// claim, the contract, and operator activation config (targets and budgets,
// and for go_reachability the one host-minted token); a megabyte is orders of
// magnitude above any legitimate scanner request.
const maxRequestBytes = int64(1024 * 1024)

// hostTokenKey is the request config key under which the host delivers a
// per-claim GitHub installation token as {token, scope_id}. It mirrors eshu
// core's extensionhost.HostMintedGitHubTokenKey.
const hostTokenKey = "host_github_app_token" // #nosec G101 -- names a config key, not a credential value

// Config is the operator activation config a scanner component accepts
// inside the host request. It carries target material and budgets only:
// repository roots, rootfs paths, image references, and digests stay out of
// labels, logs, metrics, and errors. The only credential is the host-minted
// token go_reachability receives; every other component refuses it.
type Config struct {
	// hostToken is the host-minted credential, extracted before the strict
	// decode because the host may add fields to its stanza. It never formats.
	hostToken goreachability.HostToken
	// hostTokenPresent reports whether the request carried the token key at all.
	hostTokenPresent bool

	// Targets carries the analyzer-native target documents. Each entry
	// decodes into the analyzer's own TargetConfig shape (imageanalyzer,
	// osruntime, or the SBOM repository targets), so the binary accepts
	// exactly what the in-tree worker accepts and nothing more.
	Targets []json.RawMessage `json:"targets"`
	// AcceptanceUnitID names the accepted unit the claim covers. It is
	// operator-declared per activation and must agree with the claim scope
	// on target-kind derivation.
	AcceptanceUnitID string `json:"acceptance_unit_id"`
	// PageBoundBytes optionally narrows the per-call page byte bound below
	// the stdout-derived default (tests and constrained hosts). Zero keeps
	// the default; a value above the default is clamped to it, so pages
	// always fit the host stdout limit. A negative value fails closed.
	PageBoundBytes int64 `json:"page_bound_bytes,omitempty"`
}

// parseConfig decodes and validates the component config block.
func parseConfig(raw map[string]any) (Config, error) {
	stripped := maps.Clone(raw)
	delete(stripped, hostTokenKey)
	payload, err := json.Marshal(stripped)
	if err != nil {
		return Config{}, fmt.Errorf("encode component config: %w", err)
	}
	var config Config
	if stanza, ok := raw[hostTokenKey]; ok {
		config.hostToken = goreachability.ParseHostToken(stanza)
		config.hostTokenPresent = true
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode component config: %w", err)
	}
	if len(config.Targets) == 0 {
		return Config{}, fmt.Errorf("at least one component target is required")
	}
	if strings.TrimSpace(config.AcceptanceUnitID) == "" {
		return Config{}, fmt.Errorf("acceptance_unit_id must not be blank")
	}
	if config.PageBoundBytes < 0 {
		return Config{}, fmt.Errorf("page_bound_bytes must not be negative")
	}
	return config, nil
}
