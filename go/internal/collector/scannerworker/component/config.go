// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
)

// maxRequestBytes bounds one stdin request document. A request carries the
// claim, the contract, and activation config (targets and budgets, and for
// go_reachability the host's target and token); a megabyte is orders of
// magnitude above any legitimate scanner request.
const maxRequestBytes = int64(1024 * 1024)

// Host-owned request config keys go_reachability reads. They mirror eshu core's
// extensionhost.HostMintedGitHubTokenKey and HostDerivedTargetKey. Every other
// component refuses them through its strict decode.
const (
	hostTokenKey         = "host_github_app_token" // #nosec G101 -- names a config key, not a credential value
	hostDerivedTargetKey = "host_derived_target"
	// goModulesDeriveKey is the coordinator's activation section. The component
	// ignores its contents: it plans nothing.
	goModulesDeriveKey = "derive_from_go_modules"
)

// Config is the activation config a scanner component accepts inside the host
// request. It carries target material and budgets only: repository roots, rootfs
// paths, image references, and digests stay out of labels, logs, metrics, and
// errors. The only credential is the host-minted token go_reachability receives.
type Config struct {
	// hostToken is the host-minted credential. It never formats.
	hostToken goreachability.HostToken
	// derivedTarget is the host's target for a go_reachability claim.
	derivedTarget goreachability.TargetConfig

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

// parseConfigFor decodes the config block for one analyzer.
func parseConfigFor(analyzer scannerworker.AnalyzerKind, raw map[string]any) (Config, error) {
	if analyzer == scannerworker.AnalyzerGoReachability {
		return parseGoReachabilityConfig(raw)
	}
	return parseConfig(raw)
}

// parseConfig decodes and validates the component config block.
func parseConfig(raw map[string]any) (Config, error) {
	config, err := decodeConfig(raw)
	if err != nil {
		return Config{}, err
	}
	if len(config.Targets) == 0 {
		return Config{}, fmt.Errorf("at least one component target is required")
	}
	if strings.TrimSpace(config.AcceptanceUnitID) == "" {
		return Config{}, fmt.Errorf("acceptance_unit_id must not be blank")
	}
	return config, nil
}

// parseGoReachabilityConfig reads the host's target and token. The two host keys
// and the derive section leave the strict decode because the host owns their
// shape. Static targets and an acceptance unit are refused, so activation config
// cannot forge a commit or a remote. The acceptance unit is the scope, as the
// core planner sets it. A target or token defect never echoes its value.
func parseGoReachabilityConfig(raw map[string]any) (Config, error) {
	stripped := maps.Clone(raw)
	delete(stripped, hostTokenKey)
	delete(stripped, hostDerivedTargetKey)
	delete(stripped, goModulesDeriveKey)
	config, err := decodeConfig(stripped)
	if err != nil {
		return Config{}, err
	}
	if len(config.Targets) > 0 || config.AcceptanceUnitID != "" {
		return Config{}, errors.New("go reachability takes its target from the host, not from activation config")
	}
	target, err := goreachability.ParseDerivedTarget(raw[hostDerivedTargetKey])
	if err != nil {
		return Config{}, err
	}
	config.derivedTarget = target
	config.AcceptanceUnitID = target.ScopeID
	config.hostToken = goreachability.ParseHostToken(raw[hostTokenKey])
	return config, nil
}

// decodeConfig runs the strict decode every component shares.
func decodeConfig(raw map[string]any) (Config, error) {
	payload, err := json.Marshal(raw)
	if err != nil {
		return Config{}, fmt.Errorf("encode component config: %w", err)
	}
	var config Config
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode component config: %w", err)
	}
	if config.PageBoundBytes < 0 {
		return Config{}, fmt.Errorf("page_bound_bytes must not be negative")
	}
	return config, nil
}
