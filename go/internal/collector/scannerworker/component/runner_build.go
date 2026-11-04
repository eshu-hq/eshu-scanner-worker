// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/ospackagevulnerability/osruntime"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/imageanalyzer"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/sbomgenerator"
)

// claimInput assembles the analyzer input from the SDK claim and the
// operator config. Every field derives from claim-carried or
// operator-declared values: the locator hash is recomputed from the scope
// ID (never invented), and the owner/correlation IDs name this executor
// (they never cross the wire and no analyzer reads them into facts).
func claimInput(claim sdkcollector.Claim, config Config, analyzer scannerworker.AnalyzerKind, now time.Time) (scannerworker.ClaimInput, error) {
	if strings.TrimSpace(claim.WorkItemID) == "" {
		return scannerworker.ClaimInput{}, errors.New("claim work_item_id must not be blank")
	}
	if strings.TrimSpace(claim.InstanceID) == "" {
		return scannerworker.ClaimInput{}, errors.New("claim instance_id must not be blank")
	}
	if strings.TrimSpace(claim.SourceRunID) == "" {
		return scannerworker.ClaimInput{}, errors.New("claim source_run_id must not be blank")
	}
	if strings.TrimSpace(claim.GenerationID) == "" {
		return scannerworker.ClaimInput{}, errors.New("claim generation_id must not be blank")
	}
	if strings.TrimSpace(claim.Scope.ID) == "" {
		return scannerworker.ClaimInput{}, errors.New("claim scope_id must not be blank")
	}
	fencing, err := strconv.ParseInt(strings.TrimSpace(claim.FencingToken), 10, 64)
	if err != nil || fencing <= 0 {
		return scannerworker.ClaimInput{}, errors.New("claim fencing_token must be a positive integer")
	}
	target, err := scannerworker.TargetScopeForComponent(claim.Scope.ID, config.AcceptanceUnitID, claim.SourceRunID, claim.GenerationID)
	if err != nil {
		return scannerworker.ClaimInput{}, err
	}
	limits, err := scannerworker.DefaultResourceLimits(analyzer)
	if err != nil {
		return scannerworker.ClaimInput{}, err
	}
	return scannerworker.ClaimInput{
		WorkItemID:     claim.WorkItemID,
		ClaimID:        fmt.Sprintf("%s/%s/attempt-%d", claim.ComponentID, claim.WorkItemID, claim.Attempt),
		FencingToken:   fencing,
		OwnerID:        claim.ComponentID,
		Analyzer:       analyzer,
		Target:         target,
		Limits:         limits,
		GenerationID:   claim.GenerationID,
		Attempt:        claim.Attempt,
		ClaimedAt:      now,
		LeaseExpiresAt: claim.Deadline,
		ObservedAt:     now,
	}, nil
}

// buildAnalyzer constructs the analyzer for one component from the operator
// targets. Targets decode strictly into the analyzer-native shape so the
// binary accepts exactly what the in-tree worker accepted. A nil provider
// keeps the analyzer default.
//
// A nil provider or inventory keeps the analyzer default; only the parity
// tests set them. A rootfs target whose source_uri is missing or sanitizes
// to empty is a bad config (errBadTargetConfig): every fact needs a
// non-empty source_ref.uri.
func buildAnalyzer(analyzer scannerworker.AnalyzerKind, claim sdkcollector.Claim, config Config, now time.Time, provider osruntime.SnapshotProvider, inventory sbomgenerator.Source) (scannerworker.Analyzer, error) {
	switch analyzer {
	case scannerworker.AnalyzerSBOMGeneration:
		var targets []sbomgenerator.RepositoryTarget
		if err := decodeTargets(config.Targets, &targets); err != nil {
			return nil, err
		}
		source, err := sbomgenerator.NewRepositorySource(targets)
		if err != nil {
			return nil, err
		}
		if inventory != nil {
			source = inventory
		}
		return sbomgenerator.Analyzer{Source: source, Now: func() time.Time { return now }}, nil
	case scannerworker.AnalyzerImageUnpacking:
		var targets []imageanalyzer.TargetConfig
		if err := decodeTargets(config.Targets, &targets); err != nil {
			return nil, err
		}
		for _, target := range targets {
			if err := requireSourceURI(target.SourceURI); err != nil {
				return nil, err
			}
		}
		return imageanalyzer.NewAnalyzer(imageanalyzer.AnalyzerConfig{
			CollectorInstanceID: claim.InstanceID,
			Targets:             targets,
			Provider:            provider,
		})
	case scannerworker.AnalyzerOSPackageExtraction:
		var targets []osruntime.TargetConfig
		if err := decodeTargets(config.Targets, &targets); err != nil {
			return nil, err
		}
		for _, target := range targets {
			if err := requireSourceURI(target.SourceURI); err != nil {
				return nil, err
			}
		}
		return osruntime.NewAnalyzer(osruntime.AnalyzerConfig{
			CollectorInstanceID: claim.InstanceID,
			Targets:             targets,
			Provider:            provider,
		})
	default:
		return nil, fmt.Errorf("no component analyzer for %q", analyzer)
	}
}

// buildGoReachability constructs the go_reachability analyzer from the
// host-derived target and the host-minted token. Any target defect is a bad
// config: the target can never be served, and retry cannot fix it. A target for
// another scope is the same defect, so it fails here with no facts.
func buildGoReachability(claim sdkcollector.Claim, config Config, options goreachability.Options) (scannerworker.Analyzer, error) {
	if config.derivedTarget.ScopeID != claim.Scope.ID {
		return nil, fmt.Errorf("%w: host_derived_target is for another scope", errBadTargetConfig)
	}
	if len(config.allowedCloneHosts) > 0 {
		options.AllowedCloneHosts = config.allowedCloneHosts
	}
	analyzer, err := goreachability.NewAnalyzer(goreachability.Config{
		CollectorInstanceID: claim.InstanceID,
		Target:              config.derivedTarget,
		Token:               config.hostToken,
		Options:             options,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadTargetConfig, err)
	}
	return analyzer, nil
}

// errBadTargetConfig marks an operator target the component can never serve,
// mapped to the component_bad_config terminal class.
var errBadTargetConfig = errors.New("bad component target config")

// requireSourceURI rejects a target source_uri that is missing or that the
// fact sanitizer would drop (for example, one carrying a credential), so the
// defect surfaces as bad config before any analysis instead of as an empty
// source_ref.uri. The value is never echoed.
func requireSourceURI(raw string) error {
	if ospackagevulnerability.SanitizeURL(raw) == "" {
		return fmt.Errorf("%w: source_uri is missing or not a credential-free URI", errBadTargetConfig)
	}
	return nil
}

// decodeTargets decodes raw target documents strictly into the
// analyzer-native shape.
func decodeTargets(raw []json.RawMessage, targets any) error {
	payload, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encode component targets: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(targets); err != nil {
		return fmt.Errorf("decode component targets: %w", err)
	}
	return nil
}
