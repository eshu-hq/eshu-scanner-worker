// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"strings"
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
)

func goReachabilityClaim() sdkcollector.Claim {
	return testClaim(IDGoReachability, goReachabilityScope, "gen-go-1")
}

func validDerivedConfig() map[string]any {
	return goReachabilityConfig("https://github.com/o/r", strings.Repeat("a", 40), goReachabilityTokenStanza())
}

// TestGoReachabilityDerivedTargetDefectsAreTerminal is the host_derived_target
// contract: identity and commit come from that key alone, and any missing or
// malformed form fails the claim with no facts before git runs.
func TestGoReachabilityDerivedTargetDefectsAreTerminal(t *testing.T) {
	t.Parallel()

	field := func(name string, value any) func(map[string]any) {
		return func(config map[string]any) {
			config["host_derived_target"].(map[string]any)[name] = value
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing":            func(config map[string]any) { delete(config, "host_derived_target") },
		"not an object":      func(config map[string]any) { config["host_derived_target"] = "go-reachability://repository:r_1a2b3c4d" },
		"null":               func(config map[string]any) { config["host_derived_target"] = nil },
		"blank scope":        field("scope_id", ""),
		"scope not a string": field("scope_id", 7),
		"other scope":        field("scope_id", "go-reachability://repository:r_ffffffff"),
		"another repositorys whole target": func(config map[string]any) {
			field("scope_id", "go-reachability://repository:r_ffffffff")(config)
			field("repository_id", "repository:r_ffffffff")(config)
		},
		"blank repository":  field("repository_id", ""),
		"other repository":  field("repository_id", "repository:r_ffffffff"),
		"blank commit":      field("source_commit_sha", ""),
		"short commit":      field("source_commit_sha", "abc123"),
		"branch as commit":  field("source_commit_sha", "main"),
		"commit not string": field("source_commit_sha", true),
		"blank clone url":   field("clone_url", ""),
		"file clone url":    field("clone_url", "file:///srv/x"),
		"credentialed url":  field("clone_url", "https://user:pw@github.com/o/r"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			config := validDerivedConfig()
			mutate(config)
			page := runTerminal(t, IDGoReachability, testRequest(t, goReachabilityClaim(), config), "component_bad_config")
			if len(page.Facts) != 0 {
				t.Fatalf("facts = %d, want none", len(page.Facts))
			}
		})
	}
}

// TestGoReachabilityRefusesStaticTargetMaterial proves static activation config
// cannot stand in for the host's target, so it cannot forge a commit or a remote.
func TestGoReachabilityRefusesStaticTargetMaterial(t *testing.T) {
	t.Parallel()

	for key, value := range map[string]any{
		"targets":            []any{map[string]any{"scope_id": goReachabilityScope}},
		"acceptance_unit_id": goReachabilityScope,
		"surprise":           true,
		"page_bound_bytes":   int64(-1),
	} {
		config := validDerivedConfig()
		config[key] = value
		runTerminal(t, IDGoReachability, testRequest(t, goReachabilityClaim(), config), "component_bad_config")
	}
}

// TestGoReachabilityToleratesFutureTargetFields follows the core planner: the
// host may add target fields without breaking a deployed component.
func TestGoReachabilityToleratesFutureTargetFields(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n\nrequire m.test/b v1.0.0\n"))
	config := goReachabilityConfig(cloneURL, sha, goReachabilityTokenStanza())
	config["host_derived_target"].(map[string]any)["target_kind"] = "repository"
	page, _ := runGoReachability(t, config, nil)
	if page.State != sdkcollector.ResultPartial {
		t.Fatalf("state = %q", page.State)
	}
}

// TestGoReachabilityAcceptsTheCoreActivationShape feeds the exact config block
// the core planner documents: no targets, a derive section, and the two host
// keys.
func TestGoReachabilityAcceptsTheCoreActivationShape(t *testing.T) {
	t.Parallel()

	cloneURL, sha := goReachabilityRepo(t, goModFile("module m.test/a\n\nrequire m.test/b v1.0.0\n"))
	page, _ := runGoReachability(t, map[string]any{
		"derive_from_go_modules": map[string]any{"enabled": true, "scan_interval": "6h"},
		"host_derived_target": map[string]any{
			"scope_id": goReachabilityScope, "repository_id": goReachabilityRepository,
			"source_commit_sha": sha, "clone_url": cloneURL,
		},
		"host_github_app_token": goReachabilityTokenStanza(),
	}, nil)
	if page.State != sdkcollector.ResultPartial || len(page.Facts) != 1 {
		t.Fatalf("state = %q facts = %d", page.State, len(page.Facts))
	}
	if got := page.Facts[0].Payload["source_commit_sha"]; got != sha {
		t.Fatalf("source_commit_sha = %v, want the host's commit", got)
	}
}

// TestOtherComponentsRefuseEveryHostKey keeps each key private to
// go_reachability.
func TestOtherComponentsRefuseEveryHostKey(t *testing.T) {
	t.Parallel()

	for key, value := range map[string]any{
		"host_github_app_token":  goReachabilityTokenStanza(),
		"host_derived_target":    map[string]any{"scope_id": testImageScopeID},
		"derive_from_go_modules": map[string]any{"enabled": true},
	} {
		claim := testClaim(IDOSRuntime, testImageScopeID, "scanner-worker:generation-test")
		config := osruntimeConfig(parityRootFS(t, 2), 0)
		config[key] = value
		runTerminal(t, IDOSRuntime, testRequest(t, claim, config), "component_bad_config")
	}
}

// TestDefaultFrameKeepsTheSnapshotResult pins the shape the three ported
// components still emit: a nil Completion is a complete snapshot with no
// attestation and no extra log figures.
func TestDefaultFrameKeepsTheSnapshotResult(t *testing.T) {
	t.Parallel()

	frame := frameFor(nil, 0, 3, 7)
	if frame.state != sdkcollector.ResultComplete || frame.freshnessHint != "snapshot" || frame.trustedDeletion || frame.figures != nil {
		t.Fatalf("frame = %+v", frame)
	}
	if status := frame.status; status.Class != sdkcollector.StatusComplete || status.FactCount != 3 || status.SourceLatencyMS != 7 {
		t.Fatalf("status = %+v", status)
	}
}
