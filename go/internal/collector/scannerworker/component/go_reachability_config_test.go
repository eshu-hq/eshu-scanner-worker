// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package component

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker/goreachability"
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

// TestAllowedCloneHostsIsTheOperatorsSetting proves the activation key reaches the
// policy, replaces the default, and fails closed when unusable. No defect echoes a
// value. The target cannot supply it: an unknown target field is ignored.
func TestAllowedCloneHostsIsTheOperatorsSetting(t *testing.T) {
	t.Parallel()

	base := func() map[string]any {
		return goReachabilityConfig("https://git.corp.example/o/r", strings.Repeat("a", 40), goReachabilityTokenStanza())
	}
	build := func(raw map[string]any) error {
		config, err := parseConfigFor(scannerworker.AnalyzerGoReachability, raw)
		if err != nil {
			return err
		}
		_, err = buildGoReachability(goReachabilityClaim(), config, goreachability.Options{})
		return err
	}
	if err := build(base()); err == nil {
		t.Fatal("a host outside the default allowlist passed")
	}
	inTarget := base()
	inTarget["host_derived_target"].(map[string]any)["allowed_clone_hosts"] = []any{"git.corp.example"}
	if err := build(inTarget); err == nil {
		t.Fatal("the target widened the allowlist")
	}
	listed := base()
	listed["allowed_clone_hosts"] = []any{"git.corp.example"}
	if err := build(listed); err != nil {
		t.Fatalf("listed host: %v", err)
	}
	for name, value := range map[string]any{
		"empty":      []any{},
		"not a list": "git.corp.example",
		"not text":   []any{7},
		"ip":         []any{"169.254.169.254"},
		"port":       []any{"SENTINEL.example:8443"},
		"null":       nil,
	} {
		raw := base()
		raw["allowed_clone_hosts"] = value
		err := build(raw)
		if err == nil {
			t.Errorf("%s: error = nil", name)
		} else if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
	}
}

// TestEmptyAllowlistFailsClosedOnTheDefaultTarget proves a present but empty
// allowed_clone_hosts is an error rather than the default: without the
// component-level validation the empty list would silently keep github.com.
func TestEmptyAllowlistFailsClosedOnTheDefaultTarget(t *testing.T) {
	t.Parallel()

	raw := validDerivedConfig()
	raw["allowed_clone_hosts"] = []any{}
	if _, err := parseConfigFor(scannerworker.AnalyzerGoReachability, raw); err == nil {
		t.Fatal("an empty allowed_clone_hosts passed")
	}
	if _, err := parseConfigFor(scannerworker.AnalyzerGoReachability, validDerivedConfig()); err != nil {
		t.Fatalf("no allowlist: %v", err)
	}
}

// TestOtherComponentsRefuseAllowedCloneHosts keeps the key go_reachability's alone.
func TestOtherComponentsRefuseAllowedCloneHosts(t *testing.T) {
	t.Parallel()

	raw := map[string]any{"targets": []any{map[string]any{"x": 1}}, "acceptance_unit_id": "u", "allowed_clone_hosts": []any{"a.example"}}
	if _, err := parseConfigFor(scannerworker.AnalyzerImageUnpacking, raw); err == nil {
		t.Fatal("another component accepted allowed_clone_hosts")
	}
}

// TestComponentConfigNeverPrintsTheToken covers component.Config.hostToken, the
// unexported field fmt cannot call Format on. Every verb, including the bad-verb
// path that prints a pointer's target.
func TestComponentConfigNeverPrintsTheToken(t *testing.T) {
	t.Parallel()

	config, err := parseConfigFor(scannerworker.AnalyzerGoReachability, goReachabilityConfig("https://github.com/o/r", strings.Repeat("a", 40), goReachabilityTokenStanza()))
	if err != nil {
		t.Fatalf("parseConfigFor: %v", err)
	}
	for _, verb := range "vbcdoOqxXUeEfFgGstp" {
		for _, format := range []string{"%" + string(verb), "%+" + string(verb), "%#" + string(verb)} {
			for _, value := range []any{config, &config} {
				text := fmt.Sprintf(format, value)
				if strings.Contains(strings.ToLower(text), strings.ToLower(goReachabilityToken)) {
					t.Fatalf("%s leaks the token: %s", format, text)
				}
				if strings.Contains(strings.ToLower(text), hex.EncodeToString([]byte(goReachabilityToken))) {
					t.Fatalf("%s leaks the token as hex: %s", format, text)
				}
			}
		}
	}
}

// TestAnalyzeContextStopsBeforeTheClaimDeadline proves an analysis stops before the
// host's own kill: the earlier of the budget and the deadline, less the margin.
func TestAnalyzeContextStopsBeforeTheClaimDeadline(t *testing.T) {
	t.Parallel()

	now := testClock()
	runner := Runner{Clock: func() time.Time { return now }}
	for name, tc := range map[string]struct {
		lease   time.Time
		timeout time.Duration
		want    time.Duration
	}{
		"lease first":   {now.Add(time.Minute), 10 * time.Minute, time.Minute - leaseStopMargin},
		"budget first":  {now.Add(time.Hour), 10 * time.Minute, 10 * time.Minute},
		"no budget":     {now.Add(time.Minute), 0, time.Minute - leaseStopMargin},
		"no lease":      {time.Time{}, 10 * time.Minute, 10 * time.Minute},
		"inside margin": {now.Add(leaseStopMargin - time.Second), 10 * time.Minute, 10 * time.Minute},
	} {
		input := scannerworker.ClaimInput{LeaseExpiresAt: tc.lease, Limits: scannerworker.ResourceLimits{Timeout: tc.timeout}}
		ctx, cancel := runner.analyzeContext(context.Background(), input)
		deadline, ok := ctx.Deadline()
		cancel()
		if !ok {
			t.Errorf("%s: no deadline", name)
			continue
		}
		if got := time.Until(deadline); got > tc.want || got < tc.want-30*time.Second {
			t.Errorf("%s: deadline in %s, want about %s", name, got, tc.want)
		}
	}
}

// TestGoReachabilityArmsTheGuard proves production wires the guard, that a binary
// that cannot locate itself fails rather than run unguarded, and that no other
// component gets it or answers to it.
func TestGoReachabilityArmsTheGuard(t *testing.T) {
	t.Parallel()

	options, err := goReachabilityOptions(IDGoReachability, func() (string, error) { return "/bin/component", nil })
	if err != nil || len(options.GitGuard) != 2 || options.GitGuard[0] != "/bin/component" || options.GitGuard[1] != goreachability.GitGuardCommand {
		t.Fatalf("options = %+v, error = %v", options, err)
	}
	if _, err := goReachabilityOptions(IDGoReachability, func() (string, error) { return "", errors.New("SENTINEL") }); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("error = %v, want a bounded refusal", err)
	}
	if options, err := goReachabilityOptions(IDImage, func() (string, error) { return "", errors.New("unused") }); err != nil || options.GitGuard != nil {
		t.Fatalf("another component: options = %+v, error = %v", options, err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main(context.Background(), IDGoReachability, "app", []string{goreachability.GitGuardCommand}, strings.NewReader(""), &stdout, &stderr); code == 0 {
		t.Fatalf("the guard ran with no command: stdout = %q", stdout.String())
	}
	code := Main(context.Background(), IDImage, "app", []string{goreachability.GitGuardCommand, "true"}, strings.NewReader("{"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("another component answered to the guard: code = %d", code)
	}
}
