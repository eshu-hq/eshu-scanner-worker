// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// scopePrefix is the derived-scope prefix the coordinator plans. The rest of
// the scope is the canonical repository id, so no URL enters the scope.
const scopePrefix = "go-reachability://"

var (
	scopePattern = regexp.MustCompile(`^go-reachability://(repository:r_[0-9a-f]{8})$`)
	// A full object name: SHA-1 or SHA-256. This matches core's planner.
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)

// TargetConfig is the target the host derived for one claim, delivered under the
// host_derived_target request key. It holds identity and location only, and it
// is the only source of the repository id and commit: nothing is read from the
// checkout. The clone URL must be free of userinfo; the token arrives separately
// as HostToken.
type TargetConfig struct {
	// ScopeID is the derived claim scope this target serves.
	ScopeID string
	// RepositoryID is the canonical repository id. It must match ScopeID.
	RepositoryID string
	// CloneURL is the credential-free remote to fetch from.
	CloneURL string
	// SourceCommitSHA is the full commit id Eshu observed for this scope.
	SourceCommitSHA string

	// origin is scheme://host of CloneURL, set by validate. The credential header
	// is scoped to it.
	origin string
}

// ParseDerivedTarget reads the raw host_derived_target config value. A missing or
// malformed value is an error: retrying cannot repair it, so the caller fails the
// claim terminal with no facts. The host may add fields, so unknown keys are
// ignored. An error names the key, never the value.
func ParseDerivedTarget(raw any) (TargetConfig, error) {
	stanza, ok := raw.(map[string]any)
	if !ok {
		return TargetConfig{}, errors.New("host_derived_target is not an object")
	}
	var target TargetConfig
	for key, field := range map[string]*string{
		"scope_id":          &target.ScopeID,
		"repository_id":     &target.RepositoryID,
		"source_commit_sha": &target.SourceCommitSHA,
		"clone_url":         &target.CloneURL,
	} {
		value, ok := stanza[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return TargetConfig{}, fmt.Errorf("host_derived_target.%s is required", key)
		}
		*field = value
	}
	return target, nil
}

// RepositoryIDFromScope returns the canonical repository id a derived claim
// scope names. Any other scope fails, and the error never echoes the scope.
func RepositoryIDFromScope(scopeID string) (string, error) {
	match := scopePattern.FindStringSubmatch(scopeID)
	if match == nil {
		return "", fmt.Errorf("claim scope is not %srepository:r_<8 hex>", scopePrefix)
	}
	return match[1], nil
}

// validate checks one target against the allowed transports and clone hosts and
// returns it with its origin set. Errors name the defect, never the value: a
// rejected URL may hold a credential.
func (t TargetConfig) validate(schemes, hosts []string) (TargetConfig, error) {
	repositoryID, err := RepositoryIDFromScope(t.ScopeID)
	if err != nil {
		return TargetConfig{}, err
	}
	if t.RepositoryID != repositoryID {
		return TargetConfig{}, errors.New("repository_id does not match the target scope")
	}
	if !commitPattern.MatchString(t.SourceCommitSHA) {
		return TargetConfig{}, errors.New("source_commit_sha is not a full lowercase object name")
	}
	origin, err := cloneURLOrigin(t.CloneURL, schemes, hosts)
	if err != nil {
		return TargetConfig{}, err
	}
	t.origin = origin
	return t, nil
}
