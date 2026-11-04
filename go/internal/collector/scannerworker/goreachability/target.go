// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// scopePrefix is the derived-scope prefix the coordinator plans. The rest of
// the scope is the canonical repository id, so no URL enters the scope.
const scopePrefix = "go-reachability://"

var (
	scopePattern  = regexp.MustCompile(`^go-reachability://(repository:r_[0-9a-f]{8})$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// TargetConfig is one host-derived repository target. It holds identity and
// location only. Credentials never appear here: the clone URL must be free of
// userinfo and the token arrives separately as HostToken.
type TargetConfig struct {
	// ScopeID is the derived claim scope this target serves.
	ScopeID string `json:"scope_id"`
	// CloneURL is the credential-free remote to fetch from.
	CloneURL string `json:"clone_url"`
	// SourceCommitSHA is the full commit id Eshu observed for this scope.
	SourceCommitSHA string `json:"source_commit_sha"`

	// origin is scheme://host of CloneURL, set by validate. The credential header
	// is scoped to it.
	origin string
}

// RepositoryIDFromScope returns the canonical repository id a derived claim
// scope names. Any other scope fails, so a claim cannot select identity from
// anywhere else. The error never echoes the scope.
func RepositoryIDFromScope(scopeID string) (string, error) {
	match := scopePattern.FindStringSubmatch(scopeID)
	if match == nil {
		return "", fmt.Errorf("claim scope is not %srepository:r_<8 hex>", scopePrefix)
	}
	return match[1], nil
}

// validate checks one target against the allowed transports and returns it with
// its origin set. Errors name the defect, never the value: a rejected URL may
// hold a credential.
func (t TargetConfig) validate(schemes []string) (TargetConfig, error) {
	if _, err := RepositoryIDFromScope(t.ScopeID); err != nil {
		return TargetConfig{}, err
	}
	if !commitPattern.MatchString(t.SourceCommitSHA) {
		return TargetConfig{}, errors.New("source_commit_sha is not a full lowercase commit id")
	}
	origin, err := cloneURLOrigin(t.CloneURL, schemes)
	if err != nil {
		return TargetConfig{}, err
	}
	t.origin = origin
	return t, nil
}

// cloneURLOrigin allows only a plain URL on an allowed transport and returns its
// scheme://host. Rejecting everything else keeps option-shaped values and git's
// remote helpers (ext::, fd::) away from the git command line.
func cloneURLOrigin(raw string, schemes []string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("clone_url is not a plain URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("clone_url is not a plain URL")
	}
	if !slices.Contains(schemes, parsed.Scheme) {
		return "", errors.New("clone_url uses a transport this component does not allow")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("clone_url must not carry userinfo, a query, or a fragment")
	}
	if parsed.Scheme != "file" && parsed.Host == "" {
		return "", errors.New("clone_url has no host")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// HostToken is the per-claim credential the host mints, delivered under the
// host_github_app_token request key as {token, scope_id}. It never formats or
// encodes its value.
type HostToken struct {
	value   string
	scopeID string
}

// ParseHostToken reads the raw host_github_app_token config value. A missing or
// malformed value yields an empty token, which Analyze refuses as auth_denied.
// The host may add fields later, so unknown keys are ignored.
func ParseHostToken(raw any) HostToken {
	stanza, ok := raw.(map[string]any)
	if !ok {
		return HostToken{}
	}
	value, _ := stanza["token"].(string)
	scopeID, _ := stanza["scope_id"].(string)
	return HostToken{value: strings.TrimSpace(value), scopeID: strings.TrimSpace(scopeID)}
}

// usableFor reports whether the host minted this token for the claim scope.
func (t HostToken) usableFor(scopeID string) bool {
	return t.value != "" && scopeID != "" && t.scopeID == scopeID
}

const redactedToken = "[redacted]"

// String keeps the token out of every fmt verb.
func (HostToken) String() string { return redactedToken }

// GoString keeps the token out of %#v.
func (HostToken) GoString() string { return redactedToken }

// MarshalJSON keeps the token out of any encoded config or log record.
func (HostToken) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedToken + `"`), nil }
