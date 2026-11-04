// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"fmt"
	"io"
	"strings"
)

const redactedToken = "[redacted]"

// HostToken is the per-claim credential the host mints, delivered under the
// host_github_app_token request key as {token, scope_id}. It never formats or
// encodes its value. Format covers every fmt verb. fmt cannot call Format on an
// unexported field, and for a bad verb it prints a pointer's target, so the value
// sits in a closure: at any depth, with any verb, fmt can only print a code address.
type HostToken struct {
	secret func() tokenSecret
}

// tokenSecret holds the values. Nothing outside this file names its fields.
type tokenSecret struct {
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
	secret := tokenSecret{value: strings.TrimSpace(value), scopeID: strings.TrimSpace(scopeID)}
	return HostToken{secret: func() tokenSecret { return secret }}
}

// usableFor reports whether the host minted this token for the claim scope.
func (t HostToken) usableFor(scopeID string) bool {
	return t.reveal() != "" && scopeID != "" && t.secret().scopeID == scopeID
}

// reveal returns the value for the one place that sends it: the fetch environment.
func (t HostToken) reveal() string {
	if t.secret == nil {
		return ""
	}
	return t.secret().value
}

// Format implements fmt.Formatter, so no verb or flag reaches the value.
func (HostToken) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redactedToken) }

// String keeps the token out of a direct conversion.
func (HostToken) String() string { return redactedToken }

// GoString keeps the token out of a direct conversion.
func (HostToken) GoString() string { return redactedToken }

// MarshalJSON keeps the token out of any encoded config or log record.
func (HostToken) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedToken + `"`), nil }
