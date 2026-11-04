// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"fmt"
	"testing"
)

// formatVerbs is every fmt verb with a meaning for some kind, plus nonsense ones,
// each with the flags that change how a value prints.
func formatVerbs() []string {
	var formats []string
	for _, verb := range "vTtbcdoOqxXUeEfFgGspw" {
		if verb == 'T' {
			continue
		}
		for _, flag := range []string{"", "+", "#", " ", "0", "-", "10"} {
			formats = append(formats, "%"+flag+string(verb))
		}
	}
	return formats
}

// TestHostTokenRedactsEveryVerb is the F5 regression: %d printed the token as
// {%!d(string=ghs_...)}, and %v of a struct holding it unexported printed it raw.
// assertNoToken checks the raw and encoded forms, so it catches hex through %x
// only by the forms below.
func TestHostTokenRedactsEveryVerb(t *testing.T) {
	t.Parallel()

	token := ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID})
	if !token.usableFor(testScopeID) {
		t.Fatal("the fixture token is not usable; the check would prove nothing")
	}
	type holder struct {
		token  HostToken
		Public HostToken
	}
	values := map[string]any{
		"value":       token,
		"pointer":     &token,
		"unexported":  holder{token: token, Public: token},
		"pointer to":  &holder{token: token, Public: token},
		"slice":       []HostToken{token},
		"map":         map[string]HostToken{"k": token},
		"config":      Config{Token: token},
		"analyzer":    Analyzer{token: token},
		"pointer an":  &Analyzer{token: token},
		"nested":      struct{ inner holder }{inner: holder{token: token}},
		"interface":   struct{ any any }{any: token},
		"interface2":  struct{ any any }{any: holder{token: token}},
		"pointer ptr": struct{ p *HostToken }{p: &token},
	}
	forms := append(tokenForms(),
		fmt.Sprintf("%x", testToken), fmt.Sprintf("%X", testToken), fmt.Sprintf("% x", testToken), fmt.Sprintf("%q", testToken),
		testScopeID,
	)
	for name, value := range values {
		for _, format := range formatVerbs() {
			text := fmt.Sprintf(format, value)
			for _, form := range forms {
				if containsFold(text, form) {
					t.Errorf("%s with %s leaks %q: %s", name, format, form, text)
				}
			}
		}
	}
}

// containsFold reports a case-insensitive substring match, because %X uppercases.
func containsFold(text, form string) bool {
	lowerText, lowerForm := []byte(text), []byte(form)
	for i := range lowerText {
		if c := lowerText[i]; c >= 'A' && c <= 'Z' {
			lowerText[i] = c + 'a' - 'A'
		}
	}
	for i := range lowerForm {
		if c := lowerForm[i]; c >= 'A' && c <= 'Z' {
			lowerForm[i] = c + 'a' - 'A'
		}
	}
	return len(lowerForm) > 0 && indexOf(lowerText, lowerForm) >= 0
}

func indexOf(text, form []byte) int {
	for i := 0; i+len(form) <= len(text); i++ {
		if string(text[i:i+len(form)]) == string(form) {
			return i
		}
	}
	return -1
}
