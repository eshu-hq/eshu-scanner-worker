// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"strings"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

func validTarget() TargetConfig {
	return TargetConfig{ScopeID: testScopeID, RepositoryID: testRepositoryID, CloneURL: "https://github.com/org/repo", SourceCommitSHA: strings.Repeat("a", 40)}
}

// TestRepositoryIDFromScopeIsStrict accepts only the canonical derived shape.
func TestRepositoryIDFromScopeIsStrict(t *testing.T) {
	t.Parallel()

	got, err := RepositoryIDFromScope(testScopeID)
	if err != nil || got != testRepositoryID {
		t.Fatalf("RepositoryIDFromScope = %q, %v", got, err)
	}
	for _, scope := range []string{
		"", "repository:r_1a2b3c4d", "go-reachability://", "go-reachability://repository:r_1a2b3c4",
		"go-reachability://repository:r_1a2b3c4dd", "go-reachability://repository:r_1A2B3C4D",
		"go-reachability://repository:r_1a2b3c4d/extra", "scanner-worker://repository/x",
		" go-reachability://repository:r_1a2b3c4d",
	} {
		if _, err := RepositoryIDFromScope(scope); err == nil {
			t.Errorf("RepositoryIDFromScope(%q) error = nil, want rejection", scope)
		}
	}
}

// TestNewAnalyzerRejectsUnsafeTargets is the production transport policy: only
// credential-free https URLs and full lowercase commit ids pass. Errors never
// echo the rejected value.
func TestNewAnalyzerRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()

	token := ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID})
	build := func(target TargetConfig) error {
		_, err := NewAnalyzer(Config{CollectorInstanceID: "i", Target: target, Token: token})
		return err
	}
	if err := build(validTarget()); err != nil {
		t.Fatalf("valid target: %v", err)
	}
	for _, url := range []string{
		"", "http://github.com/o/r", "file:///etc", "ssh://git@github.com/o/r", "git@github.com:o/r",
		"ext::sh -c id", "https://user:SENTINEL@github.com/o/r", "https://github.com/o/r?x=SENTINEL",
		"https://github.com/o/r#SENTINEL", "https://github.com/o/r?", "https:///o/r", "--upload-pack=SENTINEL",
		"https://github.com/o/r\nSENTINEL", "https://github.com/o/ r", "%zz://github.com/o/r",
	} {
		target := validTarget()
		target.CloneURL = url
		err := build(target)
		if err == nil {
			t.Errorf("clone url %q: error = nil, want rejection", url)
		} else if strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("clone url %q: error echoes the value: %v", url, err)
		}
	}
	for _, sha := range []string{"", "abc", strings.Repeat("A", 40), strings.Repeat("g", 40), strings.Repeat("a", 41), strings.Repeat("a", 63), strings.Repeat("a", 65), "--upload-pack=x", "HEAD", "main"} {
		target := validTarget()
		target.SourceCommitSHA = sha
		if err := build(target); err == nil {
			t.Errorf("sha %q: error = nil, want rejection", sha)
		}
	}
	for _, scope := range []string{"", "repository:r_1a2b3c4d"} {
		target := validTarget()
		target.ScopeID = scope
		if err := build(target); err == nil {
			t.Errorf("scope %q: error = nil, want rejection", scope)
		}
	}
	for _, repository := range []string{"", "repository:r_ffffffff", testScopeID} {
		target := validTarget()
		target.RepositoryID = repository
		if err := build(target); err == nil {
			t.Errorf("repository %q: error = nil, want rejection", repository)
		}
	}
	if err := build(TargetConfig{}); err == nil {
		t.Error("empty target: error = nil, want rejection")
	}
	if _, err := NewAnalyzer(Config{Target: validTarget(), Token: token}); err == nil {
		t.Error("blank instance: error = nil, want rejection")
	}
}

// TestAnalyzeRefusesAClaimOutsideItsTarget proves a claim for another repository
// is never served.
func TestAnalyzeRefusesAClaimOutsideItsTarget(t *testing.T) {
	t.Parallel()

	other := validTarget()
	other.ScopeID = "go-reachability://repository:r_ffffffff"
	other.RepositoryID = "repository:r_ffffffff"
	analyzer := fixtureAnalyzer(t, "https://github.com/o/r", strings.Repeat("a", 40), func(c *Config) {
		c.Target = other
		c.Options.AllowedSchemes = nil
	})
	_, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassUnsupportedTarget, false)
}

// TestBudgetsFailClosed covers the file, input, and fact budgets over a real
// checkout, each terminal with its own class.
func TestBudgetsFailClosed(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1, "a.txt": strings.Repeat("x", 512), "b.txt": "y"})
	for name, tc := range map[string]struct {
		limit func(*scannerworker.ResourceLimits)
		class scannerworker.FailureClass
	}{
		"files": {func(l *scannerworker.ResourceLimits) { l.MaxFiles = 2 }, scannerworker.FailureClassFileLimitExceeded},
		"input": {func(l *scannerworker.ResourceLimits) { l.MaxInputBytes = 256 }, scannerworker.FailureClassInputLimitExceeded},
		"facts": {func(l *scannerworker.ResourceLimits) { l.MaxFacts = 0 }, scannerworker.FailureClassFactLimitExceeded},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			input := testInput(t)
			tc.limit(&input.Limits)
			_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(context.Background(), input)
			wantFailure(t, err, tc.class, false)
		})
	}
}

// TestOversizedGoModWarnsInsteadOfBeingRead keeps the other modules and names
// the oversized file.
func TestOversizedGoModWarnsInsteadOfBeingRead(t *testing.T) {
	t.Parallel()

	big := "module m.test/big\n\n// " + strings.Repeat("x", maxGoModBytes) + "\n"
	url, shas := fixtureRepo(t, map[string]string{"go.mod": "module m.test/ok\n\nrequire m.test/a v1.0.0\n", "big/go.mod": big})
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], nil))
	if got := warningsOf(result.Output); len(got) != 1 || got[0] != "go_mod_too_large big/go.mod" {
		t.Fatalf("warnings = %v", got)
	}
	if c := result.Completion; !c.Partial || c.TrustedDeletion || c.FailureClass != scannerworker.FailureClassAnalysisFailed {
		t.Fatalf("completion = %+v", c)
	}
}

// TestSymlinkedGoModIsNotFollowed proves a link cannot read a file outside the
// repository, and that the regular module beside it keeps its evidence.
func TestSymlinkedGoModIsNotFollowed(t *testing.T) {
	t.Parallel()

	url, shas := symlinkRepo(t)
	result := analyze(t, fixtureAnalyzer(t, url, shas, nil))
	if got := evidenceOf(result.Output); len(got) != 1 || got[0] != "go.mod m.test/a v1.0.0" {
		t.Fatalf("evidence = %v, want only the regular go.mod", got)
	}
	if got := warningsOf(result.Output); len(got) != 1 || got[0] != "go_mod_not_regular sub/go.mod" {
		t.Fatalf("warnings = %v", got)
	}
}
