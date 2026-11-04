// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/collector/scannerworker"
)

// tokenForms is every encoding of the token a leak could take.
func tokenForms() []string {
	return []string{
		testToken,
		base64.StdEncoding.EncodeToString([]byte("x-access-token:" + testToken)),
		base64.StdEncoding.EncodeToString([]byte(testToken)),
	}
}

func assertNoToken(t *testing.T, where, text string) {
	t.Helper()

	for _, form := range tokenForms() {
		if strings.Contains(text, form) {
			t.Fatalf("%s carries the token (form %q):\n%s", where, form, text)
		}
	}
}

// TestTokenStaysOffTheCommandLine records every git call: no argument carries
// the token, only the fetch's environment does, and the other calls never see
// it.
func TestTokenStaysOffTheCommandLine(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, log := gitShim(t, "")
	result := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }))
	text := readLog(t, log)
	sawHeader, calls := 0, 0
	for _, call := range strings.Split(text, "ARGV ")[1:] {
		calls++
		argv, env, _ := strings.Cut(call, "\n")
		assertNoToken(t, "argv", argv)
		carriesToken := strings.Contains(env, base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken)))
		if carriesToken {
			sawHeader++
			if !strings.Contains(argv, "fetch") {
				t.Fatalf("token reached a non-fetch call: %s", argv)
			}
		}
	}
	if calls < 4 || sawHeader != 1 {
		t.Fatalf("calls = %d, token-bearing calls = %d, want the fetch alone to carry it\n%s", calls, sawHeader, text)
	}
	raw, err := json.Marshal(result.Output.Facts)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	assertNoToken(t, "facts", string(raw))
}

// TestGitEnvironmentIgnoresInheritedGitSettings is not parallel: it sets a
// process environment that a leaky child environment would pass to git. The
// trace would write the Authorization header to stderr.
func TestGitEnvironmentIgnoresInheritedGitSettings(t *testing.T) {
	t.Setenv("GIT_TRACE", "1")
	t.Setenv("GIT_TRACE_CURL", "1")
	t.Setenv("GIT_CURL_VERBOSE", "1")
	t.Setenv("GIT_SSH_COMMAND", "/bin/false")

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	shim, log := gitShim(t, "")
	analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.GitPath = shim }))
	text := readLog(t, log)
	for _, name := range []string{"ENV GIT_TRACE", "ENV GIT_CURL_VERBOSE", "ENV GIT_SSH_COMMAND"} {
		if strings.Contains(text, name) {
			t.Fatalf("git child inherited %s", name)
		}
	}
	for _, name := range []string{"ENV GIT_TERMINAL_PROMPT=0", "ENV GIT_CONFIG_NOSYSTEM=1", "ENV GIT_CONFIG_GLOBAL=/dev/null", "ENV LC_ALL=C", "ENV GIT_ALLOW_PROTOCOL=file"} {
		if !strings.Contains(text, name) {
			t.Fatalf("git child lacks %s", name)
		}
	}
}

// recordingStage is a stage B stand-in that inspects the finished checkout.
type recordingStage struct {
	t       *testing.T
	input   StageInput
	outcome StageOutcome
	err     error
	inspect func(StageInput)
}

func (s *recordingStage) Run(_ context.Context, input StageInput) (StageOutcome, error) {
	s.input = input
	if s.inspect != nil {
		s.inspect(input)
	}
	return s.outcome, s.err
}

// TestTokenIsNotPersistedInTheCheckout scans every file git wrote, .git
// included, for the token, from inside the seam stage B will use.
func TestTokenIsNotPersistedInTheCheckout(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	scanned := 0
	stage := &recordingStage{t: t, inspect: func(input StageInput) {
		err := filepath.WalkDir(input.CheckoutDir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return walkErr
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			assertNoToken(t, path, string(raw))
			return nil
		})
		if err != nil {
			t.Errorf("WalkDir: %v", err)
		}
	}}
	analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.Stage = stage }))
	if scanned == 0 {
		t.Fatal("scanned no files; the check proved nothing")
	}
}

// TestCheckoutDirectoryIsRemovedAfterAnalysis proves nothing stays on disk
// after success or failure.
func TestCheckoutDirectoryIsRemovedAfterAnalysis(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	for name, sha := range map[string]string{"success": shas[0], "failure": strings.Repeat("a", 40)} {
		root := t.TempDir()
		analyzer := fixtureAnalyzer(t, url, sha, func(c *Config) { c.Options.TempRoot = root })
		_, _ = analyzer.Analyze(context.Background(), testInput(t))
		claims, err := filepath.Glob(filepath.Join(root, workspaceRootName, claimDirPrefix+"*"))
		if err != nil {
			t.Fatalf("%s: Glob: %v", name, err)
		}
		if len(claims) != 0 {
			t.Fatalf("%s: left %v in the workspace root", name, claims)
		}
	}
}

// TestHostTokenDefectsAreTerminalBeforeGitRuns covers the #9182 satellite
// contract: missing key, empty token, malformed stanza, and scope mismatch.
func TestHostTokenDefectsAreTerminalBeforeGitRuns(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]any{
		"missing":   nil,
		"not map":   "ghs_bare",
		"empty":     map[string]any{"token": "  ", "scope_id": testScopeID},
		"no scope":  map[string]any{"token": testToken},
		"mismatch":  map[string]any{"token": testToken, "scope_id": "go-reachability://repository:r_ffffffff"},
		"non-token": map[string]any{"token": 7, "scope_id": testScopeID},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			shim, log := gitShim(t, "")
			analyzer := fixtureAnalyzer(t, "file:///unused", strings.Repeat("a", 40), func(c *Config) {
				c.Token = ParseHostToken(raw)
				c.Options.GitPath = shim
			})
			_, err := analyzer.Analyze(context.Background(), testInput(t))
			wantFailure(t, err, scannerworker.FailureClassAuthDenied, false)
			if _, statErr := os.Stat(log); statErr == nil {
				t.Fatalf("git ran despite the token defect: %s", readLog(t, log))
			}
		})
	}
}

// TestHostTokenNeverEncodes proves the direct conversions and the JSON encoder
// redact. TestHostTokenRedactsEveryVerb covers fmt.
func TestHostTokenNeverEncodes(t *testing.T) {
	t.Parallel()

	token := ParseHostToken(map[string]any{"token": testToken, "scope_id": testScopeID})
	raw, err := json.Marshal(struct {
		Token HostToken
	}{token})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	assertNoToken(t, "encoded", string(raw)+token.String()+token.GoString())
	if !strings.Contains(string(raw), redactedToken) || token.String() != redactedToken || token.GoString() != redactedToken {
		t.Fatalf("raw = %s, String = %s, GoString = %s, want the redaction", raw, token, token.GoString())
	}
}

// TestSourceRefusalIsAuthDenied drives real git against loopback servers: the
// header reaches the origin, and a refusal maps to terminal auth_denied.
func TestSourceRefusalIsAuthDenied(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			var header atomic.Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header.Store(r.Header.Get("Authorization"))
				if status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			analyzer := fixtureAnalyzer(t, server.URL+"/org/repo.git", strings.Repeat("a", 40), func(c *Config) { c.Options.AllowedSchemes = []string{"http"} })
			_, err := analyzer.Analyze(context.Background(), testInput(t))
			wantFailure(t, err, scannerworker.FailureClassAuthDenied, false)
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken))
			if got, _ := header.Load().(string); got != want {
				t.Fatalf("Authorization = %q, want the token as a basic credential", got)
			}
		})
	}
}

// TestRedirectDoesNotCarryTheTokenToAnotherHost proves redirects stop at the
// origin: the other host never receives a request, let alone the header.
func TestRedirectDoesNotCarryTheTokenToAnotherHost(t *testing.T) {
	t.Parallel()

	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path+"?"+r.URL.RawQuery, http.StatusFound)
	}))
	defer origin.Close()
	analyzer := fixtureAnalyzer(t, origin.URL+"/org/repo.git", strings.Repeat("a", 40), func(c *Config) { c.Options.AllowedSchemes = []string{"http"} })
	_, err := analyzer.Analyze(context.Background(), testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
	if reached.Load() != 0 {
		t.Fatalf("the redirect target received %d requests", reached.Load())
	}
}

// TestCheckoutFailuresAreRetryable covers an unreachable source, a commit the
// source does not have, and a missing git binary, with bounded reasons.
func TestCheckoutFailuresAreRetryable(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL + "/org/repo.git"
	closed.Close()
	for name, tc := range map[string]struct {
		url, sha, git, reason string
		schemes               []string
	}{
		"unknown commit": {url: url, sha: strings.Repeat("a", 40), reason: reasonFetchFailed, schemes: []string{"file"}},
		"unreachable":    {url: closedURL, sha: shas[0], reason: reasonFetchFailed, schemes: []string{"http"}},
		"git missing":    {url: url, sha: shas[0], git: filepath.Join(t.TempDir(), "no-such-git"), reason: reasonGitUnavailable, schemes: []string{"file"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			analyzer := fixtureAnalyzer(t, tc.url, tc.sha, func(c *Config) {
				c.Options.AllowedSchemes = tc.schemes
				c.Options.GitPath = tc.git
			})
			_, err := analyzer.Analyze(context.Background(), testInput(t))
			wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
			wantReason(t, err, tc.reason)
			assertNoToken(t, "error", err.Error())
			if strings.Contains(err.Error(), tc.url) {
				t.Fatalf("error names the URL: %v", err)
			}
		})
	}
}

// TestCancelledContextStopsTheCheckout proves a spent claim deadline stops git
// and reports a retryable failure.
func TestCancelledContextStopsTheCheckout(t *testing.T) {
	t.Parallel()

	url, shas := fixtureRepo(t, map[string]string{"go.mod": goModV1})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fixtureAnalyzer(t, url, shas[0], nil).Analyze(ctx, testInput(t))
	wantFailure(t, err, scannerworker.FailureClassCheckoutFailed, true)
}
