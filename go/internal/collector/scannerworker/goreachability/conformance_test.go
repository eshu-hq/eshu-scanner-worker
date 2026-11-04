// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package goreachability

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/collector/conformance"
	"github.com/eshu-hq/eshu-sdk/factschema"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"

	"github.com/eshu-hq/eshu-scanner-worker/go/internal/factenvelope"
	"github.com/eshu-hq/eshu-scanner-worker/go/internal/facts/supply/chain"
)

const conformanceGoMod = `module example.test/app

go 1.24

require (
	example.test/plain v1.0.0
	example.test/indirect v1.1.0 // indirect
	example.test/forked v1.2.0
	example.test/local v1.3.0
)

replace example.test/forked => example.test/fork v9.9.9

replace example.test/local => ../local
`

// TestModuleEvidenceConformsToThePublishedSchema pushes real analyzer output
// through the published contract three ways: the JSON Schema shipped in the
// factschema fixture pack, the SDK result validator, and the typed decoder the
// reducer uses. The payload crosses JSON first, as it does on the wire.
func TestModuleEvidenceConformsToThePublishedSchema(t *testing.T) {
	t.Parallel()

	fileURL, shas := fixtureRepo(t, map[string]string{"go.mod": conformanceGoMod})
	url, requests := serveFixture(t, strings.TrimPrefix(fileURL, "file://"))
	output := analyze(t, fixtureAnalyzer(t, url, shas[0], func(c *Config) { c.Options.AllowedSchemes = []string{"http"} })).Output
	if requests.Load() == 0 {
		t.Fatal("the fixture server saw no request; the fact path did not use the credential")
	}

	wire := make([]sdkcollector.Fact, 0, len(output.Facts))
	for _, envelope := range output.Facts {
		fact, err := factenvelope.SDKFactFromInternal(envelope)
		if err != nil {
			t.Fatalf("SDKFactFromInternal: %v", err)
		}
		wire = append(wire, fact)
	}
	result := roundTrip(t, sdkcollector.Result{
		ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
		State:           sdkcollector.ResultComplete,
		Claim: sdkcollector.Claim{
			ComponentID: "eshu.scanner.go-reachability", InstanceID: "instance-1", CollectorKind: "scanner_worker", SourceSystem: "scanner_worker",
			Scope: sdkcollector.Scope{ID: testScopeID, Kind: "repository"}, SourceRunID: "run-1", GenerationID: "gen-1", WorkItemID: "work-1",
			FencingToken: "7", Attempt: 1, Deadline: testInput(t).ObservedAt.Add(time.Minute), ConfigHandle: "cfg",
		},
		Generation: sdkcollector.Generation{ID: "gen-1", ObservedAt: testInput(t).ObservedAt},
		Facts:      wire,
	})

	schemas := fixturepack.Schemas()
	if _, ok := schemas[chain.VulnerabilityGoModuleEvidenceFactKind]; !ok {
		t.Fatalf("fixture pack has no schema for %s", chain.VulnerabilityGoModuleEvidenceFactKind)
	}
	if err := conformance.ValidatePayloadSchemas(schemas, result); err != nil {
		t.Fatalf("ValidatePayloadSchemas() error = %v", err)
	}
	validator := sdkcollector.NewValidator(sdkcollector.Contract{
		ProtocolVersion: sdkcollector.ProtocolVersionV1Alpha3,
		Facts: []sdkcollector.FactDeclaration{{
			Kind: chain.VulnerabilityGoModuleEvidenceFactKind, SchemaVersions: []string{"1.0.0"},
			SourceConfidence: []sdkcollector.SourceConfidence{sdkcollector.SourceConfidenceReported},
		}},
	})
	if _, err := validator.ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}

	var got []string
	for _, fact := range result.Facts {
		typed, err := factschema.DecodeVulnerabilityGoModuleEvidence(factschema.Envelope{
			FactKind: fact.Kind, SchemaVersion: fact.SchemaVersion, Payload: fact.Payload,
		})
		if err != nil {
			t.Fatalf("DecodeVulnerabilityGoModuleEvidence() error = %v", err)
		}
		if typed.RepositoryID != testRepositoryID || typed.RelativePath != "go.mod" {
			t.Fatalf("typed identity = %+v", typed)
		}
		if typed.RequiredVersion == nil || typed.LineNumber == nil || *typed.LineNumber == 0 || typed.Indirect == nil {
			t.Fatalf("typed optional fields absent: %+v", typed)
		}
		switch typed.ModulePath {
		case "example.test/indirect":
			if !*typed.Indirect {
				t.Fatalf("indirect not carried: %+v", typed)
			}
		case "example.test/forked":
			if typed.ReplacementPath == nil || *typed.ReplacementPath != "example.test/fork" || typed.ReplacementVersion == nil || *typed.ReplacementVersion != "v9.9.9" {
				t.Fatalf("replace not carried: %+v", typed)
			}
		case "example.test/local":
			if typed.ReplacementPath == nil || *typed.ReplacementPath != "../local" || typed.ReplacementVersion != nil {
				t.Fatalf("local replace not carried: %+v", typed)
			}
		default:
			if typed.ReplacementPath != nil || typed.ReplacementVersion != nil {
				t.Fatalf("unexpected replace on %+v", typed)
			}
		}
		got = append(got, typed.ModulePath)
	}
	slices.Sort(got)
	want := []string{"example.test/forked", "example.test/indirect", "example.test/local", "example.test/plain"}
	if !slices.Equal(got, want) {
		t.Fatalf("modules = %v, want %v", got, want)
	}
}

// serveFixture serves a fixture over loopback smart HTTP through the real git
// http-backend and refuses any request without the expected credential, so a
// passing fetch proves the header reached the origin. It returns the URL and a
// count of the requests it served. The SDK rejects a file source_ref.uri, so
// the host-accepted path needs a URL like this.
func serveFixture(t *testing.T, root string) (string, *atomic.Int32) {
	t.Helper()

	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	backend := &cgi.Handler{
		Path: filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend"),
		Root: "/",
		Dir:  root,
		Env: []string{
			"GIT_PROJECT_ROOT=" + filepath.Dir(root), "GIT_HTTP_EXPORT_ALL=1", "HOME=" + root,
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		},
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testToken))
	requests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		requests.Add(1)
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL + "/" + filepath.Base(root), requests
}

func roundTrip(t *testing.T, result sdkcollector.Result) sdkcollector.Result {
	t.Helper()

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded sdkcollector.Result
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return decoded
}
