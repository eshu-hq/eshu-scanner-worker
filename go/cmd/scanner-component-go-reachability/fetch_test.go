// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fixtureGit runs git in dir, isolated from the machine's configuration.
func fixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=f", "GIT_AUTHOR_EMAIL=f@example.invalid", "GIT_COMMITTER_NAME=f", "GIT_COMMITTER_EMAIL=f@example.invalid",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// tlsOrigin serves root over real TLS through git http-backend, refusing any request
// without the credential, and counts what it saw.
func tlsOrigin(t *testing.T, root string) (*httptest.Server, *atomic.Int32) {
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
			"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "HOME=" + root,
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		},
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+smokeToken))
	var authorized atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		authorized.Add(1)
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &authorized
}

// connectProxy tunnels every CONNECT to target, so a clone of the allowlisted name
// reaches the loopback origin over real TLS without leaving the machine.
func connectProxy(t *testing.T, target string) string {
	t.Helper()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || !strings.HasPrefix(r.Host, smokeHost) {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = client.Close() }()
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
		<-done
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

// TestBinaryFetchesOverHTTPSWithoutLeakingTheToken is the sentinel proof on the
// production path: the real binary, the https transport, the guard, an allowlisted
// host, and every git tracing variable set on the parent. Facts arrive, the origin
// saw the credential, and neither output stream nor the temp volume holds the token.
func TestBinaryFetchesOverHTTPSWithoutLeakingTheToken(t *testing.T) {
	bin := buildBinary(t)
	projects := t.TempDir()
	repo := filepath.Join(projects, "org", "repo")
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fixtureGit(t, repo, "init", "--quiet", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module m.test/a\n\ngo 1.24\n\nrequire m.test/b v1.0.0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fixtureGit(t, repo, "add", "--all")
	fixtureGit(t, repo, "commit", "--quiet", "--message", "fixture")
	sha := fixtureGit(t, repo, "rev-parse", "HEAD")

	origin, authorized := tlsOrigin(t, projects)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	temp := t.TempDir()
	page, stdout, stderr := serve(t, bin, smokeCall{
		token: smokeTokenStanza(), cloneURL: "https://" + smokeHost + "/org/repo", sha: sha, hosts: []string{smokeHost},
		env: []string{
			"HTTPS_PROXY=" + connectProxy(t, origin.Listener.Addr().String()), "GIT_SSL_CAINFO=" + caFile, "TMPDIR=" + temp,
			"GIT_TRACE=1", "GIT_TRACE_CURL=1", "GIT_CURL_VERBOSE=1", "GIT_TRACE_PACKET=1",
		},
	})
	if page["state"] != "partial" {
		t.Fatalf("state = %v, stderr = %q", page["state"], stderr)
	}
	factsJSON, err := json.Marshal(page["facts"])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(factsJSON), "m.test/b") {
		t.Fatalf("facts = %s", factsJSON)
	}
	if authorized.Load() == 0 {
		t.Fatal("the origin saw no authorized request; the check proved nothing")
	}
	header := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + smokeToken))
	for name, text := range map[string]string{"stdout": stdout, "stderr": stderr} {
		for _, form := range []string{smokeToken, header} {
			if strings.Contains(text, form) {
				t.Fatalf("%s leaks %q", name, form)
			}
		}
	}
	claims, err := filepath.Glob(filepath.Join(temp, "eshu-go-reachability", "claim-*"))
	if err != nil || len(claims) != 0 {
		t.Fatalf("left %v, error = %v", claims, err)
	}
}
