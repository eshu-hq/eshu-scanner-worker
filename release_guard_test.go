// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package ciworkflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// guardRepo is a scratch origin with a main branch, a side branch, and
// release tags, plus a full clone the guard runs in (the shape
// actions/checkout leaves with fetch-depth: 0).
type guardRepo struct {
	t      *testing.T
	origin string
	work   string
	commit map[string]string
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=guard@example.invalid", "-c", "user.name=guard", "-c", "init.defaultBranch=main", "-c", "tag.gpgSign=false", "-c", "commit.gpgSign=false"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newGuardRepo builds main: m1 -> m2 -> m3 and side: m1 -> s1, then clones.
func newGuardRepo(t *testing.T, tags map[string]string) *guardRepo {
	t.Helper()
	root := t.TempDir()
	r := &guardRepo{t: t, origin: filepath.Join(root, "origin"), work: filepath.Join(root, "work"), commit: map[string]string{}}
	if err := os.MkdirAll(r.origin, 0o755); err != nil {
		t.Fatal(err)
	}
	git(t, r.origin, "init", "-q")
	for _, name := range []string{"m1", "m2", "m3"} {
		git(t, r.origin, "commit", "-q", "--allow-empty", "-m", name)
		r.commit[name] = git(t, r.origin, "rev-parse", "HEAD")
	}
	git(t, r.origin, "checkout", "-q", "-b", "side", r.commit["m1"])
	git(t, r.origin, "commit", "-q", "--allow-empty", "-m", "s1")
	r.commit["s1"] = git(t, r.origin, "rev-parse", "HEAD")
	git(t, r.origin, "checkout", "-q", "main")
	for tag, at := range tags {
		git(t, r.origin, "tag", tag, r.commit[at])
	}
	git(t, root, "clone", "-q", r.origin, r.work)
	return r
}

// guard runs scripts/release-tag-guard.sh for one tag and returns its exit
// status and stderr.
func (r *guardRepo) guard(tagName, at string) (int, string) {
	r.t.Helper()
	script, err := filepath.Abs(filepath.Join("scripts", "release-tag-guard.sh"))
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", script)
	cmd.Dir = r.work
	cmd.Env = append(os.Environ(), "TAG_NAME="+tagName, "TAG_COMMIT="+r.commit[at])
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode(), string(out)
	}
	r.t.Fatalf("run guard: %v", err)
	return -1, ""
}

// TestReleaseTagGuard pins the tag gate: a tag publishes only when its
// commit is on main, its version is strictly newer than every other
// release, and it does not roll back to an ancestor of the latest release.
func TestReleaseTagGuard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing map[string]string
		tag, at  string
		allowed  bool
	}{
		{name: "first tag on main head", tag: "v0.1.0", at: "m3", allowed: true},
		{name: "newer tag on main head", existing: map[string]string{"v0.1.0": "m2"}, tag: "v0.2.0", at: "m3", allowed: true},
		{name: "main moved before the job ran", existing: map[string]string{"v0.1.0": "m1"}, tag: "v0.2.0", at: "m2", allowed: true},
		{name: "same commit re-released under a newer version", existing: map[string]string{"v0.1.0": "m3"}, tag: "v0.1.1", at: "m3", allowed: true},
		{name: "release after its prerelease", existing: map[string]string{"v0.1.0-rc.1": "m2"}, tag: "v0.1.0", at: "m3", allowed: true},
		{name: "older version", existing: map[string]string{"v0.2.0": "m2"}, tag: "v0.1.9", at: "m3", allowed: false},
		{name: "prerelease after its release", existing: map[string]string{"v0.1.0": "m2"}, tag: "v0.1.0-rc.2", at: "m3", allowed: false},
		{name: "newer version rolled back to an ancestor of the latest release", existing: map[string]string{"v0.1.0": "m3"}, tag: "v0.2.0", at: "m2", allowed: false},
		{name: "commit not on main", tag: "v0.1.0", at: "s1", allowed: false},
		{name: "not a version tag", tag: "v1.2", at: "m3", allowed: false},
		{name: "alphanumeric prerelease identifier above numeric", existing: map[string]string{"v1.0.0-alpha.1": "m2"}, tag: "v1.0.0-alpha.beta", at: "m3", allowed: true},
		{name: "numeric prerelease identifier below alphanumeric", existing: map[string]string{"v1.0.0-alpha.beta": "m2"}, tag: "v1.0.0-alpha.1", at: "m3", allowed: false},
		{name: "shorter prerelease below longer", existing: map[string]string{"v1.0.0-alpha.1": "m2"}, tag: "v1.0.0-alpha", at: "m3", allowed: false},
		{name: "numeric prerelease compared numerically", existing: map[string]string{"v1.0.0-rc.9": "m2"}, tag: "v1.0.0-rc.10", at: "m3", allowed: true},
		{name: "major compared numerically", existing: map[string]string{"v9.0.0": "m2"}, tag: "v10.0.0", at: "m3", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := newGuardRepo(t, tt.existing)
			code, out := repo.guard(tt.tag, tt.at)
			if (code == 0) != tt.allowed {
				t.Fatalf("guard(%s at %s) exit=%d, allowed=%t\n%s", tt.tag, tt.at, code, tt.allowed, out)
			}
		})
	}
}

// TestReleaseTagGuardIgnoresShadowingRefs proves a local tag or branch named
// origin/main cannot stand in for the fetched main branch.
func TestReleaseTagGuardIgnoresShadowingRefs(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"tag", "branch"} {
		repo := newGuardRepo(t, nil)
		git(t, repo.work, kind, "origin/main", repo.commit["s1"])
		if code, out := repo.guard("v0.1.0", "s1"); code == 0 {
			t.Fatalf("%s named origin/main let a side-branch commit pass:\n%s", kind, out)
		}
	}
}

// TestReleaseTagGuardRejectsMalformedCommit proves TAG_COMMIT must be a full
// 40-hex commit id before any git command runs.
func TestReleaseTagGuardRejectsMalformedCommit(t *testing.T) {
	t.Parallel()

	repo := newGuardRepo(t, nil)
	repo.commit["bad"] = "--upload-pack=touch /tmp/x"
	if code, out := repo.guard("v0.1.0", "bad"); code == 0 || !strings.Contains(out, "TAG_COMMIT") {
		t.Fatalf("malformed TAG_COMMIT exit=%d out=%q, want a TAG_COMMIT rejection", code, out)
	}
}
