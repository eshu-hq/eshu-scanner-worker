// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package ciworkflow holds the contract test for .github/workflows/ci.yml:
// the lane bodies live in the pinned eshu-hq/.github reusable, and this
// caller must keep its three jobs, the pin, and the coverage-floor parity.
package ciworkflow

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// reusablePin is the exact eshu-hq/.github commit the caller must pin. A
// pin move fails the test until the new reusable body is re-verified.
const reusablePin = "eshu-hq/.github/.github/workflows/go-collector-ci.yml@4d01ab90baf5dd77c21cc1ee6bdf701332613449"

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestCallerCallsPinnedReusable pins the thin-caller shape: the lanes job
// uses the reusable at an exact SHA, and no inline lane bodies remain.
func TestCallerCallsPinnedReusable(t *testing.T) {
	t.Parallel()

	text := readFile(t, ".github/workflows/ci.yml")
	if !strings.Contains(text, "uses: "+reusablePin) {
		t.Errorf("ci.yml does not call the reusable pinned at %s", reusablePin)
	}
	for _, inline := range []string{"golangci-lint run", "go test ./... -race", "govulncheck ./...", "gosec -no-fail"} {
		if strings.Contains(text, inline) {
			t.Errorf("ci.yml still carries inline lane body %q: lane bodies live in the reusable", inline)
		}
	}
}

// TestCallerKeepsFrozenJobNames keeps the org contract: exactly changes,
// lanes, and ci-complete (the only ruleset-required context).
func TestCallerKeepsFrozenJobNames(t *testing.T) {
	t.Parallel()

	text := readFile(t, ".github/workflows/ci.yml")
	jobKey := regexp.MustCompile(`^  ([a-z][a-z-]*):\s*$`)
	var got []string
	inJobs := false
	for _, line := range strings.Split(text, "\n") {
		if line == "jobs:" {
			inJobs = true
			continue
		}
		if inJobs {
			if m := jobKey.FindStringSubmatch(line); m != nil {
				got = append(got, m[1])
			}
		}
	}
	want := []string{"changes", "lanes", "ci-complete"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ci.yml jobs = %v, want exactly %v", got, want)
	}
}

// TestChangesRunsOnEveryEvent guards the schedule trap: every lane needs
// the changes job, so skipping it on schedule would skip every lane.
func TestChangesRunsOnEveryEvent(t *testing.T) {
	t.Parallel()

	text := readFile(t, ".github/workflows/ci.yml")
	start := strings.Index(text, "\n  changes:")
	end := strings.Index(text, "\n  lanes:")
	if start < 0 || end < start {
		t.Fatal("ci.yml has no changes job ahead of the lanes job")
	}
	if strings.Contains(text[start:end], "\n    if:") {
		t.Error("changes job has an if: guard; lanes would skip on schedule runs")
	}
}

// TestLanesWireEveryRunInput fails if a lane selector input is dropped:
// the lane would silently un-run.
func TestLanesWireEveryRunInput(t *testing.T) {
	t.Parallel()

	text := readFile(t, ".github/workflows/ci.yml")
	for _, input := range []string{
		"run-lint:", "run-test:", "run-race:", "run-shell:", "run-image:",
		"run-govulncheck:", "run-gosec:", "run-actionlint:",
		"coverage-floor:", "golangci-lint-version:", "go-version-file:",
	} {
		if !strings.Contains(text, "      "+input) {
			t.Errorf("lanes call drops input %s", input)
		}
	}
}

// TestCoverageFloorParity pins the CI floor to the Makefile floor.
func TestCoverageFloorParity(t *testing.T) {
	t.Parallel()

	makeFloor := regexp.MustCompile(`(?m)^COVERAGE_FLOOR \?= ([0-9.]+)`).FindStringSubmatch(readFile(t, "Makefile"))
	ciFloor := regexp.MustCompile(`(?m)^      coverage-floor: ([0-9.]+)`).FindStringSubmatch(readFile(t, ".github/workflows/ci.yml"))
	if makeFloor == nil || ciFloor == nil {
		t.Fatalf("floor not found: Makefile=%v ci.yml=%v", makeFloor, ciFloor)
	}
	if makeFloor[1] != ciFloor[1] {
		t.Errorf("ci.yml coverage-floor %s != Makefile COVERAGE_FLOOR %s", ciFloor[1], makeFloor[1])
	}
}

// fork-pr lane proof, do not merge
