// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package ciworkflow

import (
	"regexp"
	"strings"
	"testing"
)

// TestReleaseWorkflowContract pins the scanner image publish shape the eshu
// re-pin relies on: every action pinned to a full commit SHA, the three
// components published as ghcr.io/eshu-hq/scanner-<name> for amd64 and
// arm64, SLSA provenance pushed to the registry and verified against this
// repository, and no pull_request trigger (a fork PR must never publish).
func TestReleaseWorkflowContract(t *testing.T) {
	t.Parallel()

	text := readFile(t, ".github/workflows/release.yml")
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "uses:") && !strings.HasPrefix(trimmed, "- uses:") {
			continue
		}
		if !regexp.MustCompile(`@[0-9a-f]{40}( |$)`).MatchString(trimmed) {
			t.Errorf("action not pinned to a full commit SHA: %s", trimmed)
		}
	}
	required := []string{
		"component: [image, sbom, osruntime]",
		"IMAGE_NAME: ${{ github.repository_owner }}/scanner-${{ matrix.component }}",
		"target: scanner-${{ matrix.component }}",
		"platforms: linux/amd64,linux/arm64",
		"uses: actions/attest-build-provenance@",
		"push-to-registry: true",
		`gh attestation verify "${OCI_IMAGE_REF}"`,
		"id-token: write",
		"attestations: write",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Errorf("release.yml lost %q", want)
		}
	}
	trigger := text[strings.Index(text, "\non:"):strings.Index(text, "\nconcurrency:")]
	if strings.Contains(trigger, "pull_request") {
		t.Error("release.yml must not run on pull_request")
	}

	// A v* tag on any commit other than the protected main head must never
	// publish: the guard runs before the first build step and compares the
	// tagged commit with a fresh fetch of origin/main.
	guard := strings.Index(text, "- name: Require the tag to point at the protected main head")
	build := strings.Index(text, "- name: Set up Docker Buildx")
	if guard < 0 || build < 0 || guard > build {
		t.Error("release.yml must check the tag against the protected main head before any build step")
	} else {
		body := text[guard:build]
		for _, want := range []string{"if: github.ref_type == 'tag'", "TAG_COMMIT: ${{ github.sha }}", "git fetch origin main", `"${TAG_COMMIT}" != "${main_head}"`, "exit 1"} {
			if !strings.Contains(body, want) {
				t.Errorf("main-head guard lost %q", want)
			}
		}
	}

	// Both attestation verifications must pin the signing workflow, not only
	// the repository.
	signer := `--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/release.yml"`
	if got := strings.Count(text, signer); got != 2 {
		t.Errorf("gh attestation verify pins the signer workflow %d times, want 2 (provenance and SBOM)", got)
	}
}

// TestDockerfileStagesMatchChartSeedCommand pins the three final stages and
// the binary path the eshu chart's seed init container executes.
func TestDockerfileStagesMatchChartSeedCommand(t *testing.T) {
	t.Parallel()

	text := readFile(t, "Dockerfile")
	for _, name := range []string{"image", "sbom", "osruntime"} {
		for _, want := range []string{
			"AS scanner-" + name + "\n",
			"/usr/local/bin/eshu-scanner-component-" + name,
			`ENTRYPOINT ["/usr/local/bin/eshu-scanner-component-` + name + `"]`,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("Dockerfile lost %q", want)
			}
		}
	}
	if !strings.Contains(text, "CGO_ENABLED=0") {
		t.Error("Dockerfile must build static binaries (CGO_ENABLED=0)")
	}
}
