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
		"component: [image, sbom, osruntime, go-reachability]",
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

	// The ref allowlist runs first: only refs/heads/main and vMAJOR.MINOR.PATCH
	// tags may publish.
	allow := strings.Index(text, "- name: Require an allowed release ref")
	checkout := strings.Index(text, "- name: Checkout repository")
	if allow < 0 || checkout < 0 || allow > checkout {
		t.Error("release.yml must check the ref allowlist before checkout")
	} else {
		body := text[allow:checkout]
		for _, want := range []string{"SOURCE_REF: ${{ github.ref }}", "refs/heads/main)", "refs/tags/v*)", "exit 1"} {
			if !strings.Contains(body, want) {
				t.Errorf("ref allowlist lost %q", want)
			}
		}
	}

	// A v* tag must point at a commit already on the protected main branch:
	// the guard runs before the first build step on a full-history checkout.
	guard := strings.Index(text, "- name: Require the tag to be on the protected main branch")
	build := strings.Index(text, "- name: Set up Docker Buildx")
	if guard < 0 || build < 0 || guard > build {
		t.Error("release.yml must check the tag against the protected main branch before any build step")
	} else {
		body := text[guard:build]
		for _, want := range []string{"if: github.ref_type == 'tag'", "TAG_NAME: ${{ github.ref_name }}", "TAG_COMMIT: ${{ github.sha }}", "run: bash scripts/release-tag-guard.sh"} {
			if !strings.Contains(body, want) {
				t.Errorf("main-branch guard lost %q", want)
			}
		}
	}
	// Refs are compared only by fully qualified names (the guard script uses
	// refs/remotes/origin/main); a short origin/main could be shadowed.
	if regexp.MustCompile(`[^/]origin/main`).MatchString(text) {
		t.Error("release.yml must not use the short ref origin/main")
	}
	if !strings.Contains(text[checkout:], "fetch-depth: 0") {
		t.Error("checkout must fetch full history for the ancestry check")
	}

	// Verification binds to this workflow at the allowed ref and to the exact
	// source commit; no regular-expression identity is allowed anywhere.
	identity := "CERTIFICATE_IDENTITY: https://github.com/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}"
	if got := strings.Count(text, identity); got != 2 {
		t.Errorf("exact signer identity is set on %d verify steps, want 2 (cosign and attestations)", got)
	}
	if !strings.Contains(text, `--certificate-identity "${CERTIFICATE_IDENTITY}"`) {
		t.Error("cosign verify must use the exact --certificate-identity")
	}
	for _, flag := range []string{`--cert-identity "${CERTIFICATE_IDENTITY}"`, `--source-ref "${SOURCE_REF}"`, `--source-digest "${SOURCE_DIGEST}"`, "--deny-self-hosted-runners"} {
		if got := strings.Count(text, flag); got != 2 {
			t.Errorf("gh attestation verify uses %q %d times, want 2 (provenance and SBOM)", flag, got)
		}
	}
	if strings.Contains(text, "regex") {
		t.Error("release.yml must not match a signer identity by regular expression")
	}

	// eshu core's verify-scanner-digest-pins.sh resolves
	// scanner-<name>:sha-<Scanner-Publish-SHA>, a tag only main pushes publish;
	// a tag run builds a different digest for the same commit (its
	// SCANNER_VERSION differs), so its summary must not invite a re-pin.
	summary := strings.Index(text, "- name: Record the image digest")
	nextStep := strings.Index(text, "- name: Generate build provenance attestation")
	if summary < 0 || nextStep < summary {
		t.Error("release.yml lost the digest summary step")
	} else {
		body := text[summary:nextStep]
		for _, want := range []string{"REF_TYPE: ${{ github.ref_type }}", "Scanner-Publish-SHA", "Do not re-pin eshu core from a tag run"} {
			if !strings.Contains(body, want) {
				t.Errorf("digest summary lost %q", want)
			}
		}
	}

	// The publishing job runs in the release environment so required
	// reviewers apply once the repository setting exists.
	if !strings.Contains(text, "    environment: release\n") {
		t.Error("the publishing job must run in the release environment")
	}
}

// TestDockerfileStagesMatchChartSeedCommand pins the four final stages and
// the binary path the eshu chart's seed init container executes.
func TestDockerfileStagesMatchChartSeedCommand(t *testing.T) {
	t.Parallel()

	text := readFile(t, "Dockerfile")
	for _, name := range []string{"image", "sbom", "osruntime", "go-reachability"} {
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

// TestDockerfileCarriesThePinnedToolchain pins the go-reachability stage: one
// toolchain from the digest-pinned GO_IMAGE with no RUN, so the multi-platform
// build needs no emulation, a scanner built from go.sum rather than installed from
// a floating version, and the GOROOT trimmed of what go list does not read.
func TestDockerfileCarriesThePinnedToolchain(t *testing.T) {
	t.Parallel()

	text := readFile(t, "Dockerfile")
	start := strings.Index(text, "AS toolchain\n")
	stage := strings.Index(text, "AS scanner-go-reachability\n")
	if start < 0 || stage < 0 {
		t.Fatal("Dockerfile lost the toolchain or scanner-go-reachability stage")
	}
	for _, want := range []string{
		"FROM --platform=$TARGETPLATFORM ${GO_IMAGE} AS toolchain\n",
		"-o /out/govulncheck golang.org/x/vuln/cmd/govulncheck",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Dockerfile lost %q", want)
		}
	}
	if regexp.MustCompile(`govulncheck@|go install`).MatchString(text) {
		t.Error("the scanner must come from go.sum, never go install or a version suffix")
	}
	body := text[stage:]
	if strings.Contains(body, "\nRUN ") {
		t.Error("the final stage must have no RUN: it has no shell and no emulation")
	}
	for _, want := range []string{"VERSION", "go.env", "bin", "src", "pkg", "lib"} {
		line := "COPY --from=toolchain /usr/local/go/" + want + " /usr/local/go/" + want + "\n"
		if !strings.Contains(body, line) {
			t.Errorf("stage lost %q", line)
		}
	}
	for _, trimmed := range []string{"/usr/local/go/test", "/usr/local/go/api", "/usr/local/go/doc", "/usr/local/go/misc", "COPY --from=toolchain /usr/local/go /"} {
		if strings.Contains(body, trimmed) {
			t.Errorf("stage must not copy %q", trimmed)
		}
	}
	if !strings.Contains(body, "COPY --from=build /out/govulncheck /usr/local/bin/govulncheck\n") {
		t.Error("stage lost the scanner")
	}
	goMod := readFile(t, "go.mod")
	if !strings.Contains(goMod, "tool golang.org/x/vuln/cmd/govulncheck") {
		t.Error("go.mod lost the tool directive that pins the scanner in go.sum")
	}
}
