# Security Policy

## Supported Versions

Security fixes target the latest published images only. The scanner images
are consumed by digest, so a fix ships as a new publish from `main` (or a
`v*` tag) followed by an eshu core re-pin of the new digests.

| Version | Supported |
| ------- | --------- |
| Latest publish from `main` or the latest `v*` tag | Yes |
| Older digests | No |

Before the first tag the module is pre-release with no cutover authority:
report issues against `main` and name the commit SHA (Refs
`eshu-hq/eshu#8878`).

## Reporting a Vulnerability

Do not open a public GitHub issue for security problems.

Instead:

1. Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) if enabled for this repository.
2. If private reporting is unavailable, contact the maintainers privately before disclosure.
3. Include the impact, reproduction steps, affected component (`image`, `sbom`, or `osruntime`), and any suggested mitigation.

The analyzers parse untrusted input: container rootfs metadata, image layer
archives, RPM databases, and repository lockfiles. Resource-limit bypasses,
parser crashes, path escapes, and credential leaks into emitted facts are in
scope.

## Supply Chain

`.github/workflows/release.yml` publishes
`ghcr.io/eshu-hq/scanner-{image,sbom,osruntime}` for `linux/amd64` and
`linux/arm64` with SLSA build provenance, a keyless cosign signature, and an
SPDX SBOM attestation, and verifies all of them against this repository
before the job succeeds. Verify a digest yourself with:

```sh
gh attestation verify oci://ghcr.io/eshu-hq/scanner-osruntime@sha256:<digest> \
  -R eshu-hq/eshu-scanner-worker
cosign verify ghcr.io/eshu-hq/scanner-osruntime@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/eshu-hq/eshu-scanner-worker/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

CI runs `govulncheck` and `gosec` on every push to `main` and on the weekly
schedule, `govulncheck` on pull requests that change `go.mod`, and `gosec`
on pull requests that change Go code.

## Version Pairs

The images are only valid against the eshu core and SDK versions below. A
change to any row lands in this repository and in the eshu re-pin PR in the
same release.

| This repository | Pairs with | Where it is pinned |
| --- | --- | --- |
| component manifest `0.1.0` (`component.Version`) | eshu core `compatibleCore: >=0.0.5 <0.2.0`, `scannercomponent.Version` `0.1.0` | `go/internal/collector/scannerworker/component/manifest.go`, `testdata/manifests` |
| wire protocol `collector-sdk/v1alpha3` | eshu core extension host v1alpha3 pagination | `component.protocolVersion` (from eshu-sdk) |
| `github.com/eshu-hq/eshu-sdk/collector` `v0.2.0-rc.3` | eshu core `go/go.mod` `v0.2.0-rc.3` | `go.mod` |
| `github.com/eshu-hq/eshu-sdk/factschema` `v0.1.0-rc.12` | eshu core `go/go.mod` `v0.1.0-rc.12` | `go.mod` |
| image digests from this repository's `release` workflow | eshu core `scannercomponent` manifest pins and `Scanner-Publish-Repo` | eshu re-pin PR (`eshu-hq/eshu#8878` box 10) |

Until the re-pin lands, eshu core admits only the images built from eshu
commit `a371d1e21f`.

## Disclosure Guidelines

- Do not publicly disclose an issue before a fix is released.
- Avoid testing in ways that could harm users, systems, or data.
- Report in good faith with enough detail to reproduce the issue.
