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
SPDX SBOM attestation.

Verify a published digest yourself. Use the exact signer identity for the ref
that built it (`refs/heads/main`, or `refs/tags/vX.Y.Z` for a release), never
a regular expression:

```sh
IMAGE=ghcr.io/eshu-hq/scanner-osruntime@sha256:<digest>
REF=refs/heads/main            # or refs/tags/vX.Y.Z
IDENTITY="https://github.com/eshu-hq/eshu-scanner-worker/.github/workflows/release.yml@${REF}"
gh attestation verify "oci://${IMAGE}" -R eshu-hq/eshu-scanner-worker \
  --cert-identity "${IDENTITY}" --source-ref "${REF}" --deny-self-hosted-runners
cosign verify "${IMAGE}" --certificate-identity "${IDENTITY}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Enforced inside the workflow

These checks run in `release.yml` and fail the job before anything is built:

- The ref is `refs/heads/main` or a `vMAJOR.MINOR.PATCH[-prerelease]` tag.
- A tag's commit is on `main`: `scripts/release-tag-guard.sh` fetches it
  into the fully qualified `refs/remotes/origin/main` and checks ancestry
  there, so a tag or branch named `origin/main` cannot stand in for it.
- A tag's version is strictly newer, by semantic version, than every other
  release tag (a prerelease sorts before its release), and its commit is not
  an ancestor of the latest release's commit. A newer version number cannot
  publish older code.
- A tag matches `component.Version`.

After publishing, the job verifies the cosign signature and both attestations
against the exact identity `release.yml@<triggering ref>`, the triggering
ref, and the source commit, and rejects self-hosted runners.

Limit: these checks live in the workflow file at the triggering ref. A person
who can push a `v*` tag can push a tag whose `release.yml` skips them. Only the
repository settings below close that gap.

### Repository settings (required hardening, not yet applied)

- A tag ruleset that restricts creating, updating, and deleting `v*` tags to
  repository administrators. It is also the only control for tag
  immutability: the workflow cannot tell a deleted-and-re-pushed version tag
  from a new one, so without the ruleset an existing version can be re-pushed
  at a different commit.
- A `release` environment with required reviewers and a deployment policy
  limited to `main` and `v*` tags. The publishing job already runs in
  `environment: release`; until the environment is configured, GitHub creates
  it on first use with no protection.
- `main` already requires `ci-complete` through the `main-ci-complete`
  ruleset. Adding a required pull-request review to that ruleset is
  recommended, because a tag can only publish commits that reached `main`.

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

Re-pin rule: take the digests from the `release` run of a **push to
`main`**, never from a tag run. eshu core's
`scripts/verify-scanner-digest-pins.sh` resolves
`ghcr.io/eshu-hq/scanner-<name>:sha-<Scanner-Publish-SHA>` and requires each
pin to equal that digest; only main pushes publish the `sha-<commit>` tag,
and a tag run builds a different digest for the same commit because its
`SCANNER_VERSION` is the tag. Set `Scanner-Publish-SHA` to that main commit
and `Scanner-Publish-Repo` to `eshu-hq/eshu-scanner-worker`. The job summary
of each run says which case it is.

Until the re-pin lands, eshu core admits only the images built from eshu
commit `a371d1e21f`.

## Disclosure Guidelines

- Do not publicly disclose an issue before a fix is released.
- Avoid testing in ways that could harm users, systems, or data.
- Report in good faith with enough detail to reproduce the issue.
