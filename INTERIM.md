# INTERIM — staged migration state (Refs eshu-hq/eshu#8878)

Execution sources were removed from eshu in eshu-hq/eshu#9741; the pinned
images were built from eshu commit `a371d1e21f`; the destination port into
eshu-hq/eshu-scanner-worker is in progress (eshu-hq/eshu#8878 box 10).

The port source of truth is eshu commit `a4df1d2c9f^` (the parent of the
#9741 removal merge). No piece is carried via `replace` directive, and
`go/boundary_test.go` fails the build on any `github.com/eshu-hq/eshu/`
import or any `replace` line. Core-internal imports are replaced by the
published eshu-sdk modules or by small satellite-local copies, listed below.

## Landed

Byte-identical relocations (zero semantic delta):

- `go/internal/collector/scannerworker/`: `doc.go`, `analyzer.go`
  (analyzer kinds + scanner-vs-reducer lane map) + `analyzer_test.go`.
- `go/internal/collector/ospackagevulnerability/`: `doc.go`, `distro.go`,
  `types.go`, `apk_parser.go`, `dpkg_parser.go`, `rpm_parser.go`, parser
  tests, text fixtures. `rpm_database.go` has since gained the RPM header
  guards (#23, #26) and is ahead of the eshu copy. `envelope.go` and
  `types.go` are ahead of it too (#33): `EnvelopeContext.ObservedAt` is the
  claim observation time and a zero value is an error, not a `time.Now`
  stamp.

Component lane, first slice (os_package_extraction):

- `ospackagevulnerability/envelope.go` + envelope and credential-canary
  tests (replaces the interim `warning.go` copy), RPM fixtures.
- `ospackagevulnerability/osruntime/` (analyzer, local rootfs provider,
  types, errors) + analyzer and RPM tests.
- `scannerworker/`: `types.go`, `claim.go`, `defaults.go`, `failure.go`,
  `analyzer_failure.go`, `output.go`. The workflow-coupled pieces
  (`NewClaimInput*`, `TargetScopeFromWorkItem`, `TargetScope.validateFor`)
  are not ported: the component lane derives input from the SDK claim
  through `TargetScopeForComponent`.
- `scannerworker/component/`: `paging.go`, `config.go`, `runner.go`, `runner_build.go`,
  `runner_failure.go`, `ids.go`. Paging, the request continuation, and the
  result page envelope now use eshu-sdk/collector `v0.2.0-rc.3` types.
- `scannerworker/imageanalyzer/` (second slice): analyzer, layer and rootfs
  snapshots, analysis and warning facts. `AnalyzerConfig.Provider` is new
  (default `osruntime.LocalRootFSProvider`, the provider the in-tree code
  hard-coded); it is now the failure-injection seam for tests, not a clock
  pin (see "Fact clock" below).
- `scannerworker/sbomgenerator/` (third slice): analyzer, repository
  source, lockfile parsers, envelopes, warning aggregation; wired into the
  runner as sbom_generation.
- `go/internal/packageidentity/`: verbatim copy with its tests (it has no
  eshu-hq imports; the SDK has no package-identity package).
- Parity proof: `component/parity_{osruntime,image,sbom}_test.go` reproduce
  the core goldens `testdata/scanner-parity/{osruntime,image,sbom}.json`
  byte for byte, and the runner's v1alpha3 pages equal the pages built from
  each golden.
- Commands (fourth slice): `go/cmd/scanner-component-{image,sbom,osruntime}`
  as thin mains over `component.Main` (version probe, `seed`, one stdio
  call); `component/manifest.go` and `seed.go` on the eshu-sdk
  `collector/conformance.Manifest` type; `go/internal/buildinfo` verbatim.
  `ManifestFor` carries no digest pin (a binary cannot embed its own image
  digest); Seed stamps the digest-pinned `--image-ref`, and eshu core keeps
  the admission pins and `VerifySeededArtifact`. `reconcile.go` and
  `RequiredGrants` stay core-side for that reason.
  `component/testdata/manifests` pins byte equality with core's manifests.
- Build and release (fifth slice): `Dockerfile` with stages
  `scanner-image`, `scanner-sbom`, `scanner-osruntime` (static pure-Go
  binaries on distroless, at the path the chart's seed init container
  executes); `.github/workflows/release.yml` publishes
  `ghcr.io/eshu-hq/scanner-{image,sbom,osruntime}` by digest for amd64 and
  arm64 with SLSA provenance, cosign signature, and SBOM attestation, all
  verified in the job against the exact `release.yml@<ref>` identity and
  source commit; a tag must be on `main`, strictly newer than every other
  release, and not a rollback (`scripts/release-tag-guard.sh`).
  `SECURITY.md` has the version-pair table and the applied repository
  settings: the `release-tags` ruleset (only admins create, update, or
  delete `v*` tags), the `release` environment (maintainer approval; `main`
  and `v*` only), and the `main-ci-complete` ruleset (pull request,
  `ci-complete`, no force-push or deletion). Every publish, including each
  main push, waits for the environment approval before its digests exist.
  Re-pin eshu core only from an approved main-push run (`sha-<commit>` tag),
  never a tag run (SECURITY.md, "Version Pairs"). The first publish and the
  eshu re-pin have not happened. Owed before the first publish: the
  `ghcr.io/eshu-hq/scanner-{image,sbom,osruntime}` packages are linked to
  eshu-hq/eshu today, so this repository needs write access to them (package
  settings, "Manage Actions access") or its push fails.
- Hostile-input proof: `component/hostile_test.go` (the #9380 full-range
  run for all three analyzers: 50,000 facts each at the 4,128,768-byte
  bound, reassembled byte-identical to one direct analysis); repository_url
  sanitization, opaque-credential differential, and FIFO/symlink rootfs
  rejection tests in `ospackagevulnerability`, `osruntime`, and
  `imageanalyzer`.
- SBOM repository manifests (eshu-hq/eshu-scanner-worker#37, fixed here, a
  deliberate delta from the eshu source): `sbomgenerator` opens each manifest
  non-blocking and tests the opened handle for a regular file, so a file
  swapped for a FIFO, device, socket, or directory after the walk fails
  closed as terminal `unsupported_target` instead of blocking the claim. On
  unix builds the open also does not follow a final symlink, so a swapped-in
  symlink fails the same way; non-unix builds have no no-follow open and
  read a manifest swapped for a symlink to a regular file. The guard covers
  the final path component only; a parent directory swapped for a symlink
  after the walk is still followed. Reads stop one byte past the byte budget.
- Fact clock (eshu-hq/eshu-scanner-worker#33, fixed here, a deliberate
  contract delta from the eshu source): every fact of one claim carries
  `ClaimInput.ObservedAt`, the claim observation time minted on page 0 and
  carried in the page cursor. The rootfs `Snapshot` carries no clock
  (`osruntime.Snapshot.ObservedAt` and `imageanalyzer.Snapshot.ObservedAt`
  are removed, along with `AnalyzerConfig.Now` in both analyzers), and
  `ospackagevulnerability.BuildEnvelopes` rejects a zero `ObservedAt`
  instead of stamping `time.Now`. The runner's stderr record gains
  `observed_at` next to the call clock `at`. Before this, each stateless
  page call re-read the rootfs with a fresh wall-clock stamp whose
  RFC 3339 trailing zeros changed fact sizes and moved page boundaries
  (measured: 50,000 osruntime facts reassembled as 50,120, 960 lost and
  1,080 duplicated; image rootfs 49,890, 1,100 lost and 990 duplicated).
  Consequence: `vulnerability.os_package` `observed_at` moves from the
  rootfs read time to the claim observation time, so the readiness scan
  tier's `latest_observed_at` agrees with `scanner_worker.analysis`. The
  `osruntime.json` and `image.json` parity goldens changed only in that
  field (`testdata/scanner-parity/PROVENANCE.md`).
- Known defects (pre-existing in the eshu source, behavior unchanged here):
  - eshu-hq/eshu-scanner-worker#35: no decompressed-byte budget or
    cancellation inside a long layer entry.
  - eshu-hq/eshu-scanner-worker#36: layer whiteouts and opaque markers do
    not follow OCI semantics.

Core-import replacements:

| Core package | Replacement | Why |
| --- | --- | --- |
| `internal/facts` (`Envelope`, `Ref`, confidence, scanner_worker kinds, `StableID`) | satellite-local `go/internal/facts`; `StableID` forwards to eshu-sdk `factschema/identity.StableID` | the SDK `factschema.Envelope` is a different shape; the golden needs the core field set |
| `internal/facts/supply/chain` (SBOM + vulnerability kinds, versions) | satellite-local `go/internal/facts/supply/chain`, kinds bound to eshu-sdk `factschema.FactKind*` | the SDK has kind constants but no schema-version tables or `vulnerability.warning` |
| `internal/scope` (`CollectorScannerWorker`) | satellite-local `go/internal/scope` | the SDK has no scope package |
| `internal/factenvelope` (`SDKFactFromInternal`) | satellite-local `go/internal/factenvelope` | projection of the local envelope |
| `internal/urlredact` (`CarriesUserinfo`) | verbatim `authority.go` in `go/internal/urlredact` | the SDK exposes no userinfo check |
| `internal/packageidentity` | verbatim copy in `go/internal/packageidentity` | the SDK has no package-identity package; the copy must track core changes |

## Not yet ported

| Piece | Blocker | Owning work |
| --- | --- | --- |
| `go/cmd/scanner-worker/` + the `scannerworker` claim loop | `internal/app`, `runtime.OpenPostgres`, postgres claim + ingest stores, `workflow`, `telemetry` | eshu-hq/eshu#8877 + eshu-hq/eshu#9376 |

Still NOT_CHECKED: the first satellite publish, the eshu re-pin to its
digests, production cutover, and rollback rehearsal. The standalone
`scanner-worker` claim loop stays core-side (last table row).
