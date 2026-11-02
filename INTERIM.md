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
  guards (#23, #26) and is ahead of the eshu copy.

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
- `scannerworker/component/`: `paging.go`, `config.go`, `runner.go`,
  `runner_failure.go`, `ids.go`. Paging, the request continuation, and the
  result page envelope now use eshu-sdk/collector `v0.2.0-rc.3` types.
- `scannerworker/imageanalyzer/` (second slice): analyzer, layer and rootfs
  snapshots, analysis and warning facts. `AnalyzerConfig.Provider` is new
  (default `osruntime.LocalRootFSProvider`, the provider the in-tree code
  hard-coded) so the parity tests can pin the captured snapshot time.
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
  release, and not a rollback (`scripts/release-tag-guard.sh`). `SECURITY.md` has the version-pair
  table and the required repository hardening (a `v*` tag ruleset and a
  protected `release` environment), which is not yet applied. The first
  publish and the eshu re-pin have not happened.
- Hostile-input proof: `component/hostile_test.go` (the #9380 full-range
  run for all three analyzers: 50,000 facts each at the 4,128,768-byte
  bound, reassembled byte-identical to one direct analysis); repository_url
  sanitization, opaque-credential differential, and FIFO/symlink rootfs
  rejection tests in `ospackagevulnerability`, `osruntime`, and
  `imageanalyzer`.
- Known defect: wall-clock snapshot time can shift page boundaries between
  calls (eshu-hq/eshu-scanner-worker#33).

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
