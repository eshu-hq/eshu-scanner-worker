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
- Parity proof: `component/parity_osruntime_test.go` and
  `component/parity_image_test.go` reproduce the core goldens
  `testdata/scanner-parity/{osruntime,image}.json` byte for byte, and the
  runner's v1alpha3 pages equal the pages built from each golden.
- Hostile-input proof: `component/hostile_osruntime_test.go` (the #9380
  full-range run: 50,000 facts at the 4,128,768-byte bound); repository_url
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

## Not yet ported

| Piece | Blocker | Owning work |
| --- | --- | --- |
| `scannerworker/sbomgenerator/` | needs a `packageidentity` local copy (SDK has none) | eshu-hq/eshu#8878 box 10, next slice |
| `scannerworker/component/` `manifest.go`, `seed.go`, `reconcile.go` | need a local subset of core `internal/component` manifest types | eshu-hq/eshu#8878 box 10 |
| `go/cmd/scanner-component-{image,sbom,osruntime}/` | need `buildinfo` local copy + the manifest/seed slice | eshu-hq/eshu#8878 box 10 |
| `Dockerfile`, publish workflow, `SECURITY.md` | need the three commands | eshu-hq/eshu#8878 box 10 |
| `go/cmd/scanner-worker/` + the `scannerworker` claim loop | `internal/app`, `runtime.OpenPostgres`, postgres claim + ingest stores, `workflow`, `telemetry` | eshu-hq/eshu#8877 + eshu-hq/eshu#9376 |

Production cutover, rollback rehearsal, and the satellite publish remain
NOT_CHECKED.
