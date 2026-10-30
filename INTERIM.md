# INTERIM — staged migration state (Refs eshu-hq/eshu#8878)

The first Go module lands only the pieces that compile on the public
surface today. Everything below stays in-tree, untouched, until its owning
gate lands. No piece was carried via `replace` directive (`boundary_test.go`
fails the build on any `github.com/eshu-hq/eshu/go` import or any
`replace` line). In-tree sources are not removed until cutover acceptance
(per the extraction prep census, removal is explicitly out of scope).

## Landed (byte-identical relocation, zero semantic delta)

- `go/internal/collector/scannerworker/`: `doc.go`, `analyzer.go`
  (analyzer kinds + scanner-vs-reducer lane map) + new `analyzer_test.go`
  lane proof.
- `go/internal/collector/ospackagevulnerability/`: `doc.go`, `distro.go`,
  `types.go`, `apk_parser.go`, `dpkg_parser.go`, `rpm_parser.go`,
  `rpm_database.go`, parser tests, three text fixtures.
- `go/internal/collector/ospackagevulnerability/warning.go`: verbatim copy
  of the `OSPackageWarning` declaration owned in-tree by `envelope.go`.
  Delete this file and land `envelope.go` whole when its gate clears.

## Staying in-tree

| Piece | Needs the shared package | Owning gate |
| --- | --- | --- |
| `go/cmd/scanner-worker/` (`main.go`, `config.go`, `service.go`) | `internal/app`, `runtime.OpenPostgres`, `storage/postgres` claim + ingest stores, `workflow` | eshu-hq/eshu#8877 (claim client) + eshu-hq/eshu#6709 (public contract) |
| `scannerworker` claim loop (`claim.go`, `service.go`, `service_facts.go`, `service_telemetry.go`, `output.go`, `types.go`, `defaults.go`, `failure.go`, `analyzer_failure.go`, `warning_analyzer.go`) | `workflow` work item + claim, `facts.Envelope`, `factenvelope`, `scope` kinds, `telemetry` instruments, postgres commit fence | eshu-hq/eshu#8877 + eshu-hq/eshu#6709 |
| `scannerworker/imageanalyzer/`, `scannerworker/sbomgenerator/` | parent `ClaimInput` / `FactOutput` / `TargetScope` API + `facts`, `scope`, `packageidentity` | eshu-hq/eshu#6709 (+ eshu-hq/eshu#9385 SDK bound + pagination for the emission path) |
| `ospackagevulnerability/osruntime/` | parent analyzer API over `ClaimInput` / `AnalyzerResult` | eshu-hq/eshu#6709 |
| `ospackagevulnerability/envelope.go` (+ envelope, canary, rpm-database tests; `testdata/rpmdb.sqlite`, `Packages.*.xz`) | `facts.Envelope`, `facts/supply/chain`, `scope`, `urlredact` | eshu-hq/eshu#6709 |
| `scannerworker/component/` + `go/cmd/scanner-component-{image,sbom,osruntime}/` | component lane on `collector-sdk/v1alpha3`; not in the listed scope | eshu-hq/eshu#9385 + eshu-hq/eshu#8877 |

Cutover blockers already recorded in the prep census (`contract_blocked`):
eshu-hq/eshu#9385 and the eshu-hq/eshu#8877 claim client. Production
cutover, rollback rehearsal, and extracted-path parity still NOT_CHECKED.
