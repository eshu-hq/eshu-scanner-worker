# Architecture

## Place in Eshu

These scanners are leaf workers in Eshu. Core's host starts
one per job; the scanner reads one request, scans one
target, writes one result page, and exits; the host sends
the result to core, which commits the facts. Nothing here
stays running between jobs. Three scanners were moved here
from core; go-reachability is new here and core doesn't
admit it yet (see [INTERIM.md](../../INTERIM.md)).

Diagrams live in [diagrams](../diagrams/README.md). The
[top-level README](../../README.md) keeps one overview
diagram.

## Per-binary map

All four live under `go/cmd/` and share one entry point,
`component.Main`, speaking `collector-sdk/v1alpha3`:

| Program (source) | Image binary | Component id | Scans |
|---|---|---|---|
| `go/cmd/scanner-component-image` | `eshu-scanner-component-image` | `eshu.scanner.image` | Container images: unpacks layers and finds OS packages |
| `go/cmd/scanner-component-sbom` | `eshu-scanner-component-sbom` | `eshu.scanner.sbom` | Repositories: builds an SBOM from lockfiles |
| `go/cmd/scanner-component-osruntime` | `eshu-scanner-component-osruntime` | `eshu.scanner.osruntime` | An unpacked OS file system: lists installed OS packages |
| `go/cmd/scanner-component-go-reachability` | `eshu-scanner-component-go-reachability` | `eshu.scanner.go-reachability` | One Go repository at one commit: module evidence and call reachability |

What each emits is listed in
[contracts](../concepts/contracts.md). How each gets
installed is in the [seed guide](../guides/seed.md).

## Related repos

- [eshu](https://github.com/eshu-hq/eshu): core. Its host
  starts these programs and commits their facts.
- [eshu-sdk](https://github.com/eshu-hq/eshu-sdk): the
  collector contract (`collector-sdk/v1alpha3`).
- [eshu-extension-host](https://github.com/eshu-hq/eshu-extension-host):
  the standalone supervisor for component collectors like
  these.
