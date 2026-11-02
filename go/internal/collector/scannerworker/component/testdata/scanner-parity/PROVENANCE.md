# Scanner parity goldens: provenance

These files are byte-for-byte copies of the committed scanner parity goldens
in the Eshu core repository. They are the frozen in-tree analyzer truth this
satellite port must reproduce. Do not regenerate or hand-edit them; a
mismatch means the port drifted.

| File | Source repository | Source path | Added in | Blob | sha256 |
| --- | --- | --- | --- | --- | --- |
| `osruntime.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/osruntime.json` | `aa95dbcdac` (#9741) | `8ed6ac336de402b3ff5e4182fbec7663df071622` | `5f6a853a17a572324b2c8d86e32a2cffdc0a18b58b75b314e8a550f3d7ad47d4` |

Copied from eshu `origin/main` at `f12ebc5f046f`. Refs eshu-hq/eshu#8878.

## Capture inputs

The goldens were captured at the #9741 removal from the pre-removal parity
driver (`go/internal/collector/extensionhost/analyzer_parity_test.go` at eshu
`aa95dbcdac^`): a 60-package synthetic Alpine 3.19.1 rootfs, scope
`image://registry.example/parity@sha256:deadbeef...`, generation
`scanner-worker:generation-parity`, fencing token 13, collector instance
`scanner-parity`, source URI `oci://registry.example/parity@sha256:deadbeef`.
The satellite parity test rebuilds the same inputs.

## The one nondeterministic input

`osruntime.LocalRootFSProvider` stamps the snapshot with the wall clock
(`time.Now`), not the injected analyzer clock, so every
`vulnerability.os_package` fact in `osruntime.json` carries the capture time
`2026-10-31T16:08:20.743925041Z`. The parity test pins the snapshot time to
that literal through a wrapping `SnapshotProvider`; every other byte is
computed by the ported analyzer.
