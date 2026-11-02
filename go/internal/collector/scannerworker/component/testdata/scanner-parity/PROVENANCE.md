# Scanner parity goldens: provenance

These files are byte-for-byte copies of the committed scanner parity goldens
in the Eshu core repository. They are the frozen in-tree analyzer truth this
satellite port must reproduce. Do not regenerate or hand-edit them; a
mismatch means the port drifted.

| File | Source repository | Source path | Added in | Blob | sha256 |
| --- | --- | --- | --- | --- | --- |
| `osruntime.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/osruntime.json` | `aa95dbcdac` (#9741) | `8ed6ac336de402b3ff5e4182fbec7663df071622` | `5f6a853a17a572324b2c8d86e32a2cffdc0a18b58b75b314e8a550f3d7ad47d4` |
| `image.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/image.json` | `aa95dbcdac` (#9741) | `2ab1453d8135a1eab188282633b653bee5e792dc` | `cc4df57904eb652251ba0fb90a8886d29392233af4fb3b1e4e823471a284de5a` |

Copied from eshu `origin/main` at `f12ebc5f046f`. Refs eshu-hq/eshu#8878.

## Capture inputs

The goldens were captured at the #9741 removal from the pre-removal parity
driver (`go/internal/collector/extensionhost/analyzer_parity_test.go` at eshu
`aa95dbcdac^`): a 60-package synthetic Alpine 3.19.1 rootfs, scope
`image://registry.example/parity@sha256:deadbeef...`, generation
`scanner-worker:generation-parity`, fencing token 13, collector instance
`scanner-parity`, source URI `oci://registry.example/parity@sha256:deadbeef`.
The image capture adds image reference `registry.example/parity:1.0` and
image digest `sha256:aaaa...`. The satellite parity tests rebuild the same
inputs.

## The one nondeterministic input

`osruntime.LocalRootFSProvider` stamps the snapshot with the wall clock
(`time.Now`), not the injected analyzer clock, so every
`vulnerability.os_package` fact carries its capture time:
`2026-10-31T16:08:20.743925041Z` in `osruntime.json` and
`2026-10-31T16:08:20.742184584Z` in `image.json` (the image analyzer reads
the rootfs through the same provider). The `scanner_worker.analysis` fact in
`image.json` uses the injected clock. The parity tests pin the snapshot time
to the captured literal through a wrapping `SnapshotProvider`; every other
byte is computed by the ported analyzers. The wall-clock stamp is the
cross-page drift defect tracked in eshu-hq/eshu-scanner-worker#33.
