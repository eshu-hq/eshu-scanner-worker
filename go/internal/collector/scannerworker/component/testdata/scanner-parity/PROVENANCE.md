# Scanner parity goldens: provenance

These files are the frozen in-tree analyzer truth this satellite port must
reproduce. `sbom.json` is a byte-for-byte copy of the committed parity golden
in the Eshu core repository. `osruntime.json` and `image.json` differ from the
core copies in exactly one field, `ObservedAt` on the `vulnerability.os_package`
facts (see "The one documented delta"). A golden changes only with a
documented contract delta and the normalized diff below; a mismatch otherwise
means the port drifted.

| File | Source repository | Source path | Added in | Core blob | Core sha256 |
| --- | --- | --- | --- | --- | --- |
| `osruntime.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/osruntime.json` | `aa95dbcdac` (#9741) | `8ed6ac336de402b3ff5e4182fbec7663df071622` | `5f6a853a17a572324b2c8d86e32a2cffdc0a18b58b75b314e8a550f3d7ad47d4` |
| `image.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/image.json` | `aa95dbcdac` (#9741) | `2ab1453d8135a1eab188282633b653bee5e792dc` | `cc4df57904eb652251ba0fb90a8886d29392233af4fb3b1e4e823471a284de5a` |
| `sbom.json` | eshu-hq/eshu | `go/internal/collector/extensionhost/testdata/scanner-parity/sbom.json` | `aa95dbcdac` (#9741) | `00906c1da3c64b27e086c178696541921722c1f7` | `0c20b90f53fedf5d32eb49404c4fbfb6b8bb20b7f4bed15314a384352ca20171` |

Copied from eshu `origin/main` at `f12ebc5f046f`. Refs eshu-hq/eshu#8878.

## Capture inputs

The goldens were captured at the #9741 removal from the pre-removal parity
driver (`go/internal/collector/extensionhost/analyzer_parity_test.go` at eshu
`aa95dbcdac^`): a 60-package synthetic Alpine 3.19.1 rootfs, scope
`image://registry.example/parity@sha256:deadbeef...`, generation
`scanner-worker:generation-parity`, fencing token 13, collector instance
`scanner-parity`, source URI `oci://registry.example/parity@sha256:deadbeef`.
The image capture adds image reference `registry.example/parity:1.0` and
image digest `sha256:aaaa...`. The SBOM capture used scope
`scanner-worker://repository/parity-repo` and a synthetic 40-component npm
inventory from a fake source, not a repository walk. The satellite parity
tests rebuild the same inputs.

## The one documented delta (eshu-hq/eshu-scanner-worker#33)

In the core goldens `osruntime.LocalRootFSProvider` stamped each snapshot with
the wall clock, so every `vulnerability.os_package` fact carried its capture
time: `2026-10-31T16:08:20.743925041Z` in `osruntime.json` and
`2026-10-31T16:08:20.742184584Z` in `image.json`. That stamp shifted page
boundaries between the stateless per-page calls of one claim. The satellite
stamps every fact of a claim with the claim observation time instead, so
those facts now carry the parity test clock, `2026-07-08T12:00:00Z`, as the
other image facts already did. The snapshot carries no clock any more, so
the parity tests no longer pin one.

| File | Core blob sha256 | Satellite sha256 | Delta |
| --- | --- | --- | --- |
| `osruntime.json` | `5f6a853a17a572324b2c8d86e32a2cffdc0a18b58b75b314e8a550f3d7ad47d4` | `96bca0f6d7dfd59cc0736ebbde580d8baab481760f528222c6787ab4bd461e66` | `ObservedAt` on the 60 `vulnerability.os_package` facts: `2026-10-31T16:08:20.743925041Z` to `2026-07-08T12:00:00Z` |
| `image.json` | `cc4df57904eb652251ba0fb90a8886d29392233af4fb3b1e4e823471a284de5a` | `ec959b2729a40c70303db2eba804f6ec3cda7318eaa27037815bcd945c3f2728` | `ObservedAt` on the 60 `vulnerability.os_package` facts: `2026-10-31T16:08:20.742184584Z` to `2026-07-08T12:00:00Z` |
| `sbom.json` | `0c20b90f53fedf5d32eb49404c4fbfb6b8bb20b7f4bed15314a384352ca20171` | `0c20b90f53fedf5d32eb49404c4fbfb6b8bb20b7f4bed15314a384352ca20171` | none |

Normalized diff against the core copy (the goldens marshal `facts.Envelope`,
whose field is `ObservedAt`); both must print nothing, and the unique-value
query must print exactly `["2026-07-08T12:00:00Z"]`:

```sh
diff <(jq 'map(del(.ObservedAt))' core/osruntime.json) <(jq 'map(del(.ObservedAt))' osruntime.json)
diff <(jq 'map(del(.ObservedAt))' core/image.json) <(jq 'map(del(.ObservedAt))' image.json)
jq -c '[.[].ObservedAt] | unique' osruntime.json image.json
```

Every other byte is computed by the ported analyzers. If core later
converges its copies, the delta disappears; core's parity test never reads
`observed_at`, so the two copies can differ without a core failure.
