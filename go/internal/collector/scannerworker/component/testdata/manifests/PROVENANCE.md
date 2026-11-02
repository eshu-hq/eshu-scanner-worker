# Scanner component manifests: provenance

These are the manifests eshu core's admission pins expect, captured by
marshaling `scannercomponent.ManifestFor` for each analyzer with
`gopkg.in/yaml.v3` from eshu `origin/main` at `82c9ef362e` (the encoder
the seed step uses). The satellite `ManifestFor` plus the seeded image must
reproduce them byte for byte; core keeps the digest pins and enforces
equality at admission (`VerifySeededArtifact`). Refs eshu-hq/eshu#8878.

| File | sha256 |
| --- | --- |
| `image_unpacking.manifest.yaml` | `a7ff5da29feb1de5f117fd23301176f9e8d7db8158fea934e0469cc83339a0ed` |
| `os_package_extraction.manifest.yaml` | `5ee12b0533129c31d46538162ec4585d764c37af0dd023e9ba0b38d440840c07` |
| `sbom_generation.manifest.yaml` | `437e1e4184c9818fc198c25e590448d9cd89e1b4c0eb3e1bdb74b9ab24b518ab` |

Recapture after a core manifest change (kinds, versions, compatibleCore) and
land the satellite change in the same release.
