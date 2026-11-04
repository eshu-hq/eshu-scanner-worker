# eshu-scanner-worker

[![ci](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml)

Eshu scanner execution and worker lifecycle. Pre-release: holds no cutover authority until its reviewed cutover. Refs #8878, part of #6707.

## Layout

Go module `github.com/eshu-hq/eshu-scanner-worker`: the scanner component
lane ported from Eshu core (eshu-hq/eshu#8878 box 10). Landed so far:
analyzer kinds and lanes, the OS package parsers and envelopes, the
`osruntime`, image, and SBOM analyzers, and the v1alpha3 stdio runner
(`go/internal/collector/scannerworker/component`), proven byte-identical
to the core parity goldens except `observed_at` on rootfs
`vulnerability.os_package` facts, which carries the claim observation time
(#33), the three ported `scanner-component-*` commands, and
the image build (`Dockerfile`) and publish (`.github/workflows/release.yml`).
See [INTERIM.md](INTERIM.md) for the port state and [SECURITY.md](SECURITY.md)
for verification and version pairs.

A fourth component is new rather than ported. `eshu.scanner.go-reachability`
(#47, part of eshu-hq/eshu#10002) fetches a claimed repository at one commit with
a host-minted installation token and emits `vulnerability.go_module_evidence`
from each `go.mod`. It sends the token only to `github.com` unless the activation's
`allowed_clone_hosts` names other hosts. It reports every module-bearing result as
partial until the govulncheck stage (#48) lands. Core does not admit it yet.

```sh
make ci   # lint + test + race, same commands CI runs
```
