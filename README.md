# eshu-scanner-worker

[![ci](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml)

Eshu scanner execution and worker lifecycle. Pre-release: holds no cutover authority until its reviewed cutover. Refs #8878, part of #6707.

## Layout

First Go module (`github.com/eshu-hq/eshu-scanner-worker`): the
dependency-free scanner pieces relocated byte-identical from Eshu core —
analyzer kinds and lanes (`go/internal/collector/scannerworker`) and OS
package parsers (`go/internal/collector/ospackagevulnerability`). The
claim loop, analyzers, envelopes, and binary stay core-side until the
claim-client and public-contract gates land; see [INTERIM.md](INTERIM.md).

```sh
make ci   # lint + test + race, same commands CI runs
```
