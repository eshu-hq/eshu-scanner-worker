# eshu-scanner-worker

[![ci](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml/badge.svg)](https://github.com/eshu-hq/eshu-scanner-worker/actions/workflows/ci.yml)

Eshu scanner execution and worker lifecycle. Pre-release: holds no cutover authority until its reviewed cutover. Refs #8878, part of #6707.

## Layout

Go module `github.com/eshu-hq/eshu-scanner-worker`: the scanner component
lane ported from Eshu core (eshu-hq/eshu#8878 box 10). Landed so far:
analyzer kinds and lanes, the OS package parsers and envelopes, the
`osruntime`, image, and SBOM analyzers, and the v1alpha3 stdio runner
(`go/internal/collector/scannerworker/component`), proven byte-identical
to the core parity goldens. The component commands and the image publish
follow; see [INTERIM.md](INTERIM.md).

```sh
make ci   # lint + test + race, same commands CI runs
```
