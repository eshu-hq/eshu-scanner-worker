# Contributing

Thanks for helping. Read [CONTRIBUTING.md](../../CONTRIBUTING.md)
before opening a pull request; this is the short version.

Go version is pinned in `go.mod` (`go 1.26.10`, module
`github.com/eshu-hq/eshu-scanner-worker`). SDK pins from
`go.mod` are `eshu-sdk/collector v0.2.0-rc.3` and
`eshu-sdk/factschema v0.1.0-rc.17`; `govulncheck` is pinned
by the `tool` directive.

```bash
make ci       # lint + test + race, same commands CI runs
make ci-lint  # vet, golangci-lint, tidy check, 500-line cap
make ci-test  # build + full test suite
make ci-race  # race suite + coverage floor (96.8)
make help     # list targets
```

One local extra: `scripts/scanner-worker-seed-matrix.sh`
proves each lint and test lane catches a planted defect.
It's a checker for the checks, not a CI gate.

Report security problems as described in
[SECURITY.md](../../SECURITY.md). Source files carry
`SPDX-License-Identifier: MIT`; there's no separate LICENSE
file in this tree.
