# goreachability

The `go_reachability` scanner analyzer: for one claimed repository it fetches the
commit Eshu observed, emits `vulnerability.go_module_evidence` from each `go.mod`, and
runs a pinned govulncheck per module to emit `vulnerability.go_call_reachability`.
[doc.go](doc.go) holds the package contract.

## What a generation means

Every committed generation is the full snapshot of one commit, so it sets
`TrustedDeletion=true`. A unit the component could not observe is named by a
`scanner_worker.warning` in the same generation. `Partial` is telemetry and readiness
only; it never decides supersession.

| Outcome | State | Partial | Failure class | Facts |
| --- | --- | --- | --- | --- |
| Checkout failed or auth denied | retryable or terminal | n/a | the class | none, no generation |
| Tree over a budget | terminal | n/a | the class | none, no generation |
| Module counts do not add up | terminal | n/a | `self_check_failed` | none, no generation |
| A retryable module class, first attempt | retryable | n/a | the class | none, no generation |
| No `go.mod` of any type | complete | false | empty | one `no_go_modules` warning |
| Every module parsed and analyzed | complete | false | empty | evidence and reachability |
| A module omitted for a terminal reason | partial | true | the class; toolchain wins | the rest, plus one warning per omitted module |
| No stage wired, any `go.mod` | partial | true | empty | evidence only |

A failed module has no reachability fact. Its earlier fact leaves truth with the prior
generation and the finding reads as missing evidence: the old verdict measured another
commit or database, so it is never carried forward.

Retryable classes are `analysis_timeout`, `module_download_failed`, and
`vulndb_unavailable`. They fail the whole claim once. From the second attempt each is
terminal for its module and the rest of the result commits.

## Freshness

The hint hashes the commit, the component version, the vulnerability database timestamp,
the pinned toolchain, and the govulncheck version. The store skips a generation whose hint
matches the current one, so an unchanged scan commits nothing, and an upgraded component,
scanner, or toolchain rescans the same commit.

A partial result also hashes its sorted warning keys. Otherwise a failed module's
generation would freeze a later clean scan of the same inputs. The same failure still
repeats as a duplicate. Stable fact keys do not include any of this.

## Warnings

Warnings are `scanner_worker.warning` facts with `analyzer: go_reachability`, the class
in `reason`, and `warning_class` always `scanner_worker_warning`. `relative_path` is the
go.mod file path, byte-equal to that file's evidence rows, and is absent for a
whole-repository warning. The stable key is `(analyzer, repository_id, relative_path,
reason)`. `repository_id` and `relative_path` are written as JSON keys until this module pins
factschema `v0.1.0-rc.17`, which types them.

| Reason | Meaning |
| --- | --- |
| `toolchain_unsupported` | A `go` or `toolchain` directive, or a dependency, needs a newer Go than the pin. |
| `cgo_required` | A package needs cgo, which the scan disables. |
| `analysis_timeout` | The scan did not finish in its budget. |
| `module_download_failed` | A required module would not fetch, including a private one. |
| `vulndb_unavailable` | The vulnerability database was not reachable. |
| `analysis_failed` | Any other failure, such as a type error or a crash. |
| `module_budget_exceeded` | Whole repository: more modules than one claim scans. |
| `go_mod_parse_failed`, `go_mod_too_large`, `go_mod_not_regular`, `go_mod_invalid_path` | The `go.mod` could not be used. |
| `no_go_modules`, `no_module_requirements` | The scan finished with nothing to report. |

## The scan

`ScanStage` runs `govulncheck -json -mode source ./...` in each module directory, as a
child in its own process group, so a crash or timeout costs one module. The child's
environment is built from nothing; a test asserts it whole. The token never reaches it.

Operators may set `GOPROXY`, `GOSUMDB`, `GOVULNDB`, `HTTPS_PROXY`, `NO_PROXY`, and
`SSL_CERT_FILE`. A Go policy variable such as `GOFLAGS`, or a `GOPROXY` naming `direct`,
fails the claim with `component_bad_config` and the stderr reason `env_refused`.

`GOVCS` is `*:off`. The go command reads it as `pattern:vcslist` and calls a bare `off`
malformed (`cmd/go/internal/vcs/vcs.go`, `parseGOVCS`).

Real output that shaped the code, recorded in
[testdata/govulncheck](testdata/govulncheck/README.md):

- A cgo dependency does not print anything about cgo. On eshu-hq/eshu the scan printed
  only `undefined: tree_sitter.Node`, so a failed scan asks `go list` whether any file
  the build excluded from a non-standard package imports `"C"`.
- A module with no Go files and a module whose only Go file imports `"C"` print the
  same line and exit 2. A scan that matched no packages reads the tree to tell them
  apart. A module with no Go files is a finished scan with no facts.
- A vulnerable module that is required but never imported produces no finding at all, so
  it has no fact and no warning and stays `unknown`. It is never `not_called`: a run that
  required `golang.org/x/crypto` at a vulnerable version without importing it reported
  nothing for that module. A fixture corpus must expect `unknown` for this case.
- govulncheck v1.9.0 emits `SBOM` messages, and osv bodies are 99% of the stream.

## Measured budgets

Host: linux/arm64, sharing load with other work, so walls are upper bounds. Toolchain
and scanner seeded from a local image build: Go `go1.26.10`, `govulncheck@v1.9.0`, DB
`2026-11-02T22:01:43Z`. Exact child environment. Each repository ran cold (empty caches)
then warm. Peak RSS is `/usr/bin/time -v`, per module. Cache is `GOMODCACHE` plus
`GOCACHE` after the cold run.

| Repository | Files / tree | Modules | Run | Checkout s | Largest module: download + scan s | Claim wall s | Peak RSS MiB | Cache | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Fixture (x/text v0.3.5) | 2 / 321 B | 1 | cold | 0.04 | 1.48 + 14.23 | 15.75 | 309 | 47 MB | 1 symbol, 3 not_called |
| | | | warm | 0.06 | 0.02 + 1.07 | 1.15 | 314 | | same |
| Fixture with nested `go 1.99` | 4 / 540 B | 2 | cold | 0.05 | 0.69 + 1.22 | 2.14 | 320 | shared | root clean; nested fails `go.mod requires go >= 1.99` |
| | | | warm | 0.04 | 0.01 + 0.87 | 1.03 | 286 | | same |
| eshu-hq/eshu-scanner-worker `7014e64` | 196 / 1.0 MB | 1 | cold | 0.40 | 4.19 + 4.83 | 9.42 | 1,235 | 619 MB | clean, no findings |
| | | | warm | 0.31 | 0.02 + 2.58 | 2.92 | 1,153 | | same |
| eshu-hq/eshu (cgo) | 30,909 / 208 MB | 15 | cold | 14.83 | 31.55 + 102.83 | 165.9 | **10,561** | 2.12 GB | `go` module fails on cgo; 11 of 15 clean |
| | | | warm | 8.16 | 0.57 + 9.38 | 33.35 | **10,492** | | same |
| golang/tools `1ca5072e6fc6` | 1,648 / 18 MB | 3 | cold | 1.20 | 0.26 + 3.48 | 5.46 | 1,342 | 30 MB | 2 symbol, 1 not_called; `gopls` needs Go 1.27 |
| | | | warm | 1.29 | 0.01 + 3.40 | 5.52 | 1,340 | | same |
| etcd-io/etcd `65da638638b2` | 1,501 / 15 MB | 14 | cold | 0.70 | 0 + 0.3 | 2.9 | 15 | none | all 14 need Go 1.27 |

What this decided, against the ruling's threshold of 10 minutes and 4 GiB:

- **Memory did not hold.** eshu-hq/eshu's `go` module peaked at 10.6 GiB, the highest of
  any run here, and that run stopped at type checking, so a large module that passes could
  go higher. The analyzer row rises to 12 GiB, and eshu-hq/eshu-deploy#40 carries the pod
  limit, so a live run needs a node with that headroom. Below it the kernel kills the scan,
  which costs one module as `analysis_failed` if it picks the child. Every other repository
  here stayed under 1.4 GiB.
- **Wall time held.** No claim passed 166 s and no module passed 135 s against the 10
  minute and 5 minute budgets.
- **The cache limit held.** The largest single repository left 2.12 GB against the 4 GiB
  prune threshold, but a pod scanning several large repositories will prune often.
- `toolchain_unsupported` is expected on recent repositories: every module of etcd at HEAD
  and golang/tools' `gopls` need Go 1.27, above the pinned `go1.26.10`. This is the largest
  source of missing evidence in this sample, and it ends when the pin moves.

Numbers not yet recorded: a large many-module repository that scans cleanly (etcd at a
tag older than Go 1.27), and a re-run on the final image.
