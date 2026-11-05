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
| A failure a retry could still change (table below) | retryable | n/a | the class | none, no generation |
| No `go.mod` of any type | complete | false | empty | one `no_go_modules` warning |
| Every module parsed and analyzed | complete | false | empty | evidence and reachability |
| A scan over a cgo-incomplete graph | partial | true | `analysis_failed` | the rest, the module's `symbol` facts, one `cgo_excluded` warning; its `not_called` pairs withheld |
| A module omitted for a terminal reason | partial | true | the class; toolchain wins | the rest, plus one warning per omitted module |
| No stage wired, any `go.mod` | partial | true | empty | evidence only |

A failed module has no reachability fact. Its earlier fact leaves truth with the prior
generation and the finding reads as missing evidence: the old verdict measured another
commit or database, so it is never carried forward.

Retry is per class, read against the claim's attempt number (the first run is attempt
1). The satellite never hardcodes the host's attempt budget: the claim does not carry
it, and the host ends an always-retryable class as `attempt_budget_exhausted` with no
generation. When a failure is retryable on this attempt, the stage stops scanning the
remaining modules and returns at once — nothing from the run commits, so each further
scan would only pay a full package load before the same outage. Terminal module
failures keep the loop going so the commit carries the rest of the repository.

| Reason | Attempt 1 | Attempt ≥ 2 | `retry_after_seconds` |
| --- | --- | --- | --- |
| `vulndb_unavailable` | retryable, no generation | retryable, every attempt; never commits a warned module | 300 |
| `module_download_failed` naming `404 Not Found` or `410 Gone` | terminal for the module: commits with the warning | same | — |
| `module_download_failed`, any other marker | retryable, no generation | retryable, every attempt | 300 |
| `analysis_timeout` | retryable, no generation | terminal for the module: commits with the warning | 60 |
| `source_unavailable` (scan cache or scratch will not open) | retryable | retryable, every attempt | 60 |

A 404 from the proxy is deterministic under the fleet policy (no `GOPRIVATE`), so it is
terminal like `toolchain_unsupported`; when a 404 line and a `dial tcp` line both
appear, the status code wins because the proxy answered. A committed generation
therefore never carries a `vulndb_unavailable` warning, and its
`module_download_failed` warnings are always the 404/410 kind.

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
reason)`. factschema `v0.1.0-rc.17` types `repository_id` and `relative_path`. One edge is not
byte-equal: a valid path holding `%` whose `go.mod` declares invalid text gets an escaped
`go_mod_invalid_path` warning path, so it does not join its evidence rows. That module then
has no reachability evidence, and never reads `not_called`.

| Reason | Meaning |
| --- | --- |
| `toolchain_unsupported` | A `go` or `toolchain` directive, or a dependency, needs a newer Go than the pin. |
| `cgo_required` | A package needs cgo, which the scan disables. No facts from this module. |
| `cgo_excluded` | The scan finished, but a file only cgo excluded was not in its graph, so `not_called` could be wrong. The module's `symbol` facts are written, its `not_called` pairs withheld. |
| `analysis_timeout` | The scan did not finish in its budget. |
| `module_download_failed` | A required module would not fetch, including a private one. |
| `vulndb_unavailable` | The vulnerability database was not reachable. |
| `analysis_failed` | Any other failure, such as a type error or a crash. |
| `module_budget_exceeded` | Whole repository: more modules than one claim scans. |
| `go_mod_parse_failed`, `go_mod_too_large`, `go_mod_not_regular`, `go_mod_invalid_path` | The `go.mod` could not be used. |
| `replace_outside_checkout` | A local `replace` leaves the checkout, as written or through a link. A scan would report that code as this commit's, so the module is not scanned and its evidence stays. Terminal for the commit. |
| `link_outside_checkout` | A link under the module, or under one of its local replace roots, resolves outside the checkout. The go command reads a linked `.go` file and a linked package directory from outside the module, so no child starts; the evidence stays. Terminal for the commit. A link that stays inside the checkout, and a dangling link, are allowed. |
| `go_sum_not_regular` | The `go.sum` beside the `go.mod` is a link. The go command would write through it, so the module is not scanned and its evidence stays. |
| `no_go_modules`, `no_module_requirements` | The scan finished with nothing to report. |

## The scan

`ScanStage` runs `govulncheck -json -mode source ./...` in each module directory, as a
child in its own process group, so a crash or timeout costs one module. The child's
environment is built from nothing; a test asserts it whole. The token never reaches it.
Before any child starts, the module directory and every local replace root are walked
without following links, and a link resolving outside the checkout refuses the module
(`link_outside_checkout`): measured, `go list` reads a linked `.go` file and a linked
directory from outside the module, so it would report code that is not in this commit.

`not_called` means govulncheck's static call graph found no path under the scan
configuration GOOS=linux, GOARCH of the image, CGO_ENABLED=0, no build tags, no test
code; calls through `reflect`, `unsafe`, and function values are the documented
govulncheck caveats. The stderr record carries `goos` and `goarch` labels for the
configuration a run used. GOOS, GOARCH, and custom-tag exclusions are this stated
caveat, never a withheld verdict: withholding for them would make `not_called`
unreachable on nearly every module that depends on `golang.org/x/sys`. Cgo is the one
exception, because a `!cgo` fallback beside a cgo file is a stub for a build the author
does not ship, so the cgo-off graph is systematically not the deployed graph. A fold
that produced at least one `not_called` pair therefore pays one `go list -e -deps`
probe (the same probe that names a failed scan `cgo_required`), under the module
context that bounded the scan. If a file in a non-standard package was excluded only
by cgo, the module keeps its `symbol` facts and withholds every `not_called` pair
under `cgo_excluded`; a probe that errors fails the module whole rather than guess.
This finished-but-incomplete shape refines the factschema warning table: the scan
finished with a trustworthy config, so its symbol facts are written beside the warning
(a doc-comment row for it is owed by the next factschema release candidate). The
stderr figures count it as `modules_cgo_excluded` and `findings_not_called_withheld`.

Operators may set `GOPROXY`, `GOSUMDB`, `GOVULNDB`, `HTTPS_PROXY`, `NO_PROXY`, and
`SSL_CERT_FILE`. A Go policy variable such as `GOFLAGS`, or a `GOPROXY` naming `direct`,
fails the claim with `component_bad_config` and the stderr reason `env_refused`.

`GOVCS` is `*:off`. The go command reads it as `pattern:vcslist` and calls a bare `off`
malformed (`cmd/go/internal/vcs/vcs.go`, `parseGOVCS`).

Real output that shaped the code, recorded in
[testdata/govulncheck](testdata/govulncheck/README.md):

- A cgo dependency does not print anything about cgo. On eshu-hq/eshu the scan printed
  only `undefined: tree_sitter.Node`, so a failed scan asks `go list` for the files the
  build excluded from non-standard packages. A file counts only if it imports `"C"` and
  `go/build` accepts it with cgo on, so only cgo excluded it. `golang.org/x/sys/unix` ships
  `//go:build ignore` files that import `"C"`, and those never name a failure.
- A module with no Go files and a module whose only Go file imports `"C"` print the
  same line and exit 2. A scan that matched no packages reads the tree to tell them
  apart. A module with no Go files is a finished scan with no facts.
- A vulnerable module that is required but never imported produces no finding at all, so
  it has no fact and no warning and stays `unknown`. It is never `not_called`: a run that
  required `golang.org/x/crypto` at a vulnerable version without importing it reported
  nothing for that module. A fixture corpus must expect `unknown` for this case. The
  same holds for a module imported only from a cgo-excluded file: no finding, no fact,
  missing evidence — so a fold with no `not_called` pair runs no cgo probe and earns no
  warning.
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

- **Memory did not hold.** eshu-hq/eshu's `go` module peaked at 10.3 GiB, the highest of
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

The cgo probe over the same repositories (2026-11-05, this host under shared load, the
pinned `go1.26.10`, warm module cache, `go list -e -deps` under the scan environment;
`-mod=readonly`, so measuring a live checkout could not rewrite its go.mod). Only a
module whose fold produced a `not_called` pair, or whose scan failed with a plain
`analysis_failed`, ever pays it — these totals are the pay-for-every-module upper
bound, and `findings_not_called_withheld` is from the real scan where one ran:

| Repository | Modules | `modules_cgo_excluded` | Withheld | Probe wall s (per module: max / total) |
| --- | --- | --- | --- | --- |
| Fixture (cgopair: a `//go:build cgo` caller beside a `!cgo` stub) | 1 | 1 | 4 | 0.09 / 0.09 |
| eshu-hq/eshu-scanner-worker | 1 | 0 | 0 | 1.38 / 1.38 |
| eshu-hq/eshu (16 tracked modules outside testdata) | 16 | 0 reported; 1 probe-positive (`go`, whose scan already fails `cgo_required` on the probe's failure arm, so it withholds nothing and never reaches the figure) | 0 | 32.74 (`go`; every other module about a second or less) / 33.62 |
| golang/tools `1ca5072` | 3 | 0 | 0 | 0.18 / 0.19 (`gopls` does not list on Go 1.26; its scan fails `toolchain_unsupported` before any probe) |

A second probe run the same day, through the production probe on the same four
repositories, reproduced every excluded verdict above (fixture 1; eshu `go` only;
scanner-worker and golang/tools 0, with `gopls` not listing on Go 1.26) at lower
walls under lighter load (`go` 15.06 s; the real cgopair scan again withheld 4).

**The budgets held unchanged.** The probe shares the scan's 5-minute module context:
the worst module here (`go`, 32.74 s) spent 134.38 s scanning cold before failing, so
scan plus probe stays well inside it, and no claim approaches the 10-minute budget —
eshu-hq/eshu's warm claim was 33.35 s against a 33.62 s all-modules probe upper bound
it would only partly pay. The real cgopair scan through `ScanStage` withheld its 4
`not_called` pairs under one `cgo_excluded` warning and emitted no `not_called` fact;
the control without the constraint read `findings_symbol: 1` with no warning.

Numbers not yet recorded: a large many-module repository that scans cleanly (etcd at a
tag older than Go 1.27), and a re-run on the final image.
