# Recorded govulncheck output

Test input only. Messages are re-serialized one per line, with key order and values
unchanged; govulncheck itself prints indented JSON.

## From eshu-hq/eshu#10028

- Tool: `govulncheck@v1.9.0`, Go `go1.26.6` (linux/arm64), DB `https://vuln.go.dev`
  last modified `2026-11-02T22:01:43Z`.
- Module: `example.com/gvcexp` requiring `golang.org/x/text v0.3.5`; `main` calls
  `language.Parse` and never calls `language.ParseAcceptLanguage`.

| File | Command | Notes |
| --- | --- | --- |
| `xtext_v0_3_5_symbol_source.jsonl` | `govulncheck -json -mode source ./...` (exit 0) | All 27 `finding` messages, `config`, `SBOM`, and both `progress` messages kept. 188 of 192 `osv` messages dropped. |
| `xtext_v0_3_5_package_source.jsonl` | `govulncheck -scan package -json ./...` (exit 0) | Only the x/text `finding` messages and the two matching `osv` messages. |
| `toolchain_unsupported_config_only.jsonl` | same module with `go 1.99`, `GOTOOLCHAIN=local` (exit 1) | The only stdout govulncheck wrote: the `config` message. |
| `toolchain_unsupported.stderr.txt` | same run | stderr of the failed run. |

## From eshu-hq/eshu-scanner-worker#48

Recorded with the toolchain and scanner seeded from the built image, in the exact child
environment: Go `go1.26.10`, `govulncheck@v1.9.0`, the same DB timestamp.

| File | Command | Notes |
| --- | --- | --- |
| `gvcexp_go1_26_10_symbol.jsonl` | `govulncheck -json -mode source ./...` (exit 0) | Every message except `osv`, whose bodies are 99% of the 585 KB stream. |
| `gvcexp_go1_26_10_package.jsonl` | `govulncheck -json -scan package -mode source ./...` (exit 0) | The same, at package level. |
| `gvcexp_go1_26_10_symbol.txt` | `govulncheck -mode source ./...` (exit 3) | govulncheck's own text summary, the parity oracle. |

Each `stderr_*.txt` is a failed run's stderr under the same environment, with
machine-local path prefixes removed and blank lines dropped.

| File | Run | Exit |
| --- | --- | --- |
| `stderr_proxy_down.txt` | `GOPROXY` at a closed port, empty module cache | 1 |
| `stderr_private.txt` | `require example.invalid/private`: the proxy answers 404 | 1 |
| `stderr_db_down.txt` | `-db` at a closed port | 1 |
| `stderr_type_error.txt` | a package that does not type-check | 1 |
| `stderr_no_packages.txt` | a module with no Go files | 2 |
| `stderr_cgo_only.txt` | a module whose only Go file imports "C" | 2 |

The last two are byte-identical, which is why a scan that matched no packages reads the
tree to tell them apart.
