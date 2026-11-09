# The per-job contract

Every program runs the same lifecycle. Only the scan in the
middle differs. See [diagrams](../diagrams/README.md) for
the placement diagram and the invocation sequence, with
captions and text versions.

In prose: the host validates the claim, the activation (its
saved settings), and producer grants (permission records for
fact kinds). Then it runs the seeded program with no
arguments and one request JSON on stdin. The program scans
and writes one result page to stdout. Exit `0` is success;
exit `1` is a failure the host treats as retryable. If more
pages remain, the host runs it again with the cursor. The
protocol on the wire is `collector-sdk/v1alpha3`.

Data in is one request holding the claim, the contract, and
config. For image, SBOM, and osruntime the config carries
`targets`, `acceptance_unit_id`, and optional
`page_bound_bytes`. Every key is in
[configuration](../reference/configuration.md).

## What each one emits

These lists mirror the `emittedKinds` declarations in
`go/internal/collector/scannerworker/component/manifest.go`,
which is what `seed` stamps into each `manifest.yaml`. If
you change a list there, update this section in the same
change.

- image: `scanner_worker.analysis`, `scanner_worker.warning`,
  `vulnerability.os_package`, `vulnerability.warning`
- sbom: `sbom.document`, `sbom.component`, `sbom.warning`
- osruntime: `vulnerability.os_package`, `vulnerability.warning`
- go-reachability: `vulnerability.go_module_evidence`,
  `vulnerability.go_call_reachability`, `vulnerability.warning`,
  `scanner_worker.warning`

The first three scanners were ported from core, and their
output is tested against recorded expected outputs from
core. There's one known difference: rootfs
`vulnerability.os_package` facts carry the claim observation
time, not the file-read time. See [INTERIM.md](../../INTERIM.md).

## Go reachability is the odd one out

It differs in three ways. First, it takes its target and a
short-lived GitHub installation token from the host
(`host_derived_target`, `host_github_app_token`), not from
saved settings, and core doesn't admit it yet (see
[INTERIM.md](../../INTERIM.md)). Second, it fetches one
commit, reads `go.mod` files, then runs the seeded
`govulncheck` per module; the token goes only to
`github.com` unless `allowed_clone_hosts` names other hosts.
Third, it needs a `git` binary on `PATH`. Limits and token
rules are in [SECURITY.md](../../SECURITY.md).
