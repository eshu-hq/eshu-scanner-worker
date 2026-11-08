# Getting started

There's nothing to deploy, so getting started means running
one scanner once, the same way the host does: one JSON
request in on stdin, one JSON result page out on stdout,
then exit.

```bash
go run ./go/cmd/scanner-component-osruntime --version   # probe only
go run ./go/cmd/scanner-component-osruntime < request.json > result.json
```

You'll need a request shaped like the ones the host builds.
The component tests under
`go/internal/collector/scannerworker/component/` are the
most honest examples in the tree.

## How Eshu runs it, in four lines

A seed step installs each program from its digest-pinned
image into a runtime directory. Core checks the stamped
image reference against its own pins before admitting work.
Then, per claim, the host runs the seeded program with no
arguments and re-invokes with a cursor if more pages remain.

Next: the [per-binary map](../architecture/README.md), the
[seed guide](../guides/seed.md), and the request keys in
[configuration](../reference/configuration.md).
