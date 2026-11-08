# Seed the scanner programs

Eshu doesn't exec the image entry point per claim. First, a
seed step installs the program from its image into a runtime
directory:

```bash
/usr/local/bin/eshu-scanner-component-<name> seed --dest DIR --image-ref REF
```

Seed writes `DIR/collector` (the program itself) and
`DIR/manifest.yaml` (its declaration, with `REF` stamped in).
`REF` must be the digest-pinned image for that component,
`ghcr.io/eshu-hq/scanner-<name>@sha256:...`. Anything else is
refused before a byte is written. Core then checks the
stamped reference against its own pins before admitting
work, so a drifted or foreign binary doesn't get to scan
anything.

The go-reachability seed also copies a Go toolchain and
`govulncheck` to `DIR/toolchain`, because the program runs
`govulncheck` per module and can't assume the worker has
one.

Re-running seed is safe, and it's the fix for most drift.
When in doubt, re-seed.

To build one image locally:

```bash
docker build --target scanner-osruntime -t scanner-osruntime .
```
