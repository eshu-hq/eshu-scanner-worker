# Release the scanner programs

One `Dockerfile` builds all four binaries. Each final image
stage holds one program on a distroless base with no shell:
`ghcr.io/eshu-hq/scanner-image`, `ghcr.io/eshu-hq/scanner-sbom`,
`ghcr.io/eshu-hq/scanner-osruntime`, and
`ghcr.io/eshu-hq/scanner-go-reachability`. That last one also
carries `govulncheck` and a trimmed Go toolchain for its
seed step.

Pushes to `main` and version tags run
`.github/workflows/release.yml`, which publishes the images.
Core consumes them by digest, and a new publish only takes
effect when core re-pins it (see [SECURITY.md](../../SECURITY.md)).
So "we shipped a fix" and "the fix is live" are two
different moments. Check the pin before you celebrate.

Port state and what's still staged live in
[INTERIM.md](../../INTERIM.md). Run `make ci` before you
tag; see [contributing](../contributing/README.md).
