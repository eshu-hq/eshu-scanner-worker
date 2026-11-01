# Contributing to eshu-scanner-worker

## CI gates (epic #1)

Every PR runs the path-aware lanes in `.github/workflows/ci.yml`. A PR only
pays for lanes its paths can affect; `ci-complete` is the only required
status on `main` and succeeds when lanes were legitimately skipped
(docs-only PRs run no lane and stay mergeable).

Run the local mirror before pushing:

```sh
make ci   # lint + test + race, same commands CI runs
```

`scripts/scanner-worker-seed-matrix.sh` is the local proof that those lanes
catch what they claim to: it plants a seeded vet error, lint finding,
unformatted file, data race, `go.mod` drift, 501-line file, and an unreachable
coverage floor, asserts each lane turns red and names the seed, removes the
seed, and asserts green again. It is a local runner, not a CI gate, and it
leaves the tree as it found it.

Two rules hold for every change:

- Coverage only rises: the `race` job fails below `COVERAGE_FLOOR`, which
  sits at the highest measured baseline and ratchets to 90%. First
  measured baseline was 67.4% (analyzer lanes + OS parsers, PR #20); it is
  now 96.8% after the coverage-90 tests. Raise
  the floor in `Makefile` and `.github/workflows/ci.yml` together as
  tests land, never lower it.
- No Go file may exceed 500 lines (`ci-lint` and the `lint` lane enforce it
  with a plain `wc -l` step).

Docs-only PRs (Markdown, `LICENSE`) run no lane; `ci-complete` reports
success and the PR stays mergeable.
