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

Two rules hold for every change:

- Coverage only rises: the `race` job fails below `COVERAGE_FLOOR`, which
  starts at the first measured baseline and ratchets to 90%.
- No Go file may exceed 500 lines (`ci-lint` and the `lint` lane enforce it
  with a plain `wc -l` step).

Docs-only PRs (Markdown, `LICENSE`) run no lane; `ci-complete` reports
success and the PR stays mergeable.
