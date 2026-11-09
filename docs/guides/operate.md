# Operate the scanner programs

Don't deploy these as services. Eshu runs them per claim, so
operating them means publishing images and seeding from them
(see [seed](seed.md)). If you're writing a Deployment
manifest with replicas, put the keyboard down.

## Signals from a single run

There's no health endpoint, because there's no server. You
read a run from three things:

- Exit code: `0` is success, `1` is failure, and the host
  treats a failure as retryable.
- stderr: structured log lines for the run. Target names,
  paths, and credentials stay out of logs and errors by
  design, so don't expect to find them there while debugging.
- stdout: exactly one result document. Warning facts inside
  it name what couldn't be read, so a partial scan still
  tells you what's missing instead of pretending everything
  was fine.

Results can span several pages; the host re-invokes the
program with a continuation cursor until the final page. A
request is capped at 1 MiB.

Diagrams live in [diagrams](../diagrams/README.md).
