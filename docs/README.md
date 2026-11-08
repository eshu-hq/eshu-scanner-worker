# Documentation

Welcome in. This is the map for `eshu-scanner-worker`.
First things first: this repo is not a service. There's no
daemon, nothing listens on a port, and nothing polls for
work. It's four short-lived scanner programs that Eshu's
host starts once per job.

If you're deciding whether you need this repo at all, the
concepts pages will settle it quickly. If you're seeding or
debugging a run, head for the guides.

| Start here | What's in it |
|---|---|
| [Getting started](getting-started/README.md) | Probe a binary and drive one stdio call by hand |
| [Guides](guides/README.md) | Operate, troubleshoot, seed, and release |
| [Concepts](concepts/README.md) | The per-job contract and the isolation boundary |
| [Reference](reference/README.md) | Request config keys and the command-line surface |
| [Architecture](architecture/README.md) | Place in Eshu, with the per-binary map |
| [Diagrams](diagrams/README.md) | Every diagram, with captions and text versions |
| [Decisions](decisions/README.md) | Architecture decision records |
| [Contributing](contributing/README.md) | Local checks before you open a pull request |

A claim is one unit of work Eshu hands out, a fact is one
stored observation, an SBOM is a list of the components in a
build, and a rootfs is a container image's file system after
unpacking. The [top-level README](../README.md) keeps the
short version and one overview diagram.
