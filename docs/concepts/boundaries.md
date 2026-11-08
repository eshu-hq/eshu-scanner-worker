# Boundaries

Scanners parse untrusted input: image layers, package
databases, lockfiles, repository checkouts. That's exactly
the sort of code you don't want living inside a long-running
process with credentials and a database handle. So each scan
runs in its own one-shot program that owns no claim, no
store, and (except for go-reachability's one fetch) no
network. The host validates the claim and permissions before
launch, and if a scanner falls over, it falls over alone.

These programs talk to stdin and stdout, plus, for
go-reachability only, the git remote. They never touch
Postgres, the graph, queues, or claim state.
`boundary_test.go` fails the build on any import of core
internals, so that boundary isn't just a convention.

They take no environment variables, listen on no ports, and
read no config files. Everything arrives inside the
request's config block, per run: the host decides, the
scanner obeys, and there's no ambient state to drift.
Unknown component ids and unknown config keys fail closed.
