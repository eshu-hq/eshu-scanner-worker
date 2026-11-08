# Configuration reference: scanner programs

There's less here than you might expect. These programs take no
environment variables, listen on no ports, and read no config files.
Everything they need arrives inside the request's config block, per
run. If you're looking for a settings file to edit, stop. There
isn't one, and that's deliberate: the host decides, the scanner
obeys, and there's no ambient state to drift.

## Keys inside the request

| Key | Used by | What it means |
|---|---|---|
| `targets` | image, sbom, osruntime | What to scan. At least one required |
| `acceptance_unit_id` | image, sbom, osruntime | Unit the claim covers. Must not be blank, and must match the claim scope |
| `page_bound_bytes` | all | Optional smaller page cap. Values above the default are clamped, negative fails |
| `host_derived_target` | go-reachability | Host-supplied repository and commit |
| `host_github_app_token` | go-reachability | Host-minted token for the fetch. Other components reject this key |
| `allowed_clone_hosts` | go-reachability | Hosts the token may reach. Absent means `github.com` only |

A few things worth slowing down on:

- `targets` has a different shape per scanner, because an image, a
  lockfile set, and an unpacked rootfs aren't the same kind of
  thing. Don't copy a working target block from one scanner to
  another and expect it to mean anything.
- Unknown keys fail closed. A typo'd key is an error, not a hint
  that gets ignored. Same for unknown component ids.
- `page_bound_bytes` can only shrink a page. If you ask for more
  than the default you get the default, and if you ask for a
  negative number the call fails.

## The token, carefully

`host_github_app_token` deserves its own paragraph. It's a
short-lived GitHub installation token the host mints and passes in
the request. Go reachability uses it for exactly one fetch, to
`github.com` by default, or to the hosts named in
`allowed_clone_hosts` if the operator widened that. The other three
components reject the key outright, so a token can't wander into a
scanner that has no business holding one. Target names, paths, and
credentials stay out of logs and errors by design.

The full rules, including input budgets and failure behaviour, are
in [SECURITY.md](../../SECURITY.md). That document wins if this one and
it ever seem to disagree.

## The command line

Per program, the surface is small:

- No arguments: run one stdio call. This is what the host does.
- `--version` (or `-v`): print the version and exit. Handy as a
  probe to confirm you're running the binary you think you are.
- `seed --dest DIR --image-ref REF`: install the program into a
  runtime directory. The [operations doc](../guides/seed.md) explains
  seeding properly.

You can drive the stdio path by hand while developing:

```bash
go run ./go/cmd/scanner-component-osruntime < request.json > result.json
```

You'll need a request shaped like the ones the host builds. The
component tests under `go/internal/collector/scannerworker/component/`
are the most honest examples in the tree.
