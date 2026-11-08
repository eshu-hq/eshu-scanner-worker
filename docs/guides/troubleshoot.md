# Troubleshoot the scanner programs

## When Eshu refuses the work

Admission is the common failure point, and it's usually
boring. Check that the seeded `manifest.yaml` image
reference matches core's pin, and that `DIR/collector` is
executable. Re-seeding repairs both (see [seed](seed.md)).
If it still refuses, look at which digest core has pinned
versus which digest you seeded. Nine times out of ten
that's the whole story.

## Go reachability specifics

- Confirm `git` is on `PATH` in the process that runs it.
- Confirm the clone host is either `github.com` or named in
  `allowed_clone_hosts`.
- Remember its target and token come from the host
  (`host_derived_target`, `host_github_app_token`), not from
  saved settings. See
  [configuration](../reference/configuration.md) and
  [SECURITY.md](../../SECURITY.md).

## Reading a failed run

Exit `1` is a retryable launch failure to the host. Check
stderr for the run's structured lines, and check the warning
facts in stdout on partial scans; they name what couldn't be
read. Unknown component ids and unknown config keys fail
closed, so a typo is an error, not a silent skip.
