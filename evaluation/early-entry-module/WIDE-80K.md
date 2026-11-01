# Optional-entry 80,000-step profile

`qualification-feature-optional-entry-80k-v1` is a separate full-state
qualification profile, with its own `normal-early-entry-state-80k` command,
`state_wide_80k.py` recipe and profile identifier on every result row. Its
instruction budget is 80,000 steps per child. The strict 20,000-step profile
and recipe remain unchanged and continue to run and report their failures.
No strict failure is relabeled as an 80k pass.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

The wider profile retains all 288 pairs, 576 children, twelve cohorts and 640
witness words, the same architectural-state and control-flow comparisons,
the shared 15-second pair deadline and two-second child cleanup. It uses a
separate typed oracle wrapper; no runtime budget argument changes the strict
oracle. Both result readers reject rows carrying the other profile's name.

Each profile runs as a separate fixed campaign from the beginning, with a new
output directory, no replacement attempts and every failed or unobserved
cohort retained. Run assertions-enabled Python with `-I -B`, using the same
`--revision`, `--root`, `--toolchain`, `--user-home`, `--cargo-home` and
`--output` arguments as `state.py`. Reserve a single disjoint CPU externally
and preserve the existing cumulative capacity budget. Builds use the release
profile; timing measurements are not part of this qualification.

The [results at `b9995b86`](presence-80k/README.md) record all 288 pairs,
576 children and 139,872 state comparisons passing under this named profile.
The same revision replaces repeated presence scans with exact occupancy masks.
The strict 20,000-step campaign remains FAILED, and the full workspace gate
timed out at its unchanged limit. This is a review checkpoint, with no timing
or complete A4/A5 qualification. The [earlier strict results](README.md) remain
available unchanged.
