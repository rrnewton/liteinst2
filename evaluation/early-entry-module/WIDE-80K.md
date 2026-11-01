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

No 80k execution result is recorded by this source addition. The existing
[strict results](README.md) remain FAILED. Reducing callback cost, including
the repeated presence scans, is separate work toward passing the strict gate.
