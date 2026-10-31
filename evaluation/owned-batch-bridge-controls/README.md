# Owned-batch and full-program bridge focused validation

Both focused runs passed their four commands. These results do not replace the earlier failed full gates or establish native execution.

| Revision | Results |
|---|---|
| `09f736a064b571cecb5f70166e380cfa06e99573` | Formatting and strict rapid-profiler Clippy passed; `owned_` library filter: **14 passed, 0 failed, 1 ignored**, 562 filtered; two compile-fail examples passed. |
| `5f605b7b3eb09dd6c3bd037b1d571fdf2da30d7b` | Formatting and strict rewrite Clippy passed; **7 bridge tests passed**; all existing/new E9-sites Python controls completed with exit 0. |

The first library filter includes the six new pure controls. Its one ignored test is the explicit fresh-process owned-module native control; this receipt gives it no execution credit. The doctest output contains a zero-test summary followed by the two successful compile-fail examples. The Python script reports 3 accepted/24 refused base fixtures and all 14 control-group markers, including the three PIE groups; it emits no aggregate individual-case total.

[receipt.json](receipt.json) records each exact argv, revision/tree, start time, duration, CPU assignment, load and private log hash. Every command ran once under the existing `evaluation/admission/processes.py::run_command` owner with 180 s/8 MiB bounds, normal exit 0, complete cleanup and zero reaped descendants. Hardware: AMD EPYC Zen 5 dev host; configured stable rustc 1.97.1. Nine environment overrides are recorded; other environment was inherited.

To reproduce, check out each exact revision, apply those overrides, reserve four disjoint HARD CPUs, and run its four listed commands in order through that existing bounded owner with fresh log paths. No new runner is required. Compile-fail failures and synthetic argument refusals are expected assertions, not skipped failures.

This is focused validation only. Full-program code/data admission, actual upstream rewriting and common-program execution remain separate work. The real owned-module native result is also separate. No performance, hardware single-step, full-A5 or historical profiler-population claim changes; all original bounds and prior failures remain.
