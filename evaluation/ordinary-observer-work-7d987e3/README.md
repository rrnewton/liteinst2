# Ordinary native and always-on common work

At `7d987e39135725611ab2e5fa208025b3a6795127`, both fresh release processes
completed the same 3,072 Exact37 calls through the existing 67-byte ordinary
C caller: 1,536 helper returns and 614,400 original-body semantic instructions
per process. All returned values and complete inputs matched.

Always-on retained all 3,072 records across 128 drains, checked all 65,536
journal words, and joined one final Report with exactly two publication-history
actions. Lifetime invocation IDs continued across every drain. Native created
no SDK journal/controller. This adds functional groundwork for comparing
observers; it supplies no throughput or accuracy result.

One fixed qualification ran on the AMD EPYC Zen 5 dev host. `cpuset-alloc`
reserved CPUs 3, 8, 25 and 40 for the owned tree; each new caller used CPU 3.
Load averages (1/5/15 minutes) were 34.77/31.80/32.98 before and
29.65/30.49/32.33 after. All 34 top-level stages passed, including the unchanged
prerequisite chain, seven new Rust controls and eleven parser controls.
The full run closed in 120.913 seconds, without timeout, rescue or retry.
That duration describes validation work, not application throughput.

Workspace validation passed 3,088 tests with zero failures and 36 ignored,
plus two custom harnesses. Serial launch passed 1,039 tests; allocation and
prefixed-pun regressions passed 3 and 36. All eight historical mapping cases
passed under the default workspace harness. Strict Clippy, check and fmt passed.

Reproduce at the revision above, with Python 3.12.15, Rust 1.97.1 and the tool
versions recorded in `receipt.json`. Set the absolute repository, toolchain,
user-home and Cargo-home paths; choose a fresh `$RAW` directory under `ignored/`:

```sh
cpuset-alloc run --cores 4 --sample-s 1 --tag li2-observer-work -- \
  python3 -B "$REPO/tools/rapid-profiler/verify_normal_interval.py" \
  --revision 7d987e39135725611ab2e5fa208025b3a6795127 \
  --reference-exact --reference-work --reference-leg --observer-work \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`modes.csv` records both functional outcomes; `checks.csv` records the full
checks. The receipt pins source, tools, binaries, commands and private captures.
Every call was parsed and checked; per-call captures and raw logs stay under
`ignored/`. No call population was reduced to produce these two summary rows.
The earlier strict 2 ms deadline failures remain failures. Perf, matched
observer overhead and the remaining A5 release criteria are still open.
