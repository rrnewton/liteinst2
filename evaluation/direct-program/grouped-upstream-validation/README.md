# Bounded upstream correctness

Revision `319d363a0094ca8fcb0d1bf768a35799733d5700` passed full correctness validation on an AMD EPYC Zen 5 dev host. Workspace: **4,675 top-level + 11 nested = 4,686 raw passes, zero failures, 43 unchanged ignores**. Serial launch: **1,039 passed, zero failures or ignores**. The complete prior roster remains, with fourteen Rust additions: seven core, four frontend and three CLI controls. Five inherited and four new Python linkage controls pass separately from Rust totals.

The separate focused-v2 run passed all **44 controls** (35 Rust and nine Python). All 25 full-campaign and 14 focused-v2 owners exited zero with complete cleanup and zero rescues. Formatting, strict Clippy, workspace check and every inherited command passed. Workspace took 827.303 seconds within 1,800; serial took 138.670 within 360. These are validation costs, not benchmarks.

Focused-v1 remains **FAILED**: 26 inherited controls and six of seven new core controls passed; later new stages were unobserved. The correction changes one fixture, not production code. The allocator retains an available certified seed before minimizing page offset. The test now checks the independently derived target `0x064168fc`, offset `0x8fc`, certificate fit, exact entry bytes and page containment, preserving the arena, candidate budget, population and original exact-profile refusal.

The census retains all 27 workspace/five serial critical cases, 21 short-neighbor cases, 539 should-panic rows and eight harnessless backing records. [receipt.json](receipt.json) records exact commands, source/tree, CPU sets, loads, storage ceilings and census digests. Compiler versions were not freshly measured by these validation commands. Prior [grouped corpus failures](../grouped-program-result/README.md) remain unchanged; these checks grant no upstream corpus, general stack/fault, complete CFG, runtime exemption or performance qualification.

Reproduce from a clean checkout of the exact revision. Set `CPUSET_ALLOC` to the allocator, `TOOLCHAIN` to the existing stable toolchain directory and `OUTPUT` to an unused directory:

```sh
AGENT_UTILS_ENGINE=python "$CPUSET_ALLOC" run --cores 12 --tag li2core-grouped-upstream-full -- python3.9 -I -B evaluation/direct-program/validate_grouped_upstream.py --revision 319d363a0094ca8fcb0d1bf768a35799733d5700 --output "$OUTPUT" --toolchain "$TOOLCHAIN"
```

For the focused profile, add `--focused`, change the tag to `li2core-grouped-upstream-focused` and use another unused output. CPU, cumulative storage, cleanup and finite native 20,000-step/15-second bounds remain unchanged. Focused success alone is not full validation.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
