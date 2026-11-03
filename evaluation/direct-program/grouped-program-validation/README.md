# Grouped program-adapter correctness

Revision `52ec3184b994cf10eb6cdfcbd8c8a361d7e14961` passed full correctness validation on an AMD EPYC Zen 5 dev host. Workspace: **4,661 top-level + 11 nested passes, zero failures, 43 unchanged ignores**. Serial launch: **1,039 passed, zero failures or ignores**. The previous Rust roster is preserved with 21 additions: seven core, seven frontend, four finite native and three CLI controls. Five Python linkage controls pass separately from Rust totals. Strict Clippy, formatting and workspace check passed.

The focused run passed those 26 controls. The full run also retains prior emission/observer, selection, native-stack, shared-CFG and critical regression checks. All 21 full-campaign owners and ten focused owners exited normally with code zero, complete cleanup and zero rescues. Each campaign ran once with twelve reserved CPUs, twelve Cargo jobs and twelve harness threads; serial launch used one thread and the existing 360-second limit.

Controls cover grouped windows, selected and unselected entry routes, per-member outcomes, atomic withholding, bound metadata, and finite native entry/branch/RSP/later-fault fixtures. They do not establish successful grouped cat/head/wc execution or general stack/fault transparency. The [ungrouped stack-profile failures](../jump-stack-result/README.md) remain unchanged. Complete CFG recovery, runtime page exemption and performance are outside this validation.

[receipt.json](receipt.json) records source/tree, commands, limits, CPU sets, loads, capacity and census digests. Durations are validation costs, not benchmarks. Tool versions come from a separately identified later CLOSED query using the same toolchain directory.

Reproduce from a clean checkout of the exact revision using [../validate_grouped_program.py](../validate_grouped_program.py). Set `CPUSET_ALLOC` to the CPU allocator and `TOOLCHAIN` to the recorded stable toolchain directory; use an unused output path:

```sh
AGENT_UTILS_ENGINE=python "$CPUSET_ALLOC" run --cores 12 --tag li2core-grouped-program-full -- python3.9 -I -B evaluation/direct-program/validate_grouped_program.py --revision 52ec3184b994cf10eb6cdfcbd8c8a361d7e14961 --output "$PWD/ignored/grouped-program-reproduction-full" --toolchain "$TOOLCHAIN"
```

For the focused profile, add `--focused` and use the distinct unused `ignored/grouped-program-reproduction-focused` output. The validator retains its clean revision, CPU-count, cumulative capacity, command and cleanup guards. Raw captures remain private.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
