# Whole-loader graph experiment

`evaluation/inprocess/loader_loop.py` builds the explicit `add-guard` decoder
feature in release mode, runs the ADD model and native comparison, then plans
both real relocation loops with and without guarded ADD. Run from a clean
committed revision on one CPU reserved with `cpuset-alloc`:

```sh
cpuset-alloc run --cores 1 -- python3 -B evaluation/inprocess/loader_loop.py \
  --expect-revision REVISION --interpreter REFERENCE_INTERPRETER
```

The reference interpreter is the 939,216-byte x86-64 ELF with SHA-256
`34c232018a619b0091e97add6805072d00db3250937fc049a1ef968cecfa99c9`.
The script extracts all 8,192 bytes at file/ELF offsets `0x10000` and `0x11000`,
authenticates the executable segment and all 143 relocation records, and
requires that no relocation targets those pages. These are file bytes, not a
captured process memory image. Source load bias and generated near placement
are supplied descriptive premises in the planner component.

Both roots retain every alternate branch and the original 128-head/eight-exit
bounds. Root `0x1002e` has 53 heads and seven exits in the baseline. The new
register-source 64-bit memory ADD at `0x10021` reaches the already-described
`0x10025` successor, closing the type-7 back edge: the additive graph must have
54 heads and six exits. The other six literal frontiers remain, including the
distinct immediate-source ADD at `0x100a0`. Root `0x102c8` already has its MOV
loop back edge and must retain 27 heads, four exits and five guarded MOVs in
both profiles. Full and compact reconstruction must succeed for each graph.

This experiment does not enable ADD in the production recipes. The current
compiled-block owner requires a real active rseq registration. These graphs
therefore do not establish admission during unregistered loader startup,
whole-process acceleration, or application signal-handler continuation.
The native ADD component checks the actual instruction, flags, integer state,
memory and faults separately from page-owner qualification.

Commands, hardware, exact revision, outcomes and capture hashes are recorded
under `evaluation/inprocess/results/` as compact JSON/CSV. Raw output remains
under `target/`. The original five prerequisite cohorts, full state checks,
30-CPU-second target limit and all existing failed attempts are unchanged.
