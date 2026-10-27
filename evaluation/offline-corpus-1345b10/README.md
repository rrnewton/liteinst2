# Finite offline comparison at 1345b10

At `1345b10dc4ca76ccabcde7c60cc94934a7b14541`, checksum and RLE roundtrip each passed ten deterministic datasets in four lanes: native, LiteInst, stock E9 and bootstrap-patched-reference E9. All **80 rows passed** with exact complete stdout, empty stderr and exit zero; rewritten outputs also equal their native counterparts. `cases.csv` is the unchanged original 80-row CSV, including output hashes and elapsed seconds. Its rows overlap by program/dataset and are not 80 unique programs.

Four phases and 99 inner commands closed successfully, with 103 strict ECHILD receipts. Release builds used opt-level 3, debug-info 0, debug assertions and overflow checks enabled. Hardware: **AMD EPYC Zen 5 dev host**. Times include bounded process/helper startup and I/O; they are not isolated kernel measurements or a speedup claim.

The byte witness checks all 14 selected LiteInst branches and complete source-derived save/call/restore prefixes, exact logical PCs/hook target, both unconditional-jump terminal tails, original overlays, and 28 E9 branch images. The separate **96 saved-artifact controls** comprise eight valid positives, 20 deliberate legacy-gap acceptances and 68 expected refusals. `controls.csv` preserves every observation and assertion line. The controls execute Python witnesses over copies, never candidate ELFs; they add no native comparison rows.

The earlier `2cf9a6e` run also passed 80 output rows, but its witness admitted reindexed helper-prefix bypasses. That coverage gap remains disclosed; it was not an observed bypass in the emitted products. The first proposed guard correction missed an unreachable JMP tail and remained HELD/UNRUN. The corrected guard and this fresh run are separate evidence. No historical outcome is relabeled.

## Reproduce

Use a clean checkout of the exact revision and the pinned prerequisites in [REPRODUCE.md](../offline-corpus/REPRODUCE.md). Run [reproduce.py](../offline-corpus/reproduce.py), then [controls.py](../offline-corpus/controls.py), using the exact argv/env/cwd contexts in `commands.json`. Substitute `${REPO}`, `${TOOLCHAIN}`, `${USER_HOME}`, `${CARGO_HOME}`, `${E9_STOCK}`, `${E9_TRANSPORT}` and `${E9_ABI}` with their documented local inputs; `${RUN_RAW}` and `${CONTROL_RAW}` must be separate fresh directories under the checkout's `ignored/`. These roles normalize host paths, not program semantics. Preserve the declared time/file limits and strict helper closure. The scripts record the complete nested commands; this compact report pins their saved command list rather than reproducing every request.

`summary.json` retains phase limits, exact build-product and receipt/result hashes. Public data contains no raw logs, captures, memory or private paths. Regenerating this report is distinct from rerunning the programs.

This finite expansion does **not** satisfy the original **704 core-null or 2,112 recording pairs**. Full GPR/flags/XSAVE/stack replay, general normal-loader qualification and full A3 remain incomplete. Existing comparators, fixed cases and historical failures remain mandatory.

CPU model, architecture, kernel and libc are recorded in [hardware.json](hardware.json). They come from a separate closed same-host inline-pure observation before this run, not from the offline wrapper. Its complete original file hash is retained.
