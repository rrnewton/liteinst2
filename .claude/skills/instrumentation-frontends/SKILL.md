---
name: instrumentation-frontends
description: "Choose the LiteInst frontend and evidence needed for a scanner, offline rewrite, page-gate, JIT or architecture change. Use when adding an instrumentation client or extending its admitted program profile."
---

# Select a frontend and qualify its result

Choose the layer that owns the requested operation. The
[crate map](../../../guide/src/appendix-crates.md) locates the implementations;
current manifests and module contracts determine the supported surface.

| Work | Start here | Evidence boundary |
| --- | --- | --- |
| x86/AArch64 instruction facts | [liteinst-x86](../../../crates/liteinst-x86/src/lib.rs), [liteinst-aarch64](../../../crates/liteinst-aarch64/src/lib.rs) | Descriptive `no_std`, unsafe-free facts; no entry ownership, mapping freshness, CPU support or execution authority |
| Admission and scan caching | [liteinst-admission](../../../crates/liteinst-admission/README.md) | All-start facts and a mock gate; an accepted model transaction is not live publication |
| Offline ELF rewriting | [liteinst-rewrite](../../../tools/elf-rewrite/README.md), [offline contract](../../../A3-OFFLINE.md) | An authenticated structural candidate retains separate runtime qualification requirements |
| Stopped launch and remote page gates | [liteinst-launch](../../../crates/liteinst-launch/README.md) | The selected gate's explicit instruction/lifecycle profile; a held task is not by itself full quiescence |
| Caller-owned in-process gating | [liteinst-inprocess](../../../crates/liteinst-inprocess/CONTRACT.md) | Caller-certified ownership, entries, signal state and lifecycle; eager publication and lazy first touch are distinct |
| AArch64 executable patching | [liteinst-aarch64-patch](../../../crates/liteinst-aarch64-patch/src/lib.rs) | Unsafe mappings, cache maintenance and aligned stores under stopped-executor custody; no lock-free toggle claim |
| Out-of-place translation | [liteinst-jit](../../../crates/liteinst-jit/README.md) | Bounded Linux x86-64 translation and software branch-count oracles, not general whole-program or PMU equivalence |

## Admission and architecture changes

Keep decoding policy with the walker. A scanner choosing every byte offset
must retain overlapping/embedded candidates and boundary dependencies;
hardware feature masks are not permission to omit instruction encodings.
New facts invalidate dependent plans and cached reports. Cache hits require
the complete identity, bytes, entries, target and policy; stale or corrupt
material must retain the documented runtime-scan/refusal path.

AArch64 decoding is partial: `Insn::Other` is not evidence that a rewrite is
safe. Decode/encode round trips can test facts on another architecture, but
only native execution can qualify that architecture's cache maintenance and
publication. Apply [patching-contracts](../patching-contracts/SKILL.md) when a
frontend crosses into executable memory.

## Offline candidates

After preparing an ELF and a selection file under the
[selection schema](../../../tools/elf-rewrite/SELECTION.md), run from the root:

```sh
cargo run --locked -p liteinst-rewrite -- prepare INPUT_ELF SELECTION NEW_DIRECTORY
```

The output directory must be new. Exit 0 and `COMPLETE` establish a complete
structural candidate; exit 2 records requested-site or placement refusals;
exit 1 reports invalid input or an I/O/format failure. A partial directory
cannot be consumed. The command does not run the result, make it executable
or overwrite the input. Hashes establish integrity, not runtime admission.

Keep source identity separate from patched-artifact identity. Before claiming
native success, join the emitted artifact with actual hook activity, original
program behavior, target CPU/state, loader bias, ABI and startup requirements.
Retain every requested site's result in the denominator. Structural comparison
against another rewriter is not an execution comparison.

## Page-gate and JIT changes

Check the chosen gate's real launch, thread, signal and mapping restrictions;
do not transfer support between the trap reference, selected-instruction,
core-publication and concurrent gates. The in-process gate consumes completed
publication and does not discover arbitrary instruction heads for its caller.

For the JIT, inspect the current README and test for the exact execution path.
Local and remote signal handling have different qualified envelopes. Keep
indirect-flow, writable-code, exec and signal outcomes visible as implemented
refusals or recovered outcomes. A software counter's native oracle result
does not establish hardware retired-branch equivalence.

Use [development](../development/SKILL.md) for crate checks and fixture setup.
Report which stage succeeded: facts, plan, candidate emission, publication or
native execution. Do not promote one stage's receipt into another's result.
