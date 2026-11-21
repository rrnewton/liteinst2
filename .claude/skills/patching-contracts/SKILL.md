---
name: patching-contracts
description: "Choose and preserve LiteInst publication and lifetime contracts. Use when changing patch planning, executable stores, trampolines, activation, rollback or retirement."
---

# Change patching without losing its contract

Start by naming the actual API. Similar patch bytes do not make publication
contracts interchangeable:

| API | Contract to read |
| --- | --- |
| `InstalledHook`, `LiveJumpPatch`, `RapidProbe` | [Patch-site decision tree](../../../PATCH_SITE_DECISION_TREE.md), then the selected method's safety documentation |
| `quiescent::plan_install` and `InstalledOnce` | [Standalone interfaces](../../../INTERFACES.md) and [quiescent publication](../../../A1-QUIESCENT.md) |
| Composed plans and bundles | [Composition](../../../A2-COMPOSITION.md), including shared byte ownership and aggregate allocation limits |
| `patcher::synchronized` | [Synchronized publication](../../../A4-SYNCHRONIZED.md), including terminal failure and the native gate |
| AArch64 site publication | [Runtime types](../../../crates/liteinst-aarch64-patch/src/lib.rs), [site custody](../../../crates/liteinst-aarch64-patch/src/site.rs) and [foreign-text stores](../../../crates/liteinst-aarch64-patch/src/store.rs) |

The legacy decision tree does not describe the newer quiescent planner's
upstream selection. Read the matching API rather than carrying a capability
claim from one interface to another.

## Trace the proof through publication

1. Bind source bytes to their content identity, mapping incarnation and
   generation. An address or build ID is insufficient. Entry, alias or policy
   changes invalidate the old generation even when source bytes match.
2. Authenticate complete legal entries and saved continuations. Symbols,
   linear decoding and a page that has never executed do not prove an empty
   resume set. Include signal frames, CALL returns and parked execution.
3. Inspect exact reads, semantic edits, actual store spans, unchanged padding,
   fetch dependencies and generated images. Preserve logical-site behavior
   when the physical patch starts elsewhere. Planning neither publishes code
   nor installs the fallback requested by a refusal.
4. Establish the selected exclusion or concurrent-publication proof for the
   whole affected range. A `QuiescenceLease` must borrow a real gate owner
   excluding execution, data readers/writers, signal reentry and uncoordinated
   aliases for its lifetime. NX alone is insufficient. Legacy unsafe
   quiescent methods require exclusion throughout each publication call.
5. Preserve revalidation, generated-code/route publication, source-write order,
   final permissions and instruction-stream synchronization. A receipt must
   certify the actual plan and generation. Mock receipts certify mock storage
   only; they cannot admit a live executable mapping.

For legacy `LiveJumpPatch`/`InstalledHook` concurrent split-word publication,
retain the qualified `StalenessBudget` and guarded protocol. Missing calibration
requires a declared refusal/fallback, not an unsupported quiescent call. The
separate synchronized protocol uses `SyncCore` barriers and has no staleness-delay
fallback. Preserve each method's router, signal-mask, alias and mapping obligations.

## Keep failure and retirement semantics exact

In generation-bound publication, a prewrite failure leaves source unchanged;
a potentially written failure keeps the lease poisoned and admission held
until verified rollback plus synchronization, or termination. Dropping the
error or lease does not authorize execution. The synchronized batch API has
different terminal custody semantics: a postwrite error retains ownership and
routes, with no automatic retry or rollback; retained ownership does not imply
that execution is stopped. Use the concrete failure type, not a generic error.

Keep installed handles and generated code alive for their documented lifetime.
Install-once retirement needs a fresh generation-bound lease covering source
dependencies and generated allocations, with executable and saved references
drained. Toggling off or suppressing an optional callback is not drainage or
reclamation. Do not infer transactional activation of every member from a batch
that merely shares synchronization barriers.

Trampolines must preserve the declared GPR, flags, stack/red-zone and extended
state contract. Callbacks must honor their ABI and no-unwind obligations. PC
translation alone supplies neither signal delivery nor unwind metadata. Read
the actual callback and trampoline layout types before changing either side.

Use [development](../development/SKILL.md) for test commands. Include both the
successful rewrite and refusal/custody cases adjacent to the changed proof;
compare native state at the same architectural boundaries. Report unsupported
entry shapes or host capabilities as limits, never as successful coverage.
