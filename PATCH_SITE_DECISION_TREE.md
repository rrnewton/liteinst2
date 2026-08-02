# Patch-site decision tree

This is the exhaustive policy for a LiteInst client that has a ptrace slow
path. A **logical site** is the instruction where the hook belongs; a
**physical site** is the instruction whose bytes are changed. Every candidate
ends in one of four measured outcomes. Before examining the site, the client
must select a publication contract. Failure never authorizes a weaker live
write.

```text
can the caller prove that no other thread, signal handler, or code writer can
touch the patch window for the complete publication call?
|
+-- yes: QUIESCENT publication
|   `-- retain full site planning and relocation, but publish through the
|       caller-verified quiescent entrypoint without WordPatch++ guards
|
`-- no: CONCURRENT publication
    `-- retain WordPatch++ atomic/guarded publication for every patch; a split
        requires a machine-qualified staleness budget or takes ptrace fallback

Within the selected publication contract:

decoded, current logical instruction head
|
+-- exact five-byte pun is safe and its exact trampoline is available?
|   `-- yes: DIRECT_PUN -- one-byte opcode publication at the logical site
|
`-- no: search at or before the logical site for the nearest physical site and
    a relocatable whole-instruction interval that contains the logical site
    |
    +-- proof succeeds, a near trampoline is available, and the physical patch
    |   is single-line?
    |   `-- yes: RELOCATED -- atomic-word publication
    |
    +-- proof succeeds, a near trampoline is available, and the physical patch
    |   straddles a cache line?
    |   |
    |   +-- QUIESCENT: RELOCATED -- unchecked-for-tearing publication under the
    |   |              caller's no-concurrent-access proof
    |   |
    |   +-- CONCURRENT with calibrated staleness budget: RELOCATED -- guarded
    |   |              WordPatch++ publication
    |   |
    |   `-- otherwise: PTRACE_STRADDLER_BAIL -- retain ptrace
    |
    `-- every other rejection: PTRACE_OTHER_FALLBACK -- retain ptrace
```

An invalid/stale scan, an address that is not an instruction head, an
unrepresentable range, insufficient complete instructions, an interior branch
target, an unproved indirect entry, a trampoline-allocation failure, mapping
churn, ownership contention, or an unsupported platform all take the final
ptrace branch. There is no “try the write anyway” outcome.

## 1. `DIRECT_PUN`

Use the existing [`RapidTogglePlan`](https://github.com/rrnewton/liteinst2/blob/main/src/rapid.rs)
only when all of its proofs hold:

- the logical site begins a decoded instruction and owns the complete five-byte
  pun window;
- bytes 1–4 encode a reachable, unoccupied exact trampoline address;
- no instruction head or known direct branch enters the window interior; and
- the executable/writable aliases agree and the first opcode byte is atomically
  writable.

Registration allocates and validates first. Publication changes only the first
opcode byte. If exact trampoline allocation races or collides, continue to the
upstream-relocation branch; do not partially publish the pun.

## 2. `RELOCATED` (same-site or upstream)

A zero-distance selection is the current same-site relocation path. A
positive-distance selection is the PLDI'17 upstream optimization; both are one
safe relocation action and one statistics outcome.

When a direct pun is unavailable, scan backward over complete decoded
instructions without crossing the permitted function/basic-block boundary.
Choose the nearest physical site for which all of these hold:

1. the displaced interval begins at that physical site, contains the logical
   site, and is at least five bytes;
2. its physical patch is either single-line, covered by the caller's quiescence
   proof, or covered by calibrated concurrent WordPatch++ publication;
3. every instruction in the interval can be relocated, including rewritten
   PC-relative operands and expanded short branches;
4. no unhandled direct or indirect control-flow entry can reach the displaced
   interval interior (otherwise reject it or provide an explicit router); and
5. a reachable trampoline can execute the upstream prefix, invoke the hook at
   the logical PC, execute the suffix, and return after the interval.

This is the port policy derived from PLDI 2017 §5.2, “Probe Site Selection,”
and §5.3, “Trampoline Construction and Coalescing.” The original artifact grows
a short range backward over whole instructions in
[`coalesceProbes`](https://github.com/iu-parfunc/liteinst/blob/ce70c4625e10a0f685a8ca4140f3ccb6f6709521/libliteinst/src/liteprobes/liteprobe_injector.cpp#L264-L312)
and emits the logical probe inside the relocated stream in
[`emitSpringboard`](https://github.com/iu-parfunc/liteinst/blob/ce70c4625e10a0f685a8ca4140f3ccb6f6709521/libliteinst/src/liteprobes/code_jitter.cpp#L173-L321).
The paper is [Instruction Punning: Lightweight Instrumentation for
x86-64](https://doi.org/10.1145/3062341.3062344).

The current Rust [`TrampolinePlan`](https://github.com/rrnewton/liteinst2/blob/main/src/trampoline.rs)
relocates a complete interval beginning at the requested site, but it does not
yet perform this upstream search or prove/reroute every interior entry. Until
that search is implemented, a client must choose ptrace rather than claim this
branch.

## Publication contracts

[`LiveJumpPatch::bind`](https://github.com/rrnewton/liteinst2/blob/main/src/patcher.rs)
and the ordinary `InstalledHook` constructors select the concurrent contract.
Single-line words publish atomically. Split words trap every byte before the
split, publish the back and front words in the WordPatch++ order, and wait out
the caller-supplied staleness interval before removing the guards. This remains
the default for ordinary threaded applications.

`LiveJumpPatch::bind_quiescent` and the quiescent `InstalledHook` constructors
select the quiescent contract. Planning, expected-byte checks, punning, and
relocation are unchanged, including for a cache-line straddler. Activation and
deactivation require the unsafe quiescent entrypoints. They deliberately skip
trap registration, atomic-envelope reservation, and the split protocol. The
single unaligned store may tear, so the caller's exclusion of every concurrent
instruction fetch and data access is a correctness precondition, not a
performance hint. Hermit's sequentialized guest execution can establish this
at its ptrace-controlled patch point; an in-process threaded client cannot.

## 3. `PTRACE_STRADDLER_BAIL`

If no direct pun or proved upstream site avoids the split, and the client can
provide neither a quiescence proof nor a calibrated concurrent staleness
budget, refuse the patch and keep that site on ptrace. A client must not turn a
failed quiescence assertion or missing WordPatch++ calibration into an
uncertain cross-line write.

This branch is per site. Other sites in the same process remain eligible for a
direct pun or upstream relocation.

## 4. `PTRACE_OTHER_FALLBACK`

Every rejection not covered above retains ptrace for the site. This includes
bad or changing code snapshots, missing mapping ownership, unsafe control-flow
entries, relocation or allocation errors, registry exhaustion, and future
failure modes not yet named. New planner errors default here until code and this
document deliberately assign them to a safer successful branch.

[`PunPlan::TrapRequired`](https://github.com/rrnewton/liteinst2/blob/main/src/planner.rs)
is the library-level signal for this fail-closed client action. “Trap” means the
client’s existing interception fallback; for the Hermit hybrid that is ptrace.

## Required statistics

One distinct logical RIP contributes exactly once to one outcome counter:

| Counter | Decision-tree outcome |
| --- | --- |
| `direct_pun_patched` | branch 1 |
| `relocated_patched` | branch 2 (zero-distance now; upstream when implemented) |
| `ptrace_straddler_bail` | branch 3 |
| `ptrace_other_fallback` | branch 4 |

Their sum is `patch_candidates`; the first two sum to
`distinct_rips_patched`. The companion site-shape statistics report
`cacheline_straddlers`, `non_straddling`, first-instruction length buckets
`5+ / 4 / 3 / 2 / 1`, and straddle prefixes `1 / 2 / 3 / 4`. Counts describe
the decision input even when the action is ptrace bailout; they must not relabel
a fallback as a patched RIP.

## Current implementation boundary

The Rust port currently implements direct rapid planning, same-site relocation,
both publication contracts, and explicit `TrapRequired` fallback in
[`plan_hook`](https://github.com/rrnewton/liteinst2/blob/main/src/planner.rs).
Upstream selection is specified here but remains implementation work. Therefore
the exhaustive behavior today is branch 1 when its proof succeeds, fully proved
same-site relocation under the selected publication contract, and ptrace for
everything else. Adding upstream selection may move candidates from branches 3
or 4 into branch 2; it may never remove the fallback branches.
