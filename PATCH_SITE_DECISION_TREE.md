# Patch-site decision tree

This is the exhaustive policy for a LiteInst client that has a ptrace slow
path. A **logical site** is the instruction where the hook belongs; a
**physical site** is the instruction whose bytes are changed. Every candidate
ends in one of four measured outcomes. Failure never authorizes a weaker live
write.

```text
decoded, current logical instruction head
|
+-- exact five-byte pun is safe and its exact trampoline is available?
|   `-- yes: DIRECT_PUN -- one-byte opcode publication at the logical site
|
`-- no: find a non-straddling upstream physical site and a relocatable
    whole-instruction interval that contains the logical site
    |
    +-- proof succeeds and a near trampoline is available?
    |   `-- yes: UPSTREAM_RELOCATED -- patch upstream, run the hook at the
    |            logical PC inside the relocated stream, then return
    |
    +-- logical/physical candidate is a cache-line straddler?
    |   `-- yes: PTRACE_STRADDLER_BAIL -- do not patch; retain ptrace
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

## 2. `UPSTREAM_RELOCATED`

When a direct pun is unavailable, scan backward over complete decoded
instructions without crossing the permitted function/basic-block boundary.
Choose the nearest physical site for which all of these hold:

1. the displaced interval begins at that physical site, contains the logical
   site, and is at least five bytes;
2. its five-byte physical patch does not cross a cache line;
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

## 3. `PTRACE_STRADDLER_BAIL`

If no direct pun and no proved non-straddling upstream site are available,
refuse the patch and keep that site on ptrace. In particular, the Hermit hybrid
must not select `PatchStrategy::GuardedSplit` as a last resort. It does not
reimplement the original lock-front/lock-back/long-wait WordPatch++ protocol.
Ptrace already supplies a correct slow path, so bailout is both simpler and
safer than making an uncertain cross-line write.

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
| `upstream_relocated_patched` | branch 2 |
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
and explicit `TrapRequired` fallback in
[`plan_hook`](https://github.com/rrnewton/liteinst2/blob/main/src/planner.rs).
Upstream selection is specified here but remains implementation work. Therefore
the exhaustive behavior today is branch 1 when its proof succeeds, same-site
relocation only when it is non-straddling and fully proved, and ptrace for
everything else. Adding upstream selection may move candidates from branches 3
or 4 into branch 2; it may never remove the fallback branches.
