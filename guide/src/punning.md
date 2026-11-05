# How instruction punning works

Overwriting live code is dangerous: another thread can fetch an
instruction mid-edit and execute half of the old bytes and half of the
new. How do you replace an instruction in a program that never stops?

LiteInst's answer is *instruction punning*: publish the patch as a
single atomic store that reuses ("puns") existing bytes, so that every
possible concurrent instruction fetch sees either the complete old
instruction or the complete new one — never a torn mix. Two ideas make
this work on x86-64:

1. **One store inside a single cache line is untearable by a racing
   fetch.** The atomic-word strategy publishes an 8-byte store fully
   inside one cache line (alignment is not required; *not straddling
   the line* is), and a pun's actual store may be 1, 2, or 4 bytes.
   If the whole patch fits in one such store, no fetch can observe a
   partial patch.
2. **x86 instructions are variable-length and self-synchronising from a
   known entry.** Bytes that are the tail of the old instruction can
   become the displacement bytes of the new jump. The new instruction
   *puns* on the old bytes: the same bytes mean two things depending on
   which instruction stream decodes them, and both streams are valid.

A concrete shape: to replace a short first instruction (1–4 bytes) with
a five-byte `jmp rel32` (`E9` plus a four-byte displacement), the
*generalized pun* writes `E9` over the first byte and free low
displacement bytes over the rest of the old instruction; the unchanged
successor bytes supply the fixed high displacement bytes. The arena
must be placed so that those forced high bytes still name the
trampoline — placement is part of planning, not luck. A *prefixed pun*
variant spends redundant `0x2E` segment prefixes to reach sites the
plain form cannot.

## When one store is not enough

Some sites straddle a cache line, so no single atomic store covers the
patch. Those use **WordPatch++**, a guarded cross-modification
protocol: guard bytes before the split force any racing fetcher into a
trap (handled by the library's SIGTRAP router) while the patch is
completed, and the caller must supply a machine-qualified
`StalenessBudget` — a bound on how long a core may execute stale bytes.
Without that calibration, split sites must fall back to traps. There is
no third, quieter option: an unguarded split patch is exactly the torn
fetch this library refuses to risk.

A third publication mode, **sync-core**, uses serializing barriers
for word publication and batches — split sites still publish `0xCC`
front-fragment guards; the barriers replace the staleness waits, not
the guards — under its own geometry and caller obligations.

## Where the ideas come from

The techniques are from two PLDI papers and the original C++ library
that introduced them:

* Original implementation (C++):
  [iu-parfunc/liteinst](https://github.com/iu-parfunc/liteinst).
* *Living on the Edge: Rapid-Toggling Probes with Cross-Modification
  on x86* (PLDI 2016) — the guarded split-site word-patching protocol.
* *Instruction Punning: Lightweight Instrumentation for x86-64*
  (PLDI 2017) — instruction punning and generalized WordPatch++.

`liteinst` is a Rust reimplementation of that work, extended with the
plan/lease/receipt discipline of the next chapters. This book explains
the ideas well enough to use the library soundly; the papers carry the
proofs.

> 🚧 **Under construction — worked byte-level examples.** TODO: add
> annotated before/after byte diagrams for a generalized pun, a
> prefixed pun, and a WordPatch++ guarded split, generated from the
> planner's own test fixtures so the diagrams cannot drift from the
> implementation. <!-- UC: pun-diagrams -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`pun-diagrams`).
