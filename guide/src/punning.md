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

## Worked examples, byte by byte

These three diagrams rebuild the planner's own overlay fixtures
(`src/artifact_overlay_tests.rs`): the starting byte streams are the
fixtures' literal bodies, and each store/target value is one the
test suite asserts. Addresses are offsets from the patch site `S`;
stored bytes are the single atomic store, inherited bytes are
successor bytes that are already there and become high displacement
bytes of the new jump. Both pun fixtures apply one predecessor edit
before planning — shown as its own row, because the edit is what
turns the successor into `mov ecx, 43` and supplies the inherited
bytes.

**Generalized pun** — displace a 3-byte `nop` whose successor is
`mov ecx, 43`:

```text
fixture  0f 1f 00 | b8 2a 00 00 00 | c3
         \_ nop _/   mov eax, 42      ret
edited   0f 1f 00 | b9 2b 00 00 00 | c3    (bytes at S+3, S+4)
store    e9 00 80 b9                        (one 4-byte store at S)
after    e9 00 80 b9 2b 00 00 00 c3
         \____ jmp rel32 = 0x2bb9_8000 ___/
                      ^
                      inherited: the successor's 0x2b immediate
                      byte is the jump's top displacement byte
```

The store writes the `E9` opcode and the displacement's free low
bytes (`00 80 b9`); its top byte, `2b`, was already in memory. That
is why placement is part of planning: the arena must be allocated so
that the *forced* top byte still names the trampoline
(`target = S + 5 + 0x2bb9_8000` in the fixture).

**Prefixed pun** — the same trick one byte longer, for a 2-byte
`mov eax, eax` head. A redundant `0x2E` (CS) prefix buys the extra
byte, and *two* displacement bytes are inherited:

```text
fixture  89 c0 | b8 2a 00 00 00 c3
edited   89 c0 | b8 b9 2b 00 00 c3    (bytes at S+3, S+4)
store    2e e9 80 b9                        (one 4-byte store at S)
after    2e e9 80 b9 2b 00 | 00 c3
         \___ jmp rel32 = 0x002b_b980 ___/
```

**WordPatch++ guarded split** — an 8-byte patch window starting four
bytes before a cache-line boundary (`|`), so no single store covers
it. `o` = old byte, `n` = new byte:

```text
before    ... o o o o | o o o o ...
guard     ... CC CC CC CC | o o o o ...   CAS front word, then wait
back      ... CC CC CC CC | n n n n ...   store back word, then wait
front     ... n n n n | n n n n ...       store front word
```

Every front-fragment byte is guarded with `0xCC` first. A racing
fetch during the window traps into the library's SIGTRAP router
instead of executing a torn mix; the two bounded staleness waits
(the caller's `StalenessBudget`) separate the three atomic
publications. Only the finished streams — all old, or all new —
ever execute as instructions.

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

