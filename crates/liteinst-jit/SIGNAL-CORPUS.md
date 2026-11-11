# Signal corpus (frozen at I1-H H1)

Every signal fixture of P1b I1-C through I1-G2, plus the I1-H
fixtures, under a stable ID. Each row gives the rule-matrix cell
the fixture covers, the oracle its test checks against, and the
SHA-256 of its exact bytes. Every test pins its fixture through
`tests/common/corpus.rs` before running anything, so changing a
fixture fails by ID until its row here is updated in a reviewed
edit. Fixtures whose bytes embed a run-dependent value are listed
as unpinned, with the reason.

## Oracles

- **native child**: the same bytes run natively in
  `liteinst-jit-signal-native-child`, with the same register,
  stack, and signal arrangement. Its guest-visible witness (the
  handler log, syscall results, ucontext words) must equal the
  translated run's. It is not a count oracle.
- **O1-S**: `liteinst_jit::o1::run_o1s` single-steps the same
  bytes natively in the remote fixture child, so the process
  signal state matches the translated run's. The kernel makes
  every delivery for real: the oracle re-injects each
  signal-delivery stop with `PTRACE_SINGLESTEP(sig)` and steps on
  through the handler, the restorer, and `rt_sigreturn`.
  - It counts every retired instruction and every retired
    conditional branch.
  - It credits an interrupted syscall the way the translated
    substrate does: once, at completion. A rewound restart is
    not credited; `-EINTR` is credited at the delivery.
  - It checks every step's decoded length and branch target
    against the next RIP the trap reports (the per-step RIP-delta
    check, coord7 Q4(b)). A mismatch fails the oracle.
  - Every differential test also runs O1-S and requires the
    following.
    - Its witness equals the native child's (a sanity check of
      O1-S itself).
    - Its counts equal the fixture's own instruction
      enumeration (its self-check).
    - The translated counts and final register image equal its
      own, with addresses compared as (region, offset).
- **pinned enumeration**: translated counts pinned to the
  fixture's instruction list, for shapes O1-S does not run:
  refusals, which have no native completion to compare.
- **named refusal**: the exact recovered stop or `Refuse` value
  the stage defines for an unadmitted shape, and where it says
  so, the native errno.
- **kernel readback**: the tracer's mirrored registry compared
  with what the kernel reports, for I1-C.
- **O1-S at k** (I1-H sweep): an arrival placed at a generated
  PC by the hardware-breakpoint seam is delivered translated.
  The seam records the recovered `(src_pc, instructions,
  branches)`. O1-S then sends the same signal after exactly
  `instructions` retired steps. Both runs must agree on:
  - the full handler-visible frame (siginfo, all 18 ucontext
    registers, the saved mask);
  - the final register image;
  - the counts;
  - the guest buffer.

### Known common-mode risk (coord7 Q4(a))

O1 and O1-S build their decoder with the same shared
`liteinst_x86::decoder64` as the translator. Their step
classification is their own: `src/o1.rs` imports no translator
module, and `o1_oracle_imports_no_translator_classification`
checks that from the source module graph. Instruction counts come
from single-step traps and need no decoding. Branch counts use
O1's own classification applied to the shared decode, so a shared
decoder error is a **common-mode risk for branch counts only**.

The per-step RIP-delta check bounds that risk:
- a wrong length on any retired instruction fails;
- so does a real branch, decoded as a non-branch, that is taken.

What the check cannot catch:
- a non-branch decoded as a branch (its fall-through looks
  correct);
- a real branch decoded as a non-branch that is never taken in
  the run.

Capstone cross-decoding stays optional, for the case where the
check ever disagrees (coord7 Q4(c)).

## Allowed refusal windows at H1

The sweep classifies each arrival's generated PC by its PC-map
class. At H1 the only named refusals it allows are:

- **W1**, the common exit: `resume_gen` refuses common-exit
  stages, so the run ends with a recovered AsyncSignal at the
  exit's source PC;
- **W2**, generated PCs with no PC-map entry. This class is
  **empty** in the remote substrate:
  `w2_remote_translation_maps_every_generated_byte` shows that
  every byte the remote translation emits lies in exactly one
  PC-map entry, because the tracer enters blocks by setting
  registers and there is no generated entry bridge;
- **W3**, an arrival while the tracer steps an original
  `cpuid`. The breakpoint cannot place this one; it is held by
  the pre-original-step seam.

W5 (a stale mirrored mask during a handler) is held by
`w5_stale_mirror_stops_in_handler_today`. W1, W3 and W5 are closed
in H2, and their held tests then flip to delivered-and-equal.

## Regenerating hashes

Run the tests with `LITEINST_CORPUS_RECORD=/abs/path/file`. Each
pin then appends `ID SHA256` to that file instead of asserting.
Diff the result against the table and edit only the rows whose
fixture change was intended.

## Fixtures
