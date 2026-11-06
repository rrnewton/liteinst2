# liteinst-jit

Bounded direct-block translation (phase P1a) for Linux x86-64: guest
basic blocks are copied out-of-place into a code cache with a
flag-neutral retired-conditional-branch counter folded into the emitted
code. Syscall-class and nondeterministic instructions end their block
and exit to a caller-supplied handler; they are never executed natively
from the cache.

P1a envelope, honestly bounded:

- Straight-line code plus direct branches/calls; indirect control flow
  stops at the dispatcher and is refused by name.
- Private, non-writable source mappings only; writable or
  self-modifying code is refused, not tracked.
- Single-threaded guests; `execve` successors refuse by name.
- Asynchronous signals are never guest-delivered mid-cache: they
  are blocked during a run, a per-block poll stops the run with a
  recovered async outcome once one is pending, and a process with
  an installed async handler is refused at admission. This is a
  disclosed reduction from transparent delivery, pending an
  explicit owner scope decision. The remote ptrace substrate
  (`src/remote.rs`, P1B-DESIGN §8) additionally performs
  tested genuine delivery shapes (I1-D/I1-E plus I1-F masks, altstack, and capped nesting for SIGUSR1/SIGUSR2); every
  other shape there — including async stops in common-exit
  spilled stages and at generated PCs with no pcmap entry
  (entry-loader bridge class) — still stops as a recovered
  outcome, and no asynchronous-transparency claim is made
  beyond those tests.
- Counts are software counts validated by the `o1` ptrace single-step
  oracle in the integration tests, never PMU-equivalence claims.

This crate makes no whole-program claim. Counting every branch on a
real program such as `/bin/ls` is the later P1b/M4 slice and stays
gated on the oracle suite plus adversarial review of invalidation.
