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
- Counts are software counts validated by the `o1` ptrace single-step
  oracle in the integration tests, never PMU-equivalence claims.

This crate makes no whole-program claim. Counting every branch on a
real program such as `/bin/ls` is the later P1b/M4 slice and stays
gated on the oracle suite plus adversarial review of invalidation.
