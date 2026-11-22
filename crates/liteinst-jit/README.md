# liteinst-jit

Bounded direct-block translation (phase P1a) for Linux x86-64: guest
basic blocks are copied out-of-place into a code cache with a
flag-neutral retired-conditional-branch counter folded into the emitted
code. Syscall-class and nondeterministic instructions end their block
and exit to a caller-supplied handler; they are never executed natively
from the cache.

P1a envelope, honestly bounded:

- Straight-line code plus direct branches/calls. P1b.1 adds in-region
  indirect jumps and calls, resolved through the dispatcher;
  out-of-region and unsupported indirect forms refuse by name.
- Private, non-writable source mappings only, as asserted by the
  caller: admission checks the caller's
  `RegionFacts::immutable_private` flag and does not read the
  mapping's protections ([#107]). Self-modifying code is not tracked,
  and nothing invalidates a translation when a mapping changes yet:
  dispatch looks translations up by address ([#104]).
- Single-threaded guests; `execve` successors refuse by name. One
  in-process `run` at a time per host process: its signal state is
  process-global, and a second concurrent `run` is not refused
  ([#105]).
- Asynchronous signals are never guest-delivered mid-cache: they
  are blocked during a run, a per-block poll stops the run with a
  recovered async outcome once one is pending, and a process with
  an installed async handler is refused at admission. This is a
  disclosed reduction from transparent delivery, accepted for P1a
  by the 2026-11-05 scope decision recorded in P1B-DESIGN.md
  ([#106]). The remote ptrace substrate
  (`src/remote.rs`, P1B-DESIGN §8) additionally performs
  tested genuine delivery shapes (I1-D/I1-E, I1-F masks,
  altstack, and capped nesting, I1-G1 real-time ordering,
  `SI_QUEUE` self-queueing, and back-to-back frames, for
  SIGUSR1/SIGUSR2 and signals 34..=64; I1-G2 delivery when
  a signal interrupts `rt_sigsuspend`, `FUTEX_WAIT_PRIVATE`
  without a timeout, or `nanosleep`, with the kernel applying
  `SA_RESTART`/`-EINTR`; I1-H H2b delivery of async stops in
  the common exit of a RETURN, SYSCALL, NONDET or POLL exit
  (W1) and before a single-stepped original `cpuid` (W3); and
  I1-H H2d delivery of an async stop before a stepped syscall
  enters the kernel (W3s), when a four-part provenance guard
  shows the exact pre-step state, with the call retried after
  sigreturn; W3 and W3s retries are bounded and refuse by
  name past the bound); every other shape there — including
  async stops in the common exit of an INDIRECT exit, at
  generated PCs with no pcmap entry, an entry-phase syscall
  stop that fails the guard, and the sigreturn interception's
  own entry stop — still stops as a recovered outcome or
  refuses by name, and no asynchronous-transparency claim is
  made beyond those tests. A signal with a positive kernel
  `si_code` outside the fault set (SIGALRM from `setitimer`,
  SIGCHLD, an `F_SETSIG` signal) is never delivered there, even
  to an installed handler: the run stops with a recovered
  `AsyncSignal` outcome where the state is exact, and refuses by
  name elsewhere (a capability limit; P1B-DESIGN §8, H3k).
- Counts are software counts validated by the `o1` ptrace single-step
  oracle in the integration tests, never PMU-equivalence claims.

This crate makes no whole-program claim. Counting every branch on a
real program such as `/bin/ls` is the later P1b/M4 slice and stays
gated on the oracle suite and on the invalidation work that the
adversarial review found missing ([#104]).

[#104]: https://github.com/rrnewton/liteinst2/issues/104
[#105]: https://github.com/rrnewton/liteinst2/issues/105
[#106]: https://github.com/rrnewton/liteinst2/issues/106
[#107]: https://github.com/rrnewton/liteinst2/issues/107
