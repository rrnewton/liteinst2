# Appendix C: further reading

* *Living on the Edge: Rapid-Toggling Probes with Cross-Modification
  on x86* (PLDI 2016,
  [doi:10.1145/2908080.2908084](https://doi.org/10.1145/2908080.2908084))
  — WordPatch++ guarded split-site patching.
* *Instruction Punning: Lightweight Instrumentation for x86-64*
  (PLDI 2017,
  [doi:10.1145/3062341.3062344](https://doi.org/10.1145/3062341.3062344))
  — punning and generalized WordPatch++.
* The original C++ implementation:
  [iu-parfunc/liteinst](https://github.com/iu-parfunc/liteinst).
* In this repository: `INTERFACES.md` (core contract),
  `A1-QUIESCENT.md`, `A2-COMPOSITION.md`, `A3-OFFLINE.md`,
  `A4-SYNCHRONIZED.md`, `PATCH_SITE_DECISION_TREE.md`,
  `COALESCED-CONTROLS.md`, and the published crates' READMEs.
* The Reverie guide — for building complete tools on these blocks.
* API reference: docs.rs per release
  ([docs.rs/liteinst](https://docs.rs/liteinst) once docs.rs has built
  the release you want) and the sibling crates linked from there;
  `cargo doc` locally is the fallback.

## Neighbouring systems

* [E9Patch](https://dl.acm.org/doi/abs/10.1145/3385412.3385972) —
  static x86-64 binary rewriting *without control-flow recovery*. It
  uses instruction punning, padding, and eviction to insert jumps to
  trampolines without moving other instructions, and is therefore the
  closest offline counterpart to this book's patch-site vocabulary.
  Read it for what can be decided before load time when the whole file
  is available. The contrast is equally instructive: a static rewrite
  has no running threads to race, no live retirement problem, and no
  dynamically generated successor code unless another mechanism admits
  it.
* [zpoline](https://www.usenix.org/system/files/atc23-yasukata.pdf) —
  syscall-only binary rewriting. It replaces the two-byte
  `syscall`/`sysenter` instructions with a two-byte indirect call
  through `%rax`, whose value is the syscall number, into a trampoline
  page mapped at address zero. Read it for an elegant answer to the
  two-byte patch-site problem and as a warning about exhaustive
  *static discovery*: byte sequences inside immediates or data can
  look like syscall instructions, and mapping page zero changes what a
  null-pointer access does.
* [lazypoline](https://people.cs.kuleuven.be/~stijn.volckaert/papers/2024_DSN_Lazypoline.pdf)
  — hybrid syscall interposition that pairs Syscall User Dispatch
  (SUD) with lazy binary rewriting: SUD catches a syscall site the
  first time it executes, the site is rewritten zpoline-style, and
  later executions take the fast path. Read it for the completeness
  argument—a trap discovers dynamically generated sites that a static
  scan can miss or misidentify—and for its careful treatment of
  extended CPU state at the interposition boundary. It intercepts
  syscalls, not arbitrary program points.
* [DynamoRIO](https://dynamorio.org/) — a mature runtime code
  manipulation system that copies executed blocks into a code cache
  and lets clients transform or instrument them there. Read it for
  code-cache organisation, fragment linking, clean calls, and the
  transparency problems created when the bytes that execute are not
  the bytes in the original image. It is the out-of-place end of this
  book's spectrum: discovery by execution handles unknown code
  uniformly in exchange for a null-client tax and a second copy of
  the program text to manage.
* [Intel Pin](https://software.intel.com/sites/landingpage/pintool/docs/99977/Pin/doc/html/index.html)
  — a JIT-based dynamic binary instrumentation framework whose tools
  insert C/C++ analysis code at image, routine, trace, basic-block, or
  instruction granularity while the program runs. Read Pin for its
  tool API and granularity choices rather than its patching
  mechanics: it makes arbitrary dynamic instrumentation comparatively
  easy to express, while still executing a dynamically compiled
  version of the program rather than the original bytes in place.
* [gVisor systrap](https://gvisor.dev/blog/2023/04/28/systrap-release/)
  — gVisor's default platform uses `seccomp` trapping to route a
  sandboxed workload's syscalls to the Sentry, a userspace
  implementation of much of the Linux kernel interface. Read it for a
  production completeness trap at sandbox scale and for the cost of
  reimplementing kernel semantics faithfully. It is an isolation
  architecture, not a general-purpose way to install tool hooks: the
  Sentry mostly *replaces* the syscall implementation rather than
  letting the original syscall proceed under observation.
