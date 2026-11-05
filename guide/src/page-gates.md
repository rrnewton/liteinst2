# Page gates: first-touch admission

Eager scanning assumes you can enumerate the code before it runs. Page
gates invert the order: pages start **non-executable**, and the first
instruction fetch faults into a handler that verifies the final bytes
and dependency closure, opens the pages RX, and resumes — with the
kernel context untouched. Publication is eager; *admission* is lazy.
This is how LiteInst handles code that is only known when it is about
to execute, without pretending to have scanned what it never saw.

Two crates implement the idea in two settings.

## In-process: `liteinst-inprocess`

A singleton, caller-owned gate inside the same process — no ptrace
supervisor. Core publication completes *before* the gate is armed; the
SIGSEGV handler then only verifies final bytes and releases a prepared
page bundle. The handler performs no allocation, decoding, locking, or
libc calls: it checks fault provenance and every final byte in the
bundle, opens RX via a raw `mprotect`, runs the registered sync-core
serialization, and returns with the `ucontext` untouched. Foreign or
nested faults, changed bytes, and uncertain permission restoration
poison and terminate rather than guess.

The `selected` module uses the genuine core planner and publisher to
replace CPUID, RDTSC, selected returning syscalls (`read`, `write`,
`getpid`, `gettid`), RDRAND, and RDSEED before execution. Fixed bounds
(16,384 source pages, 262,144 final heads, a guarded 256 KiB
altstack) are this leaf crate's limits, stated so you can plan against
them.

What it is not: a loader, a ptrace adapter, or proof of arbitrary ELF
entry coverage. The caller owns the immutable region and certifies
complete entries and instruction extents; nothing is inferred from a
symbol table.

## At launch: `liteinst-launch`

`ExecCheckpoint::launch` owns an ELF child from its kernel exec event,
*before* its first executable or interpreter instruction. A private
pre-exec stop installs `PTRACE_O_EXITKILL`; the checkpoint exposes
bounded memory reads, registers, and entry evidence from the auxiliary
vector and mapped ELF headers. `into_stopped_process` then completes
the transition under a held stop, restoring and verifying the original
entry bytes and first-user register image before returning.

`gate::SingleThreadPageGate` revokes execute permission on all initial
user executable mappings, including the vDSO. On an authenticated
fetch fault, `RuntimeScan` checks complete pages and all-start
boundary candidates while the task is stopped; code without a census
stays gated and refuses on first touch. A concurrent variant registers
a fixed worker group, holds every task before publication, and admits
competing first faults exactly once.

The syscall policy of the restricted controller is deliberately tiny
(`read` on fd 0, `write` on fd 1/2, `getpid`, `gettid`, `exit`,
`exit_group`); everything else refuses before kernel execution. This
crate is a launch-time admission mechanism, not a general process
runtime — broader thread, signal, and mapping lifecycle support
remains open work, and the crate says so.

## Gates vs scans

Reach for a gate when code becomes known only at first execution
(lazily mapped libraries, loader-relocated text) and you can certify
its extents family-by-family. Reach for eager scanning when the code
set is closed and enumerable up front. Neither discovers *arbitrary*
dynamically generated code: a JIT emitting fresh syscall sites after
census escapes in-place patching by construction. That gap is one
reason the roadmap keeps an out-of-place translation path — see
[Interception mechanisms compared](mechanisms.md).

> 🚧 **Under construction — gate listings.** TODO: runnable listings
> for `native_probe`/`selected_probe` (in-process) and the
> `checkpoint` example (launch), each separating publication,
> first-touch, and steady-state costs as their own probes report
> them. <!-- UC: gates-listings -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`gates-listings`).
>
> 🚧 **Under construction — lifecycle coverage.** TODO: document
> fork/thread/signal behaviour per gate as that support lands; today
> both gates refuse most lifecycle operations, and this chapter must
> not outrun the code. <!-- UC: gates-lifecycle -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`gates-lifecycle`).
