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
replace CPUID, RDTSC, RDTSCP, RDRAND, RDSEED, RDPID, and selected
returning syscalls (`read`, `write`, `getpid`, `gettid`) before
execution. Fixed bounds
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

## The three probes, run

Both gate crates ship probes that report their own costs as JSON;
run them before believing any number in this chapter. The
in-process probes demand their measurement preconditions loudly:
release build, one thread, pinned to a single reserved CPU (hence
`taskset`), and no seccomp filter. A run that cannot meet them
refuses instead of timing something else.

```console
$ cargo build --release -p liteinst-inprocess --examples -p liteinst-launch --example checkpoint
$ taskset -c 3 target/release/examples/native_probe cpuid 1000
$ taskset -c 3 target/release/examples/selected_probe masked_rdrand 1000
$ target/release/examples/checkpoint /bin/true
checkpoint_only=true resumed=false startup_ns=2461771 first_image=Interpreter initial_pc=0x7f45072eb010 executable_entry=0x562ca40478c0 mappings=13
```

The costs separate exactly as the probes report them — nothing here
is a benchmark claim beyond this host and run (batch medians over
17×1000 iterations):

* **Publication** (`publication_ns`, `gate_preparation_ns`,
  `arm_ns`): one-time, before any guest instruction — 55 µs + 5 µs +
  203 µs for the `cpuid` gate, 22 µs + 5 µs + 158 µs for the selected
  `rdrand` replacement. Arming dominates; it is also amortized by
  never recurring.
* **First touch** (`handler_first_touch_ns`, `faults`,
  `admitted_pages`): one fault, one admitted page, ≈7 µs (native) /
  ≈5 µs (selected) for the handler that verifies final bytes and
  opens RX. This is the lazy-admission bill, paid once per page.
* **Steady state** (`native_steady_ns` vs `gated_`/`patched_`):
  ≈47 ns/iteration native against ≈287 ns gated for `cpuid`, and
  ≈30 ns against ≈256 ns for the patched `rdrand` — the per-call
  price that remains after admission, which is the number your
  workload actually multiplies.

The launch probe makes the opposite trade visible: `checkpoint`
stops `/bin/true` before its interpreter's first instruction
(`first_image=Interpreter`, 13 mappings recorded, `resumed=false`)
and terminates it unexecuted. There is no steady state to price —
the checkpoint *is* the product.
>
## Lifecycle, per gate

Lifecycle support is where the two gates differ most, and mostly by
refusing. This matrix is the current code's behaviour, not a
roadmap: where a cell says *refuses*, the operation is rejected by
name or contract before it can run unobserved.

| Operation | In-process gate | Launch gate (single-thread) | Launch gate (concurrent) |
|---|---|---|---|
| Threads | Singleton only: `arm()` verifies the kernel task registry holds exactly this main thread; creating threads while armed breaks the contract | One task only; `clone` is outside the syscall policy and refuses | Bounded registration only: a factory page creates 2–8 native threads under one exact clone-flags set, each captured before its first instruction; the leader stays held at its declared `INT3` |
| `fork`/`vfork` | Prohibited while armed (the armed contract excludes fork) | Refuses before kernel execution | Refuses after registration |
| `exec` successor | Not followed: the gate owns this process's source image; disarm before exec | The *initial* exec is the checkpoint itself; a successor `execve` is outside the policy and refuses | Refuses after registration |
| Signals | The gate owns `SIGSEGV`, the signal mask, and a guarded altstack while armed; disarm/Drop restores the exact prior disposition, mask, and altstack. Foreign or nested faults poison and terminate | An unowned application signal is reported at its original PC and closes the loop — the session ends rather than delivering it | Signal syscalls after registration refuse; workers may call only `getpid`, `gettid`, and individual `exit` |
| Mapping churn (`dlopen`, remap) | Prohibited while armed: no mapping, byte, or executable-owner changes | Unsupported: the census is the initial mappings; churn has no admission path | Refuses after registration |
| Exit | `disarm()` (or Drop) restores RX and signal state; leaking an armed gate does not discharge its obligations | `exit`/`exit_group` are inside the tiny policy and run; `checkpoint.terminate()` ends a checkpointed child unexecuted | Individual worker `exit` is the one lifecycle call registration permits |

Adjacent finite profiles exist outside the gates' own lifecycle —
a one-queued-real-time-signal admission profile and a bounded
singleton mapping-lifecycle profile in `liteinst-launch` — each with
its own validation protocol. They do not widen any row above:
general thread, signal, fork/exec, and mapping-churn support
remains refused until a gate claims it with evidence.
