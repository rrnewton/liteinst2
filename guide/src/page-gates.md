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
> 🚧 **Under construction — lifecycle coverage.** TODO: document
> fork/thread/signal behaviour per gate as that support lands; today
> both gates refuse most lifecycle operations, and this chapter must
> not outrun the code. <!-- UC: gates-lifecycle -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`gates-lifecycle`).
