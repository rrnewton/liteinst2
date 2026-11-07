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

### Project stage: the first-hook target behind a page gate

The [first-hook project](first-hook.md) ends here, but not by putting
its `InstalledHook` behind the gate unchanged. That hook toggles by
rewriting source bytes through a writable alias; an armed
`PreparedGate` instead requires a private, immutable RX source and
an independent final-byte snapshot, and the gate itself patches
nothing. The honest variant therefore rebuilds the same six-byte
body (`xor eax,eax; inc eax; nop; ret`) in one private anonymous
page and publishes one install-once relocation *before* the gate is
prepared.

Planning follows [Listing FH-5](contracts.md#project-stage-two-sites-one-bundle)
with one member instead of two: the same complete sole-entry claim,
`RelocationOnly`, at most five displaced bytes, and one pinned
generated page. Two details change. The semantics are
`HookSemantics::ReplaceFirst`, and the callback sets `rax` to 40, so
the relocated `inc` tail makes the published function return 41,
as in the first hook. Publication makes the single page writable,
holds a quiescence lease over it, and calls
`PlannedInstall::publish_with` with a finalizer that restores RX;
there is no second alias to keep writable afterwards.

Only then does the gate enter. The whole final page — the body at
offset 128 and `0xCC` filler elsewhere — is copied into an
independent snapshot. The certified final fetches are not the
original instruction list: they are the published five-byte jump at
the body entry and the one-byte `ret` after it, both assigned to a
one-page `PageBundle`. Any other source fetch would have to be
named here; an unlisted or foreign fault is not admitted by
approximation.

<span class="filename">Listing FH-7: publish eagerly, admit on first touch</span>

```rust,ignore
    /// Runs one complete gate cycle. This must be a process entry point,
    /// not a libtest thread: `PreparedGate::arm` verifies that the kernel
    /// task registry contains exactly this main thread.
    pub fn run() -> GateMetrics {
        CALLBACKS.store(0, Ordering::Relaxed);
        let mapping = SingleMapping::new();
        mapping
            .protect(libc::PROT_READ | libc::PROT_EXEC)
            .expect("source page becomes executable");
        assert_eq!(unsafe { mapping.function()() }, 1);
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);

        let planned = plan(&mapping, identity(&mapping));
        let installed = publish(&mapping, &planned);
        assert_eq!(unsafe { mapping.function()() }, 41);
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 1);

        let final_bytes = mapping.bytes().to_vec();
        let address = mapping.address;
        let function = mapping.function();
        let mut owner = Owner {
            mapping,
            installed: Some(installed),
        };
        let extents = [
            InstructionExtent {
                offset: OFFSET,
                len: 5,
                bundle: 0,
            },
            InstructionExtent {
                offset: OFFSET + 5,
                len: 1,
                bundle: 0,
            },
        ];
        let bundles = [PageBundle {
            first_page: 0,
            page_count: 1,
        }];
        // SAFETY: the owner retains the private RX source and installed
        // core patch; the snapshot is an independent immutable copy and
        // the extents name both final fetches in the source page.
        let prepared = unsafe { PreparedGate::new(&mut owner, address, &final_bytes, &extents, &bundles) }
            .expect("gate preparation succeeds");
        // SAFETY: this main thread is the singleton and no source call is
        // in flight while permissions change.
        let armed = unsafe { prepared.arm() }.expect("gate arm succeeds");
        assert_eq!(armed.metrics().faults, 0);
        assert_eq!(unsafe { function() }, 41);
        let first_metrics = armed.metrics();
        assert_eq!(first_metrics.faults, 1);
        assert_eq!(first_metrics.admitted_pages, 1);
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);
        assert_eq!(unsafe { function() }, 41);
        assert_eq!(armed.metrics(), first_metrics);
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 3);
        let metrics = armed.disarm().expect("gate disarm succeeds");
        assert_eq!(metrics, first_metrics);

        retire(&mut owner);
        assert_eq!(&owner.mapping.bytes()[OFFSET..OFFSET + BODY.len()], &BODY);
        assert_eq!(unsafe { owner.mapping.function()() }, 1);
        assert_eq!(CALLBACKS.load(Ordering::Relaxed), 3);
        metrics
    }
```

This code runs as a dedicated child binary, not inside a libtest
thread: `arm()` verifies that the kernel task registry contains
exactly the main thread. The binary first establishes the gate's
signal profile exactly as the shipped `native_probe` and
`selected_probe` do — block every signal except `SIGSEGV` and
`SIGILL`, reset Rust's stack-overflow `SIGSEGV` handler to the
default disposition for the gate's lifetime, and restore both
afterwards. Without that transfer, arming refuses with
`Invalid("SIGSEGV/default/unblocked/altstack contract")`.

The observed cycle is `native=1 published=41 gated=41 retired=1
faults=1 admitted_pages=1`: the first gated call pays the one
admission fault, the next changes no gate counter, and disarming
alone does not remove the hook. Removal is the separate core
retirement after disarm, under a fresh lease (as in
[Listing FH-6](contracts.md#project-stage-two-sites-one-bundle));
it restores all six source bytes and the counters stop.

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
