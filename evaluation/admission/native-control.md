# Native controller evidence boundary

`DynamicSession` executes original code without instrumentation. Its fixtures
qualify specific launch, stop, signal and cleanup behavior. They do not qualify
page publication, instrumented signal entry, dynamic membership, or a browser.
The exact-revision `run.py` protocol records these harnesses with the rest of
the admission corpus, hardware, commands and source hashes. An expected
assertion is evidence only after that revision's run passes.

The ordinary untraced signal oracle runs the same immutable ELF and compares
whole handler records and continuation bytes. Records include all 128 siginfo
bytes, handler stack address and kernel signal mask. Separate cases require two
queued realtime payloads, actual LISTEN/SIGCONT, native EINTR and native
SA_RESTART with an alternate stack. These are specific observable comparisons;
they are not claims of exhaustive signal-frame or exception coverage.

The separate control harness requires static, PIE and interpreter exec-stop
authentication, exact kernel exec return, repeated active interruption, stale
and foreign token refusal, timeout cleanup, independent wait domains, a full
raw-ptrace terminal GPR/flags/XSTATE/memory comparison with corruption controls,
and 14 explicit lifecycle/syscall-personality refusal rows. Cleanup does not
count an issued signal as a terminal receipt, and an unconfirmed SIGKILL cannot
authorize resuming original instructions.

## Private real-parent reaper

The corrected controller uses a dedicated host tracer thread and a private
raw-syscall reaper process. The reaper is the application's real parent and
sets its own child-subreaper flag. The host's process-wide setting is unchanged.
This topology changes the application's observable `getppid()` result: it names
the private reaper. It is part of this launch contract, not an assertion of
equivalence with launching directly from the embedding process.

Both clones acquire pidfds atomically with exit signal zero. The application
copies the inherited signal dispositions, process group and session before the
reaper resets its own SIGCHLD disposition and creates its own session. After
that copy, the reaper closes unrelated inherited descriptors. Its post-clone
path uses fixed storage and raw syscalls, without allocation or host callbacks.

The reaper transfers the application's pidfd over a private credential-checked
channel and retains the unreaped root identity until attachment is acknowledged
or abandoned. The tracer peeks at waits and pins newly observed identities before
consuming terminal statuses. Its terminal receipts retire numeric signalling
authority; they do not themselves establish physical removal. Final cleanup
also requires the reaper's natural-parent `ECHILD` receipt, disappearance of
retained application identities and reaping of the private reaper itself.
Client timeout requests cancellation while the original owner keeps draining;
it does not authorize killing the reaper before its descendants are gone.

Unexpected helper death loses the local natural-parent authority. It remains
failed proof, and the original owner retains application identities until their
physical disappearance is observed. If the helper died before transferring the
root identity, or an allocation failure prevented pinning a later identity, an
authenticated natural-parent drain is required to close that missing physical
witness. Without it, the owner remains retained; client waits stay bounded.
The helper-death regression uses a separate outer subreaper that deliberately
withholds the natural-parent wait, then performs it to release the physical
removal witness. A second exec-isolated regression kills the helper after its
application clone and before the pidfd handoff. It requires retained ownership
both before and after an external natural-parent reap: that external knowledge
is never inserted into the owner as a reconstructed proof. No successful
cleanup is inferred from either failure.

These implementation requirements remain unqualified until a complete exact
revision run passes. The separate fork diagnostic and strengthened public
oracles retain the original assertions and additionally check pidfd `POLLHUP`,
helper disappearance, host subreaper state and unrelated-child waitability.

## Kernel ownership argument

The source review uses upstream Linux v7.1.3. Matching a numeric upstream
version does not authenticate a vendor kernel's complete source; the recorded
native tests independently exercise the running kernel. The reviewed files
are available under
`https://raw.githubusercontent.com/gregkh/linux/v7.1.3/kernel/`.

| File | SHA-256 | Relevant functions |
| --- | --- | --- |
| signal.c | c8e3ea51d8cbbd5467477cefcd4c524dddae896925163ce44e043c9453b75a8d | do_notify_parent, ptrace_stop, do_jobctl_trap |
| ptrace.c | 6f158c7b443a7a20c36c36abbe68e012fc3dc8017d73771834648541101e85c8 | ptrace_request: PTRACE_INTERRUPT and PTRACE_LISTEN |
| exit.c | e4c0770ac99a41e6ea6cc71310b99b32daba05c67357aea42c5e1813f42cc61d | exit_notify, eligible_child, wait_task_zombie, find_new_reaper |
| fork.c | 384aabaa48c2f4bb2d619c6d561be98e62cd9527024c3eccd5853dfc1f3a76ae | copy_signal, copy_process |

The additional file `fs/pidfs.c` at the same repository and tag has SHA-256
`b762e20997be6188b8ed64edd9ef0bea91fd71d1cd081a8227e96be8f59465b9`.
Its `pidfd_poll` distinguishes an exited task from a detached task.

The bootstrap uses raw clone with CLONE_PIDFD, no shared VM and exit signal
zero. The pidfd is obtained atomically. A fresh signal structure is zeroed and
CLONE_AUTOREAP is absent. Before SEIZE, exit signal zero avoids the
SIGCHLD-specific automatic-reap rule; `__WALL` includes this clone child. After
SEIZE, both automatic-reap branches require the task to be untraced. The
original tracer remains the exclusive consumer of ptrace statuses. External
tracing or reaping violates that ownership.

That terminal status is insufficient to prove physical reaping of a traced
non-child process leader. `wait_task_zombie` uses `EXIT_TRACE`, unlinks the
ptracer and restores `EXIT_ZOMBIE` for the real parent unless it automatically
reaps. `find_new_reaper` follows real-parent ancestry when that parent exits.
Consequently, tracer-domain `ECHILD` and pidfd `POLLIN` can both hold while the
zombie remains. In the reviewed kernel, pidfd `POLLHUP` additionally requires
`pid_task(pid, PIDTYPE_PID)` to be null. A complete cleanup claim needs the real
parent's drain and physical task disappearance, beyond a ptrace terminal wait.
The failed validation at revision `59660630a936bca5271e8776ee2cc950af3139c6`
retains two outer-supervisor adoptees despite all test assertions passing; its
receipt is failed evidence, not a qualified cleanup result.

An interrupt can be satisfied by a real syscall or signal stop. The kernel
clears pending STOP at each new ptrace stop, but a request issued after an
already queued stop can require another stop after resume. The controller must
retain the real event, not replace it with a fabricated interruption. For a
seized job-control trap, the kernel emits SIGTRAP only when no group stop is
active; otherwise it reports the stopping signal. A delayed interrupt therefore
does not authorize treating a still-stopped group as continued.

To retrieve the reviewed source for inspection without adding it to the
repository, run this shell script from the repository root and compare the
printed digests with the table:

```sh
set -eu
mkdir -p target/review-linux
for name in signal ptrace exit fork; do
    curl --fail --silent --show-error --location --max-time 30 \
        --output "target/review-linux/$name.c" \
        "https://raw.githubusercontent.com/gregkh/linux/v7.1.3/kernel/$name.c"
done
curl --fail --silent --show-error --location --max-time 30 \
    --output target/review-linux/pidfs.c \
    https://raw.githubusercontent.com/gregkh/linux/v7.1.3/fs/pidfs.c
sha256sum target/review-linux/signal.c target/review-linux/ptrace.c \
    target/review-linux/exit.c target/review-linux/fork.c target/review-linux/pidfs.c
```
