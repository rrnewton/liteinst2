# Original exec under admission

This finite validation target connects one original Linux x86-64 `execve` to
the admission layer. Its intended evidence supports claims 1, 2 and 4: page
admission without cross modification, first-instruction selected coverage and
systematic tactic validation. This document describes the implementation and
required experiment; it is not an execution result. A qualification report
must identify a complete receipt at the exact source revision.

The explicit exec profile permits one singleton leader exec, without signal,
thread-creation or mapping-profile composition. It accepts actual bounded
runtime filename, argument and environment input, rather than a pathname
allowlist. Pointer slots have one combined bound including both terminating
NULL slots; string bytes have one combined bound including each NUL. Input
storage must be readable and private, disjoint from original executable source
and the trusted island. Writable private input is permitted while the sole
task is held. The original addresses and bytes are rechecked at actual syscall
ENTRY before allowing exec to proceed.

The original syscall has distinct actual ENTRY, EXEC and EXIT observations.
EXEC creates a fresh task and address-space identity at generation zero while
retaining the same process pin. Stop sequence numbers are task-local: the new
EXEC identity starts at zero. An authenticated native exec ticket and the raw
wait order connect the old and new identities; numeric stop ordering across
different tasks is not a chronology proof. Failed exec has no proved old-mm
continuity and closes the session without retry or old-code continuation.

Replacement bootstrap consumes the actual EXEC/EXIT proof. It authenticates
the first-user entry state and makes every original executable mapping NX
before source acquisition. Whole main/interpreter RX VMAs are selected from
actual ELF entry evidence and procfs device/inode backing identity; other
executable mappings, including vDSO, remain NX outside the source batch. The
existing literal vsyscall handling is unchanged. Source capture is bounded to
64 images and 64 KiB per image, with an explicit combined capture bound.
The complete maps parser has a 64 KiB/512-row bound. Visible overlapping
backing aliases refuse, including read-only aliases; pathname equality alone
does not establish backing identity.

The source resolver receives immutable owner-captured bytes and returns only
complete legal instruction heads. The owner reauthenticates the exact held
stop, full state, maps, backing identity and bytes after the callback. No
callback may supply source bytes or native publication authority. The original
absolute transaction deadline covers the selected provider, original syscall,
replacement bootstrap, resolver and final reply.

The new live domain and generation-zero census replace the old live mm in one
handoff. Old source/catalog versions, installed plans, CALL source/return
obligations, bootstrap evidence and census rows/history remain owned until
physical cleanup. This history does not authorize old-address reads,
restoration or revocation after ENTRY release. The old task is retired rather
than completed as an ordinary instruction or rebound to the new mm. Old stop,
origin and reservation identities cannot be reused in the replacement.

All six resource dimensions retain one lifetime account. The 64 MiB source
budget and other caps do not reset, and unused reservations are not refunded.
Before original restoration/release, the owner reserves input storage, raw
archive buffers, native replacement/bootstrap evidence, source capture and the
new domain/census. Actual retained-byte debits account for allocation capacity,
shared immutable allocations and moved payloads once. These are evidence-size
measurements, not allocator-private overhead or RSS measurements.

`ImageReplaced.ready` is the final bootstrap stop before any replacement
original instruction fetch. All source pages are still NX at this boundary.
The following ordinary `Advance` separately reserves and installs the first
demand-page plan. The exec transaction does not prepay or publish that plan.

The dedicated exec archive retains actual pinned raw wait headers and
initialized register/XSTATE/mask, syscall-info, event-message, siginfo and maps
read outcomes before semantic phase classification. ENTRY, EXEC, EXIT and
first-user observations remain distinct from release attempts and bootstrap
effect records. The archive preserves partial failures and physical cleanup
status, and remains readable after owner teardown. Internal bootstrap waits
are not represented as additional original exec waits. Raw addresses, maps,
registers and paths stay inside private native test observations.

The native oracle uses a static old ELF whose original CALL reaches CPUID,
returns, then executes `execve` with separate input storage. The replacement
starts with CPUID before ordinary code selects a fixed stack and reaches a
second CPUID. Independent raw original, admitted scripted CPU and admitted
native CPU lanes compare all architectural state and fixed memory. Raw CPU
boundaries use owned INT3 stops with exact RIP restoration and signal-origin
checks; they do not claim single-step trace evidence or introduce TF into the
application state. Kernel-random initial stack/auxiliary-vector data receives
independent per-lane validation before exact cross-lane fixed-stack checks.

Required controls include stale prior-session source identity, resolver panic,
resolver expiry at the original deadline and deliberate comparator corruption.
A separate private same-tracer read observes the actual first-user stop before
restoration. Borrowed pre/post-handoff inspection compares the retained old
domain and census; public CALL counts alone cannot prove payload retention.
The default oracle cache stays enabled. Its exposed usage and metrics are
compared, while its opaque internal payload is outside the dynamic field
inspection; the entire oracle moves with the old Domain unchanged.
Unsupported profiles, malformed inputs, real failed exec and unsupported
replacement shapes must fail at their exact reached phase, with physical
cleanup. They are not successful exec samples.

Run the existing six-command protocol from the clean committed revision:

```sh
python3 evaluation/admission/run.py --expect-revision "$(/usr/bin/git rev-parse HEAD)"
```

The typed JSON receipt records exact source, commands, hardware, toolchain,
harness totals, named outcomes and descendant cleanup. Failed attempts remain
tracked; raw command logs stay ignored. Validation duration is not hook latency
or application throughput. These static singleton fixtures do not complete B3
ordinary-application coverage, interpreter/PIE validation, nonleader exec,
general head discovery, B4 scan-proof artifacts or the preemption-clock claim.
