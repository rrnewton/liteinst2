# Generation-bound point controls

`data_flag::DataFlagSession` is an additive Linux x86-64 point-observation adapter. It connects actual managed `ProbeControl` flags and generated observing callbacks to the existing bounded `Session`, generation reservations and thread-local completion owners. It does not implement application entry/return intervals or complete A4 qualification. All new tests in this proposal are unexecuted.

The controller constructs its controls internally. `actions()` returns planner-readable clones for the existing `TrampolinePlan::from_controlled_actions`; the trusted publisher must preserve the PC/control association and satisfy its existing ISA, entry, code-publication and process-lifetime image obligations. The adapter never writes executable bytes. The generated observer still saves full state before testing a flag, so this is not an early cheap gate. Generalized pun remains a separate install-once tactic, not RapidProbe.

## One writer and exact callback ownership

`ControlWriter` is an unforgeable, non-Clone capability for exactly one managed block. Only the controller retains its writers. Managed public clones return `ManagedControl` from `try_set_enabled`, and the legacy void setter panics before storing. Ordinary controls retain their release-store API and ordinary callback ABI. Mandatory callbacks use a managed ordinary control initialized true; the adapter never toggles them and they do not require TLS attachment.

An optional managed callback receives a transparent, lifetime-bound `ControlIdentity`. Its higher-ranked callback signature prevents safe escape beyond the active dispatch. The image retains the block throughout that call. The adapter matches both the original logical PC and the exact retained control; an older live image with the same PC and install number cannot borrow a different installation's epoch. The token is identification only: it grants no mutation or pointer dereference.

The controller owns the Session, staged epoch handles and physical writers privately. Session's small crate-private extension runs only its atomic flag stores while holding the existing writer-then-registry lock order. No user callback runs under those locks. Public Session operations retain their existing failure/capacity logic through no-op update closures. No generation, counter or reservation algorithm is replaced.

`stage` retains each immutable epoch under the existing E budget; this first finite adapter does not recycle retained stages. `arm`, `disarm`, `deactivate` and `scan_closed` share that writer authority. A stale K request retains the existing Stale action and performs no physical flag store. The bounded existing scan recovers K closures without adding a notification queue. Each optional member gets its own flag even within a shared physical group; the installed redirect remains, and a mandatory member stays enabled.

## Admission, physical visibility and drain

Before executing optional work, the callback acquires the current registry owner and reserves it through the existing TLS `ThreadModel::enter_acquired` path. A handle acquired before close either already reserved and completes to that old owner, or is refused by the closed old epoch. It cannot silently switch to the newly published epoch. Payload, terminal and release ordering are unchanged. The private point result distinguishes a refused optional body from the public TLS `observe` API, whose body still runs once on refusal.

`admission_boundary(ticket)` joins an exact controller/epoch/transition identity to the registry lock and returns `Current(epoch)` or `Closed(epoch)`. This is an admission statement. A stale true outer flag after disarm still encounters the closed/no-current registry. A stale false flag after arm can skip the callback before that registry is reached.

Accordingly, `ToggleProbe::complete` returns `Visibility::Eventual`, including for disarm. It does not narrow the existing meaning of `Visibility::Complete`. `close_and_drain` closes the named owner and succeeds only after its callback reservations reach zero; while a callback is held it returns a bounded refusal that the caller can poll. This is metadata/optional-callback drain, not proof that executors left emitted code or that code can be reclaimed. Published trampoline storage remains process-lifetime.

A future stricter backend needs a proved all-executor data-gate visibility boundary under the same ticket and writer authority. Existing `SyncCore` supplies instruction-stream serialization for a separately validated publication protocol; its presence alone does not prove this AtomicBool gate's reader boundary or drain already-admitted callbacks. No barrier, guessed delay or Boolean-readback completion is added here.

## Finite operating scope

The immutable point map is nonempty, strictly PC-ordered and bounded by the existing 16-function limit; optional identities are unique and every dense group has an optional member. The existing Session E/T/D/A/action bounds and generation M/K limits remain exact. Mandatory-only callbacks can use permanent ordinary controls outside this adapter. Thread registration is explicit and consumes the existing non-recycled T budget.

Callbacks must obey the existing state-preserving, non-unwinding hook contract. This is ordinary-thread code, not signal, fork, longjmp or foreign-unwind support. Reentrant optional point dispatch is refused without running optional work. Missing TLS attachment likewise runs no optional body. Diagnostics retain the last result, last refusal and exact refusal count for the current attachment. Dropping a thread token while idle detaches; dropping it inside its borrowed callback retains the attachment until TLS destruction. A controller Drop closes retained epochs even if best-effort physical removal fails; it supplies no completion receipt.

The native interval-pair path is deliberately unsupported. Its entry creates bookkeeping even on `FunctionClosed`, and its exit requires that pair. Simply gating those callbacks could create an unmatched exit or strand an old frame. Always-on pairing/bookkeeping needs a separate implementation before interval toggling can be admitted.

## Prospective correctness checks

One generated MOV/NOP/NOP/RET image test uses three real controlled callbacks and four deterministic cohorts. Channel waits are bounded at five seconds; errors/panics are not converted to success. The caller's existing bounded test command remains the execution authority.

1. Pause after acquiring the old owner but before reservation, rearm, then require exact `EpochClosed`, no old record, and the later member recorded in the new epoch.
2. Pause after reservation, rearm, require drain refusal, resume to an exact old terminal/payload, and deliver an old K request without changing or invalidating the new state.
3. Pause the second coalesced member, close only the first through the real bounded scan, retain the second and mandatory callback, then verify stale-true admission refusal, explicit closure and mandatory work after disarm.
4. Attach a different controller at identical PCs/install number, execute the old live image, and require two binding refusals while the unchanged mandatory callback runs.

All cohorts retain the original return value and compare the entire emitted code bytes before/after updates. Control tests additionally cover both managed-setter refusals, exact distinct writer identity and transparent token layout; compile-fail examples cover writer duplication, token escape/static storage and private Session access. These tests do not replace the existing full-state controlled-emitter or generation/TLS suites. No performance, full architectural equivalence, completed physical visibility, interval-pair support, code reclamation or overall A4 result is claimed by this source proposal.
