# Patcher hookup design (W3 S5b lazy trap-and-patch, for musearch)

Status: design only, for architecture review before code. Inputs:
musearm1's S5b note (sha256 74cd5525…), musearm2's Q1–Q8 answers via
museli-lt, and the landed patcher design/slices 2–3 contracts. The
Android correctness requirement (press doc §5.2, relayed by museli-lt;
text not in this repo — musearch to pin the exact wording) is treated
as: **promoted execution must be guest-visibly identical to the trap
path** (same syscall result, register, and memory effects), under
Android's platform constraints below. If §5.2 says more, it wins.

## What is being hooked up

First trap at an AArch64 SVC site forwards normally (W3 S5a, landed).
A downstream promoter, called explicitly at a deterministic
ordinary-context checkpoint, drains FIFO pending addresses (ownership
transfer), qualifies each site's mapping, builds a two-word island
`[original SVC, B resume]`, and flips the site `SVC -> B island` with
the landed `Patcher::flip`. Later calls skip SIGSYS. Branch only in
hookup slice 1; BRK fallback, far veneers, eager scanning, and handler-
context draining stay out (prior design non-goals carry over).

## API additions this requires (patch crate, slice H1)

1. `SiteBacking` dispatch inside `Site` (no dyn, no generic):
   `DualAlias { rw }` (today) and `Foreign` (store through a leased
   store window). Reads always via the RX address. New constructor
   `unsafe Site::from_rx(rx_addr, original_word, facts)`; the existing
   `from_aliases` is untouched for managed mappings.
2. `MappingFacts { page_span: (u64,u64), orig_prot: i32, provenance:
   Provenance, generation: u64 }` with `Provenance::{PrivateFile,
   PrivateAnon, Shared, Unknown}` and `qualify_mapping(addr)` parsing
   `/proc/self/maps` (promoter ordinary context only). Refusals are
   named before construction: `PatchError::MappingRefused` for shared,
   unaligned, non-executable, or indeterminate mappings. `Site`
   stores the facts; `requalify(facts)` is the only way to advance a
   site's generation, and flip refuses a generation mismatch when
   fresh facts are presented.
3. Store seam, patcher-internal: `begin_write(site) -> WriteGuard`
   (mprotect: minimal page span -> RW, recording exact original
   protections; writev fallback: no window), `guard.store(word)`
   (volatile store or one `process_vm_writev` of 4 bytes, partial
   writes are errors, never retried blindly), `guard.finish()`
   (restore exact protections; post-store failure enters the existing
   `SyncPending` custody, deliberately modelling restore failure
   after the store like sync failure — slice-3 reviewers to confirm
   this mapping). Try order: mprotect window, then writev, each
   refusal named. Fork guard: `Patcher` records `getpid()` at
   construction; flip/rollback/complete_sync refuse
   `PatchError::ForkedRegistry` on mismatch (existing flipped sites
   keep executing in the child; nobody rolls back there).
4. Emit facts: `svc_island_words(original, site, entry) ->
   Option<[u32; 2]>` plus a padded variant, in `liteinst-aarch64`
   (pure, host-tested). Downstream composes nothing from constants.
5. Nothing in the flip order changes: strategy pre-decided, island
   published while unreachable, lease, exact-word revalidation,
   custody transfer, one store, sync, acknowledged resume. The only
   new wrinkle is the mprotect window living inside that lease,
   spanning step "store..sync", restored before resume.

## Promoter placement and ownership (the musearch question)

PROMOTER = the draining/checkpoint object. Recommendation: the
*mechanism* types above live in `liteinst-aarch64-patch`; the
*promoter* (drain loop, census/generation authority, arena pool of
`Island`s with entry allocator, retry/dead lists, `StopControl` impl)
lives with the backend that owns scheduling — integration owner
musepage — not in reverie-inguest and not in the patch crate. Arena
sizing: one page = 256 entries at 16 B (4 KiB) / 1024 (16 KiB Android
pages — page size is always queried); config cap on arenas, exhaustion
leaves sites trapped (deterministic function of recorded config +
drain order). Retirement stays session-permanent; rollback reuses the
site's retained entry. Fork seals the pool (existing entries keep
working because memfd arenas are `MAP_SHARED`; new allocation in
either image would race the shared bump state, so: none).

Determinism: shape A only for hookup slice 1 — flip eligibility is a
function of recorded first-trap order + checkpoint order + recorded
pool capacity. Shape B (scheduler-lock lease) is named in the
`StopControl` contract for whoever's backend proves it; the proof
obligations are already enumerated in the landed design note.

## Android correctness constraints to encode as refusals, not hopes

- W^X/SELinux: app-domain processes commonly cannot turn writable
  pages executable or vice versa, and `PROT_EXEC` memfd may be denied
  (never-execmem policies, `vm.memfd_noexec`). Consequence: island
  creation failing with `EACCES` is an expected fleet outcome, not an
  error path surprise — promotion quietly never happens there and the
  trap path remains the correct execution. No fallback may attempt to
  defeat platform policy.
- `mprotect` on linker/shared-library text: only `MAP_PRIVATE` text is
  ever windowed (COW keeps the file and other processes untouched);
  `MAP_SHARED` (incl. some Android shared RELRO-adjacent mappings) is
  refused by name. Sites in the runtime's own gate/handler text are
  additionally refused by promoter policy (denylist by mapping
  provenance), matching musearm1's non-goal.
- 16 KiB-page Android devices: page span of the mprotect window and
  arena geometry derive from `sysconf` only.
- Existing filters: the trap source is W3's own seccomp filter;
  promotion never installs/uninstalls filters and never runs inside
  the SIGSYS handler.

## Proof shape (slice H1, after this note is accepted)

`liteinst-aarch64-patch/tests/lazy_promote_exec.rs` (dual-alias and
foreign backings): test-local S5a-shaped handler + pending table +
test promoter; one SVC helper trapped once, promoted at an ordinary
checkpoint via mprotect backend, then: first result forwarded, handler
count stays 1 across repeats, results/register effects identical,
site word is the expected branch, protections restored byte-exact
(per maps), rollback returns to the trap path. Controls: shared-mapping
and out-of-range sites stay trapped; writev backend repeats the happy
path where permitted. Same static-binary metal (64 KiB) + guest
(4 KiB) route as prior slices; 16 KiB geometry covered by host unit
tests until a 16 KiB guest exists.

Open for musearch: (i) exact §5.2 wording and any Android-domain
matrix beyond the assumptions above; (ii) production promoter home
registry (inprocess vs backend crate) — the boundary does not change
either way; (iii) whether post-store mprotect-restore failure folds
into `SyncPending` as proposed or needs its own custody variant.
