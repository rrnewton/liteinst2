# Runtime patcher design (W4 next slice, for review before code)

Goal: flip one live `SVC` word to `B` (near island) or `BRK` (trap
fallback) at runtime, stopped-thread first, using only landed
`liteinst-aarch64` emit facts. Non-goals until the Section-5 gate closes
(Arm DDI0487 primary text on concurrent-modifiable membership of
SVC/BRK): no lock-free live flip, no concurrent publication claim.

## Home: new crate `crates/liteinst-aarch64-patch` (decision for review)

Argued from landed boundaries:

- `liteinst-aarch64` is unconditionally `#![no_std]` +
  `#![forbid(unsafe_code)]` and fact-only ("never execution authority";
  both reviewers credited exactly that). A patcher needs std, libc and
  unsafe (mmap/memfd, cache-maintenance asm, raw stores). It cannot
  live there without revoking the reviewed guarantee.
- The `liteinst` core package is documented "Linux x86-64 only" and its
  tree is x86 machinery (iced facts, x86 emission/trampoline/trap). It
  does not build for AArch64 today; growing an AArch64 runtime inside
  it means an arch-split refactor of the published core — wrong first
  slice, large blast radius.
- The workspace already splits runtime concerns by crate
  (`liteinst-launch`, `liteinst-admission`, `liteinst-inprocess`) over
  shared fact crates. A small `std`, AArch64-Linux-only
  `liteinst-aarch64-patch` depending on `liteinst-aarch64` follows that
  grain: facts stay pure, all unsafe is contained and auditable in one
  new crate, and core integration (a future arch split) stays possible
  without reworking this slice.

Alternative if reviewers insist on an existing home: `liteinst` core
under `cfg(target_arch = "aarch64")`, accepting that the core crate
then needs an AArch64 build story it does not have today. Not
recommended for this slice.

## Flip protocol (stopped-thread)

Invariant: at every instant the site word is either the original `SVC`
(executes and re-traps normally) or the new `B`/`BRK` whose target is
already fully written and cache-synced. Never a torn word (one aligned
4-byte store is single-copy atomic), never a branch to a half-built
island.

1. Build island in a dual RW/RX memfd mapping (`MFD_EXEC` requested;
   `EACCES` under `vm.memfd_noexec=2` degrades the site to BRK-only).
   Entry starts with the `landing_pad` for its reach; body ends with a
   branch back to site+4. All words come from `emit` constructors.
   Island placement: caller-provided RX base must satisfy
   `island_reaches`; near-allocation probing stays caller policy in
   this slice (tests use one mapping for stub + island).
2. Publish island: write via RW alias, then clear-cache the RX range
   (DC CVAU per CTR_EL0 D-line, DSB ISH, IC IVAU per CTR_EL0 I-line,
   DSB ISH, ISB; IDC/DIC elision permitted for DC/IC only, DSB/ISB
   unconditional). If EL0 cache ops trap in the execution environment,
   init-time self-test on the island detects it and refuses Branch
   strategy (BRK still needs the same sync for its own word — refusal
   then is total, reported, no flip attempted).
3. Stop the target thread through a caller-supplied `StopControl`
   trait (Hermit scheduler stop, ptrace stop, or cooperative park in
   tests). The patcher never flips a running thread in this slice.
4. Re-read the site word; require `decode == Svc` (someone else may
   have patched it). Compute the word with `patch_svc` (alignment and
   range already refused there).
5. One aligned 4-byte store of the patch word through the RW alias of
   the site's mapping (code pages arrive dual-mapped in tests; foreign
   RX text without an RW alias is out of scope until a later slice
   owns `process_vm_writev`/ptrace writes).
6. Clear-cache the site line, then resume. Rollback is the same
   protocol storing the original word back; both states stay valid.

State per site: `Unpatched -> IslandReady -> Flipped(Branch|Trap)`,
transitions only under the caller's stop; double-flip of a `Flipped`
site is refused, not re-stored.

## API sketch (all fallible, checked)

- `Island::build(page_size, words) -> Result<Island, PatchError>`
  (RAII dual map; `entry_addr()`, `sync()`).
- `cache::line_sizes() -> (usize, usize)` from CTR_EL0;
  `cache::clear_cache(rx_ptr, len)` (the emit_exec harness sequence,
  promoted to production code with SAFETY comments per asm block).
- `Patcher::flip(&self, site: &mut Site, stop: &mut dyn StopControl)
  -> Result<Strategy, PatchError>`; `Site` owns addr + RW alias ptr +
  state. `PatchError` enumerates refusals (not SVC, misaligned, out of
  range with no fallback permission, memfd/mmap errno, cache-op trap).
- No BLR low-page path: probe/refuse only, unchanged from emitter.

## Test plan

- Host unit: state-machine transitions and refusals against a fake
  store/stop (no unsafe), word-level via landed decoder.
- AArch64 execution (`tests/`, target-gated like `emit_exec`):
  (a) self-thread flip SVC->B and SVC->BRK (existing shapes, now via
  production `Patcher`); (b) stopped-thread flip: worker loops stub
  calls between cooperative park points, main parks it, flips,
  resumes, observes return-value change; (c) rollback restores SVC
  behavior. Run on 64 KiB metal + 4 KiB guest (same static-binary
  route); page size from `sysconf`, asserted never assumed.
- Slices: (1) this note; (2) crate skeleton + cache/island RAII +
  host tests; (3) flip protocol + exec proofs; (4) BRK fallback flip
  + receipts. Signed local commits, push only on museli-lt word.

Open gates carried from the evaluation report: DDI0487 concurrent-
modifiable primary text (unlocks any future non-stopped flip),
`PROT_BTI` guarded-mapping policy, foreign-text write channel.
