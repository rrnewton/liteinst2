# Changelog

All notable changes to the `liteinst` crate and its workspace are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each entry names the git tag or commit it describes. The crate was published as
`liteinst2` before version 0.2.0; see
[Releases under the `liteinst2` name](#releases-under-the-liteinst2-name).

## [Unreleased]

Changes on `main` after the 0.2.0 tag (`v0.2.0-liteinst`, commit `b11b5bd4`),
up to commit `1ccd28fc`. None of these are on crates.io yet.

### Added

- `guide/`: an mdBook guide to LiteInst. It covers instruction punning, the
  patching tactics, the plan and publication contracts, admission, page gates,
  offline rewriting, refusals, testing and performance. Some chapters are still
  marked as under construction. (commit `3e986291` and later `guide:` commits)
- `liteinst-aarch64`: a new `no_std` crate with descriptive AArch64 decode
  facts, the AArch64 counterpart of `liteinst-x86`. Every 32-bit word decodes;
  words outside the subset become `Insn::Other`. The subset covers:
  - the exclusive read-modify-write subset shared with Hermit: LDXR/STXR
    forms, exclusive pairs (recognized only), CLREX, NOP, and the ALU,
    UXTB/UXTH and CMP forms those loops use;
  - SVC and BRK with their immediates;
  - ADR/ADRP and load-literal PC-relative offsets;
  - B/BL, B.cond, CBZ/CBNZ, and complete TBZ/TBNZ and FEAT_CMPBR
    compare-and-branch operands;
  - BR/BLR/RET and BTI.

  FEAT_LSE atomics and CAS decode as `Insn::Other`; the crate only encodes
  them. It also re-encodes direct branches, ADR/ADRP and literal loads for a
  new address, and has checked encoders for an SVC patch word (a branch to a
  near island, or a BRK trap fallback), BTI landing pads and far-jump veneers.
  (commits `ec09a2a0`, `446a9d8c`, `c4217e89`, `8db4e3fc`)
- `liteinst-aarch64-patch` (`publish = false`): a runtime patcher for AArch64
  Linux built on the `liteinst-aarch64` facts. It flips a patch word while the
  target is stopped, maintains instruction and data caches across dual RW/RX
  aliases, and supports rollback. Off AArch64 Linux, its execution entry points
  return `Unsupported`.
  ([pull request 74](https://github.com/rrnewton/liteinst2/pull/74) and earlier
  `liteinst-aarch64-patch:` commits)
- `liteinst-jit` (`publish = false`): an experimental translator that copies
  basic blocks with direct edges into a code cache and counts retired
  conditional branches. Syscall-class and nondeterministic instructions exit
  to a handler the caller supplies. It recovers the precise source PC on
  synchronous faults. It has an in-process dispatcher and a ptrace-based
  remote substrate; signal delivery covers only the shapes tested in the
  remote substrate. Indirect control flow, writable source code, multiple
  threads and `execve` successors are refused by name. (commits `476afbaf`
  onward)
- `liteinst-inprocess`: in-process syscall interception mechanisms for x86-64,
  selected through a typed `liteinst_inprocess::syscall` configuration:
  - a one-site and a multi-site "zpoline" rewrite, which routes through a
    sealed NOP sled at virtual address 0. The kernel must allow a mapping at
    address 0 (normally `vm.mmap_min_addr=0` or `CAP_SYS_RAWIO`). Otherwise the
    rewrite is refused with `LowPageUnavailable` before anything is written.
    (commits `0d45cce0`, `5f65b5d9`)
  - a Syscall User Dispatch (SUD) trap substrate, which records syscall sites
    without rewriting them. (commit `cb81b6f3`)
  - a "lazypoline" mode, which patches sites that SUD discovered.
    (commit `cdf12adf`)
  - seccomp `RET_TRAP` is the default discovery substrate in the selection
    vocabulary. This crate does not yet install a seccomp runtime.
    (commit `7f3f7945`)
- `liteinst`: `SavedExtendedStateLayout::xstate_semantic_eq`, which compares two
  saved XSAVE images by restoration semantics. Inputs it cannot compare
  exactly (compacted, supervisor-state, unknown or malformed) return
  `NotComparable`. (commit `a99088d7`)
- `liteinst-x86`: an opt-in `instr-info` feature with descriptive register,
  memory and operand-access facts. (commit `90264d13`)

### Changed

- The root `liteinst` library now compiles for AArch64 Linux as well as x86-64
  Linux; non-Linux targets still do not compile. Off x86-64, extended-state
  detection refuses and names the missing Linux x86-64
  requirement, the XCR0 probe answers false, and xstate comparison answers
  `NotComparable`. Patching itself still needs Linux x86-64. (commit `f5fd865e`)
- `liteinst-launch` now compares saved extended state with
  `xstate_semantic_eq` instead of raw bytes when it authenticates task state
  across a fork, including the newly forked child; when it checks trusted
  restore, setup and interruption snapshots; and around natively executed
  selected instructions and at a selected syscall's entry. Registers, signal
  masks and all other extended-state comparisons, including the runtime
  runner's control checks, stay raw. A `NotComparable` result is refused with
  its named reason. (commits `a99088d7`, `f1976928`, `c5c395c3`, `b34c217c`)
- The published crates set `package.metadata.docs.rs` to build documentation
  for `x86_64-unknown-linux-gnu`; the root crate also enables the
  `offline-router` feature for docs.rs. (commit `3e986291`)

### Fixed

- `cargo doc -p liteinst` failed on three broken intra-doc links; they are
  fixed. Leftover "LiteInst2" names in the README and interface documents are
  corrected. (commit `3e986291`)
- Clippy findings from Rust 1.94 in the published crates. (commit `a2ead38a`)

## [0.2.0] - 2026-11-05

Published on crates.io as `liteinst` 0.2.0. This entry describes tag
`v0.2.0-liteinst` (commit `b11b5bd4ab60971b559ed02314b4ee661dbab2d1`). The
`.cargo_vcs_info.json` in the published `liteinst-0.2.0.crate` records that
commit. The crate's `src/`, `README.md` and `Cargo.toml.orig` are
byte-identical to the tag. Cargo normalizes the packaged `Cargo.toml`, so that
file differs.

The tag `v0.2.0` (commit `da8b1ab8`) is the parent commit, with the same code
under the old package name. `liteinst2` 0.2.0 on crates.io was built from
commit `5a3abdae`, one commit before that tag. The tag changes only
`crates/liteinst-launch/Cargo.toml`, and its `src/` matches the published
`liteinst2` 0.2.0.

### What LiteInst is

`liteinst` is a Rust library for hooking machine code in a running program. It
rewrites already-loaded x86-64 instructions in place, while other threads keep
running, so that a chosen point jumps into a client callback and then back. It
uses *instruction punning*: a patch is published as one atomic store that
reuses existing bytes, so a concurrent instruction fetch sees either the whole
old instruction or the whole new one. Sites split across cache lines use the
guarded WordPatch++ protocol instead. It is a reimplementation of the C++
[iu-parfunc/liteinst](https://github.com/iu-parfunc/liteinst) and the PLDI 2016
and PLDI 2017 papers cited in the README. The library is policy-free: the
embedding program owns processes, signals and syscalls.

### Supported platforms

- Linux on x86-64 only, with the System V AMD64 callback ABI
  (`INTERFACES.md`, "Initial supported envelope").
- This release has no AArch64 support. The tag contains no
  `target_arch = "aarch64"` code. `liteinst-inprocess` and `liteinst-bootstrap`
  stop with `compile_error!` on anything other than Linux x86-64.
- Minimum Rust version: 1.94 (`rust-version`); edition 2024.

### Changed

- The package and library are renamed from `liteinst2` to `liteinst`. The code
  is the same as `liteinst2` 0.2.0. Depend on `liteinst`; `liteinst2` is
  deprecated. The `v0.1.0` tag made the same rename on a side branch; 0.2.0
  makes it on the main line. At this tag, `liteinst-admission`,
  `liteinst-inprocess` and `liteinst-launch` are at 0.2.1 and depend on
  `liteinst` 0.2.0. `liteinst-x86` and `liteinst-artifact` stay at 0.2.0.
- `rust-version` rises from 1.85 to 1.94.

### Added

New public modules in the root crate (compared with tag `v0.1.0`):

- `contracts`: a versioned, policy-free boundary between planning, publication
  and admission. It holds immutable plans, legal entries, mapping generations,
  scoped leases and publication receipts.
- `quiescent`: install-once rewriting of caller-certified basic blocks under a
  scoped quiescence lease. It uses generalized short-instruction puns,
  same-block upstream relocation and prefix puns, selected by `TacticPolicy`
  (default `PreferGeneralizedPun`). Code publication is synchronized through
  Linux `membarrier` sync-core. See `INTERFACES.md` and `A1-QUIESCENT.md`.
- `composition` and `bundle`: ordered byte composition and generation-bound
  transactions that span several generated images (`A2-COMPOSITION.md`).
- `engine`: bounded install-once selection across the qualified tactics.
  `engine::plan_with_emission` produces an `ArtifactPlan` for offline use.
- `emission`: explicit targets and symbolic same-module hooks for offline ELF
  rewriting (`A3-OFFLINE.md`).
- `patcher::synchronized`: an experimental word and batch publication API that
  uses sync-core barriers (`A4-SYNCHRONIZED.md`).
- `sync_core`: process-scoped instruction-stream synchronization.
- `backedge_clock`: clocks counted on taken backward branches, including
  `BackedgeClockRegion`. Example clients: `owned_loop_clock` and
  `owned_region_clock`.
- `eviction`, `eviction_chain`, `neighbor`: tactics that evict neighbouring
  original instructions to make room for a short selected-site pun.
- `controls`: data controls that switch observing callbacks on and off in
  generated code without rewriting it.
- `precontext`: optional per-call observation selection before the full
  context is captured.
- `frame_trace` and `generated_unwind`: frame-transition records and opt-in,
  source-certified normal backtracing through generated code.
- `grouping`: immutable physical backing shared by images at dictated virtual
  addresses. Images at disjoint offsets within one page share a backing page;
  an image that crosses a page boundary gets its own backing.
- `control_flow`, `scalar_profile`, `search`: supporting analysis and planning
  facts.
- `x86`: a re-export of the new `liteinst-x86` crate.
- Features: `offline-router`, an opt-in startup bootstrap for static `ET_EXEC`
  binaries that uses the SIGILL router; and `saved-pkru-probe`, with an example.

New published workspace crates (versions at this tag):

- `liteinst-x86` 0.2.0: shared descriptive x86 decode facts over iced-x86.
- `liteinst-artifact` 0.2.0: content identities, bounded metadata and sparse
  byte overlays for offline-rewritten ELF files.
- `liteinst-admission` 0.2.1: an all-start x86-64 instruction scanner for
  CPUID, RDRAND, RDSEED, RDPID, RDTSC, RDTSCP and SYSCALL; versioned entry
  facts; and a mock page/dependency ledger. It never changes executable memory.
- `liteinst-launch` 0.2.1: captures an ELF child at its exec stop, before its
  first instruction, and gates its initial executable pages under ptrace.

### In-guest components

These run inside the instrumented process, with no ptrace supervisor:

- `liteinst-inprocess` 0.2.1: a singleton in-process NX page gate. Before
  execution, its `selected` module prepares replacements for CPUID, RDTSC,
  RDRAND, RDSEED, RDPID, RDTSCP and returning read/write/getpid/gettid
  syscalls. The gate then admits pages on first touch from a SIGSEGV handler
  on a guarded signal stack. The caller owns the code region and certifies
  instruction extents and entries.
- `tools/page-entry` (repository only, not in the crate package): a
  first-entry launcher. A freestanding ELF interpreter bridge runs the real
  dynamic linker and the application under the in-process NX gate. Its opt-in
  selected controller adds temporary CPUID, SYSCALL and RDTSC source patches.
- The `offline-router` feature above, which installs its router from a static
  binary's constructors.

### Known limitations

- Not a probe-anywhere tool. Clients must supply a trustworthy code region,
  write access to the live patch word, ownership of the mapping lifecycle,
  proof that no control flow enters the interior of a relocated window, and a
  trap fallback when the planner returns `PunPlan::TrapRequired`.
- Callbacks must not unwind, and there is no transparent signal delivery or
  exception unwinding through generated code.
  `trampoline::translate_program_counter` maps a generated PC back to the
  application PC. The opt-in `generated_unwind` module publishes call-frame
  records only for source-certified normal backtraces. The embedding runtime
  supplies the rest.
- Trampoline arenas keep separate RW and RX aliases of one sealed memfd, so
  they are not strict W^X. Arena creation fails if the required memfd seals are
  unavailable.
- Concurrent WordPatch++ installation owns the process SIGTRAP disposition. It
  refuses to install over a custom SIGTRAP handler.
- Guarded split-site publication needs a caller-supplied `StalenessBudget`.
  Clients without one should send split sites to a trap fallback.
- The unsafe `patcher` and `trampoline` quiescent entrypoints
  (`bind_quiescent`, `install_replacing_first_quiescent`,
  `install_replacing_first_in_arena_quiescent`, and the matching apply, revert,
  activate and deactivate methods) skip trap registration and guarded split
  publication. They are valid only when the caller excludes every other
  thread, signal handler, instruction fetch and code writer for the whole
  call.
- `patcher::synchronized` is experimental.
- `liteinst-inprocess`, the page-entry launcher and `liteinst-launch` support
  only narrow profiles: single-threaded or fixed-group processes, and
  caller-certified immutable code. General thread, signal and mapping
  lifecycle support is not implemented.

## [0.1.0] - 2026-10-24

Tag `v0.1.0` (commit `dc615ed0`). This tag was never published to crates.io
under the `liteinst` name. It renames the `liteinst2` package at commit
`d64dc833` to `liteinst`, without other code changes. It is not an ancestor of
0.2.0; commit `d64dc833` is.

The lists below summarize the library as of this tag. Most of it had already
shipped in `liteinst2` 0.1.0 and 0.1.1; only the exact-syscall plan (commit
`d64dc833`) and pull requests 31, 32 and 33 are newer than `liteinst2` 0.1.1.

Linux x86-64 only; `rust-version` 1.85. Public modules: `cache_line`,
`patcher`, `planner`, `probe`, `rapid`, `scanner`, `trampoline`.

### Added

- `rapid`: exact one-byte instruction puns with atomic opcode toggling.
- `patcher`: live multi-instruction jump patching with guarded WordPatch++
  publication for sites split across cache lines. Unsafe quiescent variants
  (`patcher` `bind_quiescent`, `trampoline` `install_replacing_first_quiescent`)
  skip trap registration and guarded split publication. They are valid only
  when the caller excludes every other thread, signal handler, instruction
  fetch and code writer for the whole call.
- `trampoline`: relocation-aware hook trampolines. They preserve the saved
  integer context and the exact FXSAVE64/XSAVE64 extended state, return safely
  under CET, and offer allocation-free PC translation
  (`translate_program_counter`) and controller-owned ptrace stop points.
- A plan for hooking a literal two-byte `syscall` instruction that copies no
  guest tail and leaves PKRU live (`from_scan_replacing_exact_syscall`).
  (commit `d64dc833`)
- Concurrent single-cache-line jump patches whose 8-byte stores overlap may
  coexist when their displaced instructions are disjoint. Split-word, rapid
  and true displacement conflicts are still refused.
  ([pull request 28](https://github.com/rrnewton/liteinst2/pull/28))
- Trampoline arena reservations are shared across `fork`. (commit `26931f66`)
- `planner`: chooses rapid, relocated or client-trap handling;
  `PATCH_SITE_DECISION_TREE.md` documents the decision tree.
- Examples `replace_first` and `preload_consumer`.
- The repository, but not the crate package, adds the `rapid-profiler` tool.
  ([pull request 21](https://github.com/rrnewton/liteinst2/pull/21))

### Fixed

- Branches back to a hooked instruction now revisit the live patch and run the
  observing callback.
  ([pull request 31](https://github.com/rrnewton/liteinst2/pull/31))
- Relocation preserves the original targets of PC-relative memory operands.
  ([pull request 30](https://github.com/rrnewton/liteinst2/pull/30))
- An application's own SIGTRAP at an inactive patch site is preserved.
  ([pull request 29](https://github.com/rrnewton/liteinst2/pull/29))
- CET returns, relocated PC reporting, and far direct branches relayed
  through CET landing pads.
  ([pull request 17](https://github.com/rrnewton/liteinst2/pull/17),
  [pull request 32](https://github.com/rrnewton/liteinst2/pull/32),
  [pull request 33](https://github.com/rrnewton/liteinst2/pull/33))

## Releases under the `liteinst2` name

The crate was published as [`liteinst2`](https://crates.io/crates/liteinst2)
before it was renamed. The commits come from the `.cargo_vcs_info.json` in each
published `.crate` file.

| `liteinst2` version | Published  | Source                                                            |
|---------------------|------------|-------------------------------------------------------------------|
| 0.2.1               | 2026-11-05 | commit `544c84c1`: deprecation pointer to `liteinst`              |
| 0.2.0               | 2026-11-05 | commit `5a3abdae`, parent of tag `v0.2.0`; same code as `liteinst` 0.2.0 |
| 0.1.1               | 2026-10-04 | commit `783790c1`: commit `2032b49d` with a version bump and one `#[allow(deprecated)]` in `src/trampoline.rs` |
| 0.1.0               | 2026-07-31 | commit `b21b2482`                                                 |
| 0.0.1               | 2026-07-31 | name reservation, not built from this repository's history        |

[Unreleased]: https://github.com/rrnewton/liteinst2/compare/v0.2.0-liteinst...main
[0.2.0]: https://github.com/rrnewton/liteinst2/tree/v0.2.0-liteinst
[0.1.0]: https://github.com/rrnewton/liteinst2/tree/v0.1.0
