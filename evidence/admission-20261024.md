# Admission B0 and first-instruction checkpoint evidence

Historical checkpoint receipt: revisions below precede the unpublished branch's
replay onto sanitized core history. They are retained as the original capture
identities. See [the B1 receipt](admission-b1-20261025.md) for the current
qualified CALL-return rule, live publication, concurrent gate and validation.
Earlier log digests describe their original captures, not later workspace runs.

Recorded 2026-10-24 19:50:33 EDT. Code revision: `72db37c2caa765eb18658c08a6f2abdcd4e3b84c`.
Shared core A0 contract: `b1be84f53e73e2d1cde524014f31e5bfd20a89b1`.
B0 initial implementation: `923652d34614e3b3995dca810c2c0544d0ebe746`;
boundary-dependency correction: `72385bfece6a4a56fa364e760abcc7c7e8b526f9`.

## Result and limits

B0 is implemented: all-start RuntimeScan, versioned LegalEntrySet, full
cross-page snapshot dependencies, conservative model publication/invalidation,
core fact export and negative fixtures. It uses no live publisher and grants
no executable capability. B1 has an owned ELF exec-stop checkpoint; B1's page
gate exit criterion remains open. The checkpoint never resumes application code.

The 31 admission tests cover all seven default classes and explicit syscall
aliases, cross-page encodings, full 15-byte instruction halos, embedded and
overlapping entries, absent boundary bytes, unowned writers, saved resumes,
stale primary/victim plans, incomplete site coverage, stale/replayed receipts,
possibly-written failures, dependency revocation, boundary lifecycle conflicts,
and concurrent model requests. Model concurrency is not native first-fault
concurrency. Six native launcher tests cover generated static and PIE ELF files,
a custom interpreter, unchanged original GPRs/bytes, refusal/bounds, a forced
wait timeout, and child cleanup. Their selected entry instruction is CPUID.

No patch tactic or hook was added; no no-op rewrite/state-equivalence claim is
made. Live callback semantics, OS page revocation, full-thread/data-access
rendezvous, saved-PC routing, remote publication, instruction-stream sync,
concurrent native first faults, and real page first-touch latency are unverified.
The rare kernel-delayed cleanup worker handoff is not forced by this suite.

Independent reviews approved B0 at `72385bf` and checkpoint code at `72db37c`.
No original assertion, comparator, ignore list or threshold was weakened.
Review found and fixed stale neighbor authentication, writes against an admitted
bundle's dependencies, unsafe promotion of interior resume PCs, and omitted
non-executable boundary dependencies. The previously invalid dependency-chain
publication fixture now requires refusal; graph-chain/cycle revocation still has
separate coverage.

## Local validation

The tested source was committed byte-for-byte; `git diff --exit-code HEAD`
verified its equality to the code revision above. Four commands passed with
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`, `RUST_TEST_THREADS=4`, one slot target
directory and offline dependency resolution. No network dependency was fetched.

| Command | Exit | Seconds |
| --- | ---: | ---: |
| `cargo fmt --check` | 0 | 0.315 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 0.365 |
| `cargo test --workspace` | 0 | 3.470 |
| `cargo check --workspace --all-features --all-targets` | 0 | 0.265 |

Workspace totals: **204 passed, 0 failed, 4 pre-existing ignored**.
Machine: AMD EPYC 9D85 158-Core Processor; Linux x86-64; rustc 1.97.1 (8bab26f4f 2026-07-14).
Kernel release is retained in the local manifest. Slot storage was 668 MiB.
Raw command outputs and the exact-source manifest remain under
`target/li2adm-evidence/` in the assigned slot. The manifest includes CPU/kernel,
command durations, and fixture-source/log digests. Generated ELF files are
recreated from the pinned fixture source and removed after each test.

## Informational measurements

These are debug-build synthetic baselines, not optimized admission results or
release scores. There are 100 scans of each 4 KiB fixture, with 4096 candidate
starts decoded per scan. Fixed-input fixture source is
`crates/liteinst-admission/examples/scan_metrics.rs`.

| Fixture | Verdict | Known / embedded / unresolved | p50 / p95 / p99 ns |
| --- | --- | --- | --- |
| NOP page | Clean | 0 / 0 / 0 | 842495 / 893923 / 952530 |
| CPUID head | Sites | 1 / 0 / 0 | 857117 / 945290 / 1010938 |
| CPUID in MOV immediate | Refused | 0 / 1 / 0 | 840812 / 887924 / 906311 |
| Unresolved RDSEED | Refused | 0 / 0 / 1 | 837488 / 876687 / 991449 |

Each refused fixture reports one unresolved obligation. Candidate class counts
are retained in `scan-metrics.log`. This simple all-start scanner intentionally
prioritizes total candidate coverage over speed.

Ten sequential `/bin/true` checkpoint-only launches gave median startup
2620144 ns and observed maximum 2802999 ns. With ten samples the nearest-rank
p95/p99 are both the sample maximum, not a reliable tail estimate. Startup here
includes exec-stop and metadata inspection. Every child was killed without
resuming; this does not measure application startup or page admission.
`/bin/true` SHA-256: `b9b6ec37ac996b4152caca5a87e5ae23abb649bbc82dc6e1ca1d423d7bf4c171`. Original samples remain in
`checkpoint-samples.json`.

## Next B1 work and proposal clarification

The external ptrace checkpoint needs an owned trusted syscall island, remote
memory emitter, complete thread rendezvous and core A1 integration before it
can implement page admission. The present core publisher operates on local
pointers; the checkpoint exports no unsafe lease in anticipation of a solution.
This choice needs coordination with the core owner, not a cast of remote PCs.

A never-executed page can already have a CALL return address pointing into it
when a CALL ends at an admitted page boundary. The roadmap's initial lack of
interrupted PCs must not be interpreted as absence of all continuations.
Static return sites and dynamic resumes remain explicit obligations.

## Fixture and log SHA-256

- `crates/liteinst-admission/tests/core_bridge.rs`: `9fe412d8961cc701228ad2d6912c85a523eb2b63309f6077bf79e070c0ffe012`
- `crates/liteinst-admission/tests/model.rs`: `ef0f49dd9b686875528fb486328db980273f70db2c02a08fa3e99f616192a8cc`
- `crates/liteinst-admission/tests/oracle.rs`: `90754d59cc912ac386809a597da507f12bb7bbea19b2a1d8d7f142207313f9ed`
- `crates/liteinst-launch/tests/checkpoint.rs`: `a2ccc45add858790b796a94667628d6329d5b7893a48c2d41b0adfd34435d87f`
- `target/li2adm-evidence/0-fmt.log`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `target/li2adm-evidence/1-clippy.log`: `e7fde1175e40883d20084d56a7b0f1b4a09a54bf957b199cf38a7b816aed4f36`
- `target/li2adm-evidence/2-test.log`: `98fc1786c24f1875bf93e7a7bec6963cab476ceac285ae7e4187b35ed8ee8f57`
- `target/li2adm-evidence/3-check.log`: `379a8ae384eb5debd3bbac156f847857b774edb1c4e419464274ec7b9ef5db8e`
- `target/li2adm-evidence/scan-metrics.log`: `07db09c12607f5a8892c7f6847bdd748258bd3acca59c2c6034c1a05c85c3478`
