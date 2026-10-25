# Prepared instruction-stream synchronization capability

The new `sync_core::SyncCore` capability queries Linux support, registers the
process, and completes an initial private expedited sync-core barrier before
returning a handle. Each later synchronization checks the process identity,
orders prior stores, completes the kernel barrier and serializes the caller
with CPUID. Errors preserve the exact operation and errno. There is no timing
fallback or implicit retry. A fork child must prepare its own handle.

This primitive writes no executable bytes and supplies neither quiescence nor
saved-PC translation, callback drain, or a safe patch-transition proof. A
publisher must retain an incomplete transaction if synchronization fails after
mutation. Existing publication behavior is unchanged by this increment. The
guard/sync/back/sync/front/sync publisher, batches, forced guard and saved-PC
qualification, and Intel/AMD publication matrix remain A4 requirements.

Private validation on the AMD EPYC Zen 5 dev host passed six mock tests covering
command order, either missing command, each syscall error, unexpected results,
fork identity and later denial. A fresh single-main-thread native witness
required two successful preparations, three additional synchronizations, one
exact inherited-child refusal and normal child exit. Unsupported capability is
a test failure. It does not qualify instruction coherence. The public workspace
fixture retains this witness inside the existing bounded owned-group launcher,
with CPU20/wall30, a 1MiB per-file cap and leader-last descendant cleanup.

The private package passed formatting, both fresh builds and warnings-denied
Clippy with one codegen unit and CPU60/wall90 bounds. A separate installed Rust
1.85.0 all-target check passed offline and locked. The narrowly scoped
`unused_unsafe` annotation preserves the CPUID call across compiler versions,
as in existing core CPUID helpers. No dependency upgrade is introduced.

Private build, MSRV and execution audit digests respectively:

- `77f582c86b7f65c542dddb7704097c0f4cd8a0b54d5b479a0ed9ed6d815a54d1`
- `82e45eb1b2a7c39232895840470b0ab6ae93b10e29b63053881dd5ecb0108afb`
- `5f7af01bb30255e43b8a626fe96a9a775054b25fefc597179eb568d8c85e9b57`

Earlier dependency and lint failures remain in private evidence. Initial build
wrappers also exceeded their planned compiler limits and receive no credit for
that contract; the successful fresh run restores the original bounds. Raw logs,
requests, binaries and captures remain ignored.
