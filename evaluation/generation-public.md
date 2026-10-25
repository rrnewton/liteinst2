# Public generation qualification requests

This request-only package targets the 189-file source snapshot at
`ed67f7528184bf9ba33c05946ed8b07bef1bf41d`. It starts no command, supplies no
test results, and does not activate a profiler frontend. The historical
standalone prototype report is a separate source epoch and cannot supply any
of these public-module results.

Use the existing `tools/word-sync-oracle/bounded_command.py` unchanged. Its
SHA-256 is `c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`.
No new supervisor, retry, capability skip, or fallback is introduced.

## Source and configuration admission

Run the generator only after independent source review. `prepare` accepts
explicit `--repo`, `--raw`, `--toolchain`, `--msrv-toolchain`, `--cargo-home`,
`--user-home`, `--helper-python`, and `--timeout` paths. The output must be a
fresh directory below `${REPO}/ignored`, with its parent already present.

The generator checks all 189 source hashes, the nine pinned executable roles,
the separately authenticated helper source, and Cargo configuration files at the repository and
ancestor directories, user home, and explicit Cargo home. Readable files are
copied privately. An `exists` operation denied with EPERM or EACCES is recorded
as that exact operation/errno and must remain equal; it is not called absence
or evidence of inaccessible contents. Other file/read errors fail preparation.

The source byte match is not a Git-history or runtime attestation. The operator
must independently bind actual HEAD/clean tracked state to the required revision
before each accepted phase. Untracked private captures and the uncommitted brief
are not source changes. Tool records describe only the explicit executables;
they do not invent shared-library, linker, build-script, Cargo dependency, or
CPU identities. Actual build admission must record those dependencies to the
extent required by the existing receipt policy. Configuration hidden by the
recorded permission error remains an explicit provenance limit.

Run `verify --raw ${RAW} --admission-sha256 ${ACTUAL_ADMISSION_SHA}` before and
after each command. This rechecks the same source/tool/config/request identities.
Every generated request uses a clean, explicit environment: one shared
`${REPO}/target`, four Cargo jobs, incremental disabled, offline/locked Cargo,
explicit rustc/rustdoc, and no `CARGO_ENCODED_RUSTFLAGS`. RUSTFLAGS are exactly
`-Dwarnings -Funsafe-op-in-unsafe-fn -Ccodegen-units=1`: warnings remain denied,
unsafe operations in unsafe functions remain forbidden, and one codegen unit
is used. The Rust 1.85 request uses its own pinned cargo/rustc.

Request proposal v1 added a global `-Wmissing-docs` lint that was absent from the
frozen A5 qualification contract and historical private build. V1 was held before
any request preparation or execution. V2 removes that added lint to match the
original contract; it does not turn an executed failure into a pass. All public
generation documentation and the entire ed67f752 source remain unchanged.

## Fixed seven-command inventory (version 5)

1. An explicit normal-library build, `cargo build -p rapid-profiler --lib`, with the
   same strict flags and Cargo JSON output: 60 CPU seconds, 90 wall seconds,
   128 MiB file cap.
2. A warnings-denied `rapid-profiler --lib` test build with `--no-run` and Cargo
   JSON output: 60 CPU seconds, 90 wall seconds, 128 MiB file cap.
3. The fresh admitted binary's `generation::tests:: --list`: 20/30/1 MiB.
4. The same binary's `generation::tests:: --test-threads=1`: 20/30/1 MiB.
5. Clippy for `rapid-profiler --all-targets --all-features`, warnings denied:
   60/90/128 MiB.
6. The public module's two documentation compile-fail examples, with output
   shown and one test thread: **20/30/1 MiB**.
7. Rust 1.85 `rapid-profiler --all-targets --all-features` check:
   60/90/128 MiB.

These limits are fixed before execution. The historical standalone docs command
had a different compiler budget; it does not authorize increasing this public
documentation budget. Whole-workspace required gates remain additional required
work using the existing `evaluation/required-gates.py`, without replacing any
legacy test with this focused suite.

## Actual binary admission before models

Do not execute the model requests based only on an expected filename. After the
fresh no-run build, review the helper receipt, complete Cargo records, executable
and transitive artifact/dependency/source ownership, toolchain/runtime bindings,
and actual source state. Archive needed shared-target artifacts before a later
build can replace them. Keep that independent review immutable.

Create an actual `artifact-admission.json` using the example material, with real
hashes only. It must bind the source admission, compile request/receipt, Cargo
stdout, original executable path/full hash, and the separate dependency/runtime
review hash. The `models` subcommand requires all of these exact values. It
checks a successful clean ECHILD compile receipt and its raw output hashes,
exactly one Cargo executable record, the full `rapid-profiler` path package ID,
library target/source/edition/test profile, and the actual executable hash.
It copies that executable to `${RAW}/model-tests`, then prepares list/models
requests. It does not manufacture an executable or substitute an older binary.

The supplied artifact review is an explicit human/reviewer admission boundary:
the generator authenticates its bytes and joins its fields, but does not pretend
to independently prove the review's dependency/runtime conclusion. In particular,
an arbitrary nonempty depfile is not sufficient source ownership evidence.
Recheck the archived binary and both request hashes before and after execution.

Run each request through the existing helper, for example:

```sh
${HELPER_PYTHON} -B ${REPO}/tools/word-sync-oracle/bounded_command.py \
  --request ${RAW}/compile/request.json --receipt ${RAW}/compile/receipt.json
```

The operator's existing bounded launch procedure is unchanged. This document
does not add a second process supervisor or authorize concurrent Cargo commands.

## Required result checks

Accept the list only if it exactly equals the shipped `list.stdout`: 17 named
generation tests, no benchmark. Accept models only if all those 17 IDs appear
once as successful, with zero failed/ignored/measured cases. The old profiler
tests filtered by this focused command remain required in the full workspace
gate; the actual filtered count must be recorded, not guessed here. One positive
and six negative reference-comparator controls are already inside the 17 tests,
not seven additional tests. All 16 pre-join values and the original final checks
remain in the unchanged test source.

Accept docs only if the exact two `generation::Ticket` examples at source lines
478 and 485 pass as compile-fail cases, with the first showing E0599 for missing
`clone` and the second E0382 for use after move. Reject any other diagnostic code,
extra case, missing case, or successful compilation substituted for the expected
ownership refusal. Listing a compile-fail test alone is not this evidence.

Every accepted command needs request/helper/output hashes, exit zero, no timeout,
no unexpected descendants, empty cleanup events, ECHILD, no abort/cleanup error,
and unchanged inputs. Preserve any failed attempt as its own immutable report;
do not rerun it into a passing row. Operational elapsed time is not a benchmark.

Use the existing evaluation schema for subsequent actual summaries: command rows
remain seven distinct outcomes, and case rows remain 17 model cases plus two
ownership compile-fail cases. Actual required workspace gates are separate rows.
Record the actual tested revision only after its runtime identity is verified.
All four paper claims, preemption-clock behavior, frontend activation, and full
A5 completion remain unqualified by this metadata-only suite.

Proposal v2 had an unexecuted role-count mismatch: its material map included
helper source plus nine executables, but it compared that whole map with only
the nine executable identities. V3 explicitly checks the material helper hash
against the constant, then returns only the exact nine executable hashes for
that comparison. Both preparation and verification separately hash the helper
source; helper source is not required to have executable mode. V1/v2 remain
immutable and unexecuted. No workload outcome or model assertion changed.

The `models` preparation subcommand archives the actual test binary. Its own
file-size bound must be declared by the root launcher before it runs and must
accommodate that authenticated binary. This preparation is distinct from the
fixed 20/30/1 MiB list/model runtime requests; those limits are unchanged.

Version 5 makes the normal-library compilation prerequisite explicit (A5-P3).
The original promotion contract required both library and test compilation,
but versions 1–4 prepared only `cargo test --lib --no-run`, whose cfg(test)
executable does not supply the ordinary rlib rustdoc needs. The current ordinary
artifact from different flags is larger than the documentation command's 1 MiB
cap. This is a predicted prerequisite problem, not an observed doc failure.

The sequence and aggregate preparation budget change: seven separately reported
commands now include a normal `--lib` build under the original compiler bounds.
All original six command arguments, individual limits and 17+2 cases are retained.
This does not claim that a cold Cargo documentation build succeeds within 1 MiB.
Review and archive the actual normal rlib/rmeta, complete Cargo record, profile,
source and depfile ownership before models and docs. The model-binding script
requires the successful library receipt and the externally admitted exact library
hashes. Recheck those same artifacts before and after docs; if Cargo needs another
oversized output or either ownership diagnostic is wrong, the unchanged doc gate
fails. There is no retry, cap expansion or implicit cache-warming allowance.
Versions 1–4 and the successful partial v3 run remain immutable; version 4 was
source-reviewed but not executed. Matching reused Cargo artifacts retain their
original provenance limits, including the earlier C fixture's Clang identity gap.

Version 6 authenticates Cargo's ordinary library artifact geometry (A5-P4):
`target/debug/librapid_profiler.rlib` is the exact root alias, and the accompanying
metadata file is `target/debug/deps/librapid_profiler-HASH.rmeta`. Derive the
hashed rlib from that precise metadata stem, never from a directory search.
Require all three exact files in the external admission and full byte equality
between alias and hashed rlib. Version 5's unexecuted assumption that both Cargo
filenames lived in `deps` is preserved as a source-review defect. The seven
commands, their limits, and all 17+2 cases remain unchanged.
