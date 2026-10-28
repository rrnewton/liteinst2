# Transfer bounded controller history without losing older call bindings

Opt-in streamed history can transfer bounded resident actions while older calls
retain their absolute history and generation bindings. `drain_history()` exports
immutable chunks with carry-in and stream identity; it does not reset lifetime
counters or equate report readiness with physical RET or code quiescence.
The legacy 256-total-action policy remains available and unchanged. The new
explicit 49-bit format keeps the same event and buffer capacities. Consumers
must replay contiguous chunks for full generation association: committed
high-water alone authenticates a range.

Qualification at `4f2ddf80a479fc33aaec2a9e0d788deeb62eaef9` passed all 27 release stages, 100 sequential
cleanup attempts and seven required gates. [receipt.json](receipt.json) holds
commands, source/tool/artifact hashes and separate scopes;
[cases.csv](cases.csv) is the compact native protocol, and
[cleanup-attempts.csv](cleanup-attempts.csv) contains each cleanup disposition
without duplicating 100 records in JSON. [gates.json](gates.json) preserves
commands and grouping policy: workspace **2,582 passed / 0 failed / 9 ignored**
(100 outer terminals, five nested summaries excluded), serial launch
**1,039 / 0 / 0**, staged allocation **3**, and prefixed-pun **36**.
Workspace and serial command durations were 352.867 and 126.011 seconds,
respectively; these are operational durations, not performance measurements.
The owner label is **AMD EPYC Zen 5 dev host**; observed CPU fields are separate.

The history case makes two original and two installed C-checksum calls while
performing 600 actions, 77 history transfers and 300 staged/retired epochs.
The old call retains entry prefix 1 while the controller advances to high-water
599 and exports 76 chunks. It then returns; the second call uses prefix 599.
Action 600, chunk 77 and the last retirement occur after the second return.
Independent full Action replay checks carry-in, stream identity and generation
association.
The terminal reports two completed buffers, four events and one registration.
E=2, two full 512-word journals and owner release 2→1→0 are separately labelled
source assertions. Rust checks original values, inputs, raw/report joins and
actual CALL/RET; this metadata projection does not replay those bodies.

All 26 prerequisite stages passed again with their original checks and limits.
Their separate state comparisons remain 978 / 844 / 844; exact populations,
concurrent/timed/retirement/drain and 160-call streamed results retain their own
numbers. All three release artifacts were cached (`cargo_fresh=true`) and retain
opt3/debug0/assertions/overflow profiles; no fresh compilation is claimed.
The new finite history case adds no full-state, calibrated-timing, performance,
indefinite-service or complete-A5 qualification. The new history child's bounds
remain 10 CPU / 15 wall seconds / 1 MiB, with a 40-second parent. Other stages
retain their own recorded bounds.

The cleanup fixture correction keeps reference setup on the already isolated
main-thread route, removing an unnecessary worker while retaining singleton,
ownership, cleanup and protocol checks. Its campaign runs five controls/six
trajectories per attempt, sequentially, with 180-second / 8 MiB command bounds
and stop-on-first-failure. All 100 closures were normal and clean with zero
rescues: 600 trajectory protocol completions, not 600 libtest tests. Default
316-CPU affinity and default test parallelism were retained; compiler jobs were
four. InvalidUnmap's expected SIGABRT is one explicit fixture outcome, not an
exception for unrelated failures. Five synthetic parser methods and two
explicit optimization-refusal commands have separately pinned source/closures;
method counts and the refusal message are executor-reported, not log replay.

The earlier 3062 workspace failure and diagnostic 35-pass/attempt-36 QueryError
failure remain FAILED. The diagnostic singleton assertion observed a non-main
task after join, but its numeric identity was not independently bound to the
setup worker and no kernel trace was captured. This narrow correction does not
prove every historical backing failure had that cause or eliminate all flakes.
Development failures from missing exports, Clippy's manual_div_ceil check and
omitted --runner remain recorded. Prior [backing-child](../creation-identity-088dc0a/README.md)
and [orig_rax](../merged-af5a1ef/README.md) outcomes remain historical; no orig_rax
fix is claimed. Earlier capability failures remain linked from the
[streamed report](../streamed-epochs-b895189/README.md).

The tested commit contains main `3f6056f0a249e4f2ce5ce867e8bf67ae5370224d`
and fixture correction `efa0f26e377e013a3b497de8425b56344216e21b` through merge
`62cd0195f43602c365a0e1c0c10ce2ff688047ac`. No later revision is qualified.
From a clean checkout at the tested revision, using the recorded Python 3.12.15
and other tools, choose fresh ignored output directories:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision 4f2ddf80a479fc33aaec2a9e0d788deeb62eaef9 --raw "$REPO/ignored/NEW_NATIVE" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/test_backing_singleton.py \
  --runner evaluation/admission/check_backing_singleton.py
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/check_backing_singleton.py \
  --revision 4f2ddf80a479fc33aaec2a9e0d788deeb62eaef9 --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_CLEANUP" --repetitions 100
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

This projection reads pinned CLOSED JSON only. It does not reopen raw streams,
CSV bodies, journals, binaries, tools, providers or process state. Counts remain
producer-recorded/source-attested; the gate group selection was performed by
root with unchanged `evaluation/merged-af5a1ef/summarize.py`. Complete top-level
driver exit0 is root-reported; supplied per-command closures are joined. Cleanup
source/tool pins are not a full Cargo-configuration or artifact attestation.
Given the pinned private metadata, reproduce only this public projection:

```sh
python3 -B project.py --raw "$CLOSED_NATIVE" --gates "$CLOSED_GATE_PROJECTION" \
  --campaign "$CLOSED_CLEANUP_RECEIPT" --cleanup-controls "$CLOSED_PARSER_CONTROLS" \
  --prior-gates "$FAILED_3062_GATES" --prior-diagnostic "$FAILED_DIAGNOSTIC" \
  --root-meta "$CLOSED_DEVELOPMENT" --out "$NEW_OUTPUT"
```
