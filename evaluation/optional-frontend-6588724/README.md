# Optional frontend qualification

At `658872463ad4c6a5c7e773df3c47026922d107a2`, the release recipe passed all 30 stages: the existing 27 and three optional frontend stages. [receipt.json](receipt.json) projects saved results and strict closure metadata. The separate [seven checks](gates.json) and [development history](development.csv) retain their own results.

[Eight state pairs](state-pairs.csv) cover Fast/Slow, two fixed seeds and lengths 1/64: 16 executor children, 1,956 comparisons and eight candidate-helper joins. The actual controller arms after Fast selection or removes after Slow admission while the executor is stopped at its first restored original instruction. Fast keeps its choice with zero observer entries; Slow keeps its original owner and executes both observers. ACKs read the image-retained selector. Historical group flags can remain true after removal and are checked separately from physical selection and owner/action history.

The unchanged comparator checks applicable GPR/flags/x87/SSE/AVX, complete input and `[S-128, stack_end)` from actual gate entry through post-POP. The actual outer RET then executes after restoring that child's saved harness context, preserving actual RAX and the untouched return word. Setup and the rest of the stack are outside this comparison. Each pair retains a 15-second deadline including setup/cleanup and one continuous 20,000-step allowance per executor. Each four-pair command retains 90 CPU/90 wall seconds and 1 MiB output.

The [functional case](functional.csv) separately reports 96 originals on the eventual attached thread and 96 installed returns: 32 Fast and 64 sampled Slow. Entered A survives B rearm. Three batches/128 events, two pre-call capacity refusals (including off), three empty drains, A1/B63 reports, detach and one helper join are checked. Complete frame, physical-return, input, 512-word journal and report identities are source-attested; those complete objects are not exported here. This case is not a 96-call full-state oracle. Its bounds remain 10 CPU/15 wall seconds/1 MiB.

[All 30 normalized commands](commands.csv) have parent/child exit zero, complete cleanup, ECHILD, unchanged inputs and zero rescues. Parent wall limits are child wall plus 25 seconds, from the exact recipe source; request bodies and streams are not replayed here. Release artifacts require opt3/debug0/assertions/overflow: the oracle rebuilt, ordinary client and libtest were cached. Actual artifact/ELF/tool hashes and versions are retained. The AMD EPYC Zen 5 label is owner-specified; numeric CPU fields are observed. Durations and step counts are not performance measurements.

The first attempt at `ab61461983c53c033f8a53c1e2d40c9d4900fd6e` remains FAILED: 27 stages and Fast's four pairs/978 comparisons passed; Slow exited 101 (parent 1), functional stayed UNRUN, cleanup was complete/ECHILD/no rescues. The executor reported a wrong historical-enabled assertion; source review confirms the distinction above. This projector did not read failure stderr. The correction adds actual selector checks and fixes the exact history expectation without changing comparators, populations or bounds. No failed-attempt credit transfers.

A separate core run at that earlier revision passed eight primitive pairs/148 comparisons, two malformed children and five protocol controls, with prerequisites 6 core + 2 compile-fail + 8 planner + 35 calibrations. It is a distinct population. Earlier failures remain in the [core](../precontext/README.md), [ordinary](../ordinary-interval-ff18353/README.md), [exact-work](../exact-work-723f09e/README.md), [history/cleanup](../history-stream-4f2ddf8/README.md) and [backoff](../backoff-independent/README.md) histories.

Use a clean exact revision and explicit local paths to reproduce:

```sh
REVISION=658872463ad4c6a5c7e773df3c47026922d107a2
python3 -B evaluation/precontext/verify.py --revision "$REVISION" \
  --raw "$REPO/ignored/NEW_CORE_RUN" --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
python3 -B tools/rapid-profiler/optional-work/test_recipe.py
python3 -B tools/rapid-profiler/verify_ordinary_interval.py --revision "$REVISION" \
  --raw "$REPO/ignored/NEW_OPTIONAL_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend
```

The recipe uses four CPUs, offline/jobs4, incremental0 and one repository target directory. Its source/tool/artifact checks and parsers remain authoritative. Fresh runs have their own timings and cache status.

For this historical projection only: `python3 -B project.py --passed "$PASSED_RAW" --failed "$FAILED_RAW" --core "$CORE_PUBLIC" --out "$NEW_OUTPUT"`. It reads 126 named JSON/CSV files and requires their exact aggregate hash; it runs no compiler, workload or provider query. All eight state rows, one functional row and 30 closures are retained. Prior-regression summaries come from this same successful result; their raw tables are not replayed or re-exported.

No joint whole-schedule state, optional-backoff integration, timing accuracy, throughput, measured cheap-off savings, indefinite service or full-A5 completion is claimed. Report readiness is not physical RET or code reclamation authority.

The seven checks at the same revision passed: default-parallel workspace
2,647 passed / 0 failed / 10 ignored in 336.410 seconds; serial launch 1,039
passed in 125.109 seconds; staged allocation 3 and prefixed-pun 36 passed;
fmt, strict workspace Clippy and all-target/all-feature check passed. The
workspace used all 316 available CPUs with no test-thread override (four
compiler jobs). Four nested libtest summaries were excluded from the count.
The extra ignored case is the optional functional case explicitly run by the
release recipe above. All commands exited normally with complete cleanup and
zero rescues. Reproduce with the exact revision and
`python3 -B evaluation/admission/check_exec_identity.py --checks-only
--toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
--output "$REPO/ignored/NEW_GATES"`; project with
`evaluation/merged-af5a1ef/summarize.py` as documented there.

The 16 development rows retain the initial private-field compilation failure,
Clippy item-order failure, two formatting failures, and the intentional
formatter mutation. Corrections preserve the same assertions. Dirty-tree
rows name their actual parent and before/after source-manifest hashes; the
temporary `3b1793d785a5061989befc3817cd76f7a4ea4268` commit was amended after
formatting into the qualified revision above. These are development history,
not additional native qualification. Each command had a 180-second wall and
8-MiB output limit; all closed normally with zero rescues. The same hardware
and stable Rust 1.97.1 apply. Raw logs stay ignored.
