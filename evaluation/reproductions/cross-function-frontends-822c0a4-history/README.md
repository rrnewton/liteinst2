# Preserved frontend validation attempt

This attempt tested `822c0a4f2a0c0ee53a43438c7e9c64a128d2f58f` on the **AMD EPYC Zen 5 dev host**. The complete frontend target passed 133 cases. Required validation then passed format and failed strict Clippy with `clippy::needless_lifetimes` at `tools/elf-rewrite/examples/support/common_core_foreign.rs:68`. Workspace tests, check and all four later serial/contention phases were unrun in this attempt.

The exported `validate.py` is byte-identical to the actual caller, SHA-256 `1a45d1017116b2da194acf973348a76c8f85de88407972384496c3581c345e91`. Use a clean checkout of the exact tested revision, the selected toolchain and fresh ignored output directories. The targeted invocation is:

```sh
python3.9 -B validate.py --repo "$REPO" --output "$REPO/ignored/frontend-history-targeted" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --phase targeted
```

Run `--phase required` with its own fresh output to reproduce the strict gate sequence. Its saved failure is not an expected-success test or a waiver. The later correction removes only the redundant lifetime; its validation is a separate revision and evidence cohort.

`commands.json` retains four complete contexts: targeted, enclosing required dispatch, format and Clippy. Each includes the actual argv/environment, CPU affinity, bounds, result and operational timing; direct parent start/wait records are included for the two caller executions. The remaining six command rows have literal UNRUN status and null contexts. The 1,000-second required dispatch contains the unchanged 180-second format/Clippy gates; targeted uses 180 seconds and four CPUs. Logs are bounded to 8 MiB. Debug information was disabled, while debug assertions and strict warnings remained enabled.

Paths use reversible `${REPO}`, `${RAW}`, `${TOOLCHAIN}`, `${USER_HOME}` and `${CARGO_HOME}` roles. Private inverses and raw records remain ignored. `records.json` publishes exact saved-record hashes and lengths. The summary retains hardware/tool observations, exact revision and source-map digest; the complete 2,032-file source map remains in the hash-bound saved snapshots. Before/after source, tool and configuration equality and complete cleanup are preserved for both attempted phases. Durations are operational, not performance measurements.

This record preserves a failed validation sequence. It provides no result transfer to the corrected revision, common-corpus qualification or full A3 completion.

Save the exported validation script outside the tested checkout before selecting its tested revision: these reproduction files were published in a later reporting commit. Invoke that saved script against the clean tested checkout.
