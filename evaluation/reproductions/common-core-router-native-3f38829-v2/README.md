# Synthetic router controls: saved traces and reproduction

The actual source revision is `3f388297f069432fbf5442d7003062dcf3962f95`, on **AMD EPYC Zen 5 dev host**. The native command exited 0 in 0.2592674868647009 seconds. Its strict helper proved ECHILD without unexpected descendants, cleanup events, timeout or errors. The enclosing caller was waited and exited 0 in 1.1166230759117752 seconds. Durations are operational observations, not performance measurements.

The four saved traces contain 48 rows each. Their complete instruction paths, child route table/code/global observations, signal frame and paired FP extents passed independent review. Each has 28 handler instructions stepped and 33 router stops. The unchanged control's final NOP supplies the source-attested total of 34. The actual syscall transition satisfies `R11 = post-MOV GETREGS EFLAGS & ~RF` exactly; all four values are `0x246`. The full-word R11 check has no debugger-bit exemption. The rule comes from the pinned Linux v6.13/ISA derivation; this does not authenticate the running kernel's source build.

The complete marker and reached native assertions establish four roundtrips, twelve outer full-state comparisons, ten children and two refused deliveries. These standalone traces do not include the original/after ordinary GPR, canonical XSAVE, array, complete 64 KiB application-stack or full mapping files. Those live comparisons, the final NOP, individual negative exit-124 observations and bootstrap restoration remain source-attested. The saved 968-byte ucontext and paired 2,444-byte FP extents are independently checked, without inventing an original application-state baseline.

The earlier `6d8c123531f30e1a841c52c8955d46f294811172` native attempt remains FAILED with exit 101 and no completed roundtrip. Its review SHA is `6f14806daf0e81df40b8c9a1e4719740b2c32541a7ae620258110b1f889e0c6f`. The successor uses the reviewed save-disable-restore bootstrap and keeps the original disabled-altstack assertion. It does not rename or erase that failure.

The JSON/CSV report contains exact command contexts, limits, revision/build/source hashes and four trace rows. Observed memory bytes, addresses, full maps, raw logs and private paths remain ignored. Trace hashes identify the complete diagnostic artifacts. Full command normalization has an exact private inverse. The reporter reads reviewed metadata only; it does not reopen the product or trace contents.

## Recheck the saved trace bytes

`check-traces.py` exports all five finite trace-check functions byte-identically from the independent saved-record review. Its new CLI reads only an explicitly pinned `control-files.json` and the five named control files. It preserves every trace predicate, rejects optimized Python, checks the whole index and all file bytes/six-field owners, and writes a fresh sanitized result. It neither imports nor runs the native program or the full paired auditor.

```sh
python3.9 -B "$EXPORTED_CHECK_TRACES" --traces "$RAW/controls" --index "$RAW/control-files.json" --index-sha256 "$INDEX_SHA256" --new-output "$FRESH_TRACE_RESULT"
```

This script checks saved trace content only; it does not authenticate the enclosing execution, build, original full-state baselines or unsaved negative wait records. The historical native result retains the separate complete independent record-review authority. The original index owner tuples remain exact requirements: copying or restoring bytes changes owners and does not recreate historical inode/ctime continuity. A new run produces its own index; do not refresh an old index to manufacture that continuity. The exported CLI itself is prospective and has not been executed during this report preparation.

## Run a fresh bounded native control cohort

Save these exports before selecting the exact tested revision. `build.py` is the byte-identical v5 validation driver, `run.py` is the unchanged native caller (`00661a3a…`), and `launch-historical.py` is the actual historical outer caller. The latter pins old coordinates and a particular binding; use it as provenance. The parameterized `launch.py` accepts fresh explicit paths and retains the 145-second parent wait, immediate process-group SIGKILL on error/timeout and ten-second direct-child reap bound. Relative to the previously reviewed parameterized failed-cohort wrapper, its only change is the exact revision guard.

In a clean checkout at the stated revision, use an already available offline toolchain and fresh ignored coordinates:

```sh
python3.9 -B "$EXPORTED_BUILD" --repo "$REPO" --output "$FRESH_BUILD" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --phase native-build
```

The build command is `cargo build -p liteinst2 --bin elf-exec-oracle --message-format=json`, with four CPUs/jobs, 180 seconds, an 8 MiB log, disabled debug information and unchanged debug assertions. A build parent record is mandatory for the native caller. `build-launch.py.template` exports the actual bounded build parent with reversible private path substitutions. Expand its role tokens, place the exact exported build driver at its named ignored integration coordinate, and invoke it with `native-build` from the exact checkout. Its named output/launch directories must be fresh. It supplies a 240-second enclosing wait with the original timeout cleanup. Do not execute an unexpanded template or reuse an existing historical output directory.

Create a fresh reviewed native binding before invocation. `binding.example.json` and `product.example.json` are nonactivating schemas: placeholder strings intentionally fail the caller. They require actual current tool/provider/lookup records, source and product byte hashes/owners, complete closed build and parent records, the seven-source manifest and every admitted ignored metadata file. `product.json` must carry the actual Cargo artifact and fresh executable whole hash, bytes, canonical path, dev/inode/mode/mtime/ctime/uid/gid plus build log/summary hashes. Never copy historical owner tuples into a new epoch. `source-manifest.json` preserves the exact seven tested source byte hashes; the fresh complete build source snapshot must join them literally. Capacity and fresh admission remain separate prerequisites; this packet adds no admission framework.

Copy the exact `run.py` into a canonical ignored location included in that binding. Then use fresh raw and launch paths:

```sh
python3.9 -B "$EXPORTED_LAUNCH" --repo "$REPO" --caller "$IGNORED_CALLER" --binding "$FRESH_BINDING" --binding-sha256 "$BINDING_SHA256" --raw "$FRESH_RAW" --new-launch "$FRESH_LAUNCH"
```

The unchanged native request uses **60 CPU seconds / 90 wall seconds / 64 MiB per file**, CPUs 0–3, GNU timeout 100 seconds with ten-second kill-after, and a 115-second direct helper parent. File limits are not aggregate disk reservations. Full source/tool/product/metadata equality and strict cleanup remain mandatory. A fresh outcome must be evaluated from its actual records; the historical success is not transferred.

This finite synthetic mechanism result gives no common-corpus paired-run, normal-loader, complete A3 or full Claim 4 qualification. No native rerun, compiler, trace checker or full auditor was executed to prepare this proposal.
