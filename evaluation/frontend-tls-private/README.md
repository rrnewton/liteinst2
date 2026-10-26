# Private TLS bridge qualification

These records describe two private source snapshots based on `9098a3d74309fd445fd6f56a6048c1ce517bb81f`. Both have `tested_revision: null`. The later four-file public promotion at `4c754df83b534b83f7a4725f087780e013363e4a` is not either private tested revision, and public workspace gates are separate.

| Attempt | Actual result |
| --- | --- |
| [v1](../results/frontend-tls-private-v1-20261025/summary.json) | Library, test compilation, exact listing and 74 models passed; Clippy exited 101 for a duplicated `forbid(unsafe_code)` attribute. Documentation and MSRV were not run. |
| [v2](../results/frontend-tls-private-v2-20261025/summary.json) | Seven fresh phases passed: library, test compilation, listing, 74 models, Clippy, ten intended compile-fail examples and Rust 1.85 MSRV. |
| [Public required gates at 4c754df8](../results/required-4c754df8-20261025/summary.json) | Four gates passed; 1,000 outer test passes, zero failures, four existing ignores and five separately counted nested guard executions. |

V2 removes only the newly added outer duplicate attribute. The module's inner `#![forbid(unsafe_code)]`, crate warnings policy, every test/assertion, all capture predicates and all resource caps remain. V1 remains a failed qualification. Its passing models do not qualify v2, and repeated cases are not summed as unique coverage. The predecessor formatter result is retained as preparation lineage; no formatter execution on corrected v2 is claimed.

The 74-case suite retains all 60 public-base cases and adds four Rust-thread cohorts, eight exact typed-refusal cases and two invariant cases. Both caught panics remain mandatory. The ten documentation examples retain the old eight and add two E0277 refusals for sending/sharing `ThreadRegistration`. This is safe Rust TLS ownership with synthetic slots and ordinary Rust thread/panic teardown. It does not qualify machine return-slot changes, native entry/exit, ABI/CET, signals/exceptions/longjmp, a preemption clock, module reclamation, claims 1–4 or complete A5. The inherited PMU tests retain their existing conditions; their pass is not a runtime PMU availability claim.

## Source and request preparation

`prepare.py` is a request-only source preparer. It has no subprocess call, command execution, helper implementation, supervisor or result exporter. Its execution is distinct from the historical workloads. The newly published preparer must receive its own source review and bounded preparation controls before use; historical pass rows are not validation of the preparer.

Use a public checkout containing this reproduction material and the unchanged helper as `${REPO}`. Supply a separate exact base-9098 source checkout as `${BASE}`. The script reads only the fixed 514 required paths: 510 unchanged base files and the four selected overlay files. It does not copy `.git`, unrelated files, private evidence or existing build outputs. All 514 resulting file hashes must match the selected snapshot's complete map. The v1/v2 overlays differ only in `src/lib.rs`; all other snapshot bytes remain exact.

`${RAW}` is a fresh canonical directory strictly below `${REPO}/ignored`, with an existing parent. `${TOOLCHAIN}` and `${MSRV_TOOLCHAIN}` are explicit installations whose pinned Cargo/rustc/rustdoc bytes match the prior actual 1.97.1/1.85.0 version observations. `${USER_HOME}` and `${CARGO_HOME}` are explicit local configuration owners. The published selected byte maps remain exact; a differing tool, loader/config file or registry byte is a refusal, not an automatic upgrade. Full current file metadata is captured only as a new immutable local observation. No historical identity is refreshed.

```sh
/usr/bin/python3.9 -B "${REPO}/evaluation/frontend-tls-private/prepare.py" prepare \
  --attempt v2 --repo "${REPO}" --base-root "${BASE}" --raw "${RAW}" \
  --toolchain "${TOOLCHAIN}" --msrv-toolchain "${MSRV_TOOLCHAIN}" \
  --user-home "${USER_HOME}" --cargo-home "${CARGO_HOME}"
```

For the failed source use `--attempt v1` and a different fresh raw directory. Never reuse or overwrite either attempt. The script copies sources, captures fresh identities and writes only library/compile requests. The returned preparation hash is `${PREPARED_SHA256}`. The status `PREPARED_NOT_LAUNCH_ADMITTED` deliberately requires independent inspection of source, tools, producer, registry and actual Cargo configuration before any launch. The historical 24 configuration coordinates describe the historical workspace depth; a reproduction enumerates every actual workspace ancestor plus the explicit Cargo/home owners. Permission-denied `stat` observations retain their exact error and do not imply absence or authenticated contents.

The selected 209 tool files, 995 registry/archive/marker files and 514 source files form 1,718 exact file identities. Six PATH lookups bind actual clang/cc/ld selection in both compiler environments. These are selected-input observations, not a complete compiler child or process loader closure. The script performs no tool-version query; identical role bytes join the separate published six-query record. No other tool version is inferred.

## Existing execution boundary

Run one phase at a time in the fixed order: library, compile, artifact-review pause, list, models, Clippy, docs, MSRV. Before and after each phase run the source-only `verify` command and preserve its complete output/status:

```sh
/usr/bin/python3.9 -B "${REPO}/evaluation/frontend-tls-private/prepare.py" verify \
  --raw "${RAW}" --prepared-sha256 "${PREPARED_SHA256}" --phase library
```

The request file is `${RAW}/requests/<phase>.json`; the helper receipt is `${RAW}/<phase>/receipt.json`. `prepared.json` and `remaining.json` give the exact outer argv/environment/cwd and finite parent backstop. Invoke only the already published helper, preserving helper stdout/stderr separately from its workload output files:

```text
/usr/bin/timeout --signal=TERM --kill-after=10s <wall_seconds+10>s \
  /usr/bin/python3.9 -B ${REPO}/tools/unwind-oracle/bounded_command.py \
  --request ${RAW}/requests/<phase>.json --receipt ${RAW}/<phase>/receipt.json
```

The caller must use the declared whole environment, workspace cwd and `timeout=wall_seconds+25`, and retain its status and both helper streams. Compiler phases keep 60 CPU seconds / 90 wall seconds / 128 MiB per-file limits, outer 100 seconds and finite parent 115 seconds. List/models/docs keep 20/30/1 MiB, outer 40 and parent 55 seconds. This package adds no launcher or supervisor. The helper's owned-group/ECHILD evidence is not cgroup containment or a guarantee after uncatchable supervisor death. Do not pre-open helper-owned stdout, stderr or receipt files.

Every request template is byte-identical to the reviewed seven-phase template. Expansion changes whole coordinate tokens only. Offline/locked, four Cargo jobs, incremental zero, codegen units one, `-Dwarnings -Funsafe-op-in-unsafe-fn`, exact RUSTDOC flags and the absence of `CARGO_ENCODED_RUSTFLAGS` remain required. No filters, skips, retries, hidden warming commands or larger limits are permitted. A failed command stops that attempt; unrun commands have no receipt or pass row.

## Required actual artifact review

After library and no-run compile, independently inspect both complete Cargo streams, all package/target/feature/profile/source ownership, lock/registry identities, depfiles, environment dependencies, build-script/C-fixture products and selected ELF/runtime inputs under `artifact-contract.json`. Preserve actual `fresh` flags. Archive every actual product and its source/dependency owner before target reuse, including the ordinary alias, hashed rlib/rmeta and the sole test executable. Copy the authenticated executable to `${RAW}/artifacts/model-tests`. Do not infer a future binary hash from the historical one.

An independently approved JSON review supplies the fields in `artifact-review.template.json`. Its hash is a trusted review boundary, not a claim that a self-authored approval label proves correctness. All nulls must be replaced by actual reviewed identities. The review must separately authenticate the complete helper/outer receipts and the dependency review; the preparer itself additionally checks strict inner compiler receipts, Cargo's exact target/profile and the actual archive/ordinary-library identities.

```sh
/usr/bin/python3.9 -B "${REPO}/evaluation/frontend-tls-private/prepare.py" remaining \
  --raw "${RAW}" --prepared-sha256 "${PREPARED_SHA256}" \
  --artifact-review "${ARTIFACT_REVIEW}" --artifact-review-sha256 "${ARTIFACT_REVIEW_SHA256}"
```

This writes the remaining five exact requests and returns `${REMAINING_SHA256}`. For every later pre/post verification, add `--remaining-sha256 "${REMAINING_SHA256}"` and select the actual phase. All archived byte identities and matching ordinary library identities are rechecked. The matching ordinary alias/hashed rlib/rmeta must be authenticated immediately before the unchanged 1 MiB docs phase. Missing or changed prerequisites stop admission; this is not a cold documentation build.

Compare the full list and full model stdout/stderr against `expected/`. Only the two declared positive-decimal OS thread IDs and two-decimal test elapsed field vary; no thread-ID distinctness claim is made. The intentional panics do not excuse any extra panic or failed assertion. Require exactly 74/0/0/0. For docs require all ten ordered subjects, exact source fences and intended diagnostic codes in complete captured framing. An unrelated compiler error does not satisfy a negative example. Preserve every Clippy/MSRV record and all later artifacts before reuse. No target/fixture metadata is execution of those binaries.

The copied expected contract retains its original prospective status and formatted-v1 map digest. It is an immutable specification, not a result receipt or a fabricated v2 map. V2 has its own complete source map; its sole changed file is the outer library module declaration. Every named test/doc owner, fence and panic location in the expected contract is byte-identical across the two snapshots.

## Historical reporting boundary

Each result directory has actual command rows, 84 fixed case rows and a complete source map. V1's ten doc rows are explicitly `not_run`; no command row is invented for docs or MSRV. File indexes exclude themselves. Raw captures, full host metadata, private paths and binaries remain ignored. Summary hashes join the separately frozen actual reviews, not a rerun by this report author. Hardware is labeled `AMD EPYC Zen 5 dev host`; its inherited observation is context, not continuous or v2 launch-time attestation. Elapsed seconds are operational diagnostics, not performance measurements.

The exact formatter receipt and both initial/later artifact archives remain private provenance. Full historical capture comparators and all actual source bytes are unchanged. New reproductions create their own hashes, metadata, elapsed times and results; none may reuse these rows as newly executed evidence.

The public workspace run uses the existing `evaluation/required-gates.py` at an exact clean checkout of `4c754df83b534b83f7a4725f087780e013363e4a`, with a fresh ignored output directory and a 1,000-second finite parent backstop. Its four exact commands, 180/360-second limits and process-group cleanup differ from the focused helper. Its saved selector was the separate stable Rust directory; only versioned 1.97.1 tool owners were in the historical explicit tool map. Later seven-tool byte equality is not historical stable-owner admission. Likewise `/usr/bin/git` was used by the runner but the tool map selected PATH's different Git owner. These limits remain in the public JSON; no complete tool/runtime closure or ECHILD proof is inferred.
