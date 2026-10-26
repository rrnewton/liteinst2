# ELF execution development attempts

These records preserve closed failures, source holds and two separately scoped read-only environment probes. No attempt establishes native campaign qualification or completed cross-revision static parity. The e881 record adds only the bounded original/pre-hook state prefix described below. Later campaigns have their own results and do not change these outcomes.

| Attempt | Observed outcome |
|---|---|
| `3b5aa720` | Import failed because local `select.py` shadowed Python’s standard module; zero validation commands. |
| `0c3754bb` | Formatting passed; Clippy rejected `4 | 5 | 6`. Tests, check and later stages were unrun. |
| `4a30cb07` | Four required gates and four candidate prepare/verify pairs passed. Native stopped at the first original mapping’s device check, before a seed. |
| Read-only provider probe | One bounded `PROT_READ` observation completed. Descriptor device `0:48` differed from mount-provider/VMA device `0:42`. Denied `map_files` stat remains a denied observation. |
| Provider source v1 | Held because normalized path equality did not enforce the literal link promise. V2 used OS-byte equality and added three refusal spellings. |
| Parity preflight at `4a30cb07` | Ancestor config metadata lookup returned EPERM before any helper; raw directory stayed empty. |
| Parity cwd proposal v1 | Held unexecuted: `/` violates the existing helper’s repository-cwd predicate. |
| Parity observation proposal v2 | Source review approved explicit unknown config observations, with unchanged commands and comparisons. Hidden contents and Cargo consumption remain unattested. |
| `65ae22cf` | Four required gates passed. First original `map_files` lookup returned ENOENT before a seed; its key reused padded maps addresses. |
| Parity at `13dd59f6` | Six helpers exited zero, then old-unit artifact validation failed: the exact depfile used package-relative source names. Sixteen later stages remained unrun. |

The hardware label is **AMD EPYC Zen 5 dev host**. [summary.json](results/elf-exec-development-attempts-20261026/summary.json) binds actual model/kernel records for the four fixture attempts, the provider probe and the e881 static-parity attempt. Import-only and preflight events inherit the shared-host label without a separate hardware measurement.

Required tests at `4a30cb07` report 69 outer groups, 1,167 passed, zero failed and four unchanged ignores. At `65ae22cf`, 70 groups report 1,175 passed, zero failed and the same four ignores; eight provider tests are additive. Each run has five completed one-test nested summaries counted separately and two additional child starts without separately credited results. Native captures remain partial: seven files at `4a30cb07`, fifteen at `65ae22cf`; both have zero seeds, completed traces and state comparisons, and six ordinary executions unrun. The required logs establish doctest subjects/results, not full diagnostic bodies.

[commands.csv](results/elf-exec-development-attempts-20261026/commands.csv) has 98 rows: 64 fixture campaign records, fourteen nested required gate commands, one read-only helper, sixteen parity helpers, one direct self-observation and two pure-control helpers; the second control helper precedes a failed collector postcheck. Complete argv/cwd/env/request/outer contracts use the summary’s coordinate roles. Required child environments are derived from the recorded dispatcher and pinned required-gates overrides, not captured from procfs. Original-byte hashes bind private records; coordinate expansion preserves decoded objects, not JSON key ordering. Dispatcher/helper/gate durations overlap and are not independent tests or performance measurements. [attempts.csv](results/elf-exec-development-attempts-20261026/attempts.csv) keeps source holds distinct from executed failures.

Use a clean checkout of the exact revision for a historical [fixture attempt](elf-exec/README.md):

```sh
/usr/bin/python3.9 -B "$REPO/evaluation/elf-exec/reproduce.py" \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

For the historical [static-parity recipe](emitter-parity/README.md), use its recorded revision and command:

```sh
/usr/local/bin/python3 -B "$REPO/evaluation/emitter-parity-run.py" \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`RAW` must be fresh and canonical under that checkout’s ignored directory. The command table names each historical raw role. Host-dependent failures are recorded observations, not promised replay outcomes. Changed source fixes require a new exact-revision campaign.

The byte-identical [provider probe](elf-exec/provider-probe.py) is included separately. Its tested script revision is null; the checked-out project was `4a30cb07`. `PROBE_SCRIPT` means this exact source file from the evidence package, not a file claimed to exist in that old checkout. Expand its complete recorded request/outer contract into fresh owners and invoke the existing bounded helper: 5 CPU seconds, 10 wall seconds, 1 MiB, outer 20 and parent 25 seconds. The retained original is only read and mapped without execute permission. Keep output private: the probe intentionally records local paths and mounts. The public summary contains only sanitized numeric joins and hashes; EPERM from `map_files` stat is never authentication, and no kernel-internal cause is asserted.

The later source fixes retain each preceding failure. The depfile correction preserves exact target/source ownership and bytes while resolving relative names against the authenticated package; its first proposal was itself held for a leave-and-return path gap and missing optimized-Python guard. No prospective correction is counted as an actual pass. There is no performance claim, full tool/target closure claim, or completion of A2–A5. Original comparators, cases and resource bounds remain explicit.

The separate [self-only spelling probe](elf-exec/map-files-spelling-probe.py) used an existing interpreter VMA. Its unpadded `map_files` name resolved to the interpreter; adding leading zeroes returned ENOENT while the maps row stayed unchanged. The script created no mapping or child and executed no fixture. Its source revision, project Git revision, environment snapshot, hardware observation and helper receipt are all null. The later invocation note preserves the author-observed argv, cwd and exit zero; its tool-reported wall time is operational metadata, not an independently measured helper duration. The shared hardware label is inherited only.

For reproduction, copy this exact script into a fresh ignored directory and set `SPELLING_SCRIPT` to that repository-relative script filename. From `REPO`, run the recorded command:

```sh
/usr/bin/python3.9 -B "$SPELLING_SCRIPT"
```

The original invocation used the shell’s inherited environment, which was not captured. The script exclusively creates sibling `result.json`; keep that output and stdout private because they contain process coordinates. This observation supports the procfs spelling correction but is neither a fixture execution nor a native qualification.

At exact `e88111451a92bda2d16a60bcf9dc3cc93ae4f5f6`, the separate depfile controls passed all 16 cases: three accepted owners and thirteen expected refusals. The receipt and complete named control inventory are in the summary. Only three recorded source files were checked before/after; this does not claim full tool/source closure or parity. Reproduce this historical control on that exact checkout using the command table's bounded request/outer pair and fresh `RAW_E881_DEPFILE_CONTROLS` owner. A later runner-hash update requires its own control result.

The native campaign at that revision passed all four required gates: 70 outer groups, 1,175 passed, zero failed, four unchanged ignores, five separate nested terminal passes and two uncredited child starts. Native execution then failed with clean ECHILD while trying to compare a 2,496-byte aligned allocation with a 2,440-byte raw NT_XSTATE image. Its 98 saved files contain thirteen root records, one completed original trace of fifty files and a partial rewritten trace of thirty-five files. The original completed fifteen steps and its CALL/RET. Two pre-hook before/after-CALL full-state assertions were corroborated; no restored rewritten boundary, hook RET, rewritten completion or whole campaign qualification is credited. All six ordinary executions remained unrun. The canonical saved snapshot has its separate 2,287-byte representation; it is not the raw register image or aligned allocation.

Static parity at the same revision closed ten successful helpers, including the old 58-fixture and current-feature captures, before the ordinary-library collector failed. Cargo reported the top-level library alias and a hashed dependency metadata owner; the collector had required a hashed library path. The retained alias and derived dependency library are byte-identical (30,065,938 bytes), with stable owner observations, and both depfiles join all twenty-nine prepared source members. This is an authenticated output-layout observation, not completed parity: twelve later stages, including the literal-28 link/capture, new side and cross-revision comparisons, were unrun. The subsequent source proposal is independently reviewed but receives no execution credit here.

The older prospective source descriptions are historical records; the added e881 outcomes above do not rewrite them. Both failed campaign parent exits come from explicitly labelled root tool-return observations, distinct from their strict child/helper receipts. The public record retains all earlier failures and makes no A2–A5 completion or performance claim.

The initial alias-control attempt at exact `fc830799595a6f0d4bd5e699cff0b9b1f9cf0e36` has two distinct outcomes. Its helper and bounded outer exited zero with clean ECHILD and the complete expected fourteen-control stdout (three accepted joins, eleven expected refusals). The collector then exited one when it opened the misspelled `expected-library-controls.stdout`; the frozen proposal names `expected-alias-controls.stdout`. The original source-after and tools-after records were never written and remain absent. Matching its saved stdout retrospectively does not turn this collector into a completed pass or establish the missing after state.

The exact failed launcher and its later two-line correction are hash-bound privately. That correction selects only the library invocation, the already-frozen expected alias-control output and a fresh output owner; all remaining source, assertions and resource bounds are literal. The later repetition is a separate result and supplies no retroactive completion to this attempt. The initial attempt recorded fresh hardware under the same **AMD EPYC Zen 5 dev host** label; its tool evidence contains only the recorded paths, resolutions and content hashes. No full-tool, inode/stat-continuity, native or static-parity qualification is claimed.
