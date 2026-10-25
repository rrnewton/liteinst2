# TLS request-preparer controls

[The closed result](../results/frontend-tls-preparation-controls-20261025/summary.json) records **two accepted preparations and six intended refusals**. The six refusals retain direct and helper exit **1**. All eight satisfy their declared control conditions and have clean ECHILD receipts. No generated library, compiler, model or native request was executed. An accepted preparation still says `PREPARED_NOT_LAUNCH_ADMITTED`.

These eight commands are a separate preparation-only denominator. They do not add cases to the [private TLS qualifications](../frontend-tls-private/README.md), change the failed v1 qualification, or transfer historical compiler/model results. Their uncommitted preparer/fixture source has `tested_revision: null`. The 9098 base revision identifies input bytes, not a tested revision for this preparer. The hardware record is an earlier separate observation, with no per-command or continuous attestation. Elapsed seconds are operational diagnostics, not a performance result.

## Material and coordinates

The reproducing program is the unchanged [prepare.py](../frontend-tls-private/prepare.py), SHA `361c3b5d92c2005193cef7dcb3b4334f4ca1e9e1da2a183474a63bc7d264211d`. This supplement adds data and instructions, no executable driver, supervisor, checker or materializer. [coordinates.json](coordinates.json) defines every complete token. [invocations.json](invocations.json) gives all eight exact request destinations, outer argv, environments, cwd, finite parent backstop, expected helper output and status. Each request under [requests/](requests/) is a whole-object template, not a shell command.

Use a public checkout containing the original material and unchanged helper as `${REPO}`. Give `${CONTROL_SOURCE}`, `${CONTROL_RAW}` and `${BASE}` separate canonical directories strictly below `${REPO}/ignored`; they must not be the ignored root itself. `${CONTROL_SOURCE}` owns only inputs, fixtures and control request JSON. `${CONTROL_RAW}` owns captures, scratch and preparation outputs. `${MATERIAL}` is the original whole reproduction directory, normally `${REPO}/evaluation/frontend-tls-private`. Do not modify its files or either prior publication.

Obtain the separate base source from exact commit `9098a3d74309fd445fd6f56a6048c1ce517bb81f`; for example, extract `git archive` of that commit into a fresh `${BASE}` below ignored. The commit has 512 tracked files. The preparer reads exactly the 510 non-overlay paths in the published maps, plus four selected material overlay paths. Extra base files are neither copied nor credited. Authenticate those 510 hashes using [source-files.json](../results/frontend-tls-preparation-controls-20261025/source-files.json) before the controls. Both copied snapshots must independently have the exact 514-file map.

Supply the exact pinned Rust 1.97.1 and 1.85.0 installation roots, explicit user/Cargo configuration owners, and the exact Python/timeout/helper bytes. The material's 209 selected tool rows and 995 registry/archive/marker rows remain mandatory. These controls do not execute or re-query the compiler tools. A changed required byte/owner is a refusal, not an automatic upgrade. Configuration observations distinguish absent files, readable bytes and exact permission errors; permission denial is not authenticated hidden content.

Expand **complete literal tokens** in JSON strings, including dictionary keys. Do not perform prefix rewriting or add/remove separators. Use concrete canonical coordinate values, not tokens nested inside other token values. Serialize request JSON with two-space indentation, sorted keys, `allow_nan=False`, and one final LF. Hash each actual file after expansion. The historical request hashes describe the original coordinates; a reproduction binds its own actual request hashes. The private review proved that full-token expansion recovers all eight historical requests and full outer argv/env/cwd objects.

## Exact initial fixtures

[fixtures.json](fixtures.json) is the complete deterministic fixture specification. It gives whole-byte hashes, exact mutation offsets, copy lists, modes and the unapproved review object. No generated compiler artifacts or receipt placeholders are permitted.

1. Create `${CONTROL_SOURCE}/requests`, `${CONTROL_SOURCE}/fixtures`, `${CONTROL_RAW}/outputs`, `${CONTROL_RAW}/stage2`, and `${CONTROL_RAW}/commands/<id>/tmp` for all eight IDs in `invocations.json`. Capture files do not yet exist. Only output `06-occupied-output` exists initially, with the sentinel described below. The seven other potential preparation output directories are absent; control 8 actually reuses control 2's output.
2. Create the changed-base fixture with only `.github/workflows/ci.yml`. Copy its exact 1,941 bytes from `${BASE}`, then replace byte offset 1,940 from `0a` to `0b`, preserving the length. For example, after the copy, `printf '\013' | dd of="${CONTROL_SOURCE}/fixtures/changed-base/.github/workflows/ci.yml" bs=1 seek=1940 count=1 conv=notrunc status=none` performs the declared mutation. Require the resulting SHA in `fixtures.json`. This first ordered source row must fail before any later missing fixture path is read.
3. Copy exactly the **33 listed regular material files**, with their relative directories, from `${MATERIAL}` into `${CONTROL_SOURCE}/fixtures/changed-overlay-material`. Authenticate every copied byte. Append exactly one LF (`0a`) to `sources/v2/overlay/tools/rapid-profiler/src/lib.rs`; every other copied file remains exact, including `material.json` and `prepare.py`. Require the listed before/after hashes. Run control 4's copied preparer so its own material owner sees that mutation.
4. Create canonical regular `${CONTROL_SOURCE}/fixtures/wrong-msrv-root/bin/cargo`, containing exactly UTF-8 `WRONG TOOL BYTE CONTROL` followed by LF (24 bytes), mode `0444`. It is intentionally non-executable data. The existing first selected-tool SHA/owner predicate must fail before any later tool lookup or executable-bit check. A missing file or unrelated permission error does not satisfy this control.
5. Create only `${CONTROL_RAW}/outputs/06-occupied-output/sentinel.txt`, containing exactly `Required occupied-output sentinel. Preserve every byte.` followed by LF (56 bytes), mode `0444`. Record its inode/metadata/hash before execution and require them unchanged. The directory contains no other file.
6. Write `${CONTROL_SOURCE}/fixtures/unapproved-artifact-review.json` from the exact `json` object and serialization in `fixtures.json`. Its status remains `UNAPPROVED_PREPARATION_CONTROL`; verify SHA `18067891877829e2df92c5fe530f723ba6ef40c26278bd3669ac717127130ec7`. It contains no compiler, binary or artifact approval data.
7. Expand and write the first seven request templates to their declared `${CONTROL_SOURCE}/requests` destinations. Control 7 alone uses direct preparer Python `-O`; the outer helper still runs unoptimized with `-B`. Do not create an executable eighth request yet.

The fixture setup is read/copy/data preparation, not another control or compiler phase. Use only owned ignored paths for every temporary file. No tool replacement is executed.

## Eight bounded invocations

Run the seven concrete requests in fixed order, serially. Every direct preparation retains **20 CPU seconds / 30 wall seconds / 16 MiB per-file**. Invoke only the existing helper, using each complete `outer` object from `invocations.json`:

```text
${TIMEOUT} --signal=TERM --kill-after=10s 40s ${PYTHON} -B \
  ${REPO}/tools/unwind-oracle/bounded_command.py \
  --request <exact request_destination> \
  --receipt ${CONTROL_RAW}/commands/<id>/receipt.json
```

The existing finite caller uses `cwd=${REPO}`, exactly the four declared environment keys (`LC_ALL`, `PATH`, `PYTHONDONTWRITEBYTECODE`, `TMPDIR`), and a **55-second parent timeout**. The helper streams go to the declared `helper.stdout` and `helper.stderr`; direct stdout/stderr are separate request-owned files. Do not pre-open the helper-owned direct output or receipt files. This supplement does not supply another caller or supervisor. Preserve the caller status; an expected helper exit 1 must remain 1 and must not be converted into successful preparation. Unexpected outcome, timeout, input drift or unrelated diagnostic stops the campaign without retry or output deletion.

| Control | Required direct/helper exit | Exact meaning and retained output |
| --- | --- | --- |
| 01 positive v1 | 0 / 0 | 514 exact selected v1 sources, two literal requests and `prepared.json`: 517 files. |
| 02 positive v2 | 0 / 0 | Separate 514 exact selected v2 sources and the same two-request contract: 517 files. |
| 03 changed base | 1 / 1 | First source-byte predicate at preparer line 189 refuses `.github/workflows/ci.yml`; no output root. |
| 04 changed overlay | 1 / 1 | Material predicate at line 55 refuses the changed v2 library overlay; no output root. |
| 05 wrong tool byte | 1 / 1 | Tool SHA/resolved-owner predicate at line 112 refuses the canonical fake Cargo file. Preserve precisely 514 copied source files and empty requests directory; no preparation record. |
| 06 occupied output | 1 / 1 | Existing-output predicate at line 175 refuses; sentinel bytes/inode/metadata unchanged. |
| 07 optimized Python | 1 / 1 | Exact stderr `optimized Python is forbidden` plus LF; no output root. |
| 08 remaining without review | 1 / 1 | Review-status predicate at line 232 refuses the genuine unapproved review after exact positive-v2 preparation revalidation; all 517 files unchanged. |

For every case authenticate typed receipt fields, exact request/helper/direct-output hashes, finite nonnegative elapsed time, `inputs_unchanged=true`, ECHILD, empty unexpected descendants and cleanup events, no abort/cleanup error/wall timeout. Helper stderr must be empty and helper stdout must equal the full declared line, including `success:false` for refusals. Positive direct stderr is empty; direct stdout is exactly sorted JSON containing the actual preparation hash and its two actual request records, plus LF.

The historical review compared complete negative stderr bytes against frozen expectations, not just these labels. In a new coordinate set, require the intended source assertion and complete Python 3.9 framing derived from that exact source, with only the substituted file paths changing; the source-line/function sequences are `332 <module>, 328 main, 189 prepare` (03), `332 <module>, 328 main, 171 prepare, 55 material` (04), `332 <module>, 328 main, 200 prepare, 112 observe` (05), `332 <module>, 328 main, 175 prepare` (06), and `332 <module>, 328 main, 289 remaining, 232 artifact_review` (08). The terminal assertion values are respectively the relative base path, relative overlay path, actual canonical wrong-Cargo path, no value, and no value. Control 7 has no traceback. Do not accept missing-file, parse, permission, earlier-observation or unrelated assertion failures. Raw tracebacks remain private.

## Separate eighth-request admission

After the first seven match their complete contracts, independently review control 2's receipt, whole stdout, exact source map, both literal request expansions and full output tree. Its regular-file inventory must be exactly 517. The only extra directories are the source-directory ancestors, requests, library/tmp and compile/tmp. Both compiler phases remain unexecuted, without receipts/stdout/stderr; there are no artifacts, models or later phase outputs.

Hash the **actual new** control-2 `prepared.json`. Substitute that digest into the only data-dependent token, `${ACTUAL_POSITIVE_V2_PREPARED_SHA256}`, in request 08. Expand all other coordinate tokens and write the actual request once to `${CONTROL_RAW}/stage2/08-remaining-without-review.json`. Bind its actual hash, control-2 receipt/stdout/review hashes, full 517-file tree and unapproved-review hash in a new admission before invoking it. This is a data-binding step, not a ninth execution. Never substitute the historical preparation hash into a new run or fabricate compiler evidence.

Require current selected observations to equal those recorded in the accepted positive-v2 preparation; do not refresh it. Run the eighth invocation using its exact outer binding. It must reach the explicit review-status refusal before accessing any compiler receipt or binary. Verify all positive-v2 files, identities and directories are unchanged, no `remaining.json` or later requests exist, and all generated requests remain unexecuted. Preserve all partial and negative outputs.

## Reporting limits

The [JSON](../results/frontend-tls-preparation-controls-20261025/summary.json), [command CSV](../results/frontend-tls-preparation-controls-20261025/commands.csv) and [case CSV](../results/frontend-tls-preparation-controls-20261025/cases.csv) retain each direct/helper exit and receipt digest. Source and fixture identity are separately explicit; no later publication commit is relabelled as tested. The complete before/after maps contain 2,005 authenticated input rows per case. Each positive observes 1,718 selected source/tool/registry files, six PATH lookups and its actual ancestor configuration outcomes. Those observations are not complete host/runtime closure.

The unchanged helper's process-group/ECHILD evidence is not cgroup containment or a guarantee after uncatchable supervisor death. No syscall trace or global no-child claim is made. These controls establish only the declared source/request preparation behavior. Native entry/exit, machine ABI, module reclamation, a clock, claims 1–4 and full A5 remain unqualified by this result.
