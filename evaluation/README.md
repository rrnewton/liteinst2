# Reproducible validation records

These are validation results, not performance benchmarks. Elapsed times are
operational diagnostics from a shared host without controlled affinity or cache
state. Raw captures, local tool paths, process mappings and command environments
stay under `ignored/`. The JSON and CSV files here contain sanitized summaries.

The Word result names the actual tested source revision
`7a4e5719ed06dfd55eaccb2236867f4d760e402c`. Four required gates, the Rust 1.85
check, package inventory and the public native run used that revision. The four
compiler commands ran earlier: their 53 frozen source inputs match the later
Git blobs, but their `precommit_build` source identity remains a snapshot with
`tested_revision: null`. A later byte match is not a retroactive execution claim.

The successful report contains 30 command rows and 883 case rows: 838 strict
native IDs, 26 strict calibrations, 15 output-auditor vectors and four baseline
modes. The 35 baseline cycles are separate from the 838 strict IDs. Workspace
counts are 747 top-level passes, zero failures and four explicitly named old
ignores across 44 Cargo groups. Five nested guard successes are separate and
are not added to that total. Repeated shared calibrations count as executions,
not additional unique architectural coverage. Unsupported native capabilities
fail the required case; they are not skips.

The four claim headings are fixed in each summary. This Word corpus supplies
bounded support under heading 4, **systematic everytactic**, without establishing
that complete claim or full A4. Headings 1–3 remain unqualified. All-thread
signal/router admission, broader saved midpoints, drain, reclamation, active CET
and cross-vendor qualification remain open.

## Reproduction

Keep a checkout of the tested source commit (`REPO`) separate from a checkout
containing these evaluation tools (`REPORT`). This permits a later data-only
commit without inventing a self-referential tested revision. Set `RAW` to a
fresh path beneath `REPO/ignored/`; do not modify source or build concurrently.
Use the same serial build lane and preserve artifacts before shared-target reuse.

Run the four required Cargo gates explicitly:

```sh
python3 -B "$REPORT/evaluation/required-gates.py" --repo "$REPO" --output "$RAW/required"
```

This is a narrow path-adapted copy of the existing required runner. Its exact
commands and 180-second caps (360 for the workspace test) are unchanged. Its
timeout cleanup kills a process group and waits; it does not provide the native
helper's ECHILD descendant proof, and its historical post-kill wait is unbounded.
It executes four commands, not the twenty-command focused evidence sweep.

For the public native build and run, follow
[the Word adapter instructions](../tools/word-sync-oracle/README.md). The actual
commands are `adapter.py freeze`, `build`, `runtime`, followed by the generated
authenticated `runtime/entry.py run`. Supply fresh local toolchain identities;
review the actual source freeze, compiler artifacts, and runtime requests at
their existing boundaries. The adapter retains four CPU60/wall90/file128MiB
compiler requests and twenty serial CPU20/wall30/file1MiB runtime requests.
No new supervisor or alternate comparator is introduced here.

Prepare the MSRV request without writing JSON by hand. `TOOLCHAIN` is the
Rust 1.85.0 installation root; `LOCAL_CARGO_HOME` and `LOCAL_USER_HOME` are the
reviewed local Cargo cache and home directories. `MSRV_RAW` must be a fresh child
of `REPO/ignored/` whose parent already exists:

```sh
python3 -B "$REPORT/evaluation/prepare-msrv.py" \
  --repo "$REPO" --toolchain "$TOOLCHAIN" \
  --cargo-home "$LOCAL_CARGO_HOME" --user-home "$LOCAL_USER_HOME" \
  --mode pass --output "$MSRV_RAW"
```

The generator verifies the selected published 165-file source inventory and
exact reference Cargo/rustc bytes, then writes `request.json` and a private
`admission.json`. It constructs an explicit local environment, excluding
`CARGO_ENCODED_RUSTFLAGS`, `RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER`, with four
jobs, incremental disabled, offline/locked resolution and the existing shared
`REPO/target`. The command remains the root package's all-target/all-feature
check with `-Dwarnings -Wmissing-docs -Funsafe-op-in-unsafe-fn -Ccodegen-units=1`.
CPU60/wall90/file128MiB are fixed. This is not a workspace-member or standalone
native-harness MSRV claim. Matching the source inventory does not qualify local
Cargo configuration or the entire toolchain installation; review those inputs
before launch and preserve their identities in the new attempt.

Review the generated request and source/tool identities, then invoke the
existing public helper with the reviewed `HELPER_PYTHON` and `TIMEOUT` binaries:

```sh
"$TIMEOUT" --signal=TERM --kill-after=10s 100s \
  "$HELPER_PYTHON" -B "$REPO/tools/word-sync-oracle/bounded_command.py" \
  --request "$MSRV_RAW/request.json" --receipt "$MSRV_RAW/receipt.json" \
  >"$MSRV_RAW/helper.stdout" 2>"$MSRV_RAW/helper.stderr"
```

No generator step launches a compiler or creates a supervisor. The helper
retains its existing bounded descendant cleanup. A failed or missing receipt
never establishes success or cleanup. Recheck source/tool bytes after the run,
inspect the actual Cargo records and diagnostics, and preserve artifacts before
shared-target reuse. Record the new attempt's actual checkout/snapshot identity;
preparation alone supplies no executed revision or result.

## Preserved failure

`results/msrv-v3-failed-snapshot-20261025` is the actual failed precommit attempt:
exit 101, unchanged strict flags, clean ECHILD, missing public-function docs. It
is not labelled a run of `7a4e5719`, an expected refusal, or a successful gate.
The later fix adds fourteen documentation lines in five files. The compiler
first reported three errors; the broader source scan found the remaining eleven.

To reconstruct the failed source, use a new `FAILED_REPO` and apply the published
patch with zero fuzz. These commands create new private source/output paths;
they do not alter the tested checkout or old receipt:

```sh
mkdir "$FAILED_REPO"
git -C "$REPO" archive 7a4e5719ed06dfd55eaccb2236867f4d760e402c | tar -x -C "$FAILED_REPO"
(cd "$FAILED_REPO" && patch -p1 --fuzz=0 < "$REPORT/evaluation/reproductions/msrv-v3-missing-function-docs.patch")
mkdir -p "$FAILED_REPO/ignored/evaluation"
python3 -B "$REPORT/evaluation/prepare-msrv.py" \
  --repo "$FAILED_REPO" --toolchain "$TOOLCHAIN" \
  --cargo-home "$LOCAL_CARGO_HOME" --user-home "$LOCAL_USER_HOME" \
  --mode failed-snapshot --output "$FAILED_REPO/ignored/evaluation/msrv"
```

The generator requires every failed-snapshot source hash. Invoke the same helper
command above with `REPO=$FAILED_REPO` and
`MSRV_RAW=$FAILED_REPO/ignored/evaluation/msrv`, preserving its nonzero status.
This is a new reproduction attempt against byte-identical failed source, not a
retroactive run of the later source commit. Preserve both outcomes and never
overwrite the old receipt.

## Export and data commits

`export-word.py` reads a reviewed private input inventory and the completed raw
receipts. It starts no tools or native programs. Its input inventory contains
paths/hashes, source epochs, tool observations and explicit path-to-role
substitutions; it stays private. Run it into a **new** private output directory:

```text
python3 -B evaluation/export-word.py --inputs ${RAW}/export-inputs.json --inputs-sha256 ACTUAL_SHA --output ${RAW}/public-export
```

The exporter requires all 20 ordered Word commands, their original exact output
forms, 838 ordered IDs, 26 calibration names/panic annotations and all 103 final
capture files. The existing independent architectural audits remain necessary. The exporter trusts the reviewed input metadata for source epochs, hardware and tool observations; raw receipts and independent source/artifact audits are therefore part of the evidence boundary, not replaced by the exporter.
Compiler and failed-attempt rows retain their actual status. No partial command
output is promoted to native success. The pure auditor's individual vector rows
are source-bound assertions witnessed by its exact aggregate output, not new
native executions.

Review the exported files and copy only `summary.json`, `commands.csv`,
`cases.csv`, `source-files.json` and `files.json` into a new
`evaluation/results/<run_id>/` directory. Commit source as C, test C, then commit
these result files as D naming C. Do not change the tested revision to D. Tool
hashes are exact; version fields explicitly distinguish captured banners from
directory labels or absent secondary-tool version text. Hardware was observed
read-only after this run on the same host; no continuous hardware attestation is
claimed. Private capture manifests are represented only by their digest.

JSON is the authoritative representation. CSV stores nested argv/environment
values as JSON cells. `cases.csv` never combines trace, baseline, calibration
and compiler counts into one architectural denominator. No data row is a
performance measurement or evidence for a broader claim than its scope states.


## Generation metadata records

The A5 records below concern generation bookkeeping and ownership. They do not
activate the profiler frontend or establish an in-place preemption clock. This
metadata evidence leaves all four claim headings unqualified; the separate Word
scope described above is unchanged.

| Record | Results | Reproduction |
| --- | --- | --- |
| Historical private snapshot based on `7a4e5719` | [Seven commands and 19 cases](results/generation-private-7a4e571-20261025/summary.json), with [named case rows](results/generation-private-7a4e571-20261025/cases.csv) | [Private source reconstruction and requests](generation-private.md) |
| Required regression at `ed67f752` | [Four required gates](results/required-ed67f75-20261025/summary.json) | [Required gate runner](required-gates.py) |
| Public promotion formatting | [Actual formatter and source-delta record](results/generation-promotion-format-20261025.json) | [Promotion-format recipe](reproductions/generation-promotion-format.md) |
| Preserved partial public v3 attempt | [One of six main commands completed](results/generation-public-v3-partial-20261025/summary.json); all 17 model and two doc cases remained unrun | [Exact historical generator and four actual request templates](reproductions/generation-public-v3-partial/README.md) |
| Focused public generation qualification | [Seven main commands, 16 auxiliary steps, 17 models and two exact ownership docs at ed67f752](results/generation-public-ed67f752-20261025/README.md); metadata only, all four claims unqualified | [Seven-command preparation and artifact-admission procedure](generation-public.md) |
| Historical reporting controls | [Six reporting/control invocations](results/generation-reporting-tools-20261025.json) | [Commands and expected negative outcomes](generation-reporting.md) |
| Public-source export and promotion preparation | [Two reporting invocations](results/generation-public-reporting-tools-20261025.json) | [Exact request and wrapper templates](reproductions/generation-public-reporting-controls.json) |

The `ed67f752` required regression has 766 top-level passes, zero failures and
four preexisting ignores. Its 17 generation models and two compile-fail docs are
already included in 766; five nested guard successes are reported separately.
Private, required-regression and focused public repetitions are distinct
executions, not additional unique semantic coverage, and their totals must not
be summed into one coverage denominator.

Historical private runs and private reporting scripts retain
`tested_revision: null` with their actual source snapshots. A committed source
revision used for reconstruction is not a retroactive tested revision for those
scripts. The committed required regression names `ed67f752`; later data commits
do not change that identity. Expected nonzero reporting controls remain
refusals, unrun cases remain unrun, and formatter-review assertion failures
remain distinct from the actual successful formatter command. Reporting and
request preparation do not execute the modeled workload. Timing is operational
only; per-command tool and hardware provenance limits remain in each record.

Generated-unwind consumer results and reproduction materials are indexed in [consumer-public.md](consumer-public.md). The index separates historical native/parity results, failed fresh-reproduction prerequisites, workspace regressions and reporting operations; these records do not establish full A2 or general unwind support.

The [frontend model history](frontend-model-private/README.md) preserves the held, failed and completed private ownership/controller model attempts. These snapshots do not establish public-crate qualification, native interval exits or a software preemption clock.

The [A3 common-corpus index](e9-common-public.md) separates historical prototype loader/body evidence from the four completed portable-preparation commands. The portable pipeline remains unrun beyond staging, and full A3 remains open.

The [public frontend model index](frontend-public.md) joins the focused 60-model/eight-doc qualification at `9098a3d7`, the separate required workspace pass, the preserved failed `3f87ac90` attempt and six independent tool-version observations. It retains each record's source, admission epochs and denominator. This ownership/model evidence leaves native frontend execution, a preemption clock, full A5 and claims 1–4 unqualified.

## TLS ownership evidence

[Private TLS failure and corrected qualification](frontend-tls-private.md) retain separate null-revision snapshots, exact74-model/10-doc inventories and request-only reproduction materials. [Public required gates at4c754df8](results/required-4c754df8-20261025/summary.json) report1000 outer passes/0 failures/4 existing ignores, with five nested guard executions separate. Repeated private/public runs do not add unique coverage; native machine-return-slot integration, the preemption clock and full A5 remain unqualified.
