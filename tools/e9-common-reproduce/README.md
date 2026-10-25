# Reproduce the fixed A3 common corpus

This is a source and request proposal. It has not been run. It does not certify a
new compiler, E9 binary, application, or state trace. Its historical inputs belong
to private snapshots with `tested_revision: null`; the checkout revision does
not become their tested revision.

`prepare.py` stages sources or writes requests. It never launches a process,
imports a campaign module, invokes a compiler, or executes generated code. Every
workload is a separate, explicitly selected invocation of the existing bounded
helper. That helper's SHA-256 remains
`c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`.
The existing E9 emission phase itself owns twelve serial bounded tool commands.
No application execution is hidden in that phase.

## Prerequisites

Supply a local JSON binding with exactly the shape in `local-inputs.template.json`.
Every role in the contract has a fixed whole-file hash and size. Supply an
absolute local path for each placeholder, respecting the owner classes below. The 502 roles include the six original
ELFs, prior reference outputs and RPC authorities, the modified frontend and
backend, loader objects, the original compiler archives, selected runtime and
configuration files, and historical provenance records. No input role is optional.
`input-roles.csv` identifies each role without publishing historical host paths.

This is an exact-artifact reproducer, not an acquisition script. Supply those
artifacts from the matching archive/build provenance. In particular, stock E9
binaries are not substitutes for the pinned modified reference tools. GPL
reference source and binaries are not included in this payload. Compiler archives
are authenticated in place: staging does not copy a large archive through a
16 MiB output allowance. Keep the 34 dependency files together in their exact
directory, with no extra entries, and retain the compiler installation layout.

The existing loader contract fixes the actual ELF interpreter spelling and the
absence of `/etc/ld.so.preload`. V2 also pins the lookup spelling and resolved owner
of all 155 selected system/Python/runtime inputs and the operational
`/etc/ld.so.conf.d` directory. Its member names remain exact. Same-byte copies,
retargeted same-byte symlinks, or a copied configuration directory are refused.
The one remaining selected runtime row is the historical fixture `helper.so`: it
is retained as mandatory exact-byte/identity evidence, but this pipeline never
loads it and makes no consumed-owner claim for it. Other fixture, compiler archive
and provenance roles remain movable only under their unchanged explicit input
contracts. This classification removes no file or identity check.
The 156 selected runtime file identities are observed explicitly for each fresh
stage; later verification requires the same bytes, inode, device, size, mtime,
and resolved owner. There is no automatic epoch refresh. These are selected
runtime identities, not a claim to capture every process mapping or tool input.

Use a fresh absolute raw output directory beneath the selected helper's
repository `ignored/` directory. Its exact source derives that repository from
the helper's resolved path, two parents above its containing directory. Keep
this source payload under that same repository. The preparer checks this existing
helper boundary; moving a helper to an arbitrary location is not supported.
Paths used by
the frozen RPC producer must use the admitted ASCII path alphabet. Raw bindings,
maps, logs, and descriptors stay private. `local-inputs.template.json` contains no
historical host paths. The recipe is serial and requires external review between
the stages below.

## Generate the first requests

Set `REPRO` to this directory, `PYTHON` to the selected Python executable,
`BINDINGS` to the completed local binding, and `RAW` to an existing private parent.
Read `MATERIALS_SHA` from the reviewed publication manifest and independently
compute `BINDINGS_SHA`. The actual execution Python remains the pinned CPython
3.9 executable from the binding.

```sh
"$PYTHON" -B "$REPRO/prepare.py" bootstrap \
  --materials-sha256 "$MATERIALS_SHA" \
  --bindings "$BINDINGS" --bindings-sha256 "$BINDINGS_SHA" \
  --variant sparse-v4 \
  --output "$RAW/bootstrap" --stage-output "$RAW/stage"
```

This command writes three requests and launches nothing. Review
`bootstrap/requests.json`; run `preparation-controls`, then the separate
`operational-controls`, then `stage`. The stage requires both actual successful
receipts and their complete literal stdout. The original 4-positive/16-negative
controls remain unchanged; the new owner group has 3 positives and 10 negatives.
All three requests use CPU 20 seconds, wall 30 seconds, and a 16 MiB file cap. Request generation itself can be placed under
the same existing helper by its caller.

Each row supplies the complete `helper_argv`: the pinned timeout utility wraps
the pinned Python/helper with `--signal=TERM --kill-after=10s` and an outer timeout
ten seconds longer than the command wall limit. `parent_timeout_seconds` records
the original finite caller deadline (wall + 25 seconds). A supervising caller
must retain that deadline and own the launched process; this package adds no
supervisor or descendant-cleanup implementation. The helper receipt, not the
timeout exit alone, establishes command completion and its `ECHILD` proof.

An already reviewed row can be submitted without shell interpolation:

```sh
"$PYTHON" -B -c 'import json,os,sys; r=json.load(open(sys.argv[1]))["rows"][int(sys.argv[2])]; os.execv(r["helper_argv"][0],r["helper_argv"])' \
  "$RAW/bootstrap/requests.json" 0
```

The final argument selects exactly one row. That small exec command delegates
to the existing timeout/helper; it is not a replacement for the finite owning
caller described above. Inspect and retain each receipt before selecting the
next row. Do not treat a timeout, nonzero exit, cleanup failure, or incomplete
receipt as a successful validation.

## Review and generate each phase

After staging, independently review `stage/stage.json`, the new source manifest,
the whole local input identities, and the exact generated files. A review JSON
has exactly five fields:

```json
{
  "stage_sha256": "64 lowercase hex digits",
  "source_manifest_sha256": "64 lowercase hex digits",
  "phase": "prepare",
  "decision": "approve",
  "files": {}
}
```

This document is an explicit reviewer attestation, not a decision generated by
the script. For later phases its `files` map must bind every prerequisite named
by the preparer, relative to the stage directory, including actual terminals,
plans, requests, binaries, receipts, and captures used by that review. Recheck
the underlying records; a supplied hash or review document is not independent
evidence by itself.

```sh
"$PYTHON" -B "$REPRO/prepare.py" requests \
  --materials-sha256 "$MATERIALS_SHA" \
  --stage "$RAW/stage" --stage-sha256 "$STAGE_SHA" \
  --phase "$PHASE" --review "$REVIEW" --review-sha256 "$REVIEW_SHA" \
  --output "$RAW/requests-$PHASE"
```

This writes the original phase requests without launching them. Each row also
has two explicitly separate identity-check requests: run `before`, the main
request, then `after`, serially. Each identity request uses CPU 20 / wall 30 /
16 MiB and prints the exact stage identity. They are new preparation evidence,
not extra native cases or historical command credit. Do not continue after a
failed check. Retain both check receipts together with the main receipt.

The corrected `sparse-v4` sequence is:

| Phase | Required work | CPU / wall / file bytes |
| --- | --- | --- |
| `prepare` | Explicit selected-runtime epoch and six calibration requests | 20 / 30 / 16777216 |
| `calibrations` | All six inherited groups, including exact mocked signal checks | Each 20 / 30 / 16777216 |
| `emit` | Six selected sites, twelve serial tool calls, B1 only | Outer 120 / 180 / 16777216; each tool 20 / 45 / 16777216 |
| `bind-native` | Forty exact loader requests | 20 / 30 / 16777216 |
| `native` | Four original baselines and thirty-six rewritten runs | Each 10 / 30 / 16777216 |
| `audit-native` | Unchanged complete loader/capture checks | 20 / 30 / 16777216 |
| `bind-state` | Data generated from all six actual emitted outputs | 20 / 30 / 16777216 |
| `state-build` | Compiler version, identity controls, fresh compile | First two 20 / 30 / 1048576; compiler 60 / 90 / 134217728 |
| `bind-state-run` | Actual binary and two fixed requests | 20 / 30 / 16777216 |
| `ownership-controls` | Exact 2 positives / 18 negatives | 20 / 30 / 1048576 |
| `state-native` | 144 traces / 360 points / 768 pages / zero hooks | 60 / 90 / 16777216 |
| `receipt-controls` | Exact unchanged 1 positive / 23 negatives | 20 / 30 / 16777216 |
| `audit-state` | Complete unchanged body state/ownership comparison | 20 / 30 / 16777216 |

For `receipt-controls`, the output argument must be exactly
`$RAW/stage/receipt-controls-result`. Every other output directory must be fresh.
The original per-trace limits remain 15 seconds and 20,000 ptrace steps. There
are no register/frame edits, masked comparisons, corpus filters, or enlarged
mapping bounds. Unsupported capabilities fail; they do not become skips.

The six calibration groups retain 5/55 parser cases, one mocked scenario with
six simulated signal deliveries, 1/19 prerequisites, 17/19 common cases, 4/18
sparse geometry cases, and 3/21 ledger cases. State identity controls retain
2/17 separately. These denominators, the unchanged 4/16 preparation controls, and
the separate added 3/10 operational-owner controls are different result units; do not add them into a unique architectural-coverage
count.

The successful body audit requires 36 ownership ledgers and 2,606 capture files,
12 retained instances, 16 reservation roots, 425,984 owned body bytes and 884,736
data/stack bytes. Loader admission and the manual body mapper remain separate
evidence. The manual mapper does not run the E9 bootstrap and does not prove a
bootstrap-to-body architectural handoff. The historical corrective wrapper's
2,652 evidence-file binding included historical ancillary records; a fresh
pipeline must bind its own complete records and may not borrow that count or
the old binary hash.

## Preserve the two historical failures

Use another fresh bootstrap/stage with `--variant legacy-v1` to reproduce the
original four-calibration path. Only `prepare` and `calibrations` are allowed.
The required common calibration retains the original contiguous mapping bound
and is expected to fail; the first three calibration groups are still required.
Retain the exact failure and its diagnostic, then stop. A different earlier
failure does not reproduce that observation, and no emission/native credit is
available from this variant.

Use another fresh stage with `--variant untyped-v3` for the sparse pipeline with
the original untyped `None`. All phases through `state-build` retain their
original sources and cases. The compiler command is expected to exit 1 for the
original ``error: unused import: `FileHookWitness` `` diagnostic under
`#[deny(warnings)]`, not a type-inference error. Require all diagnostic lines in
`contract-untyped-v3.json`, no additional error diagnostic and no state binary;
an earlier or different failure does not reproduce this observation. Preserve
the actual failed receipt and fresh stderr, whose source-path spellings may differ
from the historical capture. No state runtime phase is admitted. The corrected
variant changes the one reviewed full line to `None::<oracle::FileHookWitness>`,
which creates an explicit use of that imported type.
The held v2 source was never executed and has no runnable/pass label here.

These are required historical failure observations, not exceptions to a success
comparator. The preparer does not manufacture a pass receipt or repair a staged
variant in place. Every variant, source manifest, output directory, and future
result remains distinct.

## Source and reporting boundaries

All copied executable Python bodies and expected outputs are exact historical
bytes. The Rust helper changes three include-owner expressions to relative
paths and copies their exact owners; all methods and comparators remain exact.
The successful main is the independently reviewed typed-`None` main. RPC
templates change only the producer-authenticated input filename string, with
the entire remaining RPC literal. Historical Cargo record path text is rendered
as an explicitly nonexecuting hashed provenance token; the complete original
record remains an exact mandatory authority. Every actual compiler dependency
and direct archive retains its own whole-file hash. No current checkout source
or Cargo build is substituted.

Publish sanitized command/case JSON or CSV only after actual receipts and an
independent closed-record audit. Record the new source snapshot and actual tool
identities; never retroactively attach the checkout revision to these private
historical runs. The historical result CSVs retain both failures and all successful
commands separately. New timing is an operational diagnostic, not a performance
benchmark. This bounded B1 cohort supports only its stated part of systematic
tactic validation; it does not qualify all A3 behavior or any of the other three
paper claims.

## V2 review correction

V1 is held and unexecuted for the inaccurate failure description and the
operational-owner rebinding gap. V2 preserves its sources, cases, receipt checks
and caps, corrects the historical description, and adds fixed owner admission.
The separate owner controls add preparation evidence only; no historical/native
denominator or outcome changes. No complete runtime closure is inferred.

## V3 control scratch placement

V2 is held and unexecuted: its two auxiliary pure calibrators would have used
Python's default temporary directory outside the slot. V3 changes only their
scratch placement, not any synthetic case or expected result. Bootstrap adds
`TMPDIR` only to the `preparation-controls` and `operational-controls` requests.
It is their existing canonical output directory strictly below the actual
helper repository's `ignored/` root and outside the immutable material tree.
The exact whole-request checks in stage use the same control-only builder.

Both calibrators pass that explicit validated directory to `TemporaryDirectory`;
there is no fallback to `/tmp`, another environment variable, or the process
working directory. An absent, relative, nonexistent, noncanonical or unusable
scratch parent fails the command. Generated request authentication and the
whole stage comparator establish repository ownership; the calibrators do not
infer an independent repository root. Invoke these controls only through those
reviewed generated requests. Scratch cleanup stays inside the admitted parent.

The ordinary request builder, all historical phase-request generation and
before/after verification request environments remain byte-identical to v2.
The bootstrap generator and stage request retain the original three-key
environment. All old workload source/templates, native phases, output
comparators and CPU/wall/file caps are unchanged. The original 4/16 preparation
and separate 3/10 owner controls retain every case and their exact stdout;
no additional control outcome or execution credit is claimed by this source
correction. Root must independently review v3 and run its fresh preparation.
