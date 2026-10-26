# Kernel-loaded ELF frontend validation

The standalone frontend now has a completed normal-kernel-exec check at
`fc830799595a6f0d4bd5e699cff0b9b1f9cf0e36`. It emits an executable candidate,
metadata and a sparse overlay through the shared core. The fixed B1 ET_EXEC
fixture passed with both stripped and unstripped input and both null and
recording hooks. This supplies bounded evidence for claim 4, systematic tactic
validation. Full A3 and claims 1–3 remain open.

[The result packet](results/elf-frontend-fc83079-20261026/README.md) contains
sanitized JSON and CSV. Its 55 command rows keep native stages, nested workspace
gates, static parity and two pure-control runs separate. The
[development history](elf-exec-development-attempts.md) retains the failed
campaigns, failed postcheck and unexecuted source proposals. Later success does
not change their outcomes. Raw logs, mappings, captures and binaries stay in
ignored storage.

The original collector files remain byte-identical under `files.json`. A separate
`supplement-files.json` indexes the [workspace totals](results/elf-frontend-fc83079-20261026/workspace-public-summary.json),
[group summaries](results/elf-frontend-fc83079-20261026/workspace-public-groups.json),
[case inventory](results/elf-frontend-fc83079-20261026/workspace-cases.json) and
[reporting operations](results/elf-frontend-fc83079-20261026/reporting-operations.json).
Those last two operations only audit saved records and render summaries; their
prepublication script snapshots have no invented tested Git revision.

All four required workspace gates passed on the exact source revision above:
formatting, Clippy with warnings denied, workspace tests and all-target/all-feature
check. The test log has 70 outer groups, 1,175 passes, zero failures and four
unchanged ignores. Five completed nested guard tests are separate; two further
child starts have no separately credited terminal result.

The native driver completed 8 original and 16 rewritten traces, 72 full-state
assertions, 24 application CALL/RET witnesses, 8 hook CALL/RET witnesses and
4 exact journal rows. Its 1,230 saved files join held executable descriptors,
mount providers, mapping-file links, image bytes and trace records. Six separate
ordinary processes printed the required output and exited zero. Execution used
`fexecve`, kernel-owned LOAD mappings and an authored application CALL; the
driver made no manual LOAD mappings or post-seed state repairs. The original
whole-child 20,000-step and 15-second limits remain unchanged.

The four candidates are each 90,418 bytes with a 306-byte generated image.
Growth is 6,922 bytes for unstripped input and 7,994 for stripped input.
The semantic redirect occupies five instruction bytes; the exact source edit
changes four bytes because the remaining byte was already equal. The
[artifact table](results/elf-frontend-fc83079-20261026/native-artifacts.csv)
records actual edit spans, changed-byte counts and original/candidate/image
identities. These are file sizes, not resident-memory or runtime-cost results.

Static live-emitter parity compares the same candidate revision with
`474094a7355c14c673f794cf34aa63d53566f030`. All 22 bounded stages passed.
The three populations remain separate:

| Inventory | Recorded comparison |
| --- | --- |
| Historical | 28 fixtures, 33 authenticated callback operands, 114 files per side |
| Extended | 58 fixtures: 48 successes and 10 required refusals; 56 images, 138 authenticated operands, 400 files per side |
| Current chain/frame | 21 cases, 34 images, 17 callback / 3 dispatcher / 3 control operands, 219 files per side; 12 frame-metadata successes and 5 typed refusals, with 2 independent refusals recorded separately |

Only authenticated pointer fields are normalized. All other bytes, metadata,
case identities and required refusals remain exact. Static parity executes no
generated image and is separate from the native fixture. Depfile controls
passed 3 accepted and 13 refused cases; library-alias controls passed 3 accepted
and 11 refused cases. Neither control population adds native or parity credit.
Configuration read denials remain explicit unknown observations, without a
claim about hidden contents or actual Cargo configuration consumption.

Hardware was the **AMD EPYC Zen 5 dev host**, model AMD EPYC 9D85 158-Core
Processor, x86-64, kernel `7.1.3-0_fbk0_rc18_0_gd373cd4b8dbf`, glibc 2.34.
Each campaign and control has its own hardware observation. The selected Rust
toolchain is 1.97.1. Builds used four jobs, one target directory and disabled
incremental compilation. Durations in the records are operational diagnostics,
not benchmarks; nested command durations overlap their parents.

## Reproduction

Use a clean checkout of the tested commit containing both Git revisions. Keep
the later evaluation publication checkout separate: its commit is not the
tested source revision. Run the native and static recipes serially with fresh,
canonical output directories under the tested checkout's `ignored/`:

```sh
cd "$REPO"
/usr/local/bin/python3 -B evaluation/elf-exec/reproduce.py \
  --raw "$NATIVE_RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
/usr/local/bin/python3 -B evaluation/emitter-parity-run.py \
  --raw "$PARITY_RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

The [native recipe](elf-exec/README.md) retains the four required gates and
all prepare, sidecar-verification, trace and ordinary-process stages. The
[static recipe](emitter-parity/README.md) records exact prepared Git sources,
Cargo artifacts, depfiles, tool/config observations, requests and receipts.
The two control programs are
[`emitter-parity-depfile-controls.py`](emitter-parity-depfile-controls.py) and
[`emitter-parity-library-controls.py`](emitter-parity-library-controls.py).
Their complete bounded request/outer/environment objects are in
[`commands.json`](results/elf-frontend-fc83079-20261026/commands.json).
Expand its named directory roles into fresh local owners and preserve the
20 CPU-second, 30 wall-second, 16 MiB, outer-40-second and parent-55-second
control limits. Record actual tool/source hashes before and after each run.

The published [saved-record audit](reproductions/elf-exec-audit-v5/audit.py)
is byte-identical to the executed audit. It resolves the repository three
directories above its own file. To audit a fresh run of the old source without
changing tracked files, copy it into
`REPO/ignored/a3/elf-exec-audit-v5/audit.py`, then invoke it with `--raw NATIVE_RAW`.
It exclusively creates `NATIVE_RAW/runtime-audit-oracle-v3/audit.json`; the
historical output name is intentional. The audit authenticates saved ownership
and inventory records; the original driver's executed assertions supply the
architectural comparison.

The byte-identical [collector](reproductions/elf-frontend-collect-v2/collect.py)
reads only closed saved runs. It requires the actual audit digest, separately
reviewed control records and explicit confirmation that all parent processes
terminated successfully and were reaped. Its invocation is:

```sh
python3 -B "$REPORT/evaluation/reproductions/elf-frontend-collect-v2/collect.py" \
  --repo "$REPO" --native "$NATIVE_RAW" \
  --native-audit "$NATIVE_RAW/runtime-audit-oracle-v3/audit.json" \
  --native-audit-sha256 "$AUDIT_SHA256" --parity "$PARITY_RAW" \
  --depfile-controls "$DEPFILE_RAW" --alias-controls "$ALIAS_RAW" \
  --output "$FRESH_OUTPUT" --parents-closed-and-reaped
```

Independent control review must precede collection. Each control raw tree must
contain `review-core-v1/binding.json` naming its exact revision, receipt digest,
review-file hash map, `CLOSED_PURE_CONTROLS_PASS_EXECUTION_RECORD_SCOPE` verdict,
and false native/static-parity credit. A missing after-record or failed parent
cannot satisfy the collector. Do not fabricate these records from an expected
result. The collector also checks every saved input hash again before creating
output; it does not rerun a workload or inspect the shared build target.

All emitted products retain `qualification_complete=false`. This fixture has
no dynamic loader, PIE/DSO, unwind, CET, SIGILL-router or arbitrary-program
qualification. The common E9Patch site-by-site release comparison, remaining
tactics under normal loading, grouping and broader module/runtime checks are
still required. Earlier prototype loader and manual-mapping results retain
their separate scope.
