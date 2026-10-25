# Historical generation bookkeeping validation

This result describes a private four-file standalone crate based on
`7a4e5719ed06dfd55eaccb2236867f4d760e402c`. Its `tested_revision` is null.
It does not describe execution of the promoted `rapid_profiler::generation`
module or activate the profiler frontend. All four paper claims remain
unqualified by this metadata component.

The seven actual commands were: formatter, warnings-denied no-run compilation,
model listing, seventeen model tests, Clippy, two ownership compile-fail
examples, and Rust 1.85 all-target checking. All passed. The two compile-fail
examples required E0599 (no ticket cloning) and E0382 (no second completion),
not arbitrary compiler failures. The one positive and six negative reference
comparator controls are inside the seventeen model tests; they are not added
as seven extra test executions.

Formatting has its own source epoch. The initial token-preservation review
incorrectly assumed only trailing commas were inserted; it stopped on the
formatter's expression-closure block wrappers. The formatter itself passed.
The failed review hypothesis and the later complete diff review are recorded
as separate review events, not converted into formatter or test failures.
The public promotion's later formatter is another source epoch and is not one
of these seven commands.

The models cover per-function K, independent global M/A bounds, distinct old
and new generations, ticket cancellation, drain, and exact record identity.
The close-gap case retains five completed-and-dropped admissions while M=2,
and separately checks one other outstanding reservation at close. M−1 is not
a bound on all completions after K. The sixteen-value visibility witness
checks records before releasing/joining its worker; it does not isolate the
necessity of Acquire independently of OnceLock and the other operations.
Signals, nonlocal exits, cross-fork identities, actual clocks/PMU data,
physical toggles, frontend integration, and full A5 remain unqualified.

Elapsed times are operational diagnostics on the shared AMD EPYC Zen 5 dev
host, not performance benchmarks. The hardware observation is inherited from a
separate read-only observation on the same host; its phase relative to these
seven A5 commands is not established, and no continuous hardware attestation
is claimed. Tool identity scopes are listed per command admission in the report.
The formatter admission captured rustfmt and helper source hashes, but did not
capture the Python or timeout executable identity for that invocation. Later
observations do not fill that gap. The MSRV admission binds an earlier explicit
90-file/16-configuration identity map; other compiler/model admissions retain
their own captured tool identities. Capturing a tool identity is not evidence
that every such role was executed by the command. Labels distinguish
historical version information from a new version invocation, which was not
part of these seven commands.

## Reconstruct the exact historical inputs

Use `REPORT` for a checkout containing these evaluation tools and `REPO` for a
checkout containing the exact promoted source bytes named in
`reproductions/generation-private/reconstruction.json`. The generator refuses
different module/test bytes. Matching promoted bytes do not retroactively turn
the historical private runs into execution of that commit.

The two Cargo files and the exact reconstruction edits are tracked material.
The human-readable patches accompany the hash-bound line edits. Reconstruction
first recovers the tested formatted standalone source, then the original
formatter input. It produces exactly Cargo.toml, Cargo.lock, src/lib.rs and
src/tests.rs. No source file is fetched and no fuzzy patch operation is used.

`RAW` must be a new directory beneath `REPO/ignored/` with an existing parent.
Use canonical local paths without colons or line breaks. `TOOLCHAIN` and
`MSRV_TOOLCHAIN` are the pinned Rust 1.97.1 and 1.85.0 installation roots.
Supply the local Cargo cache/home and the reviewed helper Python/timeout paths:

```sh
python3 -B "$REPORT/evaluation/prepare-generation.py" reconstruct \
  --repo "$REPO" --raw "$RAW" \
  --toolchain "$TOOLCHAIN" --msrv-toolchain "$MSRV_TOOLCHAIN" \
  --cargo-home "$LOCAL_CARGO_HOME" --user-home "$LOCAL_USER_HOME" \
  --helper-python "$HELPER_PYTHON" --timeout "$TIMEOUT"
```

This writes source, a formatter request and a private config hash. It runs
nothing. Review the exact source/material/tool/config identities, including
local Cargo configuration and toolchain/runtime dependencies, before launching
anything. Hashes of selected executables alone do not qualify those other
inputs. The generator never refreshes an expected hash to match local state.

Run the formatter request with the existing public bounded helper:

```sh
"$TIMEOUT" --signal=TERM --kill-after=10s 40s \
  "$HELPER_PYTHON" -B "$REPO/tools/word-sync-oracle/bounded_command.py" \
  --request "$RAW/format/request.json" --receipt "$RAW/format/receipt.json" \
  >"$RAW/format/helper.stdout" 2>"$RAW/format/helper.stderr"
```

The formatter request remains CPU20/wall30/file16MiB. It targets src/lib.rs;
rustfmt follows the declared test module, as in the historical command. Inspect
the whole before/after delta and exact four-file result before continuing.

```sh
python3 -B "$REPORT/evaluation/prepare-generation.py" prepare-compilers \
  --raw "$RAW" --config-sha256 "$REVIEWED_CONFIG_SHA"
```

This requires the passed formatter receipt and exact historical formatted
hashes. It writes compile/Clippy/doc/MSRV requests, without executing them.
All four remain CPU60/wall90/file128MiB. In particular the historical doc check
was a Cargo compiler invocation with these bounds; it is not relabelled as a
20-second model request. Cargo keeps four jobs, incremental disabled,
offline/locked resolution, one existing `REPO/target`, and strict flags. There
is no CARGO_ENCODED_RUSTFLAGS override. The standalone private source does not
claim the public missing-documentation gate.

Run only the compile request first, using the same helper invocation with
`100s` as the outer backstop and `compile` in place of `format`. Preserve the
actual Cargo records, compiler stderr and source/tool identities. Do not run a
concurrent shared-target build. Then prepare the exact model requests:

```sh
python3 -B "$REPORT/evaluation/prepare-generation.py" bind-models \
  --raw "$RAW" --config-sha256 "$REVIEWED_CONFIG_SHA" \
  --plan-sha256 "$REVIEWED_COMPILER_PLAN_SHA"
```

The binding checks the actual no-run Cargo records, package/manifest/target,
profile, features, exact test executable and depfile source/target ownership.
It archives that binary before later compiler commands can overwrite the
shared target. The archived binary hash is new evidence, not a required match
to the historical binary's debug-path-dependent hash. Review it independently
before running list and models. Both requests remain CPU20/wall30/file1MiB;
use the same helper and a 40-second outer backstop. The exact seventeen names,
zero ignores/failures and all assertions remain required.

Finally run Clippy, docs and MSRV serially with their prepared requests and
100-second outer backstops. Preserve all seven receipts, output streams and
source/tool identities. Inspect both exact ownership diagnostics. Any failed
step is a failed required reproduction; do not retry it into a success, omit
it, or weaken an expected result. Keep the raw failure and create a separate
reviewed failed-attempt report. A missing receipt is never success or cleanup.

## Reporting

The five files in `results/generation-private-7a4e571-20261025` use the common
evaluation JSON/CSV convention. Seven command rows, seventeen model rows and
two ownership compile-fail rows remain distinct quantities. Source-files.json
contains both four-file epochs. Raw private paths, environments, compiler
records, mappings and artifact archives are not published.

`export-generation.py` reads an independently reviewed private input inventory
and all completed raw receipts. It starts no tools or native programs. The
reviewed metadata supplies source epochs, hardware/tool observations and the
explicit private-path substitutions. This trust boundary does not replace
source, artifact or semantic review. The exporter requires the exact fixed
successful cohort; partial/failed reproductions cannot produce a success report.

```text
python3 -B evaluation/export-generation.py --inputs ${RAW}/export-inputs.json --inputs-sha256 ACTUAL_SHA --output ${RAW}/new-public-export
```

The exporter verifies all bound raw files, request/output identities, clean
ECHILD receipts, original commands/environments/bounds, exact list/model output,
and the complete two-diagnostic doc output except its elapsed-time field.
It reproduces the historical JSON/CSV into a new directory. A new reproduction
needs a new reviewed metadata inventory, current hardware observations, actual
new binary/receipt hashes and a distinct run ID; never reuse the historical
metadata to claim new execution. Commit tested source first, run that source,
then publish its result commit without retroactively changing the tested epoch.
