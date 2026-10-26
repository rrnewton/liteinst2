# Static emitter parity

This finite recipe compares the live emitter at Git
`474094a7355c14c673f794cf34aa63d53566f030` with an explicitly supplied candidate
commit. It emits bytes and metadata without publishing or executing generated
code. No historical result is transferred to the candidate.

The material retains the original 28-case capture and 58-case capture literally.
The latter has 48 required successes, ten exact refusals, 56 images and 138
authenticated eight-byte pointer operands. Its comparator is also literal.
The 28-case comparator keeps its complete comparison body and old-output hash
checks, with explicit paths for the new Git pair and fresh old-capture manifest.
Neither inventory nor the allowed pointer fields changes.

`current_features.rs` adds four current chain/grouped plans, 17 frame images (twelve metadata successes and five exact metadata refusals)
and two separately recorded ptrace/overflow refusals. It preserves complete chain
nodes, search attempts/runs, bundle transactions, grouping and memory accounting.
Frame records include entry origins, every producer instruction and its before
and after state, real call/return sites, data ranges and outstanding requirements.
Only a MOV immediate already authenticated in the owned image may be replaced
with the same symbolic pointer value in a helper instruction record. Original
instructions and all other state, addresses, bytes and refusals remain exact.
The existing ptrace INT3 capture stays in the 28-case inventory; the extension
records its independent frame refusal without loosening the 58-case prologue
authenticator. These additional conditions are static source assertions,
not native observations.

Use a clean committed candidate. `REPO` is the canonical checkout containing
both Git revisions, `MATERIALS` is this directory, `RAW` is a new directory below
`REPO/ignored`, and `PREPARED` is a new child of `RAW`. Keep tool paths and full
environment explicit in each bounded request. Record the actual source revision,
tool versions/owners, hardware observation and command receipts separately; this
recipe does not infer hardware or continuous tool/runtime closure.

Run each operation through the existing bounded command helper. Source
preparation, listing, captures and comparisons retain 20 CPU seconds, 30 wall
seconds, the unchanged helper's five-second descendant cleanup deadline, and a 16 MiB capture limit. Compiler/link
operations retain 60 CPU seconds, 90 wall seconds, the same five-second cleanup deadline, and
128 MiB. Retain the existing outer timeout and parent deadline profiles. Use
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`, and one `CARGO_TARGET_DIR=REPO/target`.
No command in this material launches another workload or manages a supervisor;
the preparer invokes only read-only Git object queries.

1. Invoke `python3 MATERIALS/prepare.py --repo REPO --candidate CANDIDATE --output PREPARED`.
   It authenticates `materials.json`, reads the complete inventories from Git,
   copies only each core source tree/README and the fixed chain fixture, and
   writes distinct old/new library target identities. It preserves the exact
   dependency/feature tables and literal locked dependency closure. The only
   source additions are the capture modules and test-only self alias; the old
   58-case file is a literal prefix with one child-module declaration appended.
   `PREPARED/manifest.json` pins the full Git and prepared inventories.
2. For each side, invoke `cargo test --offline --locked --manifest-path PREPARED/SIDE/Cargo.toml --lib --no-run --message-format=json`.
   Save and review the complete Cargo stream, exact manifest/package/library
   identity, profile, features, depfiles and executable before running it. Give
   each side a separate immutable executable copy; reject accidental reuse of
   the other source's executable. The library target names include side and Git
   revision, so both use the same target directory without aliasing identities.
3. List each exact executable with `--list`, then run
   `emitter_parity::capture_extended_live_parity --exact --nocapture --test-threads=1`
   with `LITEINST_EXTENDED_PARITY_OUTPUT=RAW/SIDE-58` and
   `emitter_parity::current_features::capture_current_features --exact --nocapture --test-threads=1`
   with `LITEINST_CURRENT_PARITY_OUTPUT=RAW/SIDE-current`. Both output directories
   must be absent. This is one test artifact per side, reused for the two finite
   static captures; existing unrelated unit tests are covered by required gates.
4. Obtain each side's ordinary rlib with one
   `cargo build --offline --locked --manifest-path PREPARED/SIDE/Cargo.toml --lib --message-format=json`.
   Review and archive the actual rlib and iced-x86 dependency from the Cargo
   stream/depfiles before target reuse. The original 28-case program is a
   standalone main, so link its literal source to those artifacts using
   `rustc --edition=2024 -Dwarnings -Ccodegen-units=1 MATERIALS/capture-28.rs --extern liteinst2=SIDE_RLIB --extern iced_x86=ICED_RLIB -L dependency=REPO/target/debug/deps -o RAW/SIDE-28-capture`.
   This avoids creating another source pair or rebuilding it for each case.
   A unit-test binary is not an ordinary rlib; do not substitute one for the other.
5. Run each 28-case executable with the single argument `RAW/SIDE-28`, checking
   that directory is absent before launch. Its historical implementation uses
   `create_dir_all`, so the caller's absence check remains mandatory. After the
   old capture closes, freeze `RAW/old-28-manifest.json` with the original schema:
   `head` (the fixed old revision), `harness_path` (absolute `capture-28.rs`),
   `harness_sha256`, `rlib_sha256` (actual old rlib), and `output_sha256`
   (every absolute old-output filename and its SHA-256). Keep this record and
   actual receipt immutable before comparing against candidate output.
6. Invoke the three comparisons, with whole stdout retained:
   `python3 MATERIALS/compare-28.py RAW/old-28 RAW/new-28 --manifest PREPARED/manifest.json --old-capture-manifest RAW/old-28-manifest.json`;
   `python3 MATERIALS/compare.py RAW/old-58 RAW/new-58 --manifest PREPARED/manifest.json`;
   `python3 MATERIALS/compare-current.py RAW/old-current RAW/new-current --manifest PREPARED/manifest.json`.
   Python optimization is refused. The 58-case output inventory is exactly 400
   files per side; the current extension is exactly 219 files, 34 images and
   17 callback plus three dispatcher plus three control operands per side.
   No failed comparison becomes a partial pass. Preserve all failed attempts.

The two historical captures and the extension have separate denominators. They
do not replace the recovered eighteen artifact tests, full required workspace
gates, current native suites, or the separately scoped normal kernel-exec oracle.
Successful static parity would show equality for these finite inputs only;
artifact identity, CPU/state, relocation/immediate ownership, hook/router
readiness, unwind and code-as-data requirements remain explicit.
