# Foreign frontend validation reproduction

The tested revision is `76278bdfd19db60a0734ed1195d0f96d9da1a680`. The exported `validate.py` is byte-identical to the caller for that revision, SHA-256 `d3354949d3d021cc843ca625253ed13eccda2983b7f10f92974a4afed7c56ccd`. The saved hardware label is **AMD EPYC Zen 5 dev host**. Durations are operational measurements, not performance results.

Run the caller from a clean checkout of that exact revision, using fresh ignored output directories and an explicitly selected Rust toolchain, user home and Cargo home. Its six phases are `targeted`, `required`, `serial`, `parallel-library`, `parallel-prefixed` and `parallel-neighbor`. For example, substitute absolute local paths for these roles:

```sh
python3.9 -B validate.py --repo "$REPO" --output "$REPO/ignored/frontend-targeted" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --phase targeted
```

The target runs every target in `liteinst-rewrite`. Required validation retains format, strict workspace Clippy, workspace tests and all-target/all-feature check. Serial validation runs the complete launch-crate tests with one test thread. The three contention phases run the complete core library, prefixed-pun oracle and neighbor-eviction oracle targets with default test threading. No case filter is added. Targeted/serial use four CPUs and 180 seconds; contention uses eight CPUs and 360 seconds. The required enclosing bound is 1,000 seconds with unchanged inner gate limits. Each caller log is bounded to 8 MiB. Four build jobs, offline Cargo, zero debug information and unchanged debug assertions remain explicit in the saved command environment. Source/tool/configuration equality and process cleanup are required for a PASS.

The saved-metadata collector accepts `--inputs`, `--inputs-sha256` and `--new-output`. Its caller pins the exact six closed phase records, full logs, parser, validation driver and independent complete log inventories. The collector never launches validation. A successful phase must supply its complete log and reviewed inventory; a started or partial phase cannot be represented as UNRUN. It emits six phase rows plus four inner required-gate rows: ten reporting rows describing nine validation commands and one enclosing dispatch. Repeated case observations and nested terminal summaries are not added into a unique-test total.

The inventories retain full group/name/status identities and line joins, including prior workspace names and actual additions. Public `commands.json` holds complete command contexts normalized with injective path roles; private role maps and command inverses reconstruct the originals. Public files include command/case CSVs, full case/group JSON, parser limitations, source pins and saved-record hashes. Raw logs and private contexts stay ignored. The collector source SHA identifies the reporter separately from the tested revision.

`prior-attempt.json` preserves the distinct `822c0a4` history: 133 targeted passes, followed by a strict Clippy failure for an explicit needless lifetime. Workspace tests, check and later serial/contention phases were unrun in that attempt. The correction elides only that lifetime; it does not suppress the lint. Results for the corrected revision must come from its own closed records.

This validation does not establish a complete common-corpus campaign, a production entry-router bootstrap, general native T3 qualification or full A3 completion. The separate synthetic two-owner native result retains its own tested revision and scope.

A preserved first reporting attempt refused three actual zero-test Cargo example headers. The collector successor admits only their exact targeted source/binary identities and full zero-test blocks. The shared public parser remains unchanged; its invalid_harness_binary_path diagnostic is retained separately from the complete reviewed inventory. This reporting correction transfers no workload result and changes no validation limit or assertion.

Save the exported validation script outside the tested checkout before selecting its tested revision: these reproduction files were published in a later reporting commit. Invoke that saved script against the clean tested checkout.
