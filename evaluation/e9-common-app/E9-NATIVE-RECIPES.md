# Exact controlled E9 recipes

These assets preserve the scripts used for the eight controlled E9-null cells at tested revision `9884b7a259b4e0ea80d2cca6d726abab4594807a`. The native Rust adapter and driver are already committed at that revision; the runner and auditor recipes were executed from ignored paths. This export copies their exact bytes. It is not an all-eight end-to-end campaign launcher, and report regeneration does not rerun native validation.

Copy `materialize_e9_native.py` and its adjacent `e9-native-recipes/` directory outside the checkout before checking out the tested revision. Then, with exclusive ownership of writes to that checkout, run:

```sh
python3 -B /path/to/export/materialize_e9_native.py --repo /absolute/path/to/checkout
```

The materializer authenticates all seven assets before writing eleven fixed ignored files (each auditor receives the two common adjacent JSON supports). It refuses every existing destination and symlink parent, and never launches Git, a compiler, a helper, a namespace, an auditor or a native subject. A failed copy can leave a partial set; it does not overwrite or clean up existing files. Its completion means only that the copies were written. Full source/Git/owner admission remains the runner's responsibility. The export preserves the fixed ignored coordinates used by the existing assemblers and their source hashes.

| Asset | SHA-256 |
|---|---|
| runner.py | `3feea2da3dbc4455af5133caebc87441709a8342caa068f215640d3e3b2a6973` |
| auditor-initial.py | `3d69c425fee567dace19e72fc1cce3e65bc41ef2b8725ce74ed7b10b4c9e8008` |
| auditor-hash-reuse.py | `448d255df8220d2a2503ab13b6a2b02482dbca240986416f4c5444669f0da8ad` |
| auditor-sized-read.py | `5cf71fbe47efccd39517228f51c80513d979575ecabdd5057e179a7daa3b8700` |
| heads.json | `5e8f74c75c8274917f76c5663ad0badb7d1d7d31915fa716d29521e61e75e32c` |
| source-pins.json | `4544269294433e99aa419d8b97c6c56fb7e1adcadeae894a9e4d7fec4fdef8f1` |
| runner-parent.py | `ef498715a3dc8120725011ab71d0a57dfd16ddc984cdde044fa23aee19146ca8` |

For one freshly admitted cell, use the unchanged runner interface:

```text
${PYTHON} -B ${RUNNER} --inputs ${RUN_INPUTS} --inputs-sha256 ${RUN_INPUT_SHA256} --cell ${CELL} --raw ${RUN_RAW}
```

The exported `runner-parent.py` is the exact existing launcher. Copy it byte-identically as `launch.py` beside a fresh admitted `command.json` containing the full argv/cwd/env/affinity/recipe hash, then execute it inside the admitted runtime namespace. It records the actual direct-child wait; descendant closure comes from the runner's bounded helper receipts. Keep affinity `[0,1,2,3]`, witness limits 20 CPU seconds / 30 wall seconds / 16 MiB, and replay limits 60 / 90 / 64 MiB. These are unchanged limits, not measured performance.

The unchanged auditor interface is:

```text
${PYTHON} -B ${AUDITOR} --inputs ${AUDIT_INPUTS} --inputs-sha256 ${AUDIT_INPUT_SHA256} --raw ${AUDIT_RAW}
```

Run it through the existing bounded helper with 60 CPU seconds / 90 wall seconds / 64 MiB, the saved 100-second outer timeout with 10-second kill-after and 115-second parent backstop. The helper and namespace/controller sources, source and runtime admission, envelopes and full command records remain separate prerequisites. This materializer does not fabricate them.

Fresh inputs must retain the complete original/build/production/ordinary evidence, exact current source and tool owners, selected runtime/cache/provider identity, fresh capacity, and all prior content-reviewed cells in order. Historical pathname substitution cannot recreate those owners, PIDs, namespace identities, freshness or review authority. Raw inputs/captures remain private. The existing ordered assembler and bounded audit launcher can consume proper fresh caller descriptors; their historical pinned metadata requires an explicitly reviewed caller/template successor for a new epoch. No current end-to-end fresh-input construction is claimed here.

The fixed cell order is heap-write unstripped stock/bootstrap, heap-write stripped stock/bootstrap, jump-site unstripped stock/bootstrap, and jump-site stripped stock/bootstrap. Each retains all 87 heads, 176 cases, 352 children and 528 comparisons; the totals are 8 cells, 1408 cases, 2816 children and 4224 comparisons. Capture counts remain `8637 + 9E`, snapshots `880 + E`, and `E <= 12` per cell.

The first failed audit used `auditor-initial.py`. Passing cells 1–5 used `auditor-hash-reuse.py`; cell 6's first audit also used that version and failed. Cell 6's retry and passing cells 7–8 used `auditor-sized-read.py`. Both failed attempts retain exit -9 with unproven signal origin. Publishing the exact source and commands does not promise reproducing those signal outcomes. No failed attempt is erased or counted as passing.

Controlled E9 saved-content completion is an intermediate result. Ordinary remains 160 passed / 0 failed / 32 unrun and overall unsuccessful; production remains 62 passed / 12 failed / 0 unrun and overall unsuccessful. Core's 704 and recording's 2112 cases remain UNRUN. These sources and results supply no normal-loader or full-A3 qualification.
