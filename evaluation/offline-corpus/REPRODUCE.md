# Fresh offline comparison wrapper — source only, UNRUN

Install `reproduce.py` as `evaluation/offline-corpus/reproduce.py` beside the six exact effective comparison files pinned in its `SOURCE_PINS`. The comparison source is unchanged: root's v2 lifecycle predecessor, v3 fixed-80 retention, v4 exact image-extent check, and explicit executable-versus-loader-data role correction. Commit that source before running. This proposal has not imported or executed the wrapper, built products, read current providers/products, or launched any corpus case.

```sh
python3 -B evaluation/offline-corpus/reproduce.py \
  --repo "$PWD" --raw "$PWD/ignored/offline-new" \
  --toolchain /absolute/toolchain --user-home /absolute/user-home \
  --cargo-home /absolute/cargo-home \
  --e9-stock-dir /absolute/pinned-stock-tree \
  --e9-transport /absolute/pinned-transport-e9tool \
  --e9-abi-dir /absolute/pinned-abi-tree
```

Both E9 directories contain `e9patch` and `e9loader.bin`; stock also contains `e9tool`. All six existing byte pins must match. Loader blobs remain data and need no executable bit. The wrapper never downloads, rebuilds or chmods these providers. The direct toolchain must contain non-symlink `bin/cargo` and `bin/rustc`, with the required dependencies already available offline. The fixed comparison currently declares the AMD EPYC Zen 5 host profile; this wrapper checks the observed `AMD EPYC 9D85 158-Core Processor` before supplying that label. It does not pretend to admit a different host under that name.

The four mandatory phases are release frontend build, release target-driver build, target capture, and the fixed 80-case comparison. Each phase begins FAILED when attempted; later phases remain UNRUN after failure. Compiler process success is separate from its complete Cargo artifact/profile admission. Two Cargo invocations select `liteinst-rewrite` and `elf-exec-oracle` with opt-level 3, debug 0, assertions and overflow checking enabled. Exact source/Git bytes and modes, selected tools, configuration observations, command environments, Cargo messages, successful helper receipts, direct parent waits and products form the fresh admission. `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` are absent from the constructed environments. A successful unchanged-source Cargo cache hit is allowed and recorded; this is not a claim that every dependency was rebuilt.

The old configuration observer is reused literally via its committed module. READ_DENIED remains a recorded continuity observation, not proof of readable/absent configuration or actual Cargo consumption. This wrapper records selected tools, not process maps or complete host/dynamic-loader configuration. Existing tracked common summaries remain exact Git-authenticated bytes in the input catalog. Their historical owner fields, failed production/archive/audit results, ordinary 160/0/32 result and outstanding 704 core-null/2,112 recording pairs are never refreshed or promoted.

Each release build uses the unchanged strict helper at 120 CPU seconds / 180 wall seconds / 128 MiB per file, outer 190 with kill-after 10, direct parent 205 plus failure wait 10. Target capture uses 20/30/16 MiB, outer 40+10, parent 55+10. The complete comparison receives an additional explicit 120/180/256 MiB enclosing bound with 190+10 and 205+10 parent closure. Its unchanged inner 99-command maximum keeps 60/90/128 MiB assembler/linker limits and 20/30/16 MiB remaining limits, with all original parent/cleanup checks. The enclosing bound can fail the run; it never skips a case, retries or turns a partial result into success. Four available CPUs are selected explicitly; Cargo jobs remain four. The 256-MiB free-filesystem check is not a hard aggregate output bound or a managed-slot quota proof. Root must separately admit current compilation/storage capacity.

The wrapper checks complete source/tool/configuration equality before and after both builds and after the comparison, and complete current product equality across all subsequent phases. `inputs.json` includes the required executable/data/source leaves and the complete saved source/build/target admission records; it does not make the inner comparer rehash the entire source tree before every tiny child. The caller's final whole-tree check remains mandatory. No historical runtime/cache/namespace lease is reused.

On success, `comparison/{summary.json,cases.json,cases.csv,commands.json}` contains the unchanged full 80-row output. The wrapper's `summary.json` reports its four actual phases and keeps the separate common obligations false. Existing byte witnesses and whole native-output comparisons provide finite authored-corpus evidence; no new full-state, recording, normal-loader-generalization or whole-A3 qualification is claimed. Timing retains the original end-to-end helper/exec/I/O scope.

Source review should check exact argv order against `compare.py`, both Cargo manifest/source-path joins, all six E9 pins, loader data mode handling, fresh product ownership, target request/receipt, seven unchanged historical descriptors, command-versus-phase status, and interruption/timeout closure. No new synthetic controls or native executions are included in this packet. All earlier comparisons, assertions and budgets remain unchanged.
