This saved-result projector covers the closed opt2 native cohort at exact revision `16212e9ab00a18ce003a305f7265bce8633e1c0e`. The native run passed all 13 cases, closed 75 children and reported 130 source-attested live comparisons. The projector completed successfully in a separate recorded run. Results are in `../../data/code-point-native-opt2-16212e9/`; historical source exports are in this directory’s `historical/` subdirectory.

The build used optimization level 2, disabled debug information, enabled debug assertions and enabled overflow checks. It retained all 13 cases, the 20,000-step and 15-second trace bounds, and the original state, image, event and refusal checks. This is a distinct cohort from the three earlier opt0 attempts. Their outcomes remain 0 PASS / 1 FAILED / 12 UNRUN at dd94a43, 0 / 1 / 12 at 5403fdf, and 8 / 1 / 4 at 4fe20da. The new summary preserves those failures and their partial prefixes, with exact pins to the earlier public summary and its saved-output review. It does not transfer results between profiles or aggregate repeated attempts as unique tests.

The saved records establish 75 closed child records and 13 strict helper closures. The 130 full-state comparisons, retained old-report checks and refusal predicates were executed by the native fixture and are source-attested. The saved output does not contain every complete machine state for an independent architectural reconstruction. Four word/coalesced modes remain UNIMPLEMENTED. Whole-A4 and qualification flags remain false. Elapsed times are operational observations, not performance measurements.

To repeat the saved projection, supply the reviewed private input catalog and its exact SHA, then use a fresh ignored output directory:

```sh
python3.9 -B evaluation/reproductions/code-point-native-opt2-16212e9/collect.py \
  --inputs "$PRIVATE_INPUTS" --inputs-sha256 "$INPUTS_SHA256" \
  --new-output "$PWD/ignored/point-opt2-report-repeat"
```

This command requires the original ignored saved metadata and source records. It does not run a native case or open target products, runtime providers or native capture bodies. Its 11 public files contain all 13 ordered case rows, 30 normalized command contexts, five historical source exports, the saved hardware/tool/source/product identities, and the complete selected input hash map. Raw stdout/stderr, lifecycle text, native child records and private path inverses remain ignored. Every normalized command and source export has a complete private inverse; the public text undergoes whole-byte privacy checks, including hexadecimal forms of private literals.

The historical source exports preserve the exact executed runtime caller, build driver, constructor and parent scripts. Private path substitutions are reversible, and parent files remain templates. These exports explain the original run; the historical constructor depends on its original private evidence and is not the clean-checkout recipe.

For an independent repetition, use the separate `fresh/README.md` and its eight files. That prospective recipe is **UNRUN**. It builds and admits a new product and selected runtime owners at the exact source revision without any private prior-failure catalog. A fresh run starts its own cohort, preserves failures and UNRUN tails, and must satisfy all original case and resource bounds. The historical hardware label is the saved `AMD EPYC Zen 5 dev host` observation; the fresh recipe observes its own host and uses a neutral label. Neither path claims complete loader or process-map closure.
