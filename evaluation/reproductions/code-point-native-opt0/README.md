This saved projection covers three closed byte-point native attempts. The collector completed successfully and its outputs received an independent saved-record review. Results are in `../../data/code-point-native-opt0/`; source exports are in this directory’s `historical/` subdirectory. Each attempt retains all 13 ordered cases, including FAILED and UNRUN rows. Repeated attempts are separate cohorts, not a sum of unique tests.

The fixed opt0 cohorts are dd94a43 (0 PASS / 1 FAILED / 12 UNRUN), 5403fdf (0 / 1 / 12), and 4fe20da (8 / 1 / 4). Their Cargo profiles all record opt_level=0, debuginfo=0, debug assertions enabled and overflow checks enabled. The first two failures were fixture expectations about the allocator's shared executable mapping and the terminal record's invocation value. The third exhausted the unchanged 20,000-step oracle bound during old-reservation-seed-0. None is relabelled as success. No optimized-profile result belongs to these cohorts.

The completed third-cohort cases account for 64 closed child records and 120 live full-state comparisons. The latter are source-attested checks executed by the native fixture; the saved records do not contain every full state for independent architectural re-execution. Failed prefixes are separate: one original child in v1; an original and Armed candidate with three live comparisons in v2; and one original child in the failed v3 case. These partial observations do not complete the failed cases. The four word/coalesced modes remain UNIMPLEMENTED. Whole-A4 and qualification flags remain false.

To repeat the saved projection, supply the reviewed private input catalog and its exact SHA, then use a fresh ignored output directory:

```sh
python3.9 -B evaluation/reproductions/code-point-native-opt0/collect.py \
  --inputs "$PRIVATE_INPUTS" --inputs-sha256 "$INPUTS_SHA256" \
  --new-output "$PWD/ignored/point-native-report-repeat"
```

This command requires the original ignored saved metadata and source records. It never opens target products, runtime providers, or native capture bodies, and never runs a native case. Its public JSON/CSV files include 39 exact case rows, 34 normalized command contexts, saved source/tool/product/hardware identities, and the input record hashes. Durations are operational observations, not performance measurements. Raw stdout/stderr, lifecycle text, native child records, and private owner/path inverses remain ignored.

The historical source exports preserve the exact three runtime callers, build drivers, constructors and parents, with reversible path roles where necessary. They explain the original executions. Their constructors require private historical authority and are not a clean-checkout reproduction recipe. Parent templates are not activated scripts. The private roles/inverse file proves every normalization; a new machine must establish its own source, tools, product, runtime, capacity and parent records.

A separate prospective clean-checkout recipe is supplied in [`fresh/`](fresh/README.md), from source packet c74173480a07d214f3b9f344f29d2d38aa3efba09d4ca2fae2b681902f769476. Its fresh/build.py, fresh/prepare.py, fresh/run.py and fresh/launch.py create a new cohort without private historical failure catalogs. That recipe received source review and remains UNRUN. At exact 4fe20da its opt0 profile deliberately preserves the known failing workload and all 13 cases; it is not an expected-success demonstration. Any opt2 recipe/result requires a separately reviewed source/profile and output cohort.

All public payloads undergo whole-byte privacy checks, including hexadecimal forms of private path literals. The hardware label is the saved AMD EPYC Zen 5 dev host observation from each actual native attempt. No current provider owner or complete loader/process-map closure is claimed.
