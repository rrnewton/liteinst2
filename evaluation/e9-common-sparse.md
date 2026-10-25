# Reproducing the fixed common B1 cohort

This is an incremental source/data proposal, not yet a standalone public reproducer. The historical results and exact limits are recorded in `results/e9-common-sparse-20261025/`. All executed request fields are provided in `historical-requests.json`, with original byte hashes and placeholders for local paths. No future execution or validation credit is attached to these templates.

The existing bounded helper is `tools/word-sync-oracle/bounded_command.py` (SHA256 `c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44`). No new supervisor is proposed. After explicit source/tool/runtime rebinding and independent admission, each request is submitted to this helper with the recorded outer timeout. For ordinary 30-second phases the existing form is:

```sh
"${TIMEOUT}" --signal=TERM --kill-after=10s 40s \
  "${PYTHON}" -B "${REPO}/tools/word-sync-oracle/bounded_command.py" \
  --request "${RAW}/requests/PHASE.json" --receipt "${RAW}/receipts/PHASE.json"
```

This command is a phase template, not authorization to execute or a claim that all phases use those limits. The compiler and body-native phases retain their own 60 CPU / 90 wall budgets; each reference-tool call remains 20 CPU / 45 wall; each of the 40 loader invocations remains 10 CPU / 30 wall. Use each recorded request and corresponding outer supervisor geometry. The body trace limits remain 15 seconds and 20,000 steps.

The remaining portable adapter must: (1) materialize the exact six original files and corrected frontend/backend from their separately pinned provenance; (2) retain all validators and all failed/held lineage; (3) rebind the authenticated source-module ownership graph without cached-bytecode ambiguity; (4) capture a fresh, explicitly reviewed runtime/loader epoch rather than overwrite historical identities; (5) execute the six calibration groups, twelve tool calls, four-plus-36 loader matrix, state prerequisites and single corrected compiler, mapping controls, separate 144-trace oracle and final audit under their original limits; and (6) produce new result identities, never reuse this report as new-run credit.

The private proposal includes byte-exact frozen source and request copies and a per-phase contract for that adapter. GPL implementation code remains private; public acquisition/build instructions and provenance must be reviewed before a distributable reproducer is complete.
