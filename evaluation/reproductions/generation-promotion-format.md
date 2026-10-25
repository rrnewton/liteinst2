# Reproduce the promotion formatter input

This is a separate formatter-only private snapshot. It is not an eighth command
in the historical seven-command standalone suite, nor a model/compiler result
for the subsequently committed public module. Its `tested_revision` remains null.

The recipe JSON pins five files obtainable from
`ed67f7528184bf9ba33c05946ed8b07bef1bf41d`: `lib.rs`, `generation.rs`,
`generation/tests.rs`, `interval.rs`, and `pmu.rs` under
`tools/rapid-profiler/src`. The request-only script copies them into a fresh
private snapshot and removes exactly the optional comma after the documented
`FunctionId` field `pub u64`. Every reconstructed pre-format hash must match the
historical input; the other four files remain byte-identical.

After source review, prepare without running any formatter:

```sh
${PYTHON} -B ${REPORT}/evaluation/prepare-generation-promotion-format.py \
  --repo ${REPO} --raw ${REPO}/ignored/${FRESH_FORMAT_RUN} \
  --rustfmt ${TOOLCHAIN}/bin/rustfmt --user-home ${USER_HOME}
```

Review the actual request and admission, including current interpreter/watchdog
identities, before execution. Use the unchanged public helper:

```sh
${HELPER_PYTHON} -B ${REPO}/tools/word-sync-oracle/bounded_command.py \
  --request ${REPO}/ignored/${FRESH_FORMAT_RUN}/request.json \
  --receipt ${REPO}/ignored/${FRESH_FORMAT_RUN}/receipt.json
```

The exact formatter argv is `rustfmt --edition 2024 ${SNAPSHOT}/src/lib.rs`.
Limits remain 20 CPU seconds, 30 wall seconds, and 16 MiB per output file.
The historical request used the explicit HOME/PATH/LC_ALL/bytecode environment
in the JSON recipe. It did not record the Python or timeout executable identity;
do not reconstruct those historical identities from a new observation.

Require a successful unchanged-helper receipt with exact request/output hashes,
empty stdout/stderr, no timeout/abort/cleanup error or unexpected descendants,
empty cleanup events, and ECHILD. Verify all five final hashes and that the sole
source change is the optional comma restored after `pub u64`. The initial
historical review matcher omitted `pub` and failed its own assertion; the actual
formatter succeeded. The failed review note and subsequent exact reversal proof
remain distinct in the result JSON.

A reproduction has its own source/configuration/tool/admission/capture records.
It must not overwrite the historical receipt or reuse its elapsed time. This
script adds no supervisor and has not been executed as part of this source
proposal. All four paper claims and full A5 remain unqualified.
