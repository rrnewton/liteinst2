# Six Rust tool-version observations

The [result](../../results/frontend-tool-versions-20261025.json) records six successful `--version --verbose` queries: Cargo, rustc and rustdoc from Rust 1.97.1, then the same roles from Rust 1.85.0. The exact committed helper source was d6b56273c0d43b7d9311a5d57cb6dd0be6c51041. Each external tool is identified separately by its complete binary hash and version stdout. These are six tool observations, with zero compiler-build, model, documentation-test, native or future A5 qualification credit. No future source revision or artifact is filled from them.

`requests.json` contains the six exact JSON request templates in their recorded order. Only explicit local coordinates replace host-specific locations; private checking recovers every original request and parent record byte-for-byte. The whole-directory coordinates are deliberately distinct: `REPO` is the d6 source checkout, `RAW_VERSIONS` is the entire fresh ignored output directory, and `CURRENT_TOOLCHAIN`/`MSRV_TOOLCHAIN` are the two installed toolchain roots. This published reproduction directory is a fourth data location. Do not infer any of these directories from another file's parent, use a `bin` directory as a toolchain root, or treat a request directory as the complete output root. `PYTHON` and `TIMEOUT` name executables; `USER_HOME` supplies only the explicit HOME value.

Before reproducing, authenticate the helper at the recorded revision and all six selected binaries against the result's exact byte identities. Authenticate the explicitly selected Python and timeout bytes as well; their versions were not queried and remain null. Bind the actual local paths/resolved owners and current identities in a new admission. Use a fresh output directory under `REPO/ignored`, create the six ID directories, and materialize each template by consistent literal scalar substitution. Keep the exact request key set and environment, including the fixed `/usr/bin:/bin` PATH suffix; no inherited environment is added. The new requests receive their own hashes. The original hashes in the result remain historical evidence. No new executable generator or supervisor is provided.

Run only one request at a time through the existing helper, with the recorded outer command and an existing caller's 55-second parent deadline:

```sh
"${TIMEOUT}" --signal=TERM --kill-after=10s 40s \
  "${PYTHON}" -B "${REPO}/tools/unwind-oracle/bounded_command.py" \
  --request "${RAW_VERSIONS}/${ID}/request.json" \
  --receipt "${RAW_VERSIONS}/${ID}/receipt.json" \
  > "${RAW_VERSIONS}/${ID}/helper.stdout" \
  2> "${RAW_VERSIONS}/${ID}/helper.stderr"
```

Use the literal ordered IDs in `requests.json`; do not run the commands as compiler or test phases. Every request retains 20 CPU seconds, 30 wall seconds and a 1 MiB per-file cap; the existing wrapper retains TERM at 40 seconds, KILL-after 10 seconds and the caller's 55-second backstop. Preserve its actual argv, status, outputs and deadline. Each request must exit zero with unchanged inputs, no timeout/abort/cleanup error, no unexpected descendants and ECHILD. Retain the exact version stdout, empty stderr and helper summary. Original query elapsed times are operational diagnostics, not performance measurements.

The original raw records remain ignored; this document and the JSON templates are an unexecuted reproduction proposal. A successful new query is a new observation with its own source/tool/admission/receipt identities. It cannot retroactively fill a prior admission or replace the future A5 qualification. The descriptive hardware label comes from the owner; these six captures do not contain a separate hardware-discovery record. All four paper claims remain unqualified by this result.
