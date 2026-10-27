# Collect closed build and inventory records

`collect_build.py` projects three **separate** attempts: the successful original
8ff build, the failed c956 build, and one later closed build. Its seven public
JSON/CSV files report results; the collector does not create new build, native,
architectural-equivalence, accuracy or performance evidence. Full compiler
artifact and log-content validation remains in the named independent reviews.

```sh
"$PYTHON" -B "$REPO/evaluation/e9-common-app/collect_build.py" \
  --repo "$REPO" --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" \
  --new-output "$NEW_OUTPUT"
```

Use the committed collector at a clean tracked checkout. `NEW_OUTPUT` is a new
canonical directory under `REPO/ignored`. The collector revision and script hash
are recorded separately from every tested revision. Read-only Git operations
authenticate historical full source maps; the checkout need not equal any
tested revision. No repository module is imported. No compiler, helper, subject,
target file, archived executable or shared library is opened or executed.

The caller supplies a pinned JSON envelope with exactly `schema: 1`,
`authority: "CALLER_SELECTED_CLOSED_BUILD_RECORDS_AND_REVIEWS"`, `attempts`,
`roles`, `privacy_literals` and `files`. `files` maps canonical absolute saved
record paths to `{sha256, bytes}`. It must include every consumed record listed
below; each supplied file is read and checked again before output. A maximum
4,096 files, 64 MiB per file and 256 MiB total bounds this reporting operation.
These are collector input bounds, not changed build/test limits.

`attempts` has exactly three objects, in this order:

| id | revision | required history |
|---|---|---|
| historical-8ff | `8ff87a0a14c9348610c843063516c79190f6dede` | Completed 12-stage build; no transfer to newer source |
| failed-c956 | `c95662fed9cc139d556ad42c80d38d9b24189a6e` | fmt passed; Clippy 101; test/check and eleven later stages unrun |
| current | Caller supplies an actual closed revision | Outcome comes from its records, never from the old success |

Each object also supplies `raw`, `launch`, `review_binding`, `review_references`,
`review_revision_key` (`tested_revision`, `revision` or `source_revision`) and
`review_verdict`. The selected review must bind that exact revision, have no
unresolved findings, and carry the appropriate existing verdict:
`CLOSED_BUILD_AND_STATIC_INVENTORIES_PASS_EXECUTION_RECORD_SCOPE` or
`FAILED_BUILD_RETAINED_NO_LATER_STAGE_CREDIT`. Missing review/closure/required
records refuse before any output directory is created. A raw recipe exit or a
hash alone cannot stand in for independent review or caller parent closure.
`review_references` is the existing JSON path-to-record map named and hashed in
the review binding's `files`. Its entries may use repository-relative or
absolute paths; every supplied raw/launch record must join its exact SHA-256
and byte count there. This does not re-run the independent review or read the
other product/tool paths that its reference map describes.

For each attempt, include these explicit saved records:

- Top-level `summary.json`, `source.json`, `source-after.json`, `inputs.json`,
  `stage-inventory.json`, `results.json`, `tools.json`, `tools-after.json`,
  `configs.json`, `configs-after.json`, `config-scope.json`, `hardware.json`,
  `artifacts.json`, `cells.json`; its selected review binding/reference map; and launch
  `command.json`, `closed.json`, `stdout.txt`, `stderr.txt`.
- Every recorded stage's `command.json`, `result.json`, `stdout.txt` and
  `stderr.txt`. Every launched helper also requires `request.json`,
  `receipt.json`, `helper.stdout` and `helper.stderr`. Required gates use their
  existing dispatcher result and `required/gates/commands.json`, plus every
  actual gate log. No nonexistent UNRUN record is invented or required.
- For every producer-recorded completed inventory cell: its ten exact files,
  the stage's `inventory-files.json`, corresponding `policies/VARIANT.txt` and
  `policies/VARIANT-provenance.json`, and `target/stdout.txt`. This last file is
  a saved capability-observation text record, not a Cargo target artifact.

Partial inventory files may be included in the index and remain privately
bound, but cannot receive a completed-cell denominator without the recorded
cell and complete index joins. If helper cleanup/receipt evidence is missing or
malformed, collection holds rather than fabricating a clean failed receipt.
Such an attempt needs a separately reviewed reporting extension; the raw
failure stays unchanged. Every attempt always has twelve stage rows, four gate
rows and eight cell rows. Unrun cells have null counts. A zero-exit child followed
by a failed recipe check is `FAILED_POSTCHECK`; it does not become a passing
stage. A failure before a result remains `FAILED_BEFORE_RESULT` with no invented
exit or duration, while the original producer's unrun list is also retained.

`roles` maps explicit tokens such as `${REPO}`, `${TOOLCHAIN}`, `${USER_HOME}`,
`${CARGO_HOME}`, `${PREPARATION}`, `${RAW_OLD}`, `${RAW_FAILED}`, `${RAW_CURRENT}`
and their launch coordinates to their actual absolute string values. Prefer
specific roots before broad roots. Replacement is a single, longest-first
regular-expression pass over decoded string values and keys; every value must
round-trip exactly. Existing literal role syntax refuses. Normalized JSON does
not preserve original key order; original file hashes retain raw-byte identity.
`privacy_literals` lists the actual private usernames, FQDNs and any remaining
private coordinate spellings the caller requires excluded. The public output
also rejects home-directory prefixes. All raw logs and inverse role values
remain private. Do not copy the private binding into public results.

Output under `public/` is `summary.json`, `commands.json`, `stages.csv`,
`gates.csv`, `inventories.csv`, `artifacts.csv` and `files.json`. The last file
indexes the other six and does not hash itself. `private-binding.json` retains
the whole indexed input hash/owner map and exact coordinate inverse. Output
files are fresh; any interruption leaves an incomplete directory for the
caller to preserve, not reuse. Separate actual collector request/result/parent
closure and public-data review are still required before publication.

Hardware is copied from each saved observation with the exact label
`AMD EPYC Zen 5 dev host`; this script does not query current hardware. Required
child environments are reconstructed from saved parent environments and the
literal pinned dispatcher overrides, explicitly distinct from `/proc` capture.
Archive product hashes/counts come from the reviewed saved archive JSON. They
do not imply a fresh byte read, full target/tool closure, runtime admission or
native qualification. All 16 original observations, 74 producer stages,
192 ordinary candidate rows and later complete paired replay remain separate.

Role tokens are at most 64 characters, checked before constructing the
normalization regular expressions. Every encoded public file and the encoded
private binding must fit the same 64 MiB per-file bound; their aggregate must
fit 256 MiB. These output checks run before output-directory creation. They
change no build, test, result, case or admission predicate.
