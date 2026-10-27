# Reporting the failed common-corpus production attempt

`collect_production.py` turns a closed, independently reviewed failed production
attempt into seven public JSON/CSV files. It reads saved reporting records and
historical Git source bytes. It does not run the producer, inspect target, open
candidate binaries, or reinterpret a failure as a successful campaign.

The first input is the attempt at source
`b0d94f009196b4dea433ea2a5b267fa94f9512b0`. All 74 stage rows remain present:
42 `PASS`, 16 `FAILED`, and 16 `UNRUN`. All eight cells remain present. The eight
core commands failed with `UnsupportedRelocation { kind: 5 }`; their complete
40 selected-site input-failure rows are retained. All eight bootstrap adapter
commands failed their whole-loader-byte assertion. Their unavailable structural
inventories stay null. The eight stock adapter inventories contain all 40
selected sites, but the missing core reports prevent all 16 comparisons.
The emitted E9 artifacts and stock structural records receive no application,
architectural-state, native, performance, or full-A3 credit.

## Invocation and authority

Commit this script at its public path before invoking it from a clean tracked
checkout. The report identifies that actual reporting revision and script hash
separately from the historical tested revision and producer hash. `${REPO}`,
`${RAW}`, `${LAUNCH}`, `${REVIEW}`, `${INPUTS}`, and `${OUTPUT}` below are caller
coordinates, not literal paths or environment variables consumed by the script.

```text
/usr/bin/python3.9 -B ${REPO}/evaluation/e9-common-app/collect_production.py \
  --repo ${REPO} --inputs ${INPUTS} --inputs-sha256 INPUTS_SHA256 \
  --new-output ${OUTPUT}
```

`${OUTPUT}` must be a new directory below the checkout's ignored directory with
an existing canonical parent. The input envelope is private JSON:

```json
{
  "schema": 1,
  "authority": "CALLER_SELECTED_CLOSED_FAILED_PRODUCTION_RECORDS",
  "raw": "ABSOLUTE_SAVED_PRODUCTION_DIRECTORY",
  "launch": "ABSOLUTE_SAVED_LAUNCH_DIRECTORY",
  "review_binding": "ABSOLUTE_REVIEW_DIRECTORY/binding.json",
  "review_sha256": "EXACT_REVIEW_BINDING_SHA256",
  "roles": {
    "${REPO}": "ABSOLUTE_CHECKOUT",
    "${RAW}": "ABSOLUTE_SAVED_PRODUCTION_DIRECTORY",
    "${LAUNCH}": "ABSOLUTE_SAVED_LAUNCH_DIRECTORY"
  },
  "privacy_literals": ["ACTUAL_USER_NAME", "ACTUAL_HOST_FQDN", "ACTUAL_SHORT_HOST_NAME"]
}
```

Use real private coordinates and identities in the envelope, and pass its whole
SHA-256 on the command line. Add explicit role substitutions if an actual
command contains another private path. Substitution is longest-match,
single-pass and exactly reversible for strings and dictionary keys. Literal
role collisions and key collisions refuse reporting. The output privacy check
also rejects home-path prefixes and every caller-supplied private identity.
The envelope and the role inverse stay ignored.

The supplied review must have verdict
`CLOSED_FAILED_PRODUCTION_RECORDS_VERIFIED`, no record-integrity findings, and
the existing complete `references.json` hash map. This is a caller-selected
authority, not approval manufactured by the collector. For the first report:

| Input | SHA-256 |
| --- | --- |
| Review SHA-256 | `e253769f16f35c0b805038c8bc268ce34f505b32bd733b805c41c53e50d29675` |
| Historical producer SHA-256 | `62642769cf14c5a8baccd887942403d5e5b313b1060d823b5bc240d7261fd59c` |
| Historical raw-index SHA-256 | `ee38a98dc56238707a621339afb0a29158c6b5fb775085f09a58cc83ac1261b5` |

The caller supplies the private record coordinates separately. The collector
authenticates every reporting record it reads against that review. It also
joins all 774 indexed raw-file
facts to the review's saved hashes, sizes and historical stat tuples, without
opening those products. The full 1,512-file historical source map is projected
under the prior review authority; the producer blob is additionally read from
the exact historical Git revision. Current reporting-source identity is checked
separately. No historical inode continuity or complete new tool/configuration
closure is implied.

## Output contract

Only `${OUTPUT}/public/` is intended for publication:

| File | Complete contents for the first report |
| --- | --- |
| `summary.json` | Tested and reporting revisions, recipe/collector hashes, six hardware fields, failed campaign summary, 42/16/16 counts, separate parent wait, review/raw-index identities, scope limits |
| `stages.csv` | All 74 final rows in planned order, including each reason, command/final status distinction, actual exit, receipt hash, fixed limits and separate operational durations; absent values are empty |
| `cells.json` | Eight cells, full core failure-site rows, full available stock site rows and decoded reasons, separate lane outcomes, candidate hash/size/growth facts; unavailable inventories are null |
| `cells.csv` | Eight cell rows with style/hook/strip form, selected denominator, final lane status/failure phase and actual artifact/admitted-site counts |
| `commands.json` | One recipe context and 74 ordered stage slots, including the 58 actual whole inner/outer command contexts, receipts, waits, command results, postchecks and final results; 16 unrun contexts remain null |
| `source-files.json` | The complete reviewed historical relative source hash/size/mode map, attributed to the tested revision |
| `files.json` | Exact SHA-256 and byte length of the other six public files |

There are **59 actual command contexts**, consisting of 58 bounded helper
commands and one recipe launch. The 75 context slots include the 16 unrun
stages; they are not 75 executions. `outer.json` records its historical
`postchecks pending` status, so the collector retains that record alongside the
command result, postcheck and final result rather than treating its placeholder
status as the final stage outcome. Required nonzero process exits remain
failures here, not successful refusal controls.

Every executed stage has the original 13-key strict receipt, empty cleanup
events, `ECHILD`, no timeout and unchanged inputs. The two hook build commands
retain 60 CPU seconds / 90 wall seconds / 128 MiB per-file bounds with the
100-second outer and 115-second parent backstops. The other executed stages
retain 20 / 30 / 16 MiB, 40-second outer and 55-second parent backstops. Every
outer timeout retains the ten-second kill-after setting. Actual helper elapsed
time and enclosing operational duration are separate; none is a benchmark and
they are not summed into a performance claim.

`${OUTPUT}/private-binding.json` retains the actual command-context inverse,
role map, reporting input hashes/current read owners, reporting source owner
and public output hashes. Raw logs, complete owner records, binaries and
capture bodies remain in their existing ignored locations. The collector does
not fabricate its own enclosing-parent closure: that field stays null until
the caller records the actual invocation separately.

The script rejects optimized Python before parsing arguments. Reads are
restricted to the selected saved reporting roots, regular files without
symlinks, 64 MiB per file, at most 1,024 reporting records and 128 MiB total.
It prepares at most 256 MiB of encoded output before exclusively creating the
new output. Input bytes/owners and the clean reporting revision are checked
again before output writes, and the reporting revision is checked after them.
A read, encoding, privacy or assertion failure is a
reporter failure; existing production records are never edited. Actual reporter
execution and the resulting public data still require the caller's recorded
outcome and independent data review.
