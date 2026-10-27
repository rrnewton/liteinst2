# Report the original application observations

`collect_originals.py` projects the closed sixteen original-observation records
and their independently reviewed saved-content audit into small public data.
It does not launch an application, observer, compiler, audit or validation
campaign. It is fixed to tested revision
`b0d94f009196b4dea433ea2a5b267fa94f9512b0`; its own committed reporter revision
is recorded separately when it runs.

The actual authority is the independent observation/content review
`81b04b30d6b530eaba2df582ff07edfb9e09d5b0c5e931ab43afb183d02cfa11`, joining
the complete saved-content report
`2e4fdeb48f8e9e387d535794a547d331ac7d94c48c0b85f4e8db4d21f096ef99` and its
binding `524a2fceb5fdf5df09be481b97a209513c64db5639363919e60a388280b51824`.
The collector authenticates the full 3,512-entry reference index, then reads
only the explicit reporting records described below. It does not claim to
repeat the prior whole-capture audit or read any archived executable product.

The seven public outputs are:

- `summary.json`: exact tested/preparation/build/reporter revisions, saved
  hardware, source/tool/observer/auditor/helper hashes, authority hashes,
  distinct scope statements and literal live-only qualifications.
- `cases.csv`: all sixteen variant/dataset rows, every audited counter,
  capture/stream/content hashes, zero-visit counts and fixed recorded budgets.
- `coverage.csv`: all 87 static heads for each case, including zero visits
  (1,392 rows). Neither selected sites nor observed PCs filter this table.
- `commands.json`: complete decoded requests, environments, outer commands,
  receipts and parent records under reversible private path roles.
- `commands.csv`: nineteen separate command rows with per-command operational
  times; no aggregate duration or performance inference.
- `source-files.json`: the complete 1,512-file tested Git byte/mode map.
- `files.json`: hashes and byte lengths of the six preceding outputs; it does
  not include a self-hash.

The command inventory is sixteen original observations, their enclosing recipe
launch, the saved-input assembly command and the saved-content audit command.
An inner request and its outer helper command are one row, not two observations.
Parent waits and helper `ECHILD` receipts retain their different scopes. The
assembly and audit are reporting operations, not additional application runs.

The caller supplies a JSON input envelope with exactly these keys:

```json
{
  "schema": 1,
  "authority": "CALLER_SELECTED_REVIEWED_ORIGINAL_OBSERVATION_RECORDS",
  "records": {
    "observations": "/absolute/private/observation-records",
    "recipe_launch": "/absolute/private/recipe-launch",
    "audit_output": "/absolute/private/audit-result",
    "audit_root": "/absolute/private/audit-command-records",
    "review": "/absolute/private/independent-review"
  },
  "roles": {
    "${REPO}": "/absolute/checkout",
    "${OBSERVATIONS}": "/absolute/private/observation-records",
    "${RECIPE_LAUNCH}": "/absolute/private/recipe-launch",
    "${AUDIT_RESULT}": "/absolute/private/audit-result",
    "${AUDIT_COMMANDS}": "/absolute/private/audit-command-records",
    "${REVIEW}": "/absolute/private/independent-review"
  },
  "privacy_literals": ["actual-private-user", "actual-private-hostname"],
  "files": {}
}
```

This is a schema illustration, not a usable admission. Supply each actual saved
file's absolute path, SHA-256 and integer byte length in `files`; include private
roles for other recorded command coordinates such as build products,
preparation, observation admission and audit input assembly. Roles are single
pass and longest-path first. Decoding each normalized string must recover its
original value exactly. Tokens are at most 64 characters, must not already
occur in recorded strings, and must not collapse distinct object keys. Supply
all actual private username and full/short hostname exclusion literals; the
collector neither queries DNS nor invents hardware observations.

Required saved records comprise:

- Observation root: `inputs.json`, `source.json`, `hardware.json`,
  `summary.json`, `stage-inventory.json` and `results.json`.
- Recipe launch: `command.json`, `closed.json`, `stdout.txt`, `stderr.txt`.
- Each of the sixteen case directories: `request.json`, `command.json`,
  `outer.json`, `receipt.json`, `result.json`, `stdout.txt`, `stderr.txt`,
  `helper.stdout`, `helper.stderr`, `capture-files.json`; and
  `captures/{coverage,observations,complete,budget}.tsv`.
- Audit output: `audit.json`, `binding.json`, `read-inputs.json`.
- Each audit-root `assembly` and `audit` directory: `request.json`,
  `command.json`, `parent-closed.json`, `receipt.json`, `stdout.txt`,
  `stderr.txt`, `helper.stdout`, `helper.stderr`.
- Independent review: `binding.json`, `references.json`.

These are 255 saved reporting files. The raw capture bodies and logs remain
private; only their hashes, small decoded counter/coverage tables and exact
normalized command objects are published. A missing case or record, changed
hash, incomplete or failed audit, unresolved review, changed source map,
privacy leak or inability to invert a role substitution refuses reporting.
The script does not retry or manufacture a partial-success report. Earlier
failed attempts remain separate and do not gain credit from this cohort.

From a clean checkout containing the committed reporter:

```sh
python3 -B evaluation/e9-common-app/collect_originals.py \
  --repo "$REPO" --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" \
  --new-output "$NEW_IGNORED_OUTPUT"
```

The output directory must be new and below the checkout's `ignored` directory.
Reads are caller-pinned regular files with no followed final symlink, bounded
to 64 MiB each and 128 MiB in aggregate. Public/private encoded outputs must be
at most 64 MiB each and 256 MiB total before directory creation. All reporting
inputs and the reporter are rechecked for byte/owner drift before writes.
The private binding keeps the input/owner map, roles, exact and normalized
command contexts, reporter identity and output hashes. The caller separately
records and reviews the actual collector invocation and parent closure; the
collector cannot manufacture that authority for itself.

Successful original observation and saved-content auditing establish the
bounded ordered-PC, store, array and ownership relationships recorded by this
fixture. The public summary preserves the audit's exact distinctions: full RX
memory and instruction-byte reads, actual breakpoint restoration, intermediate
full registers/RSP/return words, call-argument registers, and live single-task
and proc/FD checks were asserted live where stated, not independently rebuilt
from nonexistent saved state. These results do not establish architectural
equivalence, manual replay, rewritten or E9 execution, full loader/configuration
closure, performance, or full A3 qualification.
