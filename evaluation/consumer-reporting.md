# Closed-record reporting commands

[The reporting result](results/consumer-reporting-steps-20261025.json) records
three actual commands: prepare the consumer export request, export its closed
qualification records, and export the four required workspace gates. These are
reporting operations, with zero native executions and no additional coverage.
All three ran the public source at `be782c88`; their private parameter files
remain separate inputs. Each retained the existing CPU20/wall30/file16MiB
helper limits, outer40/kill10/parent55 seconds, and clean ECHILD.

Use the exact historical source checkout as `REPO`, and a reporting checkout
containing these records separately. All new parameters, requests, receipts and
outputs must be beneath `REPO/ignored`, in fresh directories. Generate new raw
captures first using [the consumer adapter](../tools/unwind-oracle/README.md)
or [the required-gate runner](required-gates.py). Preserve the actual source,
tool and hardware observations for the new attempt. Historical hashes and
elapsed times cannot be reused as new observations.

For the consumer report, use the public `closed_export` phase in
`tools/unwind-oracle/aggregate-parameters.json`. Bind the actual closed runtime
manifest, qualification terminal and outer binding, schema, and reviewed
sanitized metadata. The metadata must distinguish build snapshots from later
committed runtime source and must preserve observed artifact reuse and failures.
Run `aggregate.py prepare` with those parameters and their actual digest. Review
the resulting request/binding, then run its exact aggregate launch with a finite
55-second parent timeout, retaining both helper streams and the outer exit:

```text
${TIMEOUT} --signal=TERM --kill-after=10s 40s ${PYTHON} -B \
  ${REPO}/tools/unwind-oracle/aggregate.py launch \
  --binding ${EXPORT_OUTER}/binding.json --binding-sha256 ${ACTUAL_BINDING_SHA256}
```

For preparation and the required-gate exporter, place the full child command in
the reviewed request and use the same finite 55-second parent timeout around:

```text
${TIMEOUT} --signal=TERM --kill-after=10s 40s ${PYTHON} -B \
  ${REPO}/tools/unwind-oracle/bounded_command.py \
  --request ${REQUEST} --receipt ${RECEIPT}
```

These invocations preserve the actual 40-second outer timeout and 10-second
kill-after. The aggregate launcher replaces itself with the same helper; it
adds no supervisor. Neither preparation nor export substitutes for the
independent source, artifact or native audits.

For required-workspace reporting, `evaluation/export-word.py` accepts a private
input inventory with `required` pointing to the completed `commands.json`,
`runtime: null`, `command_receipts: []`, the exact source map and reviewed
metadata. Its `raw_files` must bind all logs, context and review records used by
that metadata. Keep all four exact commands and the original 180/180/360/180
wall limits. The historical runner supplied no CPU/file caps or ECHILD proof;
do not add those claims to its result. Invoke:

```text
${PYTHON} -B ${REPO}/evaluation/export-word.py --inputs ${INPUTS} \
  --inputs-sha256 ${ACTUAL_INPUTS_SHA256} --output ${FRESH_OUTPUT}
```

The result JSON contains the complete historical request templates, including
explicit environments and limits. Materialize new requests as literal JSON
coordinate substitutions and bind their actual input digests. Run each through
the unchanged `tools/unwind-oracle/bounded_command.py` with the recorded finite
outer wrapper. Do not launch another supervisor, inherit additional environment
variables, retry into an existing directory, or change a failed result to pass.

Before and after each reporting command, authenticate its selected source,
inputs and tools. Inspect its actual helper receipt and both helper streams;
require exact request/helper/output hashes, exit zero, ECHILD, no unexpected
descendants, cleanup events/errors, abort or timeout, and unchanged inputs.
The final report must preserve its own successful or failed outcome. Review
all five exported files, screen public coordinates, and commit only the
sanitized summary, command/case CSVs and source/file maps. Keep raw captures
under ignored storage. Reporting elapsed times are operational diagnostics.
