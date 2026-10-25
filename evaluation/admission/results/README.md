# Recorded admission validation

The [qualified run](20261025T182954.768833Z-da5022715fbe.json) tested exact revision
`da5022715fbe71cbb533a85e55b2b2a9581e9c40` with the committed
[protocol](../README.md). Its JSON records hardware, tool versions and hashes,
commands, source identities, per-harness counts and explicit native outcomes.

- All four required workspace checks passed; workspace tests: 797 passed,
  zero failed, four pre-existing ignored. Nested child summaries are separate.
- Recorder: 53 passed. Serial launch: 119 passed, zero failed or ignored.
- All 33 native CPU cases completed their original, scripted and native-provider
  comparisons. Capability-fault counts are zero in this run.
- Effective UID was non-root and effective capabilities were zero. All six
  commands left zero adopted descendants; source and configuration were unchanged.

This supplies the limited evidence for claims 1, 2 and 4 described in the
protocol. Claim 3 remains unevaluated. Durations measure validation overhead.

Four earlier protocol attempts and two diagnostic attempts retain their actual
refused/failed statuses. They exposed unavailable kernel metadata interfaces,
background Git telemetry and detached Git maintenance. The fixes preserve the
same assertions and cleanup requirements. The final protocol identifies system
Git and runs maintenance in the foreground.

[Development observations](development-20261025.json) preserve the earlier
parser and telemetry captures, including the parser failure. Their precommit
source fingerprints and missing metadata are explicit; they remain unqualified
and are excluded from claim evidence. Raw output remains in ignored storage.
