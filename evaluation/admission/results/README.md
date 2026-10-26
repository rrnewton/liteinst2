# Recorded admission validation

The [merged-core qualified run](20261025T203406.943806Z-67d0b6b140f7.json) tested
exact revision `67d0b6b140f7d47ebb3de8f02b15a655c65aa6dd`, a descendant of merged
main `27df290bd203a8235bb478a210fa700d3b8feaa3`. The only code/protocol changes
after that merge update the reviewed test corpus and exact child-summary parser
cohort. Admission/launch source and core contracts are unchanged.

- All four required workspace checks passed on Rust/Cargo 1.97.1; workspace:
  929 outer passes, zero failures, four existing ignores across 60 harnesses.
  Five successful nested child summaries are separate, as are two reviewed
  child starts whose parents authenticate their exit statuses.
- Recorder: 53 passed. Serial launch: 119 passed, zero failed or ignored.
- All 33 native CPU cases completed their original, scripted and native-provider
  comparisons, with zero capability-fault/signal counts.
- Hardware: AMD EPYC 9D85, family 26, model 17, stepping 0, microcode
  `0xb101066`; non-root, effective capabilities zero. Full ISA/tool identities,
  exact commands, source hashes and per-harness observations are in the JSON.
- All six commands exited zero, completed cleanup with zero adopted descendants,
  and retained unchanged source/configuration. The workspace run took 286.736
  seconds within the unchanged 360-second deadline; this is validation overhead.

The 132 additional outer instances come from core's eight synchronized tests,
17 generation tests, two compile-fail doctests and seven shared calibration
functions compiled into 15 harnesses. Repeated calibrations are not distinct
scenarios. Serial/native coverage and the limited claims 1, 2 and 4 are
unchanged. This workspace receipt does not qualify the standalone native
synchronized-publisher campaign; claim 3 remains unevaluated.

The [earlier qualified run](20261025T182954.768833Z-da5022715fbe.json) tested exact revision
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
