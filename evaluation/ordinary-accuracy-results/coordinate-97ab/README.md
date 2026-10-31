# Coordinate campaign at 97ab: preparation failed

The campaign **FAILED before geometry review or native dispatch** at the receipt’s exact 97ab revision. The first short-preparation stage ran all 16 coordinate controls: **15 PASS, 1 ERROR, no skips**. The catalog control raised `OSError: [Errno 27] File too large` while writing synthetic `joined.json` under the unchanged **1,048,576-byte file limit**, before its catalog assertions. No total attempted serialization size was measured.

No preparation stage completed. Long preparation and both native actions remained **UNRUN, zero attempts**; geometry was UNSTARTED. No retry occurred. Child `retention_verified=false`, `source_unchanged=false` and absent after-source snapshot remain unchanged by outer `source_unchanged=true`.

| Closed action | Result | Outer seconds |
|---|---|---:|
| products | PASS | 117.6498274130281 |
| tests (compile only) | PASS | 78.21809291816317 |
| controls | 130 Rust / 104 Python PASS | 69.09971579606645 |
| short-prepare | FAILED | 64.96033078688197 |

Times are setup durations, not throughput. All four owners closed normally with complete cleanup and zero rescues. The retained three-CPU lease used controller 160, worker 163 and producer 174 on an **AMD EPYC Zen 5 dev host**. Root captured parent exit 0 and absent original processes/scope/ledger tag: lease closure only, not campaign success.

The two prescribed trial-100 cells and planned 2,048-input populations remain in `rows.csv`; zero observed counts mean no native dispatch. The 133,120-byte long input was not exercised natively. The full denominator remains **43,200**, with no native coverage added. Phase, hardware, accuracy and performance qualifications remain unresolved. The strict-clock one PASS/four FAIL, [phase-071](../phase-071/README.md), [prepared-27e](../prepared-27e/README.md) and [native-1c37](../native-1c37/README.md) outcomes are unchanged.

`receipt.json` contains seven exact planned argv templates, four actual owner/result hashes, loads, tool/source/product identities and original limits. Use its revision and the [existing retained-shell/owner recipe](../prepared-27e/README.md#reproduction-with-the-existing-owners), with fresh paths/dependency SHAs and these explicit overrides: success statuses `COORDINATE_PREPARATION_PASS` / `COORDINATE_FUNCTIONAL_STRUCTURAL_PASS`; geometry kind `selected-accuracy-coordinate-functional-geometry-acceptance-v1`, scope `selected-accuracy-coordinate-functional-v1`; each CSV row's original end/fence, replacing 5.2/7.2 s. Retain one nonrenewable 1,200-second geometry window. A safely closed short-functional failure permits only the one planned long attempt after all custody/source/retention joins; unknown closure stops it. A preparation failure stops all dependent actions, as happened here. No dispatcher or geometry approval generator is supplied.

The workspace/SDK prerequisite ran at `1bd48b13ce92f3c6b4fd14b448a2e9649bcfa473`; compiled/runtime source equality supplies applicability to 97ab, not another execution. Raw logs remain private.
