# Common-corpus build and original observations

At tested revision `b0d94f009196b4dea433ea2a5b267fa94f9512b0`, all four required workspace gates and all twelve build/inventory stages completed. The test log contains 90 outer groups with 1,671 passes and four unchanged ignores; filtered child completions remain separate. The eight complete static inventories each retain all 87 instruction heads, selecting nine jump sites or one heap-write site. These results establish the recorded build and static inventory scope, not native equivalence.

The [build report](results/e9-common-builds-b0d94f0/summary.json) preserves three attempts separately:

| Tested revision | Recorded outcome |
|---|---|
| `8ff87a0a14c9348610c843063516c79190f6dede` | Earlier twelve-stage build completed. |
| `c95662fed9cc139d556ad42c80d38d9b24189a6e` | Formatting passed; Clippy exited 101 on three diagnostics. Test/check and eleven later stages remained unrun. |
| `b0d94f009196b4dea433ea2a5b267fa94f9512b0` | Later twelve-stage build completed; no credit is transferred to another revision. |

The [original-observation report](results/e9-common-originals-b0d94f0/summary.json) covers both stripping forms and all eight datasets: sixteen original application observations with the reviewed saved-content audit. Its [coverage table](results/e9-common-originals-b0d94f0/coverage.csv) retains every head for every case, including zero visits (1,392 rows). Saved ordered PCs, stores, array/journal outcomes and provider/map relationships are checked within that audit's scope. Full intermediate architectural states and the other explicitly listed live-only checks were not independently reconstructed from absent captures. This cohort supplies no rewritten/E9 application or paired architectural-equivalence result.

The separate [74-stage production campaign](results/e9-common-production-b0d94f0/summary.json) at the same b0 revision failed: 58 stages were attempted, with 42 passes, 16 failures and 16 unrun comparisons. All eight core invocations reported `UnsupportedRelocation { kind: 5 }`, retaining all 40 selected-site input-failure rows. Eight stock E9 adapters completed their structural inventories. Eight bootstrap adapters rejected an exact loader restore-order mismatch. All sixteen structural comparisons remained unrun; no generated candidate was executed in this campaign. Subsequent fixes do not change these recorded failures. The closed failed-record review is SHA-256 `e253769f16f35c0b805038c8bc268ce34f505b32bd733b805c41c53e50d29675`.

The host label is **AMD EPYC Zen 5 dev host**; exact saved model/kernel, source hashes, command environments and separate per-command durations are in the JSON/CSV results. Durations are operational diagnostics, not benchmarks. Raw logs, captures, binaries and private path inverses remain ignored. Each summary records the reporting script's later committed revision separately from the tested revisions. Reporting creates no new build, application, accuracy or full A3 qualification.

The committed [build collector](e9-common-app/COLLECT-BUILD.md) and [original-observation collector](e9-common-app/COLLECT-ORIGINALS.md) document the reporting commands and input contracts. Each result directory's `files.json` indexes its other six public files; private bindings are excluded.

The [production collector](e9-common-app/COLLECT-PRODUCTION.md) preserves all 74 stage rows, eight cells and actual command contexts in a separate result directory. Reporting success does not change the failed production result.
