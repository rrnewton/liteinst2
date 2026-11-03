All three attempts **FAILED**: zero LI2 candidates, 18 original/E9 native PASS and nine LI2 UNOBSERVED.

| Program | Prior | Local/withheld | Delta | Refused |
|---|---:|---:|---:|---:|
| cat | 919 | 969 | +50 | 39 |
| head | 1128 | 1166 | +38 | 48 |
| wc | 1508 | 1555 | +47 | 90 |

Local acceptance rose by 135; no LI2 executable. E9 strict coverage: 3,610/3,867 (257 misses). Validation PASS: workspace 4,739 raw, serial 1,039, focused 191.

Evidence: [receipt.json](receipt.json); all 27 cases: [cases.csv](cases.csv). Use clean pinned source, fresh namespaces and reserved CPUs (12 validation; one corpus). Normalized paths.

Tables have columns. `reference` selects pinned `history` plus JSON `pointer`; `receipt_pointer`/`*_reference` select this receipt (arrays select values). Resolve references first; apply `keys`/`omit`. Commands take `slice_from`, apply `set_value_after` to each flag's next argument, substitute `${NAME}`, then concatenate prefix/suffix. CSV inherits `cases_csv.status_fields` and aliases; blank seconds are unrecorded.

Prior FAILED/unknowns remain pinned; freestanding 15/138 belongs to `26cc9b7f`. Complete-code/ownership, scratch and zero-bias premises remain. No complete-CFG, exemption, broad native or performance qualification.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
