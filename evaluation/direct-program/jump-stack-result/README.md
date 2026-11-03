# Jump and register-stack corpus

**All three attempts FAILED.** All **27 planned native rows** remain: 18 PASS, 9 UNOBSERVED. Native samples and structural N/N are separate.

| Program | Selected | LI2 structural outcome | E9 structural outcome |
| --- | ---: | --- | --- |
| cat | 1008 | FAILED: 91 core refusals; 917 otherwise-planned sites withheld atomically; 0 emitted | FAILED: 936/1008; 72 misses |
| head | 1214 | FAILED: 125 core refusals; 1089 otherwise-planned sites withheld atomically; 0 emitted | FAILED: 1130/1214; 84 misses |
| wc | 1645 | FAILED_UNVERIFIED: SIGXFSZ (-25); emission, planning and refusal quantities unrecorded; no authenticated LI2 COMPLETE/report | FAILED: 1544/1645; 101 misses |

Neither backend established full structural coverage in any attempt.

[CSV](results.csv) retains every case; `EXPECTED` means its fixture's expected-vector SHA, `EMPTY` the empty SHA, and blanks null or unrecorded. [Receipt](receipt.json) retains authorities, class counts, commands, limits, capacity and history.

Decode the receipt after removing `packing`: `['@r:NAME',...values]` maps to `packing.columns[NAME]`; `['@s:NAME']` is `packing.shared[NAME]`; `['@b:/pointer']` is that JSON Pointer in the pinned [baseline](../corpus-result/summary.json). `['@e:NAME',rows]` expands each row's first five integer cells through `packing.enums[NAME]`, preserving its final count. Other values are literal; absent and null remain distinct. Sorted-key compact ASCII JSON plus LF must match `packing.expanded` bytes/SHA.

Reproduce clean `6c9e3922293dcb848cd2ab5e103ecedcbf65d23f` via [profile](../jump-stack-profile.md) and [corpus protocol](../CORPUS.md). The receipt's actual commands use literal template substitution and explicitly normalized path prefixes. Reserve one CPU; use fresh work/log names. No automatic replay or fallback.

Hardware: **AMD EPYC Zen 5 dev host**. Selection retains declared j*, exact Push_r64/Pop_r64, RSP, prefixes and unreachable rows. Caller ownership/complete-code, helper-stack and zero-bias loader obligations remain unresolved. [Correctness controls](../jump-stack-validation/README.md) are finite; no full-program, complete-CFG, runtime-exemption or performance qualification follows. [Prior failures](../corpus-result/README.md), including cat/Clippy and 1,035 historical misses, remain unchanged.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
