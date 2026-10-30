# Whole-program broad-span result

Both whole-program rewrites **FAILED** at revision
`f2aa72189583fc8914998884ee84e09d81ace942` on an AMD EPYC Zen 5 dev host.
The separately named `offline-whole-authored-broad-span-2g-v1` profile permits
a 2 GiB virtual span. The existing [16 MiB results](../whole-authored-window-f59b215/README.md)
remain unchanged. All other allocation, file, entry and correctness limits remain.

| Program | Heads | Selected jumps | B1 | B2 | T1 | T2 | Refused |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| checksum | 80 | 16 | 7 | 3 | 2 | 2 | 2 |
| RLE | 107 | 26 | 17 | 3 | 2 | 2 | 2 |

Each program received one material/importer attempt. Sites 7 and 12 refused
with `NoPatchWindow` in both programs. All 38 locally planned sites were
then discarded by the complete-selection rule: zero candidates and zero
candidate executions. The 16 MiB profile had seven refused sites per program
and 28 locally planned sites in total. These are structural planning counts,
not successful rewrites or throughput measurements. Every selected site is
retained in [sites.csv](sites.csv).

Saved diagnostics show unavailable generalized-pun allocation at both refused
sites. Site 12 also reached its unchanged one-candidate upstream allocation
budget; this is not a proof that no placement exists. The short-neighbor API
added in this revision is opt-in and is not called by this importer’s engine.
No new E9Patch production or comparison was run; the prior whole-program E9
records and failed comparisons remain unchanged.

All 13 release-build/capture phases exited zero. The overall build still exited
2: two configuration paths were unreadable (one read, thirteen absent, two
read-denied), so configuration and qualification remain incomplete. No
configuration exemption was added. All 22 profile controls passed. A first
outer invocation rejected relative capture/output paths before material or
importer work; the corrected canonical-path invocation performed the single
attempt per program. Both records are retained in [receipt.json](receipt.json).

The fresh originals have different file hashes from the 16 MiB run. Instruction
rosters, source objects and every program-header entry match. Across all LOAD
segments, only the ELF header’s section-table offset differs; all other loaded
bytes match. The receipt records both original hashes, exact source revision,
tool hashes, release options, commands, CPU reservations and load averages.
The product membership, nested bundle index, image hashes, source ledger,
complete entry sets and all report coordinates were authenticated before
summarizing. Raw captures remain under ignored/.

To reproduce, check out the recorded revision and follow
[the build recipe](../offline-corpus/WHOLE_DISASSEMBLY.md) and
[placement-profile invocation](../offline-corpus/WHOLE-PLACEMENT.md), selecting
`offline-whole-authored-broad-span-2g-v1` for both programs. Use new absolute
capture/output directories, reserve four disjoint CPUs, and retain every
outcome. Commands and resource limits are recorded in the receipt; `${REPO}`,
`${TOOLCHAIN}`, `${CARGO_CACHE}`, `${USER_HOME}` and `${PYTHON}` denote local
absolute paths, not literal arguments. Release settings are opt-level 3,
debug-info 0, with assertions and overflow checks enabled. No performance
claim is made.
