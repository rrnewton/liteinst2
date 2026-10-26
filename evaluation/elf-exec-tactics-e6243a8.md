# Four additional tactics through normal kernel execution

Exact tested source: `e6243a862fda2572304cccbcfe698ac9ea6212a6`.
Hardware: **AMD EPYC Zen 5 dev host**, Rust 1.97.1. The saved hardware,
tool versions, commands and individual operational durations are in the
[result record](results/elf-exec-tactics-e6243a8-20261026/summary.json) and
[command record](results/elf-exec-tactics-e6243a8-20261026/commands.json).
The later publication commit contains evidence; it is not the tested source.

The frontend prepared and the kernel loaded all 16 candidates: B2 generalized
punning, T1 prefix padding, T2 successor eviction and T3 neighbor eviction,
each with stripped/unstripped inputs and null/journal hooks. Every declared
original instruction entry ran under two architectural seeds. T3 exercised
both branch outcomes; T2 and T3 exercised the displaced victim's entries.

| Tactic | Original traces | Rewritten traces | Full-state comparisons | Capture files | Required refusals |
| --- | ---: | ---: | ---: | ---: | ---: |
| B2 | 12 | 24 | 120 | 1,967 | 4 |
| T1 | 12 | 24 | 120 | 1,967 | 4 |
| T2 | 24 | 48 | 248 | 3,983 | 5 |
| T3 | 20 | 40 | 188 | 3,215 | 5 |
| Total | 68 | 136 | 676 | 11,132 | 18 |

All 93 recipe stages passed, including 24 ordinary process executions. Native
checks include 204 application CALL/RET witnesses, 32 hook CALL/RET witnesses
and 16 journal rows. Comparisons cover registers, flags under the existing
debugger-bit convention, architectural XSAVE components, application data and
stack. The original 20,000-step/15-second whole-child bounds remain unchanged.
No manual LOAD mapping or post-seed state repair was used. Exact candidate
growth, image sizes and source edits are recorded per artifact in
[CSV](results/elf-exec-tactics-e6243a8-20261026/artifacts.csv) and
[JSON](results/elf-exec-tactics-e6243a8-20261026/artifacts.json).

The independent saved-capture audit passed all 11,132 expected files, 1,014
state snapshots, 676 cross-run full-state comparisons, 134 original ISA-effect
checks and 64 gateway transfers. It authenticated the loaded file/page owners,
complete target XSAVE component coverage and all 93 strict helper receipts.
The first audit invocation failed because it compared the compact target
description with the full runtime target record. The corrected audit parses
the full record and checks its exact compact projection, retaining every old
assertion and adding two ownership/projection checks. Both invocations remain
in the [postprocessing record](results/elf-exec-tactics-e6243a8-20261026/postprocessing.json).

The unchanged B1 prerequisite passed separately at the same source revision:
27 stages, 24 traces, 72 full-state comparisons, 1,230 captures and six ordinary
executions. Its counts are not added to the four-family denominator. The four
required workspace commands passed: formatting, Clippy with warnings denied,
workspace tests, and all-feature/all-target checking. The complete test log
contains 70 outer groups with 1,175 passes, zero failures and four unchanged
ignores. Five completed nested filtered invocations are separate from those
totals; two additional guard-child starts receive no extra pass credit.

Use the [recipe](elf-exec/tactics.md) at the tested revision to reproduce the
native campaigns, beginning with its B1 prerequisite. The
[saved-capture audit](reproductions/elf-exec-tactics-e6243a8/README.md) and
result collector are published separately with their exact executed source
hashes. Raw logs, ELF files, memory captures and private host coordinates stay
under ignored storage. The public CSV/JSON files summarize those observations.
Durations are operational diagnostics; this campaign makes no performance claim.

The [development history](elf-exec-tactics-development.md) retains three
failed attempts and the separate intermediate B1 success. Successful later
runs do not revise those outcomes.

This is partial evidence for **claim 4, systematic tactic validation**, on four
finite ET_EXEC fixtures. Claims 1–3, arbitrary applications, PIE/DSO loading,
unwind and early-loader behavior, the common E9 corpus, cross-vendor and CET
execution, and full A3 qualification remain open. Artifact qualification stays
false. Earlier static-emitter parity results are unchanged and are not credited
as new executions here.
