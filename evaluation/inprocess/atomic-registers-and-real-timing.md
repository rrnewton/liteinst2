ADDS: canonical `LOCK CMPXCHG dword [base], r32` for all 16 source and
16 base registers, plus completed dynamically linked `true` using the
`-O2` controller bridge, with measured first-publication and later cache-hit costs. Only minimal REX and the mandatory RBP/R13 zero displacement or
RSP/R12 no-index SIB are admitted. The existing RIP-relative EDX form
remains separate. This is an original-address NX/TF capability; it does
not add source patches or clean-page admission.

Nine finite qualification/regression cohorts passed at
`18f8c106fe4167dce41b77956917f8e45c583b42`, after the main813 merge.
Each receipt reports unchanged source and zero finalization errors.
Expected memory faults and refusal controls remain failed operations,
accepted only because their exact failure predicates held.
The [nine-cohort projection](results/20261028-lock-register-native-18f8c106fe41.json)
retains the original receipt names and hashes. The separate
[footprint receipt](results/20261028T050446.805127Z-page-selected-write-footprint-18f8c106fe41.json)
also retains its complete per-instruction result, which that projector
does not include.

| Cohort | Actual qualification | Commands |
| --- | --- | --- |
| Fast memset integration | Five old cohorts: generic, TRACE, cache/capacity, 14 cache failures and REP; 47 native processes | 112 |
| All-source/base atomic matrix | 512 new full-state pairs, 32 paired memory faults, 1,088 footprint queries, 5,312 refusal checks, 16,384 typed acceptances | 90 |
| EDX/all-base predecessor | 152 new pairs and 24 paired memory faults | 74 |
| R13 predecessor | 36 new pairs and four paired memory faults | 28 |
| RIP predecessor | 48 new pairs and four paired memory faults | 27 |
| Write footprint | 30 actual instructions, eight supplied refusals and six API controls | 19 |
| Generic stepping | 20 new pairs plus startup and three verified failed operations | 22 |
| TRACE chaining | 12 programs/36 lanes and 11 verified failed operations | 47 |
| Inactive-rseq application with fast memset | Two completed applications and 15 required refusals; finite-profile pass | 75, including 52 finite |

The atomic matrix includes 256 matching and 256 mismatching comparisons,
with 256 page-ending and 256 page-crossing placements. Crossing cuts are
covered collectively, not at every cut of every encoding. Two former
R13 source-register refusal rows were explicitly promoted to typed
acceptance and actual matrix execution; other unrelated refusals remain.
This finite oracle does not establish concurrent atomicity or split-lock
behavior.

At final code revision `3e290637714b71d71941dbada7fba9083c0ec393`, the
[17-case inactive-rseq qualification](results/20261028T051429.914108Z-page-selected-rseq-application-fast-memset-3e290637714b.json)
passed again: two completed applications and 15 required refusals,
75 commands, unchanged source and zero finalization errors. Changes since
`18f8c106` affect validation inventory and the timing helper's local-symbol
check; the selected controller and native-oracle sources are unchanged.

The corrected [real timing run](results/20261028T051452.359565Z-page-selected-rseq-register-time-fast-memset-3e290637714b.json)
passed all six finite controls, then completed separate discovery and
measurement executions of dynamically linked `true`. Both registered
inactive rseq and matched the original native exit zero and empty output.
Discovery selected the lowest eligible interpreter ELF offset, 42828,
and froze it before building the measured bridge. The C bridge used
`-O2`; execution used one reserved AMD EPYC 9D85 CPU. All 89 commands
completed cleanup with unchanged source and zero finalization errors.

| Interval | First observation | Median of ten later hits | Later range |
| --- | ---: | ---: | ---: |
| Publication/cache API | 35.163 µs | 9.104 µs | 7.602–9.944 µs |
| Service through NX exit/reset | 174.001 µs | 155.418 µs | 146.190–161.142 µs |

All 22 raw `CLOCK_MONOTONIC_RAW` intervals are retained. Service begins
**after source fetch and planning**, immediately before publication, and
ends after the genuine NX exit/reset, before guard dispatch. The API
subinterval ends before arming execution. These are one site's observations
in one completed measured program, with no per-site native baseline;
they do not measure the full first fault. The measured whole command took
11.759 s controlled versus 3.593 ms native. The controlled duration includes
namespace preparation and is not an instrumentation-only cost.

Historical failures remain unchanged. The
[earlier real cohort](results/20261028T042920.950115Z-page-selected-rseq-real-fast-memset-631079726af7.json)
completed only default `true` (1/4), and the
[later historical cohort](results/20261028T044338.444403Z-page-selected-rseq-real-fast-memset-62466435d1c7.json)
completed both default and rseq-disabled `true` (2/4). Both cohorts remain
failed; reportless SIGKILL outcomes establish neither stopping instructions
nor kill causes, and no causal improvement or completion rate is inferred.
The [first timing attempt](results/20261028T050550.349439Z-page-selected-rseq-register-time-fast-memset-18f8c106fe41.json)
passed its six finite controls but rejected the hidden bridge's local
`memset` symbol before launching any real program. Its timing remains null.
The correction independently checks the local symbol against the exact
qualified 15-byte body and existing ELF/objdump checks; the global-symbol
contract for the extracted helper stays unchanged.

Required-check failures are retained. At `62466435`, source-inventory
preflight rejected the merge before any of the six commands ran.
At `aa4de069d97d68afbecbd930446b76cc835c3ab6`, all 345 recorder tests,
formatting and clippy passed, but the workspace command's zero exit did
not qualify its evidence: the catalog expected 15 rapid-profiler
doctests and the actual log contained 16. The exact parser returned
`changed_outer_cohort`; workspace-check and serial-launch did not run.
The missing older compile-fail doctest and the new main813 tests are
accounted for by a separately reviewed source-inventory successor;
neither failed receipt is amended.
[624 preflight failure](results/20261028T044048.981145Z-checks-62466435d1c7.json),
[aa4 evidence failure](results/20261028T045213.584104Z-checks-aa4de069d97d.json).

All six checks passed on `3e290637`: 350 recorder tests (38.27 s),
formatting (5.98 s), clippy with warnings denied (33.70 s), workspace tests
(379.20 s: 2,667 passed, zero failed, 11 ignored across 101 harnesses),
workspace all-feature/all-target check (21.53 s), and serial launch
(127.11 s: 1,039 passed across 27 harnesses). The separate strict core
precontext protocol and both backing-cleanup protocols also qualified.
Source and configuration remained unchanged; every command completed
cleanup. [Required-check receipt](results/20261028T051429.445805Z-checks-3e290637714b.json).

This supports finite instruction-coverage and tactic-validation evidence
for claims 2 and 4. It remains the intermediate original-address NX/TF
controller: source patches and clean-page admissions are zero. Full
B2/B3/B4 and a completed `ls` run remain open.
Reproduce each observation at its receipt's exact revision using its
`reproduce` argument vector and recorded environment, hardware and limits.
Native runners use one reserved CPU; required checks use four. The
existing `summarize_selected.py` can project the original receipts;
projection itself does not qualify execution. Complete numeric outcomes
and hashes remain in JSON, with raw process logs private.
