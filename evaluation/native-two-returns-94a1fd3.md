# Two-return native leaf at 94a1fd3

The four required workspace commands, native compilation, and all eight native commands passed on commit `94a1fd3ad15d88cae74390b341fc3bf890ab1f39`, on **AMD EPYC Zen 5 dev host**. This is partial evidence for claim 4. Full A2–A5 remain open; there is no performance, arbitrary-function, general unwind, admission, or preemption-clock claim.

The original 19-byte leaf and all four original modes remain covered. The additive 36-byte leaf selects its original RET at offset 27 or 35 from a zero/nonzero input. Both input orders run through original, installed, and retired phases. The required test log records 62 outer groups: 1,050 passed, zero failed, and four unchanged ignored tests. Its 98 model tests retain the old 89 and add nine branch parser tests; the 26 calibration and ten documentation cases remain. Five completed nested child summaries stay separate from those totals; two other guard starts receive no extra case credit. The required log retains documentation subjects and results, not full compiler diagnostic bodies.

| Native command | Private capture files | Helper elapsed seconds | Result |
| --- | ---: | ---: | --- |
| straight | 213 | 3.072868 | PASS |
| budget | 620 | 6.259429 | PASS |
| generation | 422 | 5.909187 | PASS |
| refusals | 13 | 0.198733 | PASS |
| two-returns-paths | 580 | 5.861051 | PASS |
| two-returns-budget | 580 | 4.756136 | PASS |
| two-returns-generation | 580 | 5.983646 | PASS |
| two-returns-refusals | 5 | 0.163609 | PASS |

The 3,013-file inventory contains 33 native children, 456 complete state comparisons against the original execution, and 72 real CALL witnesses. Twelve setup or permission refusals remain distinct from the positive executions: eight original refusals and four new missing, duplicate, non-RET, and foreign-RET refusals. Each child retains the whole 20,000-stop and 15-second bounds. The new generation cases serialize validated completed owner reports; intermediate controller reservation checks remain executed source assertions. Ptrace stop counts and operational elapsed times are not throughput or latency measurements.

[summary.json](results/native-two-returns-94a1fd3/summary.json) records the exact revision, source and artifact hashes, tools, hardware observation, every complete command/environment, request/receipt hashes, and review bindings. [commands.csv](results/native-two-returns-94a1fd3/commands.csv) has the 13 command rows. [native-cases.csv](results/native-two-returns-94a1fd3/native-cases.csv) has all 33 child phases and 12 typed refusal-result rows, with actual step/task/journal counts and metadata hashes. The complete captures, logs, maps, and binaries remain private. Earlier fixed-leaf failures remain in the [v6 report](frontend-native-v6-actual.md) and the [partial journal-row report](frontend-native-journal-row-actual.md).

Reproduce from a clean checkout of the exact tested commit using the committed [finite recipe](native-two-returns/README.md) and [reproduce.py](native-two-returns/reproduce.py). Bind `REPO` to that checkout, `RAW` to a fresh output directory inside its `ignored/`, and the tool/home roles to the documented prerequisites. Every public coordinate token is a complete path, with ordinary one-pass substitution inside decoded JSON strings; there is no special prefix substitution. The two DSO roles come from actual compiler producer records. Native environments are directly recorded. Required child environments are derived from the captured dispatcher environment plus the unchanged required runner's explicit overrides, including its output directory as `TMPDIR`; they are not a separate process-environment capture.

The native compiler retains 60 CPU seconds / 90 wall seconds / 128 MiB per file; native commands retain 20 / 30 / 16 MiB. Required command limits remain 180 / 180 / 360 / 180 seconds. Earlier private or failed results are not relabelled by this exact-revision run. The reporting author also authored the core two-exit addition. The closed native review binds all capture comparisons; the required/compiler review binds the four gates and selected compiler, producer, binary, and DSO joins. The latter reviewer authored the additive oracle adapter and discloses that role. Neither review claims a complete target or transitive tool archive.
