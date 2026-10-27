# Controlled entry-router evidence

Implementation revision `3f388297f069432fbf5442d7003062dcf3962f95` passed the controlled private-altstack router checks on the **AMD EPYC Zen 5 dev host**. This supports claim 4, systematic tactic validation. Common-application, ordinary-loader and full A3 qualification remain incomplete.

Four synthetic roundtrips cover legacy and invalid-EVEX trap encodings with two seeds and one owned route per table. The native process completed 12 comparisons using the existing full-state comparator, plus rejection of an unowned hardware fault and a user-injected signal: 10 children total. The comparator retains its existing treatment of physical RIP and debugger flag bits, canonical XSAVE, data and the complete 64 KiB application stack. No case or comparator was relaxed.

Independent review checked all 192 saved trace rows: actual router table/code observations, signal delivery, 28 handler instructions per trace, the complete ucontext with only saved RIP changed, unchanged complete FP state, and the restorer/`rt_sigreturn` register transitions. Each trace records 33 router stops; the final control NOP gives the source-checked 34-stop total. Full application snapshots, mapping checks and individual negative-case waits were checked live but were not separately saved by this synthetic control. Strict helper cleanup proved ECHILD with no unexpected descendants or cleanup errors.

| Validation at the implementation revision | Result |
| --- | --- |
| Workspace tests | 2,229 passed, 0 failed, 4 ignored |
| Rewrite targets | 138 passed |
| Serial launch tests | 995 passed |
| Default-parallel library / prefixed / neighbor tests | 212 passed + 1 ignored / 30 passed / 74 passed |
| Formatting, strict workspace Clippy, all-targets/all-features check | Passed |

All 2,233 workspace identities and statuses from the preceding source revision were retained. The three earlier allocation-contention regressions passed in both the workspace and their respective default-parallel suites. Durations in the data are operational observations, not performance measurements.

Both earlier failures remain visible. Revision `dd1ce13c4e9657257babe4cca7a804be908c312b` passed targeted tests and the native build, then failed strict Clippy because the exception fixture lacked a direct decoder dependency and two reset buffers used unnecessary allocations. Revision `6d8c123531f30e1a841c52c8955d46f294811172` fixed those issues and passed validation, but its first native router attempt found a pre-existing enabled alternate stack. That failed attempt completed no router roundtrip. The final revision explicitly saves, disables and restores that stack around the isolated oracle; the original disabled-stack assertion remains.

Exact revisions, hardware, commands, source hashes, complete test identities and failed/UNRUN rows are in [validation data](data/common-core-router-3f38829/summary.json), with [reproduction scripts](reproductions/common-core-router-3f38829/README.md). Native [failed-attempt data](data/common-core-router-native-6d8c123-failed-v1/summary.json) and [successful trace summaries](data/common-core-router-native-3f38829-v2/summary.json) have separate [failure](reproductions/common-core-router-native-6d8c123-failed-v1/README.md) and [success](reproductions/common-core-router-native-3f38829-v2/README.md) recipes. Raw logs and memory captures remain outside Git.
