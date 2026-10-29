# Merged-tree checks with the workspace timeout retained

Exact source: `4bb9ad8161015b3775d3ef376b0788227f9801c4`, merging main
`b66ce1fea7c48af00fca719574d19ed7e666cf4d`. Hardware: AMD EPYC Zen 5 dev host;
Rust 1.97.1, four compiler jobs, incremental disabled. Claim 4 functional
validation only; A5 remains open. These command durations are not performance
measurements.

Formatting, strict workspace/all-target/all-feature Clippy and check passed.
The workspace check **FAILED** its original 360-second bound (360.145 seconds,
eight rescue reaps). It reached the native neighbor-eviction oracle; completed
terminal observations contain 1,982 passes, zero reported assertion failures
and one ignore. These counts describe a prefix and may include nested summaries.
They do not prove a full-suite pass.

Only the three checks the fail-stop runner left UNRUN then ran once:

| Check | Result | Pass observations | Seconds |
| --- | --- | ---: | ---: |
| Serial launch | PASS | 1,039 | 132.006 |
| Staged allocation | PASS | 3 | 0.036 |
| Prefixed pun | PASS | 36 | 1.336 |

Both phases returned normally through their process owners with no outer
rescue. The workspace prefix also contains all three observing-control
allocation regression tests. No check was repeated or given a wider bound.
Neither a whole-workspace nor a 316-thread pass is claimed.

The first phase hard-reserved CPUs 52/121/129/130/181/189/286/302. The tail
reserved 8/37/44/73/146/169/189/198, with load 45.78/75.72/74.46 before and
39.32/61.88/69.44 after. The first-phase runner did not record load; its null
fields are intentional. Exact commands, outcomes and closed-log hashes are in
`receipt.json` and `checks.csv`; raw logs remain ignored.

The exact merged source review approved the nine oracle/session implementation
files. Root authenticated the closed review and all 1,171 native and 1,220
session source pins against the merged files. The earlier native and fixed-five
campaign results remain tied to
[`a6c8297`](../ordinary-call-pair-session-a6c8297/README.md): 192 native pairs
passed; the five session qualifications yielded one PASS and four FAILED, with
five strict deadline misses across 320 installed cases. Source continuity is
not a new qualification, and neither campaign was repeated after this merge.

To reproduce the check sequence, use the exact source and the recorded command
vectors with explicit local values for `$REPO`, `$TOOLCHAIN`, `$CARGO_HOME`,
`$AGENT_UTILS` and `$RUNTIME_DIR`. The tracked runner is
`evaluation/admission/check_exec_identity.py --checks-only`; wrap it in
`cpuset_allocator.py run --cores 8 --sample-s 1 --tag UNIQUE --` as recorded.
Use allocator revision `d0c2867be75b495eb64239e664c6306af9747783` and a fresh
ignored output directory. Keep its existing 360-second workspace and
180-second other-check bounds. If the fail-stop runner leaves the last three
checks UNRUN, the tracked
[tail generator](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py)
materializes their exact runner. Run only that unstarted tail once in a fresh
directory; retain the original failure. The generated runner's pinned hash and
invocation are in the receipt.
