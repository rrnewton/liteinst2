# Planted controls for uncalibrated-host-summary.sh

Each fixture is cut from real liteinst2 CI logs (PR 118 head 61e42c14, debug attempt 1, job 139900064168, and the green liteinst debug job 139900064436), with leading timestamps stripped and colour codes kept.
One edit per fixture plants its special path; cases.tsv names the verdict, exit status and summary text each must produce.
Synthetic parts (no real capture exists): the compiler error in build-failed.log, the spawn failure in spawn-failure.log, the Doc-tests section in doctest-unnamed.log, the exec_backing_cleanup::main gate panic (renamed from a real gate panic) in the harness-false-* and nonzero-exit fixtures, the `-> Result` test in failed-lines-no-result.log, the interleaved fragment in interleaved-failed.log, and the gate text quoted mid-line in gate-text-mid-line.log (a real gate line's tail, renamed to the failed selected_gate test).
