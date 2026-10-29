# Joined-worker shutdown and first retained perf capture

Source revision: `5fb97c53d5d5fc330bdceecb6cb7bf843b03da49`. Merge validation: `aff7bc65856ff316217586772eed605f9386d096`, including main `781209b92dbe17010a9777da86e769245f88197e`. Hardware: **AMD EPYC Zen 5 dev host**, family 26/model 17/stepping 0; Rust 1.97.1. These results support claim 4's validation machinery. A5 remains incomplete.

The ordinary consumer now captures each kernel TID before its worker closure, joins the real thread, and holds its returned value or panic while checking task absence. It requires both omission from an error-checked procfs census and direct `NotFound`, under the original absolute deadline. The session loops retain both joined results through finalization and use their existing shutdown clock. Final singleton assertions, the 2 ms gate, input/state/history checks and successful output schemas remain unchanged.

Five focused controls passed; the default workspace passed 3,093 tests with zero failures and 36 ignored tests, plus two custom harnesses. The serial launch suite passed 1,039 tests. All eight named historical mapping regressions passed. `checks.csv` separately records each required command at the source and merged revisions; repeated suites are not independent populations.

Exactly one existing STOP/K10 run per session mode passed: 64 calls in T1 and 64 in T2 (32 per worker), with one and two native joins respectively. Both stopped by `Requested` after one arm. These exercise actual finalization but do not force the transient post-join procfs window or qualify the full 520-arm timing cohort. Their complete numeric summaries are in `stops.csv`.

The first actual perf capture completed after all 34 unchanged native prerequisites and 20 limiter controls passed. It retained a 644,256-byte file for the fixed 3,072-call native workload (1,536 helper returns; 614,400 semantic original-body instructions). All three bounded perf decode commands completed. **Status remains `CAPTURED_UNQUALIFIED`:** binary record conservation, task/exec/mapping attribution, loss/throttle and terminal enabled/running accounting are pending. The period is 4,096 instructions; this is neither an accuracy result nor an overhead comparison. No second capture was made. The three earlier launches failed before capture and remain recorded in [the previous receipt](../ordinary-perf-probe-06d173d/README.md).

Fresh reservations confined the complete owned trees. Probe reservation: CPUs 90,159,170,199, application CPU 90. Loads before/after the complete probe (including prerequisites) were 36.04/36.16/38.65 and 81.59/52.85/44.37; immediately around the capture they were 78.77/51.82/43.99 and 81.59/52.85/44.37. STOP reservation: CPUs 92,113,230,313; controller 92, worker(s) 113/230, producer 313; loads 90.76/74.68/54.63 and 90.62/74.92/54.81. Reservation is not a guarantee of host scheduler quietness. All owners closed normally with zero rescues.

The executable was freshly rebuilt with release opt-level 3, debug info 0, debug assertions and overflow checks enabled, incremental compilation disabled and four compiler jobs. Raw logs, captures, transcripts and host-specific manifests remain under ignored storage. `receipt.json` retains their hashes and exact normalized commands; it contains no host paths, usernames or internal host names.

## Reproduction

Use a clean checkout at the source revision, the recorded toolchain and a fresh output directory. Reserve four CPUs with `cpuset-alloc run --cores 4 -- ...`; retain the reservation and load average. The existing complete probe script reproduces its prerequisites, limiter controls, fixed single capture and three decodes:

```sh
python3 -B tools/rapid-profiler/normal-work/perf_probe.py \
  --revision "$REV" --raw "$REPO/ignored/NEW_PROBE" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

After that owner closes, the fresh qualification's `strnlen-prerequisite` supplies `candidate.so`, `final.so` and `selection.json`; its Cargo artifact record authenticates the release binary/profile. Keep a copy of this directory's `reproduce_stops.py` outside the checked-out source revision. Supply the fresh qualified binary/selection hashes and canonical absolute paths, within another four-CPU reservation:

```sh
python3 -B "$STOP_REPRO" --revision "$REV" --raw "$REPO/ignored/NEW_STOPS" \
  --binary "$BINARY" --binary-sha256 "$QUALIFIED_BINARY_SHA256" \
  --candidate "$CANDIDATE" --final "$FINAL" --manifest "$SELECTION" \
  --manifest-sha256 "$QUALIFIED_SELECTION_SHA256" --cpus "$RESERVED_CPUS"
```

`RESERVED_CPUS` must equal the inherited affinity, sorted and comma-separated. The launcher runs the existing T1 and T2 producers once each, preserving their strict parsers and 520 configured epochs. A normally closed failure remains FAILED; uncertain custody withholds the next case. Each producer retains 20 CPU seconds/30 wall seconds/4 MiB limits, and each outer owner 55 seconds/1 MiB. There is no retry.

The repository checks use `python3 -B evaluation/admission/check_exec_identity.py --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$REPO/ignored/NEW_CHECKS" --checks-only`. They leave default libtest parallelism intact except the explicitly serial launch command.

## Interpretation limits

The earlier failure recorded an extra TID but did not identify it as the joined worker. Pinned upstream Linux v6.12 [exit](https://github.com/torvalds/linux/blob/v6.12/kernel/exit.c), [thread teardown](https://github.com/torvalds/linux/blob/v6.12/kernel/fork.c), [procfs](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c), and glibc 2.39 [join](https://github.com/bminor/glibc/blob/glibc-2.39/nptl/pthread_join_common.c) support a possible join-before-task-unlink ordering. They do not establish the observed failure's cause or the running implementation's identity. Procfs can also return ENOENT on inode allocation failure, so the added predicate is an observation, not unconditional proof of kernel unlink. Native join remains the thread return/lifetime authority. Arbitrary preemption or a blocking syscall still requires the outer process bound.

The historical fixed five-attempt strict timing campaign remains **FAILED, PASS, PASS, FAILED, PASS**. These checks and the single sampling probe do not repair those deadline failures or establish profiler accuracy, throughput, full tactic coverage or A5 completion.
