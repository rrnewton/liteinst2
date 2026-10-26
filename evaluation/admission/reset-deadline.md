# Reset-launch deadline isolation

The native test `original_deadline_expires_with_live_pre_stop_reaper`
requires a live, authenticated reset reaper that has not reached its first
stop. Its old setup started the 100 ms clock before waiting for the shared
fixture lock. Under contention, production could correctly return the exact
startup timeout before cloning, leaving absent child records that the test
then unconditionally accessed. Scheduling the real clone could likewise
consume the clock before the handoff installed the reaper record. This is a
source-grounded race diagnosis; the reported failing run did not include a
saved failure capture in this evaluation.

The correction extracts the existing post-clone handoff loop into a private
continuation. Production passes its original absolute deadline through that
continuation unchanged. The native fixture first proves the real sender's
successful exit and reap, the authenticated handoff, and the retained reaper's
live, unstopped state. It then measures that exact continuation with one 100 ms
deadline. It still requires the exact timeout, at least 100 ms elapsed, the
existing 3 s upper and cleanup bounds, both retained pidfds' terminal state,
P_PIDFD ECHILD and an empty owned wait domain. It additionally proves that the
reaper remained live at timeout and no broker handoff occurred. An added
preexpired whole-launch subcase requires timeout with no clone or archive
facts. All eight outer cases remain present.

This controlled native phase test does not measure clone scheduling inside
its 100 ms interval. The production deadline still spans the clone and all
handoff operations. No production deadline is renewed, timeout widened,
missing child accepted, failure retried, or case skipped.

The normal qualification recipe remains:

```sh
python3 evaluation/admission/run.py --expect-revision REVISION
```

An additional default-parallelism recipe is:

```sh
taskset --cpu-list CPU_LIST python3 evaluation/admission/default_parallel.py --expect-revision REVISION
```

Use the exact 40-hex revision and a locally reserved set of exactly eight
available CPUs. The script refuses any other affinity size. It runs four
fixed, sequential `cargo test -p liteinst-launch --lib` commands without
`RUST_TEST_THREADS` or `--test-threads`, allowing the Rust harness to choose
its default parallelism within that inherited resource bound. It records the
affinity count and unchanged affinity, rather than claiming a measurement of
simultaneously running workers. Build parallelism remains four jobs.

Each repetition must contain the complete current launch unit cohort, with
no filtering, unchanged ignored counts, a successful exit and zero adopted
descendants after physical cleanup. Any failure stops the experiment; later
repetitions remain unrun. The existing 180 s command, 8 MiB private output and 3 s
supervisor cleanup bounds apply. The separate result is evidence for claim 4;
it does not replace the six-command qualification, establish a new coverage
claim, or report application performance. Every result retains exact source,
configuration, toolchain, hardware and command information. Raw command logs
remain in ignored storage; public JSON contains typed summaries only.
