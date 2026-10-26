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

## Recorded validation

Exact tested source: `f5839af61934e4488092271f849cbb3fc0c50f97`, containing coordinator main
`8e3e8e473baefa05adf02da1b24b99d07d236d22`.

All six qualification commands passed. The recorder ran 230 controls;
formatting, warnings-denied workspace/all-target/all-feature Clippy and the
workspace all-target/all-feature check passed. Workspace tests produced
1,645 passes, zero failures and four unchanged ignores across 88 harnesses
in 352.141 s. Serial launch produced 565 passes and zero failures/ignores across
26 harnesses in 81.842 s. Its native collections remain 50 static cases, 15 dynamic
fixtures, 388 matrix rows and 42 named native outcomes.

The additional default-parallel experiment passed all four fixed repetitions:
278 passes, zero failures/ignores/filtered tests each, in 3.403 s, 3.416 s, 3.413 s
and 3.433 s. These are 1,112 test executions of the same 278-test cohort, not
1,112 distinct cases. The reported reset deadline test passed in each of those
four runs and in both workspace and serial qualification. Invocation context:
the command was launched through `cpuset-alloc` as follows. The typed result
verifies inherited affinity; it does not certify the allocator version or
cgroup placement:

```sh
cpuset-alloc run --cores 8 --tag li2adm-reset-default -- python3 evaluation/admission/default_parallel.py --expect-revision f5839af61934e4488092271f849cbb3fc0c50f97
```

All ten commands completed physical cleanup with zero adopted descendants.
Both experiments authenticated 1,368 source files and the exact Git tree/modes;
source and Cargo configuration remained unchanged. The default-parallel run
also checked unchanged toolchain, hardware and the same exact eight-CPU set.
The additional four runs used no thread override or test filter. No failed
command was retried, and no new ignored case was added.

Hardware was `AMD EPYC 9D85 158-Core Processor`, family 26/model 17/stepping 0,
microcode `0xb101066`; Linux 7.1.3, Rust/Cargo 1.97.1.
The kernel release SHA-256 is
`549727bb276577a43b738c4d3e8167ceb8d3d54f317035ae91560f869cf7f60d`.
The host exposed 316 logical CPUs. Qualification used four workspace test
threads and one serial launch test thread. The extra run inherited exactly
eight CPUs with default libtest threading.
Execution was nonroot with effective capability mask 0. The ptrace-scope
interface was absent; no policy value is inferred from that absence. Durations
are validation overhead, not performance measurements.

Immutable typed results:

- [Six-command qualification](results/20261026T123802.885271Z-f5839af61934.json), SHA-256 `697d981b5553aba423af0e0f373a47abdafee052ae705032ed63359340babd29`.
- [Default-parallel validation](results/20261026T124602.175412Z-default-parallel-f5839af61934.json), SHA-256 `be2dfc8fdb850ba6c6741ed5a4036e710dfc2fbc8ff443575e42e02ca2141299`.

This milestone supports systematic validation (claim 4). Repeated native
coverage results retain their finite claims 1/2 scope; no full B3/B4, arbitrary
application coverage, preemption-clock or performance claim follows.
