# Registered-rseq native page epochs

The opt-in in-process page gate now executes unchanged code at its original PCs
while rseq is registered. It accepts kernel-selected continuation PCs only after
checking the pinned zero publication word, closing the admitted page, observing
the same data allocation, and refreshing real FS/GS bases. This supports finite
evidence for claims 2 and 4. Default dynamically linked applications still fail
at the registered native entry guard; this is not full B2/B3 qualification.

Runtime source: `9dc367f8e2159810dd4160b19033475564128205`. Native qualification and
release measurements: `d0d14067c441f7cdcd324b4a34ff21f9114be4ca`. Hardware: AMD EPYC
9D85 158-Core, x86-64, Linux numeric version 7.1.3. Receipts retain the kernel
release hash, CPU features, exact commands, source/tool/binary identities and
process bounds. Native subjects and release measurements use one reserved CPU.

## Native results

All 16 same-ELF native/gated pairs passed: 32 actual subjects, 18 completed
operations and 14 required failed operations, including six signal terminations.
The scheduling-abort cases ran with two separate same-CPU contenders, both
reaped, and both subjects reached their actual abort marker.
The cohort checks original source/data/rseq bytes, complete kernel frames and FP
records, literal GPR/flag/selector effects, 32 ZMM registers and eight K registers.
It covers passive/active epochs, actual scheduling and NX aborts, coincident
addresses, distinct-address and straddler refusals, changed FS/GS selectors,
disjoint/overlapping stores, inaccessible descriptors, wrong signatures and UD2.
Fatal subjects establish their exact signal and safe pre-operation reachability;
they do not claim an observed terminal frame or exact unseen fault cause.

The same-revision six-site publication control, all 49 negative controls, and
17 inactive-rseq pairs also passed. Seven unchanged regression suites at the
runtime commit passed 301 commands, retaining all 50 required exit-125 results.
The earlier `203b83b` cohort remains failed: its native observer intercepted a
second signal and exited 98. The correction restores and observes the default
signal disposition and includes case12's publication in its critical interval.
No expected signal, state comparison or process bound was relaxed.

- [Native result and prerequisite joins](results/20261028T184206.106799Z-page-selected-rseq-native-d0d14067c441.json)
- [Earlier failed cohort](results/20261028T183158.671753Z-page-selected-rseq-native-203b83b0ab1b.json)
- [Unchanged regression results](results/rseq-native-prior-regressions-9dc367f.json)
- [Initial release build](results/20261028T180930.109441Z-rseq-native-release-build-9dc367f8e215.json)

Reproduce the native qualification on the exact revision. Each driver prints a
public path `evaluation/inprocess/results/<stem>.json`; use the corresponding
`target/evaluation/inprocess/<stem>/receipt.json` as `$POSITIVE`, `$NEGATIVE` or
`$RSEQ` for dependent commands.

```sh
REVISION=d0d14067c441f7cdcd324b4a34ff21f9114be4ca
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REVISION"
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REVISION" --positive-receipt "$POSITIVE"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REVISION" --fast-memset
python3 evaluation/inprocess/page_selected_rseq_native_run.py --expect-revision "$REVISION" --positive-receipt "$POSITIVE" --negative-receipt "$NEGATIVE" --rseq-receipt "$RSEQ"
```

## Real release applications

The unchanged five-case matrix passed three cases and failed both defaults.
Every process retained the original 30 CPU-second / 60 wall-second / 512 MiB /
16 MiB bounds. These are single whole-process observations, including carrier
startup for gated programs; they are not a statistical throughput study.

| Program | Native seconds | Gated seconds | Gated exit | Output equal |
| --- | ---: | ---: | ---: | --- |
| true, default rseq | 0.003691204 | 2.720457346 | 125 | yes, empty |
| true, rseq disabled | 0.003347818 | 6.468734540 | 0 | yes |
| ls, default rseq | 0.003413557 | 3.974128965 | 125 | no |
| ls, rseq disabled | 0.003434549 | 18.599748954 | 0 | yes |
| boundary fixture, rseq disabled | 0.003411588 | 1.217754234 | 0 | yes |

The successful disabled-rseq ls run admitted and closed 5,732 page epochs. Its
first recorded admission took 81,863 ns; the median of the first 16 recorded
revisit admissions was 82,408.5 ns. These timings describe admission work in the
loader, not application instruction throughput. All raw timing samples are in
the [compact release receipt](results/rseq-native-release-d0d1406.json).

Default true/ls report guard1473/detail11 after 31/33 registered admissions, with
30/32 successful registered closes. The ordinary fatal-close owner reports all
446/1,172 native admissions closed. Failed completion fields remain null. The
reports do not retain the failing instruction frame, so they cannot identify its
exact instruction. Supporting the bounded current-PC page-boundary retry is next;
it requires a retained zero-word/pin obligation across both genuine NX events.
This full-ELF backend still reports `source_patches=0`; separate temporary
publication controls must not be presented as full-application source patching.

```sh
python3 evaluation/inprocess/native_pages.py --expect-revision "$REVISION" --output evaluation/inprocess/results/native-pages-rseq-native-reproduction.json --cpuid-nx --rseq-native
```

The release receipt preserves every original matrix number and command, hashes
the original numeric receipt, and represents the kernel release by numeric
version plus SHA256. It adds only bounded failure-report fields authenticated
against the retained stderr hashes. Full logs, frames, addresses and binaries
remain private.

## Required checks

All six required checks passed on the merged tree at
`6d1e9f22d3aec2c147da357aca58dc9389145834`: format, warning-free workspace
Clippy, workspace tests (2,987 passed, zero failed, 36 ignored across 103
harnesses), all-feature/all-target workspace check, all 350 recorder tests, and
serial launch (1,039 passed, zero failed or ignored across 27 harnesses).
The recorder completed in 138.123 seconds under its unchanged 180-second limit;
workspace tests took 340.727 seconds and serial launch 130.563 seconds.
The run used four reserved CPUs. These are validation durations, not release
application-performance measurements. Runtime, native fixtures and measurement
drivers remain byte-identical to qualified `d0d1406`.

- [Merged-tree six-check receipt](results/20261028T194058.409047Z-checks-6d1e9f22d3ae.json)

```sh
python3 evaluation/inprocess/checks.py --expect-revision 6d1e9f22d3aec2c147da357aca58dc9389145834
```

The earlier six-check run also passed at
`e1853396c7934ef903b185f3fe0b3b2259c07dc1`:
format, warning-free workspace Clippy, workspace tests (2,957 passed, 33 ignored),
all-feature/all-target workspace check, 350 recorder tests, and serial launch
(1,039 passed, zero ignored). The full run took about 10.6 minutes on four
reserved CPUs. The native runtime, fixtures and measurement drivers are byte
identical to the qualified `d0d1406` revision; the only intervening change fixes
an integration-test readiness race.

The first required-check attempt at `d0d1406` failed because an immediate ptrace
interrupt could observe syscall-exit state before the spinner had executed a
user instruction. The test now waits, within its original deadline, for an
explicit flag- and register-preserving readiness store and the expected loop PC.
Only then does it capture the comparison baseline. Every full-state comparison,
stale/foreign-token assertion and cleanup check remains unchanged. Three
separate runs of all eight integration tests also passed. The original failure
is retained.

- [Successful six-check receipt](results/20261028T185613.666649Z-checks-e1853396c793.json)
- [Earlier required-check failure](results/20261028T184635.281816Z-checks-d0d14067c441.json)
- [Three integration-test runs](results/20261028T185559.321069Z-dynamic-interrupt-e1853396c793.json)

```sh
python3 evaluation/inprocess/checks.py --expect-revision e1853396c7934ef903b185f3fe0b3b2259c07dc1
```


Main `727ae439e99abe08e08f520cc39a29546405c0ea` merged cleanly at
`181eab81e7cf316923d725299a57616e76236832`. Its profiler additions leave the page
gate and native qualification sources unchanged. The first merged preflight
correctly refused the stale profiler inventory before executing any checks;
that [failed attempt](results/20261028T190933.884520Z-checks-181eab81e7cf.json)
is retained. The exact inventory successor accounts for 33 added Rust tests,
including three upstream ignored tests, while preserving historical counts and
source checks.

At `67a581b40f69a3892801446af43bf98261a70417`, the updated inventory passed
preflight, but the recorder suite reached its unchanged 180-second wall limit;
no later check ran. The [timeout receipt](results/20261028T191902.533130Z-checks-67a581b40f69.json)
is retained. The follow-up addresses repeated metadata parsing while retaining
whole-source authentication and every literal-value comparison.

At `ead5d4d79c360d4cbb82677d5ee39d86968929ed`, the five pinned metadata
assignment snippets preserved every check but did not resolve the timeout:
recorder again reached 180 seconds (180.070433635 observed); no later check ran.
That [failed receipt](results/20261028T192624.230237Z-checks-ead5d4d79c36.json)
also remains failed. No speedup or full-recorder pass is claimed for that change.

The final correction reuses bounded immutable syntax descriptions keyed by
exact source bytes and parser identity. Every file read, complete source hash,
historical inverse, current expected-value comparison, assertion, test case and
time limit remains live. Literal evaluation produces fresh values after each
lookup. The successful merged-tree run above follows that change; both earlier
timeouts remain failed.
