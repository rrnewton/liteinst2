# Clock admission throughput

At revision `77f83b73e308031a3fd6027d0708e2d3f1f15fc2`, this fixed release
campaign measured **7.085 ns/call native, 189.909 ns/call with ordinary per-call
Counter admission, and 26.499 ns/call with bounded-batch Counter admission**.
The paired batch/per-call ratio is **0.139302** (95% CI 0.135963–0.142723).
Batch admission requires a stronger exclusion contract across the entire batch;
these results do not establish equivalent runtime enforcement.

| Arm | Mean ns/call (95% CI) | Paired ratio to native (95% CI) |
| --- | ---: | ---: |
| Native | 7.085 (5.997–8.174) | 1× |
| Counter per call | 189.909 (183.812–196.007) | 27.375532× (24.584069–30.483959) |
| Counter batch | 26.499 (25.149–27.848) | 3.813475× (3.477085–4.182409) |

All 12 processes and all 2,448 rows passed: 36 untimed qualifications,
108 warmups and 2,304 measured batches. Every process contributes all 64
measured batches per arm. All six arm orders occur twice, shuffled once with
seed `20261101`; there are no replacement runs, outlier exclusions or timing
thresholds. The two slower final cohorts remain included. Absolute intervals
use 12 process means and Student-t with 11 degrees of freedom. Paired ratios
are geometric means with the same intervals on log ratios; batches are not
independent process samples. See the literal [statistics](statistics.json),
[campaign receipt](receipt.json) and `cohort-00/` through `cohort-11/` CSVs.

Each batch makes 2,048 calls to the same 36-byte nested-loop body: checksum
24,576, 30,720 branch encounters and 22,528 taken backedges. Both Counter arms
use one generated image and require exact clock values, remaining quantum 64,
zero callbacks and the full canary. Native must leave the clock unchanged.
Each untimed qualification also checks that every individual call returns 12.

The worker timer starts after the bounded Ready/Go exchange. It includes calls,
loop/checksum bookkeeping, and either ordinary admission/drop or batch
admission, precharged tokens, return acknowledgements and finish. Mapping,
thread creation, affinity, clock acquisition/reset and TLS setup precede timing;
final verification, lease release, join and output follow it. Batch entry and
finish perform real PID/TID checks; per-call tokens rely on the caller excluding
fork, foreign and recursive entry throughout host gaps as well as native calls.
The ordinary arm retains its owner check on every call.

All work used the same release binary, SHA-256
`80eae3100b18adc7e261b5db991796d33bb723929fbda6194fdbad20ac9cb778`.
The prerequisite old and batch oracles each passed 192 full-state gate
comparisons and two actual wrong-reply controls. The old oracle also checked
six parked stops; the batch oracle checked 352 handoffs and one fork-entry
refusal. Their ten literal CSV/JSON files are under `prerequisite/`; the
[native receipt](native-receipt.json) retains exact owner and private-witness
hashes. The [focused checks](focused.json) passed three schema tests, four Rust
tests and strict Clippy. The [full gate](validation.json) at the same revision passed formatting, strict
workspace Clippy, all-target checking, 4,417 top-level workspace tests (39
unchanged ignores; three controlled child passes counted separately), and
1,039 serial launch tests. All prior concurrency regressions passed.

The host was an AMD EPYC Zen 5 dev host with 316 logical CPUs. The campaign
reserved CPU 10 for its producer, 27 for its controller and 34 for its worker.
Load averages were 87.26/57.30/43.11 before and 86.36/57.61/43.28 after.
Every campaign owner exited normally with complete cleanup and zero rescued
descendants. Affinity and the caller's reservation are recorded; there is no
independent live allocator witness. Owner durations are operational records,
not the worker timings used in the table.

To reproduce, start from a clean checkout and select the recorded direct Rust
1.97.1 toolchain on `PATH` (`LI2_TOOLCHAIN` below). The pinned Python runtime was
3.9.25; tools and environment hashes are in the receipts. Offline dependencies
must already exist. Both output paths and their matching `target/evaluation/`
log directories must be fresh. Run the commands sequentially so each allocator
reservation lasts for its whole command:

```sh
ADMISSION_REV=77f83b73e308031a3fd6027d0708e2d3f1f15fc2
git switch --detach "$ADMISSION_REV"
mkdir -p "$PWD/ignored"
cpuset-alloc run --cores 12 --tag admission-oracle -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-batch/reproduce.py \
  "$ADMISSION_REV" "$PWD/ignored/admission-oracle-new" admission-oracle
sha256sum "$PWD/ignored/admission-oracle-new/closed.json"
# Set ADMISSION_ORACLE_SHA to that actual closed-file hash.
cpuset-alloc run --cores 3 --tag admission-throughput -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-admission-throughput/run.py \
  "$ADMISSION_REV" "$PWD/ignored/admission-throughput-new" \
  "$PWD/ignored/admission-oracle-new/closed.json" "$ADMISSION_ORACLE_SHA"
```

The prerequisite builds with 12 jobs and a 600 s wall/2 MiB capture bound.
The campaign performs one locked/offline release build with three jobs,
600 s wall and 1 MiB capture, requiring the same prerequisite binary hash.
The actual release profile was opt level 3, debug info 0, debug assertions off
and overflow checks off; explicit runtime assertions remain active. Each native
process has 60 CPU seconds, 90 wall seconds, 1 MiB per-file/capture bounds and
core dumps disabled. The owner keeps its separate three-second cleanup budget;
the worker keeps its two-second handoff deadline. CPU/file limits apply per
process and the owner wall bound covers its tree. No new address-space limit
was added to the inherited oracle arena requirements.

The exact measured [runner](run.py) and [summarizer](summarize.py) are retained.
They check revision, source, tools, prerequisites and binary continuity before
and after owned work, retain failures, and summarize only a complete passing
cohort. Raw logs and binary witnesses remain private; the public receipts
replace checkout/toolchain/output prefixes with named symbols while retaining
commands, bounds and hashes. Fresh execution creates new closures and timings.

This tiny fixture compares explicit admission strategies, including their host
bookkeeping and completion costs. It does not isolate syscall or generated-gate
cost, measure general application throughput, qualify Stop transport or a
deadline, measure production publication, or prove full state after callbacks.
Earlier per-call/Stop measurements and failed scheduling qualifications remain
unchanged; the historical 29.24× Counter result is not this campaign's baseline.

Full validation uses `evaluation/short-neighbor-parallel/validate.py`; exact
commands, environment, 12-CPU reservation and bounded owners are recorded in
`validation.json`. Serial launch uses one harness thread. The final publication
commit changes only these results and documentation, preserving tested code.
