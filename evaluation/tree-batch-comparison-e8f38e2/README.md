# Eight-call source batches: complete consumer costs

Revision `e8f38e278864cb4d7b2bfb2e4c83d99cfc1286ee` adds four checked
batch consumers and compares them with the four single-call SDK consumers and
bare native execution. Every process performs the same 1,536 tree root calls.
Each batch consumer completes 192 eight-call guards and checks the actual public
cumulative counters after every return. This is a bounded, cooperatively owned
Tree144 workload; it does not establish general application coverage or full A5.

The primary measurement is complete process wall time, including startup and
teardown. Values below are geometric means of ten within-block paired ratios.
A larger old/batch ratio means the batch consumer finished sooner.

| Consumer | Single-call SDK/native cost | Batch SDK/native cost | Old/batch speedup (conditional 95% interval) |
|---|---:|---:|---:|
| Original SDK | 404.41× | 52.34× | 7.727× [7.603, 7.853] |
| K=1 | 412.51× | 56.05× | 7.360× [7.246, 7.476] |
| K=10 | 413.17× | 56.45× | 7.319× [7.090, 7.556] |
| K=24 | 411.54× | 55.95× | 7.355× [7.273, 7.439] |

The reduction is substantial, but the remaining 52–56× native cost is substantial
as well. These compare whole checked consumers under different explicit source
policies. Batch begin/finish check full file and mapping provenance; each call
retains live source/image/input checks, actual gate/return checks and cumulative
counter checks. Continuous unsafe immutability and exclusion promises cover the
batch. Invalid-client detection coverage differs. These numbers do not isolate
file-check or hook cost, establish hardware-clock accuracy, or authorize unload.

All 182 campaign stages passed. The prospective nine-mode schedule retained all
117 fresh processes: three warmups and ten measured processes per mode, with
179,712 root calls and 9,984 batch finishes across the timed population. No trial
was retried, dropped or treated as an outlier. All 72 comparisons across six
metrics were estimable; a zero child-CPU reading would instead retain the full
comparison as unresolved. Intervals use Student t9 on paired log ratios; they
are conditional intervals without validated coverage or multiplicity guarantees.

Before timing, the same revision passed the 20 owner cases, actual-counter
controls, four full-state batch pairs and four fresh functional batch modes.
The four state pairs cover 64 roots and 2,744 full-state comparisons at batch
indices zero and seven; middle calls have functional and physical-transfer
checks. These support claim 4 within that scope. The 25 owner and nine state
stages are nested prerequisites, separate from the 182 top-level stages.
All 216 positive stage owners closed normally with ECHILD and zero rescues.

`trials.csv` contains every trial's raw clock readings, process timer readings,
functional counts and six metrics. `comparisons.csv` contains all 72 estimates
and intervals. The ten paired arrays reconstruct directly from the trial rows;
only their redundant copies stay private. `receipt.json` records exact revision,
tools, release profiles, artifact digests, source inventory digest, commands and
qualification summaries. `launch.json` records the outer launch and two failed
prelaunch attempts; neither failed attempt reached the verifier or produced a
trial. Raw logs, captures and full manifests remain under ignored/.

The **AMD EPYC Zen 5 dev host** was family 26, model 17, stepping 0. The campaign
used Rust 1.97.1, GCC 11.5.0 and Python 3.12.15, four build jobs, and release
opt3/debug0 with assertions and overflow checks enabled. cpuset-alloc reserved
four CPUs and enforced AllowedCPUs for the process tree. This is not a claim of
exclusive host isolation. The separate seven repository checks run with the
host's full 316-CPU affinity and default libtest parallelism, except the named
serial-launch check; `merged-gates.json` records their exact merged revision.

The first post-merge workspace run exposed a pre-existing TLS test setup race.
The fix waits for both registrations before either observation and asserts an
actual admitted frame; both reservations still overlap and every previous
completion check remains. Ten default-parallel library runs then passed
(356 passed / 0 failed / 28 ignored each). `tls-registration-fix.json` preserves
the failed run, source fix and exact checks. The measured workload stays pinned
to the original revision above.

To reproduce at the clean measured revision, set `PYTHON` to the recorded
interpreter, `TOOLCHAIN` to the Rust toolchain and `CARGO_HOME` to its cache.
Use a fresh ignored output directory and a working systemd user session for
cpuset-alloc. The explicit Python engine needs Python 3.12 on PATH and the
session's XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS preserved.

```sh
AGENT_UTILS_ENGINE=python cpuset-alloc run --cores 4 --tag li2core-tree-batch -- \
  "$PYTHON" -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision e8f38e278864cb4d7b2bfb2e4c83d99cfc1286ee \
  --raw "$PWD/ignored/NEW_BATCH_COMPARISON" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work --counter-probe \
  --call-tree --tree-population --tree-batch-comparison
```
