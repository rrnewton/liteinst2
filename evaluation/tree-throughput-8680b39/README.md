# Repeated caller/child SDK consumer cost

Exact source: `8680b3954ab36a681323438c15800d7322322aa8`.
Merged validation source: `8fe4f861e6dcb3b64c74781d418c6be7368721e3`,
including main `e7972d45a99a2b1ad9b65752c1ada84ff2821bd2`.
Hardware: **AMD EPYC Zen 5 dev host**, observed family 26 / model 17 / stepping 0.
Rust 1.97.1, release opt3, debug assertions and overflow checks enabled.
Four allocator-reserved CPUs; each client verifies singleton affinity. This
cooperative reservation is not a claim of exclusive hardware isolation.

All 99 release stages passed: 47 inherited correctness stages followed by all
52 planned fresh processes. Each executes 1,536 guarded root/child calls in
64 blocks. Installed modes reuse one attachment and one epoch slot, with
complete journal/Report joins and retirement before rearm. The baseline is
the guarded original SDK path. These measurements include source/input checks,
consumer validation, drains and reporting; they do not estimate bare-native
instrumentation overhead or hook latency.

Primary whole-wall cost increase, relative to the original SDK:

| Retention | Cost increase | Conditional 95% interval |
| --- | ---: | ---: |
| k1 | 1.274% | [-0.504%, 3.083%] |
| k10 | 2.045% | [0.890%, 3.212%] |
| k24 | 1.096% | [0.141%, 2.060%] |

The fixed protocol has three warmup blocks and ten measured blocks, each with
all four modes in a prospectively frozen order. The estimator uses ten paired
log ratios per comparison and Student t9; the interval assumes independent,
approximately normal log ratios. It does not establish empirical coverage or
simultaneous coverage. K is not a monotone performance result in this sample.
Mandatory hooks remain active after retention closes; no cheap-off is claimed.

`trials.csv` retains every process, including all twelve warmups, four raw
wall/CPU/wall snapshots, both resolutions, and all derived wall/CPU spans.
`statistics.json` contains all twelve comparisons and every paired ratio.
Primary wall spans use enclosing endpoints, never substituted lower spans.
There was one timing campaign, no retry, outlier removal, empty-hook subtraction
or minimum-duration filter. Clock resolution is metadata, not accuracy.
See the tracked [protocol](../../tools/rapid-profiler/tree-work/README.md) for
region boundaries, exclusions and the literal order/estimator source.

Across all 52 processes: 79,872 roots (19,968 original, 59,904 installed),
119,808 instrumented nodes, 58,240 sampled and 61,568 FunctionClosed nodes.
All 99 helpers report ECHILD and all parents close normally, with zero rescues.
The campaign took 213.983 seconds operational wall time, not a throughput metric.
The inherited tree qualification retains four pairs, 1,372 state comparisons,
24 physical CALL/RET witnesses, retained-owner control and malformed-return
refusal. This supports claim 4; full A5, hardware/perf accuracy, broader call
graphs and real-application coverage remain open.

All seven exact-source checks passed: default workspace **2,842 / 0 / 12**
(passed / failed / ignored), serial launch **1,039 / 0 / 0**, staged allocation
3 and prefixed-pun 36, fmt, strict Clippy and all-target/all-feature check.
Workspace used all 316 available CPUs with no thread override and took
333.829 seconds; serial launch took 127.642 seconds. These are operational
check durations. All seven checks also passed at the merged revision, with
the same counts: workspace 353.340 seconds and serial launch 124.170 seconds.
All 158 native source inputs are byte-identical across the merge, independently
source-reviewed; no merged-revision timing rerun is claimed. See
`continuity.json` and `merged-gates.json`. The workspace includes nine new Rust controls; thirteen
Python transcript/statistics methods also pass at the exact source revision.

Development records remain explicit: initial Clippy rejected a synthetic
fixture's range loop; replacing indexing with enumeration preserved all cases.
The first private gate projection expected five contiguous child summaries;
one was interleaved with a passing sibling line under default parallelism.
The corrected projection matches that complete split terminal, excludes all
five nested results and preserves every parent count and zero-failure check.
No test, comparator, timeout or harness parallelism changed. The private outer
launcher lacks its own optimized-Python guard; this campaign used explicit
`python3 -B`. Its source and cohort remain immutable. Independent source
reviews approved the client, parser, statistics, runner and strengthened
projection; execution and result verification are root-attested.

Reproduce from a clean checkout of the source revision, with a fresh `$RAW`
directory under `ignored/` and absolute tool paths. Raw logs stay there;
only compact numerical results and this receipt belong in Git.

```sh
AGENT_UTILS_ENGINE=python PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
  "$CPUSET_ALLOC" run --cores 4 --tag li2core-tree-throughput -- \
  "$PYTHON" -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision 8680b3954ab36a681323438c15800d7322322aa8 --raw "$RAW" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work \
  --counter-probe --call-tree --tree-population --tree-throughput
```

Each added client retains the 20 CPU-second / 30 wall-second / 1 MiB bounds.
The outer campaign was bounded to 1,200 seconds and 1 MiB. Tool and artifact
hashes, release/cache provenance, exact command and launcher environment are
in `receipt.json`; exact check commands and limits are in `gates.json`.
