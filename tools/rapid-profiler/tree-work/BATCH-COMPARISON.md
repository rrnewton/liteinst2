# Eight-call source-batch comparison

This explicit release recipe compares nine complete checked consumers: bare
native; the original single-call SDK and K=1/10/24 installed SDK; and the four
matching SDK modes with eight-call source-provenance batches. Each fresh process
executes the same 1,536 roots in 64 blocks. Installed consumers retain every
per-call result, input, ID/gate and actual counter check, all complete journal
and Report joins, and the original epoch lifetime rules. Each batch consumer
must consume 192 successful eight-call finishes inside its loop measurement.

The batch policy checks full file/mapping provenance at admission and finish,
with source/image/input checks on each call. Its unsafe contract requires
continuous immutability and exclusion of foreign execution throughout the
batch. A forbidden transient source change can escape boundary diagnostics.
The comparison includes request construction, counter observations and finish
bookkeeping. It does not isolate hook latency or the cost of one removed check.

From a clean checkout at the supplied full revision, with four CPUs reserved
under the existing host allocation protocol:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --exact-work --cache-work --counter-probe --concurrent-epochs \
  --retire-epochs --drain-completed --streamed-epochs --stream-history \
  --optional-frontend --optional-backoff-control --reference-timing \
  --call-tree --tree-population --tree-batch-comparison \
  --revision "$REVISION" --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`RAW` must be a new directory under the checkout's ignored directory. The
recipe first runs the complete original functional chain and native comparison
prerequisites. It then qualifies the twenty owner cases, ten batch pure
controls, four batch state pairs, parser/statistics controls and four new
consumer modes at that exact revision. Separate nested qualification envelopes
are 120 CPU seconds / 180 wall seconds / 128 MiB; their original inner build and
native limits are unchanged. Every timing subject retains 20 CPU seconds /
30 wall seconds / 1 MiB. Any failed prerequisite prevents the timed cohort.

The frozen plan has thirteen blocks of nine fresh processes: three fixed warmup
blocks and ten measured blocks. All 117 process records are retained, including
the 27 warmups. Their canonical request catalog SHA256 is
`1db341efa8aef143ad51683db4812b0914d181a2f13fcb7e40bc0b268c408d71`.
Historical modes retain their relative order within each block. No retry,
outlier trimming, duration threshold or overhead subtraction is applied.

Primary wall time encloses fork through `wait4`, including parent scheduling
delay; child CPU is `wait4` user plus system time. Internal whole-consumer and
loop wall/CPU clocks retain their raw sequential brackets and runtime refresh.
S1 precedes the first batch admission; S2 follows every finish and the final
installed Report drop. S0 precedes setup and S3 follows final checks and the
64-row flush. Neither clock accuracy nor simultaneous CPU/wall sampling is
assumed.

For each of six metrics, eight ratios estimate SDK/native cost and four estimate
old-SDK/batch-SDK cost factors (wall speedups for wall metrics). Each estimate is
the geometric mean of ten within-block ratios, with sample log standard
deviation (denominator nine) and a conditional two-sided 95% Student-t9 interval
using 2.2621571627409915. Negative effects remain visible. A zero measured child
CPU endpoint marks the affected complete ten-pair comparison unresolved; its
raw pairs remain. These intervals have no validated coverage or multiplicity
guarantee. Full transcripts stay private; publish the exact receipt, 117 compact
CSV rows and numerical summaries under evaluation/.
