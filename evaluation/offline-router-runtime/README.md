# Static executable router runtime and paired producer

Revision `3fa63147d3969f82c73581c36cc6b160ddcf05ff` adds an opt-in startup
catalog, activation through the production SIGILL router, and a paired producer
for both complete authored programs (80/16 and 107/26 heads/selected sites).
Consumed pun windows, neighbor relays, image ownership, file-backed stack and
terminal constructor failures are explicit. The producer withholds both
products when either program fails and publishes the outer marker last.

These results support claim 4 through catalog/compiler/producer controls and
parallel regressions. They do not qualify an executable startup package. The
separate per-product bootstrap crate is outside workspace builds and remains
unbuilt here; actual DSO, loader, saved-artifact and native corpus gates remain
open. There is no new performance result.

On the AMD EPYC Zen 5 dev host with root-attested stable Rust 1.97.1, the full workspace passed
**3,785 tests, 0 failed, 37 ignored** in 869.069 seconds, inside its fixed 900-second
bound. It retained 316 test threads on 16 reserved CPUs. All 117 source-derived
required regression pass lines were observed, including RapidProbe rejection,
short-neighbor, staged/observing-control and prefixed-pun allocation tests.
Serial launch passed **1,039 tests** in 127.010 seconds. Fmt, strict workspace
Clippy and the all-feature/all-target check passed. Five filtered child summaries
are retained separately, with no target or doctest deduplication. Every command
and its outer owner closed with source unchanged and no adopted descendants.

The development runs are retained in full in `commands.csv` and `receipt.json`:
46 artifact tests; 7 core and 8 paired-producer tests; 253 rewrite library/example
tests. Strict Clippy then rejected two integer-bound expressions and one manual
range check. Equivalent expressions fixed those lints without changing any
assertion or bound; the affected 162 rewrite tests passed again, followed by
strict Clippy and fmt. Those commands ran on the recorded 5b28b7f source overlay;
they are not relabelled as executions at the final commit.

To reproduce the required validation, check out the exact revision, reserve 16
disjoint CPUs, use one target directory, and run:

```sh
RUST_TEST_THREADS=316 CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 \
CARGO_NET_OFFLINE=true CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
python3 -B evaluation/short-neighbor-parallel/validate.py \
  --revision 3fa63147d3969f82c73581c36cc6b160ddcf05ff \
  --output ignored/reproduce-runtime-validation
```

The exact focused commands are in `commands.csv`; use the same environment and
four reserved CPUs. In particular, the opt-in producer and core controls need
`--features offline-router`. Raw logs and build captures remain in ignored/;
these compact files retain exact commands, revisions, reservations, load,
outcomes and raw-log digests. Command elapsed times use unoptimized correctness
builds and are not throughput measurements.

The compiler version is a root host attestation recorded after validation. The
command owner records the explicit toolchain path, but did not capture a
contemporaneous compiler version or binary digest before that run.
