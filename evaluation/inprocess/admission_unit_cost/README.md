# Admission unit costs and conditional model

The published November 2 measurement used the private `admission-unit-cost-r1/run.py` (19,688 bytes, SHA256 `4df200e1166a3cbe4d6a8f15d494fe710706318c6ef26a37f66e67630c9a6f6e`) at clean `4ed9d1ca1ee6c73ac7a23e3ba714d93f5783dc4d`, CPU15. Its original JSON and all245 raw CSV rows are copied byte-for-byte into `evaluation/inprocess/results/20261102-admission-unit-cost-4ed9d1ca1ee6.{json,csv}`. Receipt:164153 bytes / `723d06d6b187b814516d557fc93c06425aafb64b59f37ab497cd856350946ec0`. The public arithmetic script reproduced the packaged model byte-for-byte (8,976 bytes, SHA256 `e97eba0f94ff9b01f7ccf8cc286cb2ddeb5d9054bcebca2f99e12f8749da16f3`). The public measurement runner then completed a separate three-command reproduction at `bb3ed1733190132bdaf6d4cbbd0ff066344bcc04`, reserved CPU186. Its 245 raw rows and public JSON are retained separately as `20261102-admission-unit-cost-reproduction-bb3ed1733190.{csv,json}`; receipt167373 bytes / SHA256 `0312572fc9bbbefc98da20dc771c25179365ffbcb02b0dc452b43aac3d19abd4`. Whole source/input/artifact/capture/cleanup closure and all 22 statistics were independently checked. A later run is a separate experiment; it cannot replace or relabel this observation.

`bench.c` and `policy_lease.c` are the exact executed bytes. The public runner preserves all three child recipes, 22 operation rows, ten measured batches plus one warmup, the separate initialization/first-signal observations, and30 CPU seconds /60 wall seconds /512 MiB /16 MiB bounds. It replaces a fixed private archive location with an explicit whole-digest native receipt. No archived source, corpus, qualification or comparator is altered.

## Fresh measurement

Use a clean checkout, Python3.12 with `-B`, Linux x86-64 with the required sync-core syscall, and an externally reserved singleton. Keep the source frozen through each command. Obtain a current native archive/fixture with the existing unchanged producer (82 commands and all28 native cases):

```
python3.12 -B evaluation/inprocess/persistent_loop_effects_native.py \
  --expect-revision "$REVISION" --cpu "$RESERVED_CPU" \
  --output target/evaluation/inprocess/unit-cost-native-attempt-1
```

Require its closed `observed_native_references` receipt. Compute the SHA256 of that complete receipt, then run on an externally reserved singleton:

```
python3.12 -B evaluation/inprocess/admission_unit_cost/run.py \
  --expect-revision "$REVISION" \
  --native-receipt target/evaluation/inprocess/unit-cost-native-attempt-1/receipt.json \
  --native-sha256 "$NATIVE_RECEIPT_SHA256" \
  --output target/evaluation/inprocess/admission-unit-cost-public-attempt-1
```

The new runner requires the exact effects-native profile and closed82/28 metadata, all13 named Rust sources and Cargo files equal current source, whole archive/mode joins, the recorded compiler tools, and unchanged actual fixture headers/recipe/linker/ELF. It does not replay native validation or grant native qualification. The supplied receipt must retain its absolute local artifact paths in the current checkout; it is not a relocatable copy of another host's receipt. On another host, build a fresh local producer above: no historical archive or fixture hash is hardcoded. The public runner was exercised with the closed local full19-r3 native producer; the fresh producer command above is the reproduction path on another host. Unsupported sync support, missing executable page windows, source/tool drift or bounds failures remain failures; there is no fallback or retry.

The archive is reused compiler input, with its own source identity recorded separately. No same-revision-native qualification is claimed. Fresh `/usr/bin/ls` and `/usr/bin/true` bytes and fixed RX page/halo geometry are recorded; differing binaries can produce different results or fail the geometry check. The fixture ELF supplies data only and is never executed by this microbenchmark.

## Accounting boundaries

All timings include clock endpoints, loop/counter checks and any specified validation. Ten fixed batches yield medians and inclusive Q1/Q3; raw values and warmup are retained, with no trimming or overhead subtraction.

* The NX composite revokes X, calls a RET, checks exact SIGSEGV/SEGV_ACCERR/PC/address on an alternate stack, grants RX, and returns through sigreturn. It includes two real mprotect calls. Permission-pair, call and ucontext-return controls overlap with it; they are not additional summands. No RWX page is used.
* Sync-core QUERY+REGISTER occurs once outside timing. Each sync row invokes the required operation. Original lifecycle admission syncs per published page; native pair close syncs once per nonempty close. Use actual A+C, not an assumed C=A/2.
* The mincore row requires exact -ENOMEM on an absent predecessor page. It measures the probe syscall, not full maintained-view validation.
* Fresh maps reads all bytes through EOF using fixed storage and raw open/read/close. The observed process had3711 bytes/acquisition and two read calls including EOF. Parser and lifecycle validation are not included; do not add overlapping open/close controls again.
* Shared decoder scans are warmed after one-time initialization:4110 starts over a4 KiB page plus14-byte real halos, including the whole88-byte summary equality. All three actual pages had zero selected candidates. Default C byte-policy and current source-lease immediate refusal are separate operations. Actual masks were ls4, true/helper0, and lease2. A refusal cannot be priced as successful admission.
* Initialization was0.485669ms once, not per page. First NX cycle was14.051us; warm composite median2.316836us. Fresh anonymous write faults include actual store/zero-page work with THP disabled and record observed fault counts; mmap/madvise/munmap are outside that timed row.

## Conditional planning and historical evidence

The compact model retains every unit median/IQR and the exact historical same-run partition. Its source inputs are the three already published October29–30 comparison/counter/event JSONs; their full hashes are pinned in `model.py`. Recompute arithmetic without builds or workloads:

```
python3.12 -B evaluation/inprocess/admission_unit_cost/model.py \
  --output target/admission-unit-model-fresh.json
```

The public arithmetic script reproduced the packaged model exactly; that model is a projection of the reviewed private analysis (`model.py` SHA256 `9f9bb7a76155ceb4553a118f4ad4c82ff3c50eb559404dff314e695fdf664100`). Original micro measurements are unchanged. The model reads tracked public JSON/CSV only; it does not require private raw logs or receipts.

`A*NX+(A+C)*sync+H*probe+P*chosen_scan+R*fresh_maps+init+U` is conditional on F=A: one measured-style successful fault/grant/eventual-revoke cycle per published page. A alone is not a measured fault count. Additional NX/TRACE/refault/failure routes remain U; speculative or multi-page publication requires separate counts. H is actual predecessor probes; P includes actual rejected scan attempts. R is actual fresh acquisitions after initialization, relevant invalidations or unexplained changes, not logical queries. Seals/fstat/pread, aliases/generations/lifetimes, source comparisons, parser, CFG/proof/patch work and remaining execution remain unpriced U.

Historical LS native/DR-null/gated medians were4.168338/26.306078/19382.276182ms; true3.728928/20.089297/6769.542271ms. Gated/DR ratios were736.798414 and336.972582. Combining the LS gap with a different cohort's5393 successful admissions gives a **cross-cohort planning budget of4.104903us/page**, not a current count or matched decomposition. The single-page NX+two-sync ingredient subtotal is8.330652us (44.927206ms at5393); adding one probe gives8.522839us. These sums are not measured total latency or strict lower bounds, and leave R, initialization and U out. No combined IQR is invented.

The independent historical C partition sums exactly to20.671929099s. Inclusive clocks/sample shares and current micro medians are never added to it; its outside-handler residual is not isolated trap latency. The new target is whole-program time at most DynamoRIO null. No current full19 completion, whole-program speedup, native/owner qualification, or relaxation of original gates follows from these component measurements.
