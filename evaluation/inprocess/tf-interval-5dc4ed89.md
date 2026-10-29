# Page-entry and operation-batch latency

Finite execution and 20 timing samples were independently replayed at `5dc4ed8987fbbc8f3906c50fd4913d177e8e21af`, which includes main `85037678` and the requested `7ab` ancestor. Required checks ran separately at `99084bbff44963b3a3561766fb5f9c1bf9c26c10`.

An isolated known page executes N=1 or N=256 `ADD $1,%r8` operations under the singleton registered-rseq lease. Genuine first-byte BODY NX entry follows the pipe read with BODY non-executable, TF clear and no pending owner.

Fixture/bridge: GCC 11.5.0 (Red Hat 11.5.0-15), `-O2`; locked offline decoder release: rustc/Cargo 1.97.1. Timing uses the qualified unobserved bridge (`sha256:9cec88d19685f2dfefecabca62d795e323a7eb6833a0f5b0848e4dd1e97caa0c`), original ELF and sealed carrier.

The finite receipt accepted 17 expected outcomes: eight successful targets, five protocol failures and four pre-exec descriptor refusals. Each N has native-reference, observed-gate and native/gated timing lanes; both full-state pairs passed. N=256 recorded 256 TRACE events, 255 body transfers and one lease close; N=1 recorded one TRACE, zero transfers and one ordinary-owner close. Full FP is checked at endpoints, opening and final closure, not every compact TRACE. Same-revision 148 and fresh 6/49/17 prerequisites plus two projection tests passed.

The parent clock starts before writing GO and stops after complete DONE. It includes IPC, scheduling, remaining read return, body, closure and DONE delivery; the gated lane includes first-fault and handler work. Process creation, setup/READY, later output, records and reap are excluded. Acceptance still requires exact transcript and EOF, complete output/reports, custody and reap.

N=1 is a **first-entry workload round trip**, not isolated fault latency or cache/TLB coldness. N=256 is an **eligible-operation batch**; dividing by 256 includes first/last costs, not pure interior steady-state latency. Native timing has no reference handler; gated timing uses the unobserved release bridge with empty FD3. No baseline cost is subtracted. Real-program process times and admission-work timers remain separate evidence.

| Five samples per lane | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| N=1 native | 35.574 us | 36.725 us | 91.838 us |
| N=1 gated | 3.180199 ms | 3.650065 ms | 3.790525 ms |
| N=256 native | 37.187 us | 38.738 us | 41.333 us |
| N=256 gated | 11.210654 ms | 11.332748 ms | 11.704978 ms |

All 20 fixed alternating samples were retained without filtering or retries on CPU 308. Child limits: 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB file size. Hardware: AMD EPYC 9D85, x86-64 family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. This establishes neither general B2/B3 completion nor low overhead.

The [six failed attempts](results/tf-interval-attempts.json) remain failed: linker tokenization, untracked bytecode, reader assumptions, inventory preflight and two serial recorder timeouts. Both serial runs exited -9 at 180 seconds; five later checks did not run. Reader fixes follow exact producer/environment/shmem contracts, with one typed READ-to-BODY atime change and byte-exact later BODY stats. Failed replay gains no qualification credit.

[All six required checks](results/20261029T055128.313777Z-checks-99084bbff449.json) passed at 990: recorder 350 in 136.375 s; workspace 3,115 passed, 36 ignored, 103 harnesses in 354.210 s; serial launch 1,039 passed, 27 harnesses in 133.057 s; fmt, clippy and workspace check passed. Failures were zero; source/configuration/cleanup passed. The recorder uses at most four isolated processes, preserving assertions, parser and 180-second/8-MiB limits; workspace remains capped at 900 seconds. Only nine inventory/copy/recorder paths differ from measured 5dc. Page-entry runtime, interval scripts and `checks.source()` are unchanged; `checks.py` changes recorder argv/scope. Native/timing attribution remains 5dc.

Use Python 3.12, fresh output directories and the complete same-revision lease receipt. Run both measured invocations at 5dc on the same reserved CPU:

```sh
REVISION=5dc4ed8987fbbc8f3906c50fd4913d177e8e21af
export PYTHONDONTWRITEBYTECODE=1
python3 -B evaluation/inprocess/page_selected_tf_interval.py --expect-revision "$REVISION" --qualification-receipt "$LEASE_RECEIPT" --qualification-sha256 "$LEASE_SHA256" --output "$FINITE_OUTPUT"
python3 -B evaluation/inprocess/page_tf_interval_performance.py --expect-revision "$REVISION" --qualification-receipt "$FINITE_RECEIPT" --qualification-sha256 "$FINITE_SHA256" --output "$TIMING_OUTPUT"
```

At 990, reserve four CPUs and run `python3 -B evaluation/inprocess/checks.py --expect-revision 99084bbff44963b3a3561766fb5f9c1bf9c26c10`. Exact environment values are in the receipt.

[Finite receipt](results/tf-interval-finite-5dc4ed89.json), [timing receipt](results/tf-interval-release-5dc4ed89.json), [all 20 samples](results/tf-interval-release-5dc4ed89.csv) and [two standalone tests](results/tf-interval-projection-5dc4ed89.json) retain exact hashes/commands; raw logs and records remain private.
