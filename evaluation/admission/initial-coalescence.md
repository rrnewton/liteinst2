# Initial R/RX mapping coalescence

Removing execute permission can cause Linux to merge a read-only file page and
its adjacent executable file page. The initial runtime path preserves two
separate facts: the original RX source extent and the current mapping that
contains it. This implementation handles one finite pair; it does not infer
source authority from a containing mapping.

The accepted pair consists of contiguous 4 KiB private file mappings with
contiguous offsets and the same backing identity: one original R page followed
by one original RX page. Selection authenticates the initial executable and
entry evidence, excludes visible file-offset aliases, ambiguous multiple pairs
and a third neighboring member, and validates the complete mapping table.
Unrelated executable mappings, including the vDSO, retain their quarantine
requirements. Unsupported layouts retain the strict original path.

The native producer retains original and final pair bytes, the actual target
protection call's wait/query/result observations, restored full state, and the
complete before/after/final mapping tables. Before native effects, it reserves
all evidence and descriptor storage. Each allocated owner is installed before
the next fallible operation; an error or unwind retains the observed prefix
and prevents retry from replacing it. The old descriptor owner remains held
when the new table becomes the bootstrap inventory. Managed-storage accounting
covers these owners and temporary views; it is not a measurement of allocator
metadata, compiler stack frames or process RSS.

Preflight counts every original source window, including overlapping decoder
and dependency bytes, plus two 8 KiB whole-pair captures. A one-byte-short total
capture limit must refuse at the original held EXEC stop before bootstrap
mutation. Source identifiers and instruction heads remain scoped to original
RX bytes. Opening one instruction changes only its original fetch pages; the
header stays NX and closure must restore the exact complete baseline table.

## Validation contract

The new source inventory adds 36 pure controls and three native methods. The
native methods require an actual Linux merge, exact original-RX fetch opening
and complete-table reclosure, pristine EXEC refusal at the one-byte-short
limit, and retained native evidence through unwind and physical cleanup. The
three methods contain four owner trajectories. They do not accept an unmerged
observation as equivalent evidence or skip a missing merge.

The recorder appends these three identities after the previous 83 named native
cases. Its expected totals are 302 Python controls, 612 launcher unit tests,
1,988 workspace tests including four unchanged ignored cases, and 904 serial
launch tests. Strict historical projections preserve all previous identities,
assertions and corpus fields. Actual qualification requires every current
native identity and the unchanged command and physical-cleanup gates.

These are implementation and test requirements, not an execution result. New
results belong in tracked JSON receipts from a clean exact revision. The prior
compiler consumer failure documented in
[runtime-consumer-cleanup-results.md](runtime-consumer-cleanup-results.md)
remains failed; its missing post-quarantine maps do not establish that historical
failure's cause.

## Reproduction

Use the environment and compiler setup described in
[runtime-kernel-consumer.md](runtime-kernel-consumer.md). The existing drivers
record the exact revision, source/configuration hashes, hardware, relative argv,
observed outcomes and cleanup summaries without publishing host paths or raw
logs. Run the complete prerequisite first, using its unchanged bounds. All four
commands below must inherit the same unchanged eight-CPU reservation and
affinity; the drivers do not allocate CPUs. Use the allocator setup documented
in [runtime-consumer-cleanup-results.md](runtime-consumer-cleanup-results.md),
including the same compiler PATH setup for qualification and the consumer:

```text
python3 evaluation/admission/run.py --expect-revision <40hex>
python3 evaluation/admission/default_parallel.py --expect-revision <same-40hex> --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision <same-40hex> --cohort fork
python3 evaluation/admission/runtime_kernel_consumer.py --expect-revision <same-40hex> --correctness-receipt evaluation/admission/results/<passing-run>.json --correctness-sha256 <64hex>
```

Qualification uses eight reserved logical CPUs, four Cargo build jobs, four
workspace test threads and one thread in the separate serial cohort, with
incremental compilation disabled. The default-parallel repetitions set no test
thread override. These controls support finite evidence for page admission,
first-instruction coverage and tactic validation (candidate claims 1, 2 and 4).
They do not establish a software preemption clock, general mapping support,
complete B3/B4, useful-scale performance or a fault-transparency theorem.
