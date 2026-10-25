# A2 generated and sampled assembly campaign

This opt-in Linux/x86-64 native campaign uses the same architectural comparator
as the required workspace tests. It runs every input in a fresh process, with
explicit CPU, memory, process and wall limits. It does not qualify concurrent
publication, signal/unwind transparency, CET or every x86 program.

## Fixed inventory

The full campaign contains 512 generated inputs and 32 sampled instruction tails.
The generated cohort contains 256 unbiased inputs within a constrained grammar,
then forced B1/B2/T1/T2/T3, independently controlled coalesced and grouped probes,
allocation-policy negatives, real publication collisions, preserved-byte
ownership conflicts, unsupported CALLs and CET entry requirements. Negative
cases never replace required positive executions. The collision and ownership
cases each also require their declared successful retry or full replan.

Each input supplies literal instruction heads and expected finite paths, two
fixed register/flag seeds and an independently derived full-page memory seed.
All original heads execute. The fixed totals are 2,594 heads, 5,188 original
traces, 7,476 installed comparisons and 5,140 retired comparisons, including
144 installed and 144 retired auxiliary owner comparisons. Refusal-only cases
also require 192 unchanged-source comparisons. These are obligations until the
complete run and result audit pass.

The unbiased grammar starts with a five-byte MOV and adds one through four
uniform choices among integer LEA, MOV, ADD, SUB, memory load/store, CMP and NOP
forms. An optional forward branch skips one extra operation. Memory accesses
stay within the private application data page; every permitted head has a
finite path to RET. Alignment is drawn from eight-byte offsets within a cache
line. The biased families separately specify prefix and victim geometry.
Existing all-offset, endpoint, fault and backedge puzzles remain required.

Sample extraction pins the original binary by full SHA-256 and ELF build ID,
requires exact executable-segment bytes, and ranks deduplicated eligible tails
by a fixed digest. The declared sample population is intentionally narrow:
register/immediate integer tails without data or branch dependencies. The
selected 32 tails contain 25 LEA/RET and seven MOV/RET sequences. This is evidence
on real code bytes, not representative whole-binary coverage. The extractor
refuses a different binary instead of silently resampling it.

## Sources and private data

These scripts are source, not committed logs or captures. Copy the generator,
sample extractor, adapter and audit script into a new directory below the
repository's ignored/ directory before running them: they read/write their own
directory. The generator emits generated.json and cases.rs. The pinned extractor
emits samples.json and sample-population.json plus raw disassembly; the adapter
emits sample-runtime.json and sample-cases.rs. The audit checks the exact static
inventory. Keep all those files in ignored/.

The standalone harness includes generated tables only through the explicit
LITEINST_A2_CAMPAIGN_INPUT_DIR compile-time variable. Its shared oracle module
comes directly from tests/support/quiescent_oracle.rs. Ordinary Cargo builds do
not depend on the private tables. The helper's opt-in seeded constructor leaves
old initializers and comparators unchanged; fixed calibration vectors qualify
the complete memory pages and actual stopped-tracee flags.

The driver separates `freeze` from `run`. Freeze requires a clean tracked
checkout, captures exact offline Cargo artifact records, compiles both ordinary
and calibration binaries, and hashes the complete source/input/binary inventory.
It does not execute an input. Run requires that exact reviewed manifest hash,
checks identities before each launch, and completes all eight helper calibration
tests before any campaign input. Use `python3 driver.py --help` and the subcommand
help for the required source, input, output and installed runner paths.

## Execution and observations

The driver uses parallel-experiment-runner with at most two workers and the
fixed one-worker then two-worker ramp. Each input has one CPU, 256 MiB, 32 tasks,
60 CPU seconds and 180 wall seconds. A one-hour aggregate bound limits the run.
The architectural oracle retains its separate 20,000-step and 15-second trace
limits. These are qualification limits, not measured performance claims.

The task-local worker wrapper sets and verifies its own delegated cgroup PID
limit because the inspected runner version does not enforce that CLI field.
It never loosens an existing stricter limit. CPU, memory and time containment
remain the runner's responsibility; each worker verifies the actual inherited
limits before executing native code. Optimized Python is refused by proof and
execution scripts so disabled assertions cannot produce successful evidence.

Every required outcome, resource breach, missing record, duplicate input and
leftover task is audited. The runner's outer zero exit code alone is insufficient.
A failing input keeps the campaign incomplete; a fresh diagnostic run cannot
replace its receipt. Preserve failures and minimize mismatches without dropping
the original behavior or changing the coverage denominator.

Raw records include source/image bytes, ordered attempts, plans, exact trace and
callback counts, resource measurements and elapsed times. Parent-only memory
snapshots after reading image pages record actual whole-VMA Size/Rss/Pss,
device/inode identities and backing-file size when the kernel permits that stat.
A denied file-size query stays explicit. These observations are separate from
planned virtual/backing bytes, and retained mappings after retirement are
reported honestly. Search evidence keeps unclassified stops and incomplete
whole-tactic classification visible.

Only a sanitized summary of a completed, audited run belongs in public evidence.
