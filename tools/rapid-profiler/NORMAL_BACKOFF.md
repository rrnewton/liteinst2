# Ordinary fixed-work back-off functional qualification

`normal-work/backoff_probe.py` runs a fixed functional catalog. It does not measure elapsed time or throughput and grants no raw-tick accuracy, cheap-off, 520-arm or full-A5 qualification. It does not replace or qualify prior strict 2 ms deadline results.

The catalog contains five qualifications, each K10 followed by K1000: ten fresh processes, each with 3,072 actual calls, 1,536 helper returns and 128 checkpoints. Before those trials, the recipe requires a fresh, unchanged 34-stage `verify_normal_interval.py --reference-exact --reference-work --reference-leg --observer-work` qualification, the complete prescribed Python/Rust controls, and two separate native pending-owner controls (K10 then K1000). Those controls retain the same full work population but use commands rather than the timed Schedule; their internal absolute deadline is 15 seconds. Both must pass before any of the ten trials starts.

Run under the existing bounded process owner with a 1,200-second wall limit and an 8 MiB owner-log cap, in a clean checkout at an exact 40-character commit. Root must first reserve four CPUs and join the allocator evidence and hard AllowedCPUs boundary. The driver neither allocates CPUs nor certifies a reservation. Supply the four-CPU inherited affinity and an allocator tag:

```sh
python3 -B tools/rapid-profiler/normal-work/backoff_probe.py \
  --revision FULL_40_CHARACTER_COMMIT --reservation-tag ALLOCATOR_TAG \
  --raw /ABSOLUTE/CHECKOUT/ignored/FRESH_OUTPUT \
  --toolchain /ABSOLUTE/RUST_TOOLCHAIN \
  --user-home /ABSOLUTE/USER_HOME --cargo-home /ABSOLUTE/CARGO_HOME
```

All directory arguments are absolute, canonical existing directories except the fresh output directory. Its parent must already exist under this checkout's `ignored` directory. The toolchain directory contains `bin/cargo` and `bin/rustc`. The inherited CPU list has exactly four distinct values in 0..1023. Sorted CPU0 runs the producer, CPU1 runs the application, and CPU3 runs the captured controller; CPU2 is unused during these cohorts. The prerequisite receives all four CPUs. Affinity, tag and observed load averages do not establish quiet or exclusive hardware.

The release configuration remains optimization 3, debug information 0, assertions and overflow checks enabled, four compiler jobs, incremental disabled, and one target directory. Every new control/trial child retains limits of 20 CPU seconds, 30 wall seconds and 1 MiB per output file, inside the existing 55-second/1 MiB helper owner. The prerequisite retains its original limits. No count, case, bound or failure threshold adapts to an observation.

Every catalog entry remains PASS, FAILED or UNRUN. A normally closed nonzero/signal exit or rejected functional transcript remains FAILED and advances to the next declared entry. A failed pending-owner control still allows the other declared control after normal closure, but either failure withholds all ten trials. Source, artifact, prerequisite or custody uncertainty withholds subsequent entries. There are no retries or warm-up calls.

`public/trials.csv` retains ten concise rows, including observed and unexercised coverage. `public/receipt.json` binds source/tool/artifact/request/result hashes, prerequisite/control outcomes, reservation/load observations and raw-row counts. Full stdout, stderr, requests, closures and accepted raw call/history/Report/phase tables stay in the private output tree. A tentative projection is not completion authority: root must join the final private result with normal outer closure and immutable pins. Refused or incomplete transcripts remain as raw bytes; they are not turned into successful CSV rows. `wire_rows` counts rows admitted by the complete checker; an absent count does not assert zero application work.

Collector PID/TID and role fields are authenticated self-observations. The bounded-command receipt joins requests, streams and normal closure but has no direct-child PID field; this route claims no external receipt-to-terminal PID join. The source still performs complete input/source/helper/journal/Report/history checks and retirement. These validation costs are part of the configuration; this functional route establishes neither pure observer overhead nor application speedup.

The frozen parent protocol SHA-256 is `8bc5ec049eb2d53561544b46d0cbc50541313a1c14fa2f6aa23ccad5c2719c20`; the mandatory pending-owner supplement is `145c1932ab600bf0d482e7c999216c0ec88922fe747a69ecbc4731b0edb5a985`. Both are recorded in every public receipt, alongside the two exact wire hashes.
