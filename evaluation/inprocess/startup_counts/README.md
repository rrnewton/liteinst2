This diagnostic counts events in the same startup mode-2 fixture as the retained
failed capture. It builds a separate release bridge with the existing counter
ABI. Run it from the repository root, using the exact current revision:

```sh
cpuset-alloc run --cores 1 -- python3 -B evaluation/inprocess/startup_counts/counts.py \
  --expect-revision "$(git rev-parse HEAD)" \
  --origin-receipt target/evaluation/inprocess/20261031T114933.681207Z-startup-loop-3ce8218f1f73/receipt.json \
  --output target/evaluation/inprocess/startup-counter-diagnostic-attempt-1
```

The runner authenticates the original application, archive, source, interpreter
and namespace. The original launcher remains unchanged; the separate counter
launcher replaces the capture sink with a validated counter FD and nonce.
The existing 34 protocol checks and build byte oracle precede one target run.
Bounds remain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB
file/capture output. Counter data is read only after the target is reaped.

Each counter is reported independently. Cold attempts precede the planner;
misses follow its refusal validator; publications follow complete publication;
hits follow exact-root warm binding; completed counts follow the full drain.
No subtraction turns these separate cells into a completed transaction count.

Killed targets remain failed prefixes. Subentry opportunities, unobserved raw
planner returns and terminal proof remain unavailable. Removing capture work
changes this profile's cost, so its prefix cannot establish completed progress
or a speedup against the earlier capture. Compact results record the actual
revision, hardware, command and counters; raw records remain private.
