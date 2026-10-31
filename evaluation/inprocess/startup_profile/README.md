The startup profile observes the retained failed maintained loader-loop command.
Its original 30 CPU-second, 60 wall-second, 512 MiB address-space and 16 MiB file
limits remain. The target result is separate from successful collection by perf.
This experiment provides diagnosis, not qualification or throughput evidence.

`run.py` records the exact revision, input hashes, hardware, command and cleanup.
The tracked result `../results/20261031-startup-profile-d098034.json` contains its
reproduction command. Raw perf data and process records stay in the private
result directory. `project.py` copies the compact summary unchanged and emits
the phase and leaf-function sample counts as CSV:

```sh
python3 -B evaluation/inprocess/startup_profile/project.py \
  --summary target/evaluation/inprocess/20261031-startup-profile-d098034-attempt-1/summary.json \
  --expect-sha256 1cbc344a0608b62740812e018f164da245647d3d09a62cc5f0e2d9f332fe35e9 \
  --output evaluation/inprocess/results/20261031-startup-profile-d098034.json
```

The observed target exited with signal 9 after 30.382337016 seconds. Its 2,847
loss-free user-CPU samples place 823 samples in planning, 650 in `pe_bytes`, and
564 in compact-plan `project`: 71.55% combined. These are leaf-function shares
of sampled user CPU, not wall-time shares. The broader phase classifier places
`project` in `other_unknown`; the function attribution resolves it separately.
No event count or completed-program speedup can be inferred from this prefix.

The next experiment reuses a retained graph at a certified internal instruction
head, binding the actual entry separately from its immutable compilation root.
Full source equality, lifetime checks and generated-page RX-to-NX closure remain
required. Event counters distinguish cold attempts, validated refusals,
publications and completed warm activations before assessing the benefit.
