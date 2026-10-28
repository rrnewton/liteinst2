# Checksum and RLE comparison at e8a8b6d

At `e8a8b6d447673aa7b98e00ff18df2eedf5e07d82`, checksum and RLE roundtrip each pass ten datasets in four lanes: native, LiteInst, stock E9 and bootstrap-patched E9. All **80 complete-output comparisons pass**, including exact stdout, empty stderr and exit zero. These are two programs, not 80 different programs.

All four reproduction phases pass. The existing selected-branch witness and all **96 saved-artifact controls** pass: eight valid positives, 20 intentionally demonstrated legacy-gap acceptances and 68 required refusals. The control run executes no candidate ELF. Historical gaps remain disclosed in the [earlier report](../offline-corpus-1345b10/).

Builds use release opt-level 3/debug-info 0, with assertions and overflow checks. The observed hardware is recorded in [summary.json](summary.json), using the owner label **AMD EPYC Zen 5 dev host**. CSV durations include bounded helper/exec/I/O overhead and are not isolated kernel throughput or a speedup claim. This cohort checks finite whole outputs and selected branch bytes; the separate full-state common-corpus results are [here](../e9-common-e8a8b6d/).

Reproduce from a clean checkout at the exact revision using the existing [reproduce.py](../offline-corpus/reproduce.py), then [controls.py](../offline-corpus/controls.py). Follow [REPRODUCE.md](../offline-corpus/REPRODUCE.md) and the actual normalized argument/environment records in [commands.json](commands.json). Keep the fresh run, control and enclosing-parent paths under `ignored/`. All existing tool pins, command bounds and comparison populations remain unchanged. Raw artifacts and logs are private; only the complete numeric CSV rows, command recipe and compact summary are tracked.
