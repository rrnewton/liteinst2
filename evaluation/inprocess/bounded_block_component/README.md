# Bounded-block planner component

Run the source-owned bounded-block planner and independent emitted-byte model on one externally reserved CPU:

```text
python3 -B evaluation/inprocess/bounded_block_component/run.py --expect-revision REV --archive DECODER_ARCHIVE --archive-sha256 SHA256 --cpu CPU --output target/evaluation/inprocess/FRESH_CHILD
```

The archive is a mandatory whole-file input. This component receipt does not itself establish how the archive was built; pair it with a fresh, same-revision archive receipt from `evaluation/inprocess/call_owner/prepare_archive.py` before any owner experiment. The runner preserves the existing component collector's whole compiler-M, linker, ELF/DSO, input/alias/capture, bounded-process and cleanup checks. Builds retain 30 CPU seconds, 60 wall seconds, 512 MiB memory and 16 MiB captures; the single component retains 5/15 seconds with the same memory/capture bounds. There is no retry.

The component checks 45 plans, 8,064 byte-model selectors, 11 planning/placement refusals, 21 corruptions, six conserved old-policy outcomes, two capacity-link recoveries, 580 copied boundaries and 19,848 non-boundary refusals. Both typed recoveries must cover every actual model step. The original BFS planner remains unchanged and must still refuse its old NO_EXIT and EXIT_LIMIT examples. This new version stops at the first direct branch and sends every arm through an authenticated directory; runtime directory and entry authority are separate.

These are planner/model observations. The component does not execute the emitted code or prove a production owner, native state equivalence, whole-program completion or performance. Keep all failed attempts. Public evidence should contain compact counts, exact command/revision/hardware and the private receipt hash; raw captures remain private.
