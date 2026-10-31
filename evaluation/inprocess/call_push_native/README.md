# CALL versus literal PUSH native diagnostic

This diagnostic records original register CALL and hardware PUSH from a sealed,
read-only original-next-PC literal. It does not assert their equivalence. The
fixed matrix retains 217 pairs / 434 lanes in seven chunks, including all 16
registers, CALL RSP, 128 status/DF combinations, 16 stack alignments, 35 split-page
permission cases, 16 target/stack fault combinations, and six CALL-RSP edge cases.

Use Python 3.11 or newer, with assertions enabled, from a clean checkout. Reserve
one CPU using the repository's CPU allocation workflow, then run this command
inside that reservation (replace the complete revision and fresh attempt name):

```sh
python3 evaluation/inprocess/call_push_native/run.py --expect-revision FULL_40_HEX_REVISION --output target/evaluation/inprocess/call-push-native-FRESH_ATTEMPT
```

This installed-path recipe has not been executed. The published observation was
made with the separately authenticated private collector at revision
8fa339c98582657f6e789060d32c3df80586ba76. The C/assembly probe, compiler recipe,
raw reader and emitted-byte inspector here are byte-identical to those used.
The collector's three changes are its public profile name, use of this portable
manifest, and an explicit current revision rather than a fixed origin revision.
The complete current source and all pinned inputs must still match and remain
unchanged. Public source installation therefore requires a new revision argument.

The same existing process owner runs all 35 commands. Build commands retain
30 CPU seconds / 60 wall seconds; each of seven native chunks, the inspector and
reader retain 5 CPU seconds / 15 wall seconds. Every command retains 512 MiB
address space and 16 MiB output bounds. No retries or subsets are provided.
Before subjects, the inspector reconstructs every emitted bootstrap/reload and
recovery byte, with exact ELF symbol, permission and literal joins. Each child
PID and CPU must match its raw header. The real production CET prerequisite is
queried; CET is never disabled by the fixture. The observed machine returned
-EINVAL for the status query, which the current production predicate accepts.

Each lane retains its actual NX-before, safe bootstrap and unstepped endpoint or
synchronous-fault frames, all 23 GREGs, full 65,536-byte FP storage, FS/GS and
complete source/stack bytes. The seven raw files total 76,188,336 bytes and stay
private with the process receipts. Failure preserves partial outputs and remains
failed. The public JSON/CSV contain per-case observations and hashes, not raw
binary frames or a production admission certificate. All qualification,
production, owner and performance credits remain false.
