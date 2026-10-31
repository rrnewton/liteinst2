# CALL and literal-PUSH observations

The 217-pair native diagnostic completed all 434 lanes on one AMD EPYC 9D85 CPU.
It is unqualified diagnostic evidence. It does not establish general CALL/PUSH
equivalence or production admission, and gives no performance credit.

The raw observations show these distinctions on this machine:

- With a writable stack, each tested noncanonical CALL target causes #GP at the
  original PC and RSP before a return-address store. The standalone literal PUSH
  completes its exact eight-byte store and decrements RSP by eight.
- With the same invalid target and an inaccessible or split-invalid stack, the
  stack #PF takes priority; PC, RSP and captured stack bytes remain unchanged.
  A noncanonical RSP produces #SS / SIGBUS, also without a store.
- A canonical inaccessible target allows CALL's stack effect to commit before
  the target instruction-fetch fault. CALL RSP uses the original RSP as its
  target, then decrements RSP for the return-address store.
- All 28 split-page permission-fault pairs leave every captured stack byte
  unchanged. Writable split pairs store the exact original return PC. This is
  an observation, not a universal partial-store or fault-order guarantee.

All 434 lanes preserve the captured FP storage and FS/GS values. Every other
general register is unchanged; exact flags, exception fields and PC/SP outcomes
remain in the per-case summaries. Successful CALL and PUSH endpoints naturally
have different PCs. No comparator masks those differences or declares a pass
from their similarity. CET status returned -EINVAL, accepted by the unchanged
production prerequisite; the fixture never disabled CET.

The build took 0.214435971 seconds. Each native chunk took 0.008883790–0.010297223
seconds, and the reader took 2.048292983 seconds. These are bounded command
intervals, not a performance comparison. Original limits remain 30 CPU / 60 wall
seconds for builds and 5 CPU / 15 wall seconds per native chunk, inspector or
reader, with 512 MiB address space and 16 MiB output per command. All 35 commands
exited zero and were reaped; source, inputs and cleanup closed successfully.

The private receipt SHA is
`e029310c989143e670c6ea4f612967d2e3f6dcf420495182610a5723b1bac6f1`.
Its seven complete raw files total 76,188,336 bytes and remain private. The
published [compact result JSON](2026-10-31-call-push-native.json),
[case CSV](2026-10-31-call-push-native.csv) and
[execution provenance](2026-10-31-call-push-native-execution.json) retain every
case and source/tool/hardware/command identity, the ordered record-hash inventory
digest, and complete raw-chunk hashes. Individual record hashes remain in the
private evidence. The
[reproducer](../call_push_native/README.md) preserves the exact probe and bounds;
its installed-path invocation is separately labelled unexecuted.
