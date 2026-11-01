# Policy12 component controls

This runner is a separate component gate. Its fixed order is the unchanged
old 131-Code scalar metadata population, additive scalar-read controls, loop
chooser controls, the unchanged PF11 component, then the policy12 planner. Supplied guest bytes remain data: no
generated guest code, owner lifetime, fault recovery or performance is qualified.
The old scalar native fixture and complete owner qualification remain separate
mandatory prerequisites of an eventual execution experiment.

Invoke from a clean exact revision on one externally reserved CPU:

```sh
python3 -B evaluation/inprocess/loop_components/run.py \
  --expect-revision <40-hex-revision> --cpu <reserved-cpu> \
  --archive <same-source-scalar-read-and-mov-decoder.a> \
  --archive-sha256 <64-hex-archive-digest> \
  --output target/evaluation/inprocess/<fresh-attempt>
```

The runner authenticates supplied archive bytes and all nine required exports.
Its receipt explicitly leaves archive source provenance false: the enclosing
collector must join the actual independently checked same-source archive build.
A hash supplied by the caller is not that build evidence.

Build bounds remain 30 CPU seconds,60 wall seconds,512 MiB and16 MiB output;
component execution remains5 CPU seconds,15 wall seconds,512 MiB and16 MiB.
All compiler flags come from each whole hash-pinned existing recipe. The scalar
metadata arm uses the actual old metadata compiler line and decoder support;
it does not relabel the unrun scalar native arm as tested. Compiler-M closure,
prebound linker inputs, every compiler intermediate, actual ELF/runtime closure,
private captures, source identity, cleanup and failure retention keep the old
bounded-fusion runner's guards. No retry is introduced.

Public output is a compactable summary; full command/capture files stay private.
Expected fixed populations are source requirements, not observed results until
an attempt actually completes. The old PF result comparator is retained exactly;
new scalar and chooser fields have exact types/values and the policy12 C oracle
retains exact two-call typed recovery assertions for each independent model step.
