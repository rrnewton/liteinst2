# Packed RX runs: complete artifact and passing correctness gate

At `c622075116a0ab768c7d052b570f16baf2caf379`, all **2,053 sites / 13,143 heads**
emitted. Comparison preserves all plans, source edits and **2,090 images/pages**
in **782 RX runs**: PHDRs **2,104→796**, LOADs **2,095→787**, carrier pages **29→11**.
[layout.csv](layout.csv) gives hashes and layout changes; its LOAD hulls are not
measured kernel reservations. Opt-in packing preserves other policies/checks and adds a 1,170-PHDR ceiling.
No full-corpus native or performance qualification is claimed.

Targets passed **192 library +15 CLI** at d2d685fe and two native fixtures at c622.
The 1,172-image legacy ELF (1,176 headers) returns required ENOEXEC; packed (five
headers) produces the exact ordered trace under AS1GiB. [native.csv](native.csv)
retains all six arms. The prior 28e6 compile failed 101 with zero arms. Both short
native owners and the comparison owner lack independent root-live witnesses.

The full gate passed at **dd71eac08500b8227a00d262bff6d7017335c7f3**:
**4,356/0/39** workspace and **1,039/0/0** serial. Raw 4,359 retains the same three
controlled child exclusions; all prior identities, contexts, ignore reasons and
custom records remain, plus 15 tests. All five commands exited 0; outer 877.992705s,
normal cleanup/zero rescues and full root/owner raw identity evidence. Ten prior
source paths are byte-identical to c622; only the native combined assertion was
split into its same two comparisons. Prior measurements retain their actual revisions.

The first c622 gate remains FAILED Clippy101. The first dd71 metadata reader also
failed: root omitted its release-proof file. The unchanged reader then closed 0/0.534801s/zero rescues after fresh release proof,
without a gate rerun. Its independent live witness is absent. [receipt.json](receipt.json)
and [validation.csv](validation.csv) retain all failures, commands, bounds, CPU/load
and hashes. Host: AMD EPYC Zen 5 dev host. Durations are not performance claims.
Prior [LI2 ENOEXEC/E9 SIGSEGV](../full-program-entry-veneer/) remain failed.

## Reproduce

Keep [reproduce.py](reproduce.py) outside the exact checkout; it is source-authored,
unexecuted. Use distinct pinned inputs from the [existing recipes](../full-program-entry-veneer/#reproduce-the-measured-revision).
Reserve one HARD CPU at 100% within the 1200% lane cap; paths are absolute, OUT fresh
under ignored. All bounds remain; no retry or candidate execution:

```sh
/usr/bin/git switch --detach c622075116a0ab768c7d052b570f16baf2caf379
/usr/bin/python3.9 -I -B "$REPRODUCER" "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY" "$OUT" "$TOOLCHAIN_BIN"
```

For focused reproduction, use 12 CPUs and receipt.json's environment. Pass the
library/example/corrected-native CSV commands once each through
`evaluation/admission/processes.py::run_command` (wall 180s/log8MiB), stopping on failure.

For the full gate, reserve 12 CPUs, use the same environment and the existing
[validator](../short-neighbor-parallel/validate.py), SHA256
`968956df64edd3f5754a0adbd4b900ac68535d188be01af0628eff94d2ed6d10`.
Pass this argv through the same owner with wall 1200s/log8MiB; GATE_OUT is fresh under
ignored. Per-command walls are 180/180/180/900/180s, jobs/harness12 and serial1:

```sh
/usr/bin/git switch --detach dd71eac08500b8227a00d262bff6d7017335c7f3
/usr/bin/python3.9 "$ROOT/evaluation/short-neighbor-parallel/validate.py" --revision dd71eac08500b8227a00d262bff6d7017335c7f3 --output "$GATE_OUT"
```
