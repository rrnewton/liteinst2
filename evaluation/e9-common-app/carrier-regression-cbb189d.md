# One failed carrier selection at cbb189d

The core CLI at `cbb189d1d17f947c97194842129b66eb68b0531f` refused the complete
`null-heap-write-unstripped` selection with `NoPatchWindow` (code 9). It returned
exit **2**, produced no candidate, and left qualification incomplete. The outer
timeout/helper returned 1; the strict receipt established ECHILD, no remaining
descendants, no cleanup error and unchanged request/helper bytes. Helper elapsed time was
0.580693277 seconds; this is an operational observation, not a performance result.

The retained diagnostic includes all five tactics: GeneralizedPun (B2) and
Relocation (B1) report AllocationUnavailable; PrefixedPun (T1), SuccessorEviction
(T2) and NeighborEviction (T3) report NoPatchWindow. B1 examined **65,536**
selected-image slots and recorded **BudgetLimited**, including 3,328 address-policy
refusals. No tactic reports complete classification. That bounded search record
is preserved as recorded.

A separate source/arithmetic analysis proves that no B1 target fits the entire
declared selected arena `[0x10000000, 0x10010000)`. With next PC `0x401845`, every
arena target has displacement byte 3 equal to `0x0f`; the complete RET entry at
`0x401844` requires that byte to belong to the ILLEGAL set, which excludes `0x0f`.
This exact-arena result does not turn the recorded budget stop into an exhaustive
allocator search, establish feasibility elsewhere, or make the failed command
successful.

[Summary JSON](../results/e9-common-carrier-cbb189d/summary.json) and
[command CSV](../results/e9-common-carrier-cbb189d/commands.csv) retain the exact
revision, complete input hashes, role-based argv/environment, original receipt
and log hashes, five outcomes and independent review bindings. The six hardware
fields come from the preceding closed cbb build: **AMD EPYC Zen 5 dev host**,
AMD EPYC 9D85, x86_64, 316 logical CPUs, recorded kernel and glibc 2.34. Hardware
was not recaptured for this individual command. Raw logs, metadata and ELF files
remain private. There is no application execution, architectural-equivalence,
full 74-stage production, E9, or general A3 credit from this run.

## Reproduce the command

Supply the exact archived cbb core executable, original ELF and complete selection
whose hashes appear in the summary. The existing [build recipe](BUILD.md) and
`produce.py` use this same core `prepare` command. Use a new ignored RAW directory
and the pinned existing `tools/unwind-oracle/bounded_command.py` under REPO:

```sh
/usr/bin/python3.9 -B "$MATERIALS/reproduce_carrier.py" \
  --repo "$REPO" --core "$CORE" --original "$ORIGINAL" \
  --selection "$SELECTION" --raw "$RAW"
```

[reproduce_carrier.py](reproduce_carrier.py) is a newly published, **unexecuted**
reproducer. The actual recorded run was a direct bounded CLI invocation.
The script pins all three inputs and the existing helper, retains 20 CPU/30 wall
seconds and 16 MiB per-file limits, and uses the original 40-second timeout,
10-second outer kill grace and 55-second parent wait. Parent timeout or interruption
sends SIGKILL to the outer process group and waits for the direct outer child,
with no additional parent grace. It preserves the child exit code:
the recorded result returns 2, never an expected-failure production PASS. Fresh
outputs and receipts describe a new run and do not overwrite the retained result.
