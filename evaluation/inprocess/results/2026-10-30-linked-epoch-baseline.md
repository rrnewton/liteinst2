# Linked scalar baseline — claims 1 and 4

The linked execution experiment qualifies 22 of 23 required subjects at revision `a005a22fb174768f5822c57789a21a830efbcf1c`. The complete profile **fails**: the gated 65-entry replacement fixture exits on the unchanged 30 CPU-second limit after 30.279624034 wall seconds. All 23 attempts and all 110 commands are retained, with source unchanged, cleanup complete and no finalization errors. No performance or whole-program eligibility credit is granted.

The candidate links reachable acyclic same-page scalar heads without a signal or permission transition at each internal edge. A relocation refusal can return the unchanged frame from a fully closed TRACE predecessor, causing a real NX fault that repeats the full native admission path. Unknown or unsupported plans retain ordinary fallback.

The [JSON](20261030T195238.770351Z-linked-epoch-a005a22fb174.json) and [CSV](20261030T195238.770351Z-linked-epoch-a005a22fb174.csv) contain the compact raw case results, exact revision, command, hardware and artifact identities. The run used one reserved CPU (3), an unprivileged AMD EPYC 9D85 158-Core Processor, microcode `0xb101066`, and Linux `7.1.3`. Native executables and bridges used the recorded release `-O2` recipes. Per-program bounds remain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB per output.

Reproduce on one reserved CPU with:

```sh
python3 -B evaluation/inprocess/linked_epoch.py --expect-revision a005a22fb174768f5822c57789a21a830efbcf1c
```

Completed evidence includes six full native/gated pairs; two required read faults; four owner refusals; four real retry refusals (stale serial, double consumption, a held borrow and a changed saved frame); and one complete relocation-retry witness. That witness joins the original full frame to the immediately following hardware NX, actual native admission and complete subsequent close. Metadata has separate static qualification and no instruction-execution credit.

Supplied malformed-record controls are counted separately: 234 application, 430 owner, 4,252 terminal, 178 relocation-retry and four cause-derived CR2 controls. The failed gated replacement case supplies none of its expected 47 owner, 318 terminal or nine retry controls. Its native counterpart completes all 65 observations; its gated counterpart writes only the initial prefix and no terminal owner record. No observation was shortened or removed.

The previous failed exploratory attempts remain failures. This receipt supports bounded state and custody results for completed cases; it does not establish the complete replacement contract. The next experiment uses a separate, single-use receipt from an actual successful native publication to request the same real NX path on a matching graph refusal. It has no execution credit here. The target of at most ten times DynamoRIO remains unmet.
