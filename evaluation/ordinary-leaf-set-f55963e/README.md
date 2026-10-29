# Selected-leaf fixed-five campaign

At `f55963ea38e64b50d9300cc78d1a24e65a44df72`, the fixed campaign **FAILED**.
All 24 original-code populations passed (4,064 records, 10,160 target calls).
The first 12 installed cases passed (2,032 records, 3,048 calls, 3,009 sampled
and 39 unsampled). Attempt 1 then failed at N=3/K10/empty; the remaining
107 installed cases are UNRUN. Attempts 2–5 never started. No retry ran.

The failing application was normally reaped with SIGABRT before READY and
produced no output. Source inspection identifies a four-byte MOV/RET block in
the digit scanner, refused by the chosen certified-block planner's unchanged
five-byte minimum. The prepublication fail-stop guard hides the returned
preparation error by aborting. This is not evidence of a 2 ms deadline miss.
The retained emitted geometry and source guard establish that incompatibility.
The actual returned error and abort stack were not captured, so this is not
exclusive runtime attribution. No debugger or diagnostic rerun was performed.

Three hard-reserved CPUs were 3/50/53 (controller/worker/producer). Load was
24.46/25.81/31.29 before the driver and 26.79/26.25/30.67 after it. The outer
owner closed normally in 147.421 s with zero rescue reaps. The inner recipe
correctly withheld custody/retention acceptance and stopped future slots;
root authenticated all 987 retained file hashes after outer closure. This
authentication does not turn the failed inner result into a pass.

All required controls and all seven exact-revision checks passed. Workspace
summaries report 3,265 passes, zero failures and 36 ignores; serial launch
1,039, staged allocation three and prefixed pun 36. The checks used a separate
eight-CPU reservation. Counts may include nested child summaries. There is no
316-thread, performance or full architectural-state claim for this run.

Merged-tree validation at `76f1da7aab1628abe1140e0c4d8c903d536b38e1`
(including main `0a088d04a8a5e24ad7ad741c5469814336db95da`) also passed
all seven checks with the same counts. Its eight reserved CPUs were
25/60/91/92/110/157/178/184; the owner closed in 479.434 s with zero
rescue reaps. The relevant core, profiler, support and recipe sources are
byte-identical to the campaign revision. No campaign rerun occurred.

[receipt.json](receipt.json) records exact revision, hardware, commands,
release settings, reservation/load, source reviews and closure.
[cases.csv](cases.csv) retains all 144 original/installed slots;
[stages.csv](stages.csv) retains all 174 planned stages;
[checks.csv](checks.csv) records development controls and required checks.
Reproduce with the tracked `evaluation/ordinary-leaf-set-session/reproduce.py`
command in the receipt and a fresh ignored directory. Establish the stated
hard reservation and outer bounds first. Raw logs and captures remain ignored.
The strict 2 ms / 10 ms / 2 s gates and all earlier failures remain unchanged.
