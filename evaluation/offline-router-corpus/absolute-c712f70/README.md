# Complete-program startup attempt at c712f70

Revision `c712f7008af281191783f6478508ce4cad9d6bcb`, AMD EPYC Zen 5 dev host.
All ten preparation stages passed for the checksum and RLE programs: 187
instruction heads, 42 selected jumps and two independently reviewed complete
five-object dependency graphs. These are static checks, not native correctness.

The one observer attempt **failed**. Its checksum child reached the initial
stop and kernel exec event, then refused with `Entry`. It exited within the
unchanged 30-second child limit (23.971435 seconds), with ECHILD cleanup.
The recorded status lacks both `x86_Thread_features` fields, which the current
shadow-stack guard requires. That guard runs before the signal-state guard.
The same status also shows ignored signals 32 and 33; the child reset loop
skips those glibc-reserved signals. Their earlier origin was not recorded.
RLE remained UNRUN, as did all 20 ordinary execution pairs / 40 invocations.
The previous timeout remains a failed attempt; this result is not a retry pass.

The matched E9 preparation passed. Its first transport exited zero with complete
cleanup, but the executor's subsequent exact-membership check saw only the two
setup files instead of all eight command records. That row remains FAILED;
seven commands, four structural products and all 80 application rows are UNRUN.

A separate synchronous filesystem diagnostic reproduced the stale listing:
the same retained open directory description saw two members after six files
were added. Explicitly seeking to zero, opening a new description relative to
the retained directory, and opening a fresh store each saw all eight. This
establishes the missing transition in the earlier static-directory diagnostic;
it does not establish a particular kernel implementation defect.

A separate `ARCH_SHSTK_STATUS` query returned EINVAL without changing its
sentinel. This query alone does **not** establish that shadow stacks are disabled.
Neither diagnostic executed a rewritten program or qualifies performance.

`results.json` records the exact commands, limits, input and raw-log hashes,
reserved CPUs, load averages and every outcome. Raw captures remain ignored.
Paths use `$ROOT`, `$TOOLCHAIN`, `$CARGO_HOME` and `$USER_HOME` substitutions.
Preparation uses `../reproduce_preparation.py`, as recorded for each stage;
E9 uses `../../offline-corpus/full_startup_e9.py` and its separately selected
executor. Fresh source, build and platform records and explicit final-fact
review are required before a fresh observer attempt. Preparation does not
automatically dispatch native programs.

The two diagnostic scripts are byte-for-byte copies of the recorded scripts.
To reproduce them, use the stated revision, a fresh checkout with the two
corresponding `ignored/a3/*-diagnostic-v1` / `membership-transition-v1`
directories created, and run each script once from the repository root through
the recorded bounded command owner with four reserved CPUs. Each script writes
its result under ignored storage. The membership script deliberately pins the
historical custody implementation; a later repaired implementation is a
different experiment.

No full-A3, route-coverage, qualification or performance claim is made. All
earlier 16 MiB corpus failures and the strict 2 ms clock campaign remain intact.
