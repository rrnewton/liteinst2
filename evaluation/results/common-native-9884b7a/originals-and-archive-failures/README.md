# Original observations and retained verifier failures at 9884

At source `9884b7a259b4e0ea80d2cca6d726abab4594807a`, all sixteen original
application observations and their separate saved-content audit passed. Four
verifier compilation commands exited zero, but every enclosing
archive recipe exited one. **No fresh verifier archive was admitted.** These
results provide partial evidence for claim 4, not architectural equivalence or
full A3 qualification.

The host was recorded as **AMD EPYC Zen 5 dev host**, AMD EPYC 9D85 158-Core
Processor, x86-64, 316 logical CPUs, glibc 2.34, kernel
`7.1.3-0_fbk0_rc18_0_gd373cd4b8dbf`. The caller records affinity `[0,1,2,3]`.
This is operational validation, not a performance measurement. The verifier
attempts share this epoch context; no separate per-attempt hardware record is
invented.

[summary.json](summary.json) records the exact source, input, driver and review
hashes, counts, failures and limitations. [cases.csv](cases.csv) contains every
original case. [commands.json](commands.json) preserves all 28 decoded command
contexts: input preparation, recipe caller, sixteen observation children, two
offline audit-support stages, and four archive callers with their four compiler
children. These nested contexts are not 28 independent validation cases. Private
coordinates use explicit `${ROLE}` substitutions; every whole decoded command
has a checked private inverse. No argv, environment, limit or exit was removed.

The complete original application was prepared separately at
`ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`. Both strip forms ran all eight datasets.
Every case retains all 87 static instruction heads, including zero visits, nine
jump sites, one heap-write site, and 57 capture files. The sixteen cases total
912 captures, 35,886 steps, 35,950 events, 2,426 call records, 2,024 stores and
4,186 jump visits. The source epoch has 1,839 tracked files. The original recipe
parent closed with exit zero in 68.20951651898213 seconds.

Each observation kept 60 CPU seconds, 90 wall seconds and 64 MiB per file,
timeout100/kill-after10 and parent115. All sixteen strict receipts retained
exit zero, ECHILD and empty cleanup/abort state. The separate auditor also used
60 CPU/90 wall/64 MiB; its helper completed in 59.41307145287283 seconds and its
parent closed in 59.48008985398337 seconds. The input-envelope assembly's distinct
30 CPU/45 wall/16 MiB and timeout55/parent70 profile is recorded separately.
The helper's `inputs_unchanged` field concerns request/helper bytes; the reviewed
source, input, runtime and capture-owner checks have their own separate evidence.

The saved-content audit rechecked complete PC/control-flow records, call/store
arithmetic, full array pages, ordered jump/store streams, stdout and journals.
Full RX bytes, intermediate complete registers and actual stack return words
were asserted live rather than serialized. Those source-attested invariants
are not presented as independent saved-byte comparisons. Original observation
success does not validate rewritten applications, E9 candidates or paired replay.

| Verifier attempt | Compiler exit / ECHILD | Archive recipe / parent exit | Saved after-snapshots |
|---|---|---|---|
| 1 | 0 / yes | 1 / 1 | Absent |
| 2 | 0 / yes | 1 / 1 | Present |
| 3 | 0 / yes | 1 / 1 | Present |
| 4 | 0 / yes | 1 / 1 | Present |

All compiler requests kept 60 CPU seconds, 90 wall seconds and 128 MiB per file,
timeout100/kill-after10 and parent115. Each attempted archive reported 43 files,
204,774,633 bytes and 46 source dependencies; the failure review did not authenticate
those product bytes as a successful archive. Attempt 1 failed the combined
alias-or-target stability assertion before saving after-snapshots, so its exact
changed fields remain unknown. In attempts 2–4, the saved maps establish that
only `mtime_ns` and `ctime_ns` of one ancestor directory changed across all 46
alias proofs: 92 scalar differences per attempt. Source, tools, configuration,
target-owner maps, leaf owners and the other alias fields remained equal. The
exact timestamps are retained in the summary. The actor, syscall and kernel or
autofs cause remain unresolved; no timestamp exemption was applied.

For reproduction, use the committed observer and auditor at the exact tested
revision, following `evaluation/e9-common-app/OBSERVE.md`, `AUDIT.md` and
`PIPELINE.md`. Prepare fresh reviewed build/runtime inputs and a new ignored
output directory; do not reuse historical owner observations blindly. The entry
points are:

```sh
python3 -B "$REPO/evaluation/e9-common-app/observe_originals.py" \
  --inputs "$ORIGINAL_INPUTS/inputs.json" --inputs-sha256 "$ORIGINAL_INPUTS_SHA256" \
  --raw "$ORIGINAL_RAW"
python3 -B "$REPO/evaluation/e9-common-app/audit_originals.py" \
  --inputs "$AUDIT_INPUTS/inputs.json" --inputs-sha256 "$AUDIT_INPUTS_SHA256" \
  --raw "$AUDIT_RAW"
```

These are reproduction pointers, not new executions. Restore the exact recorded
environment, affinity and enclosing command/limits from `commands.json`; retain
the actual parent wait separately.

The four historical verifier compiler/archive recipes are now supplied as
**byte-identical sources** in [recipe-sources/](recipe-sources/), together with
[recipe-sources.json](recipe-sources.json), which fixes their exact ignored
locations and hashes. The fifth file, `admit-v2.py`, is a hash-only provenance
dependency: the four recipes check its bytes but do not import or execute it.
Do not run that older admission script as part of this reproduction.

Recover this entire source packet into a fresh checkout's ignored directory
**before** detaching to the tested revision; these newly published files did not
exist in that revision. For example, with absolute caller-selected coordinates:

```sh
mkdir -p "$REPO/ignored"
cp -R "$PUBLISHED_PACKET" "$REPO/ignored/verifier-source-packet"
git -C "$REPO" checkout --detach 9884b7a259b4e0ea80d2cca6d726abab4594807a
/usr/bin/python3.9 -B "$REPO/ignored/verifier-source-packet/materialize-recipes.py" \
  --repo "$REPO"
```

[materialize-recipes.py](materialize-recipes.py) is a new, unexecuted copy-only
utility. It verifies all five source hashes and the clean 9884 checkout, then
creates only the absent exact ignored source paths. It never compiles, runs a
recipe or changes existing files. Use a fresh checkout: occupied historical
source/output paths are refused, not replaced. A partial copy interrupted by a
failure is also retained; inspect it and use a fresh destination checkout rather
than deleting historical evidence or assuming automatic recovery.

Prepare fresh original inputs and run the committed
`evaluation/e9-common-app/build_inventory.py` according to `BUILD.md`, with its
new raw directory exactly `ignored/a3/common-native-epoch-v1/build-v1` in this
checkout. Reproduce the declared original-derived placement profile and complete
twelve-stage build from the companion build/control report. All required Cargo
products, source owners, tool/configuration snapshots and compiler request records
must exist and pass the unchanged prerequisite checks. Historical owner tuples
and input digests cannot substitute for this fresh build epoch.

The mapping is attempt1→producer-v2, attempt2→producer-v3,
attempt3→producer-v4 and attempt4→producer-v5. For each, the corresponding
`verifier-archive-attempt-N` context in `commands.json` supplies the complete
recipe argv, cwd, environment and caller affinity; the paired
`verifier-compiler-attempt-N` context supplies the exact compiler and outer limits.
Run that caller command explicitly only after the fresh prerequisites and resource
admission are ready, with the recorded zero core-dump limit and direct parent wait
recorded separately. The recipe itself invokes the existing bounded helper with
60 CPU/90 wall/128 MiB, timeout100/kill-after10 and parent115. Materialization does
not perform this step and grants no archive admission.

The experiment assertions are unchanged. These recipes can reproduce the
procedure, but a later run is not guaranteed to reproduce the nondeterministic
ancestor-directory timestamp failure. Record its actual exit and all saved maps;
never force exit1, suppress a stability check or relabel a compiler-only success
as a complete archive. The four reported historical failures remain unchanged.
