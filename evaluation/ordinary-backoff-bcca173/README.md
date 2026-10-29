# Ordinary back-off ownership and fixed-work qualification

Source revision: `bcca1737a4a0fd451a46075406e0c91116fabee4`.
This adds ordinary CALL/RET work under periodically rearmed K10/K1000 admission,
plus a separate native control that retains an old owner across two reclamation
attempts and releases it on the next entry, before checkpoint. It supports
claim 4 (systematic validation); A5 remains open.

The two required native controls passed. They each completed 3,072 calls,
1,536 helper returns, 128 complete journals, two Reports and three history
actions. Both demonstrated two SharedOwner refusals, one copy of the old Report,
next-entry reclamation before checkpoint, and all three banks returned.
The six actual phase rows are in `owner-phases.csv`.

The predeclared five K10/K1000 pairs finished with **9 PASS, 1 FAILED, 0 UNRUN**.
K10 passed four of five; K1000 passed five of five. The nine accepted transcripts
contain 27,648 call rows. All four passing K10 trials observed FunctionClosed
calls followed by sampling in a later generation. The K1000 timed trials sampled
all calls; the separate K1000 owner control supplies its forced closed-owner
coverage. Full call/journal/Report captures remain private under `ignored/`.

Trial 1 (K10) terminated with SIGABRT at the controller's required stop check,
with no stdout transcript. Authenticated source control flow implies an
EpochLimit stop before the application requested shutdown. The failed process
exported no arm count or complete work population. Its original 520-epoch limit
and requested-stop assertion remain intact. No retry was made and no scheduler
cause is established. The failure, raw-output hashes and all ten outcomes are
retained in `receipt.json`, `qualification.json` and `trials.csv`.

The AMD EPYC Zen 5 dev host had 316 available logical CPUs. The actual allocator
reserved CPUs 198, 204, 312 and 313 and verified hard AllowedCPUs containment:
producer 198, application 204, controller 313, spare 312. Recorded one-minute
load was 120.98–140.74. This cooperative reservation establishes neither a quiet
host nor exclusive hardware. Release optimization was 3, debug information 0,
assertions and overflow checks enabled, four compiler jobs and no incremental
build. The outer owner closed normally with exit 1, preserving the failed trial,
and required no descendant rescue.

All seven original checks passed at the source revision. Default workspace
parallelism used the 316-CPU affinity: 3,120 passed, 0 failed, 36 ignored, plus
the existing custom harnesses. Workspace execution took 355.245 seconds within
its unchanged 360-second limit. Serial launch passed 1,039 tests, staged
allocation passed 3 and prefixed pun passed 36. Formatting, strict workspace
Clippy and the workspace compile check passed. `checks.json` records commands,
limits, terminal counts and private-log hashes. The fresh release prerequisite
passed all 34 stages and all 50 specified Rust/Python controls. Development
records retain the initial lint refusal and a root invocation made before its
source import completed; neither is native qualification evidence.

Reproduce from a clean checkout at the source revision. Save `reproduce.py`
outside tracked files before checking out that revision; the evidence commit
comes later. Run the workspace checks separately first:

```sh
python3 -B evaluation/admission/check_exec_identity.py --checks-only \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/FRESH_CHECKS"
python3 -B "$REPRODUCER" --repo "$REPO" --raw "$REPO/ignored/FRESH_RUN" \
  --allocator "$CPUSET_ALLOC" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`CPUSET_ALLOC` names the executable cpuset-alloc entrypoint. Supply the host's
actual user-session/ledger environment; the reproducer invents none. It performs
one fresh prerequisite, two required owner controls and ten fixed trials, with
no retries. It retains every failure and withholds timed trials if an owner
control fails. It is source-reviewed but has not itself been executed; the
recorded run used the independently reviewed root launcher and the same exact
tracked driver. Both frozen protocols are included. Complete original commands,
logs and captures stay private and are bound by the public receipt hashes.

These are functional results. They establish no throughput, cheap inactive
path, raw-tick accuracy, full 520-arm qualification or full-A5 result. The earlier
five strict-2-ms outcomes remain FAILED, PASS, PASS, FAILED, PASS; this distinct
fixed-work catalog does not replace them.
