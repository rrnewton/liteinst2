# Recorder timing diagnostic

The private diagnostic completed all 366 original recorder tests in 168.435280357
seconds, within the original 180-second command bound. It is not a successful
required-check campaign. Both preserved required-check attempts timed out and
remain failed; their exact public receipt references are in observation.json.

The measured private packet was c1f231f1d9a01c1d3930c8afb3f0f71cd89489d1469c1a167d36a06bbc0ab09e.
These public run.py and recorder_parallel.py bytes are identical to that
execution. This public packaging/recipe has not been executed. SOURCE.json
pins the actual source inputs at cd435d120c3e77a5bce91459e6503e9e415bc5b0;
INVERSES.json and PATCH.diff preserve the exact four facade changes. The
scripts add diagnostic rows only; all original discovery, partition, worker
and aggregate validators are retained. Tests inspect the original tracked
source, while each child re-executes the private/public facade via __file__.
There is no caching, test subset, retry, build or qualification credit.

To reproduce, use a clean checkout of the exact source revision. The tools can
reside in a later checkout that contains this directory. Select both absolute
paths explicitly; the following is a portable recipe, not the recorded private
command. cpuset-alloc must be the installed reviewed CPU allocator. Keep its
parent affinity broad so its hard-containment probe can run.

```
RECORDER_TOOLS=/absolute/path/to/checkout-containing-these-tools
RECORDER_SOURCE_ROOT=/absolute/path/to/clean-cd435d-checkout
mkdir -p "$RECORDER_SOURCE_ROOT/target/evaluation/inprocess"
PYTHONDONTWRITEBYTECODE=1 AGENT_UTILS_ENGINE=python \
  cpuset-alloc run --cores 4 --tag li2-recorder-timing -- \
  python3 "$RECORDER_TOOLS/evaluation/inprocess/recorder_timing/run.py" \
  --root "$RECORDER_SOURCE_ROOT" \
  --expect-revision cd435d120c3e77a5bce91459e6503e9e415bc5b0 \
  --output "$RECORDER_SOURCE_ROOT/target/evaluation/inprocess/recorder-timing-reproduction-1"
```

Use a fresh output path. The existing admission.processes.run_command owns the
sole recorder command: 180 seconds, 8 MiB combined output, three-second descendant
cleanup, four workers, original controlled environment plus one explicit source
root variable. Full source/packet/configuration/CPU closure remains mandatory.
A diagnostic timeout returns 1 and keeps failed_prefix even when timings exist.

observation.json/CSV are compact projections from the retained diagnostic,
not raw logs. Module rows sum test callback intervals only. Worker spans also
include measured gaps: worker 1 has 4.915844200 seconds outside callbacks,
including a 4.911738745-second gap before the first DeclaredCorpusTests test.
That class's setUpClass runs outside the timed callbacks.
The two-module assignment model retains those gaps and projects worker spans
137.136881419/141.297148717/139.229581547/134.627418497 seconds. Changed scheduling,
setup/import/discovery and process overhead are not predicted. The model has
not run and cannot guarantee a later check will finish. All 366 tests and the
180-second limit remain required. Full raw timing logs and receipts stay
private; only their whole hashes are published here.
