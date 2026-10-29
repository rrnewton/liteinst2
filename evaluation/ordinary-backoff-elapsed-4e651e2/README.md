# Ordinary back-off elapsed qualification: prerequisite refusal

Revision `4e651e2f2af283c8d61191598e52b6dcda3b969d` adds optional setup, twelve-invocation call-loop and validated-service timing to ordinary back-off work, plus a fixed native/always-on/K10/K1000 comparison. It merges main `16c74225cb92574e84db5764823e09b940aa65ca`.

The single frozen qualification failed before measured work: the elapsed-checker control process received SIGKILL after 20.6595 seconds, under the unchanged 20 CPU-second / 30 wall-second bounds. The helper reported no wall timeout, normal ownership cleanup and no rescued descendants. This is consistent with CPU-limit exhaustion; no direct CPU-use or kernel-cause witness was captured. Nine progress markers are not a completed test result.

Both pending-owner controls and all twenty measured slots are UNRUN. There are no timing observations or performance ratios. The fresh 34-stage ordinary prerequisite and three earlier checker stages passed. The original failed outcome remains in this directory; it is not replaced by later source work.

The actual allocator reserved CPUs 103, 192, 210, 245 for producer/application/timer/controller, with hard AllowedCPUs verified from the pinned allocator command and output. One-minute load observations ranged 84.41–126.71 on the AMD EPYC Zen 5 dev host. This was not a quiet-host qualification. Release preparation used opt-level 3, debug 0, assertions/overflow checks enabled, four build jobs and incremental compilation disabled. Raw logs and captures stay ignored.

All seven exact-revision checks passed: workspace with default parallelism on 316 available CPUs: 3,127 passed, zero failed, 36 ignored; serial launch: 1,039 passed; historical staged allocation: three passed; prefixed pun: 36 passed, plus format, strict Clippy and workspace check. Existing custom harnesses also completed. The complete call/ownership checks and strict 2 ms scheduler gate remain unchanged. No full-A5 claim is made.

`receipt.json` records exact source, hardware, normalized command, reservation/load and private evidence hashes. `trials.csv` retains all 20 statuses. `qualification.json` and `checks.json` contain compact validation results; `development.json` retains all five development invocations.

To reproduce, save `reproduce.py` under `ignored/`, check out the exact revision above, and invoke it with explicit absolute `--repo`, `--raw`, `--allocator`, `--toolchain`, `--user-home` and `--cargo-home` arguments. Use a fresh raw directory and a cpuset allocator with hard AllowedCPUs. The script is source-reviewed and UNRUN; the recorded run used the reviewed private launcher with the same tracked driver. This script preserves a normally closed failure exit. Reproduction does not promise scheduler quiet or a pass.
