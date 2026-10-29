# Fixed four-mode ordinary-call elapsed observations

The single frozen qualification at `a29012f08baf7a5a334103ea9e8c95b3ffe45888` completed **20 PASS, 0 FAILED, 0 UNRUN**, plus both pending-owner controls. Each measured process executes 3,072 calls, 1,536 helper returns and 614,400 specified original instructions. All 2,600 raw setup/body/service endpoint rows are in `timing.csv`; `trials.csv` retains every process and `pairs.json` every exact numerator/denominator.

| Configuration | Segmented call time / paired native | Validated service / paired native |
| --- | ---: | ---: |
| Always-on | 16.67-19.60 | 0.528-0.575 |
| Back-off K10 | 14.68-18.48 | 0.452-0.624 |
| Back-off K1000 | 16.91-22.03 | 0.444-0.626 |

These are ranges of five fixed observations, without confidence estimates. Body spans enclose twelve guarded helper invocations. Service includes mode-specific validation and, for back-off, controller shutdown. Native performs different provenance validation work, so service ratios below one do not establish application speedup. Neither measure isolates pure observer cost. First preflight precedes service; setup plus service is not an exhaustive process partition. No subtraction or accuracy claim is made.

The only parser change moves timing validation ahead of the unchanged full functional population check. All eleven original controls passed under the unchanged 20 CPU-second/30 wall-second bound (12.340 seconds enclosing the control process). The prior qualification at `4e651e2` remains [FAILED with all 20 slots UNRUN](../ordinary-backoff-elapsed-4e651e2/README.md). This is one predeclared qualification at a changed revision, not an omitted or replaced failed attempt. No catalog, assertion, strict 2 ms gate, shutdown limit or resource bound changed.

All fourteen prerequisite stages passed, including the fresh 34-stage ordinary qualification. All 61,440 measured functional rows and 6,144 owner-control rows passed complete checks; 508 source files and release artifacts were authenticated before and after. Back-off processes observed 18-22 completed arms. Exact argv/token/PID/TID, timer, original-source and normal owner closure checks passed. The outer owner closed normally in 208.416 seconds with zero rescues.

The AMD EPYC Zen 5 dev host reserved CPUs 139/161/273/310 for producer/application/timer/controller through cpuset-alloc with hard AllowedCPUs. One-minute load observations ranged 40.45-115.03; no quiet-host claim. Release used opt-level 3, debug 0, assertions and overflow checks enabled, four build jobs and incremental compilation disabled. All seven workspace checks passed: default parallelism 3,127 passed/0 failed/36 ignored; serial launch 1,039, staged allocation three, prefixed pun 36, fmt, strict Clippy and workspace check. The two historical allocation regressions passed under default parallelism.

`receipt.json` records exact revision, hardware, command, environment, reservation, loads and private evidence hashes. `checks.json`, `qualification.json` and `development.json` summarize validation. Raw functional transcripts and logs remain ignored. A5 remains open; real-workload coverage, full synthetic accuracy and a fair perf comparison are not established here.

To reproduce, copy `reproduce.py` under `ignored/`, check out the exact revision, and supply explicit absolute `--repo`, `--raw`, `--allocator`, `--toolchain`, `--user-home` and `--cargo-home` arguments. Use a fresh raw directory and a hard-AllowedCPUs allocator. The public script is independently source-reviewed and unexecuted; the recorded experiment used the private launcher with the same tracked driver. It preserves a normally closed failure exit and does not promise a pass or scheduler quiet.
