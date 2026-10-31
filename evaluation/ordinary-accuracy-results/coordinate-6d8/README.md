# Two-coordinate campaign at 6d8

**Campaign FAILED; both native cells ran once.** Short K=1 aborted with SIGABRT at the legacy report-capacity assertion in `normal/module/session/check.rs:568`, which accepts N×10 or N×1000. No CALL/RESULT/CALLTIME, DONE or PMUCLOSE rows were emitted. This was a capacity-contract failure, not a 2 ms timing miss ([issue #37](https://github.com/rrnewton/liteinst2/issues/37)). OS reap does not establish SDK/PMU shutdown.

Long K=1000 passed the full structural reader: 2,048 calls, 2,044 sampled and four unsampled (removed owners). Its 13 ARMs had maximum lateness 18,137 ns under the unchanged 2 ms gate. First release was 371,146 ns late relative to the fixed target; phase remains UNRESOLVED. All 4,096 PMU reads returned 32 bytes, with 2,048 full-running windows. None of this qualifies PMU accuracy, native state, phase, hardware, performance, executable retirement or the matrix.

All seven actions ran once, without retries. Five setup actions passed; controls executed 130 Rust/104 Python tests (507 Rust names were separately listed). Each preparation passed five stages including 16 coordinate controls, retaining all materials/24 policies/2,048 inputs. The 43,200-cell denominator has one structural pass, one failure and 43,198 unattempted cells.

Source `6d8e99c21e97d5e5ca8bcf2ad10b7b6926dde2dd`; AMD EPYC Zen 5 dev host; one lease on CPUs 188/281/306 (controller/worker/producer). Receipt durations/loads describe setup/validation, not throughput. Parent exit 0 and absent PID/scope/ledger records close only the lease. Rust release optimization is 3; C fixtures use -O2.

Reuse the [seven-owner recipe](../prepared-27e/README.md). Concatenate receipt argv_parts: strings name argv_fragments arrays; arrays give literal elements. Resolve COORD_* paths/CPUs/tools/session once into a fresh raw directory. Dependency hashes require new owner-first closures or independent current geometry acceptance. Retain one parent lease, capacity/source/tool checks and every outcome; never replace attempts.

Use COORDINATE_PREPARATION_PASS / COORDINATE_FUNCTIONAL_STRUCTURAL_PASS and the receipt's coordinate geometry kind/scope. Both actual geometries/all nine premises/current-boot proof require one nonrenewable 1,200-second window. Setup failure stops dependencies. Closed short failure allows one planned long only after exact FAILED/attempt1/reap/source/retention/custody joins; unknown custody, rescue, source change or lost lease stops work. Aggregate failure remains.

rows.csv keeps original ends/fences, populations and actual timing samples; blank cells are absent/unavailable after abort. The 15 s producer bound and every identity/ARM2/history/2 ms gate remain unchanged. Invocation enclosures are not exact physical leaf entry/RET; no epsilon/modulo relabelling is used.

[97ab failure](../coordinate-97ab/README.md), [6d8 repair/full gate](../coordinate-fixture-6d8/README.md), strict-clock 1 PASS/4 FAIL and all earlier failures retain their outcomes. Raw captures/inventories remain private and hash-bound.
