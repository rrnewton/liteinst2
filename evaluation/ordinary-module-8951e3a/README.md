Two normally loaded functions share one source page, publication, attachment and
epoch at revision 8951e3aa3bc75dd8abd38916582c816dc4046acf. The 126-byte CSV
field scanner uses certified blocks; the 41-byte bounded-length function retains
the whole-function policy. Both complete original RET sets were observed.

One fixed release qualification ran K16 then K1, once each with no retries. Each
cohort completed 32 original and 32 installed calls with identical expected
results. K16 retained 32 samples; K1 retained two and recorded 30 FunctionClosed
calls. Every cohort checked all 512 journal words, 32 function-tagged records,
function-local ranks, global slots, two history actions, 31 next-entry
acknowledgements and the final actual-return checkpoint. The two CSV files retain
all 64 installed-call observations and their corresponding original results.

Reserved CPU 185; one-minute load 53.58 to 64.79. Both children exited normally
with ECHILD closure and no rescue. Their operational durations were 0.337 and
0.327 seconds; whole qualification took 92.238 seconds. These and raw TSC words
are not performance or accuracy measurements. Release uses opt3, debug0,
assertions and overflow checks enabled. The exact recipe, commands, hardware,
reservation, artifact hashes and fixed bounds are in receipt.json; reproduce with
evaluation/ordinary-module/reproduce.py under a fresh one-core cpuset reservation.

All seven checks passed on the exact source revision: default-parallel workspace
3,160 passed, zero failed, 36 ignored in 347.093 seconds; serial launch 1,039;
staged allocation three; prefixed-pun 36; fmt, strict workspace Clippy and
all-feature/all-target check. Eight runtime controls, four consumer controls and
eight Python controls cover the new guards. Existing controls are preserved.

Root independently rechecked all 84 original evidence/input/tool pins, both
complete ELF extents and the actual 20-byte Rust caller's CALL/result-store
continuation. Independent source reviews cover the composed exact revision.
Raw logs and ELF captures remain ignored. Separate four-call native-state
qualification is pending. This finite sequential module does not establish
nested/general module support, whole-application coverage, accuracy or full A5.
Earlier fixed five strict 2 ms results remain FAILED, PASS, PASS, FAILED, PASS;
this is a different functional experiment and does not add a sixth attempt.

After merging main 5a0bcf651e6b41d318a6202fb061c9fcd8351af0, all seven
checks passed at afe0629e3bd77d210ed0aba4a370586809494dfd: workspace
3,160 passed, zero failed, 36 ignored in 338.192 seconds; serial launch 1,039;
staged allocation three; prefixed-pun 36. The source, functional driver and
custody helpers are unchanged from the functional revision, and all 84 original
retained pins still match. merged-checks.json records the exact commands and
closure. This does not claim the separate admission evaluation pipeline ran.
