# VPTERNLOGD256: finite qualification and remaining application failure

This change adds canonical original-PC EVEX.256.W0 VPTERNLOGD256, with a register or full 32-byte memory source, every immediate value, and the old destination as the first Boolean input. It preserves the original address, complete architectural comparisons and memory-read faults. Masks, broadcast, other widths and store authority remain outside this capability.

Measured revision `9b60724f14fe2ab99ffc046ab41ae22da8b62ff8` passed the complete finite instruction cohort and all required regressions below. The unchanged real late-DSO application still fails at the next unsupported instruction, Code 2784/VPTESTMB256. Full B3 and application completion remain unqualified.

[Qualification data](2026-10-29-vpternlogd256-qualification.json) is 40,642 bytes, SHA-256 `e3dc53341d5eb5df90c4a8fd4f65ea440df2de481a82dfeb67e6aa7848520f5c`. It retains exact original public/private receipt hashes, revisions, trees, source manifests, hardware/CPU, reproduction commands, bounds and numeric outcomes. Raw state and logs remain private. Shared metadata and status dictionaries reconstruct the original values exactly; the failed precursor's never-launched slots use explicit ranges and a null template. Every observed ternary process row remains literal.

| Cohort | Retained result |
| --- | --- |
| New ternary | All 147 processes qualified: 2,250 selected cases, 2,391 completed pairs, six real failed reads |
| Truth and geometry | All 256 immediates × eight input patterns, plus 202 structural cases; 401 ending/1,849 crossing |
| Queries | 4,512 actual-before footprint queries; 32,634 supplied refusals |
| Zero and REP Q/D | Both full-range zero helpers; six positive Q pairs and six D pairs, each with its original failed operation and refusal controls |
| REP lease | All 46 profiles; 24 completed pairs, two native failures, four real signals, 28 supplied mutations and 108 reader refusals |
| Original effect/rseq | Six selected owners; 49 selectors with 48 failed operations/one refused site; 17-case rseq with two completions/15 refusals |
| Native pair | Original 16 registered/four boundary pairs, then 22 profiles/44 subjects; 11 completed pairs, 11 required refusals, 675 reader controls |
| Six instruction regressions | XOR256 193 selected/four read faults; XOR128 96, BZHI 25, BMI1 96, VPMINUB 96, KORTESTQ 80 selected cases |
| Required checks | All six passed: 350 recorder tests, fmt, clippy, workspace 3,545 passed/37 ignored across 103 harnesses, workspace check, serial 1,039 passed across 27 harnesses |

The 2,391 ternary completed pairs are 2,250 selected cases plus 141 positive startup pairs. All 147 startup prefixes are retained, including those in the six separate failed-read processes. Constant-zero and constant-one memory forms must still fault on unreadable memory. Supplied controls and required failed operations earn no completed-instruction credit.

New native subjects retain limits of five CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB file size on one CPU. Stdout/stderr capture is bounded at 65,536 bytes; complete native records remain below 16 MiB. Workspace tests retain 900 seconds and serial launch 180 seconds. Other original cohort bounds, including the late application's 30 CPU/60 wall seconds, remain explicit in the data. No limit was raised.

Two overall failures remain recorded:

- At `69f258e36b03`, group 0 completed 16 new cases/17 pairs. Group 1's record allocation returned FD 4, and the unchanged FD 3 guard rejected it before spawning. One of 147 subjects launched; 146 did not. The failed receipt retains incomplete cleanup. Correcting journal descriptor lifetime did not relabel that attempt.
- At `9b60724f14fe`, native late-DSO completed two real load/close/reload cycles, 12 effects, 24 live-state snapshots and 19 controls. Gated execution exited 125 after 7.429757836 seconds with loader 1207/detail 2784 and empty stdout/record. Its lifecycle pair remains unqualified.

The separate twelve-case storage component passed in 2.712557859 seconds on CPU 3, with zero native subjects and zero architectural-reader replays. It uses authenticated c14 completed and required-exit-125 records; those keep their historical source identity. The unchanged `page_record_storage_controls.py`, original relative arguments and portable replay arguments are recorded. Exact reproduction requires retained private captures. Accepted native records are stored losslessly; projection verifies every retained stream's original length and SHA-256.

To reproduce the compact projection, run `python3 -B evaluation/inprocess/page_vpternlogd_qualification.py --root ${REPOSITORY} --output ${NEW_OUTPUT}` with the retained receipts/captures. Each row's command template reconstructs its exact original public reproduction argv. Projection adds no native execution, performance evidence or architectural-reader replay. No assertion, comparator, tolerance, cap, required case or failure classification was weakened. Existing performance evidence remains separate.
