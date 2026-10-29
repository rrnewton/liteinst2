# Libc vector paths and main/DSO application state

ADDS original-PC execution of libc's EVEX256 VMOVDQU64, VPCMPNEQUB and
KMOVD paths, allowing the in-process page gate to run both Native and
Scripted CPUID/SYSCALL/RDTSC application state cases across a normal main
executable and its DT_NEEDED DSO.

The new instruction oracles passed 410 instruction pairs and eight genuine
failed-read cases. Existing width variants and affected load, store,
comparison and short-string suites remain mandatory. Exact revisions,
hardware, reproduction commands and aggregate results are retained in the
compact [EVEX256](evex256-validation-2b0c610e90a7.json),
[rseq/store](evex256-rseq-736e035bb8a9.json),
[NEQ256](neq256-validation-e5d4136909fb.json) and
[KMOVD](kmovd-validation-5110f2d80b8c.json) receipts. Earlier failures remain
failures: one stale source manifest and the application's successive
unsupported instructions and startup-session observation.

At `1f8b35201bf98af8000d1f0ae9114dc64b263311`, both 18-operation application
state lanes passed full architectural/XSAVE comparison against the fresh
18-operation, 36-state native reference. Each lane published and restored
307 temporary patches: 111 CPUID, 180 SYSCALL and 16 RDTSC. There were 306
returned and retired effects; the final nonreturning exit is explicitly
unreturned and unretired. Each lane's genuine NX/E9/UD2 publication evidence
passed. This establishes the two state cases, not the complete application
cohort.

The same [four-lane receipt](20261029T122524.485984Z-page-selected-provider-app-1f8b35201bf9.json)
is **failed** overall: the 9,216-operation Native reuse-stress process was
killed with signal 9 after 30.197 seconds under its original 30-second CPU
and 60-second wall bounds. It produced no final publication record. The
Scripted stress lane was not executed. Neither stress lane receives capacity
or full-state credit. These validation durations are not performance results.

Two observation repairs preceded this run. The observer now copies the actual
completed startup session after the real self-test. The strict reader now
matches the producer's exact meanings for an authenticated landing mapping,
renewal epochs, and the SYSCALL step disposition. Genuine signal frames,
source bytes, restoration and full-state comparisons remain required. The
[earlier reader failure](20261029T121434.621556Z-page-selected-provider-app-86bd72ce24cc.json)
remains failed; it is not retroactively qualified.

Main `0a088d04a8a5e24ad7ad741c5469814336db95da` is merged. All
[required checks](20261029T121434.868088Z-checks-86bd72ce24cc.json) passed at
`86bd72ce24cc69e01215494d12859c5e04c18bae`: formatting, strict workspace
Clippy, all-target/all-feature check, 3,230 workspace tests (0 failed,
36 ignored, 103 harnesses), 350 recorder tests, and 1,039 serial tests
(27 harnesses). All 34 newly merged tests appear as `ok` in the saved output.
Only the two application-reader files changed between that tested revision
and `1f8b352`; Cargo and recorder sources and checks are identical.

The bounded results support claims 1 and 4, and claim 2 for the three selected
instruction classes exercised by this application. They do not establish
unrestricted programs, active rseq, threads/signals, full B2/B3/B4, reuse-stress
capacity or a new performance result. The subsequent publication commit adds
only these compact receipts and this summary.
