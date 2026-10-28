ADDS: real unchanged-page execution in the in-process first-entry gate.
Certified pages become RX and execute at their original addresses without a
trap after each instruction. The runtime uses no ptrace supervisor. Pages
that contain selected or excluded opcode patterns remain with the existing
NX/TF controller. This unchanged-page profile keeps selected source patches zero.

The separate [one-shot publication profile](one-shot-publication.md) now
publishes and restores real syscall and RDTSC source patches. Its six-site
dynamically linked fixture completes, with restoration checked before the
kernel reads the original instruction bytes. The profiles retain separate
completion predicates.

At `1952a6bee08101b53151d59ab013902b48934f23`, canonical KMOVQ transfers
cover all 120 non-RSP register pairings. The
[new register oracle](results/20261028T070635.063273Z-page-selected-kmovq-register-1952a6bee081.json)
passes 168 full-state pairs; the
[original KMOVQ oracle](results/20261028T070751.660872Z-page-selected-kmovq-1952a6bee081.json)
passes 21, and the
[short-return oracle](results/20261028T070800.214323Z-page-selected-strrchr-short-1952a6bee081.json)
passes 61 plus its connected execution cases. Previous refusal byte strings
remain checked, with newly supported forms counted as explicit typed promotions.

The [latest real-program matrix](results/native-pages-1952a6b.json) remains
failed, with three of five cases passing under the unchanged bounds.
Rseq-disabled `ls` advances past KMOVQ and refuses `VPBROADCASTB ZMM17,ESI`,
bytes `62 e2 7d 48 7a ce`, code 3210. It closes all 4,951 admissions and
reports 39,945 NX faults. Default-rseq `ls` still ends in SIGKILL without a
terminal report. Source, tool, artifact and input checks pass; no failed
workload supplies a completed-program performance result. Earlier receipts
and their original outcomes follow.

The merged successor contains upstream main
`c0ddeee62aad2d06458f2a32cb775343730efb89`. It adds canonical register
VPTESTMB to the original-PC TF owner. All six checks pass at
`470e5110e2bbe22dda1b3342b68903d90a14404b`:
350 recorder tests (41.81 s), formatting (6.02 s), clippy with warnings denied
(15.70 s), workspace tests (355.46 s: **2,705 passed, zero failed, 11 ignored**,
101 harnesses), all-feature/all-target check (10.55 s), and serial launch
(130.32 s: **1,039 passed**, 27 harnesses). The 22 added upstream test identities
are included; historical assertions and required native protocols remain.
Source/configuration and cleanup checks passed. All six saved log hashes and
the complete original qualification parser were replayed successfully.
[New required-check receipt](results/20261028T064405.408729Z-checks-470e5110e2bb.json).

The merged-tree native instruction runs at
`d81a77a658cef48075eac62eb128822e33f33a64` pass:
[VPTESTMB](results/20261028T063808.399300Z-page-selected-vptestmb-d81a77a658ce.json)
76 pairs,
[VPTESTNMB](results/20261028T063824.139343Z-page-selected-vptestnmb-d81a77a658ce.json)
19 pairs, and
[VPCMPB](results/20261028T063832.780108Z-page-selected-vpcmpb-d81a77a658ce.json)
189 pairs. Independent replay verifies all **284 full-state pairs**, 1,774
refusals and 14 separately counted typed promotions. Promoted byte strings
remain in their original cohorts and require positive classification and
write-footprint checks. The current runtime, fixture and runner source files are
byte-identical: the only five files changed between this native revision and
`470e5110` are the admission check inventory and its calibration test.

The [successor real-program matrix](results/native-pages-d81a77a.json)
remains **failed, three of five cases passed**. Its release bridge SHA256 is
`1b5a84ab6701e145ea17ec982e3512be4e90b7659c463b5db1807f3da7cb97d6`.
All source/tool/artifact/input closure checks pass, with no final errors.
The hardware, exact commands and all raw integer timing samples are in the
receipt; timing scope and bounds remain those described below.

| Successor case | Result | Admitted / closed | Native command | Gated command |
| --- | --- | ---: | ---: | ---: |
| `true`, default rseq | completed, identical output | 415 / 415 | 3.605 ms | 10.638 s |
| `true`, rseq disabled | completed, identical output | 1,389 / 1,389 | 2.923 ms | 7.833 s |
| `ls -d .`, default rseq | SIGKILL, no terminal report | unavailable | 3.413 ms | 30.190 s |
| `ls -d .`, rseq disabled | exit 125, failure 100 | 4,928 / 4,928 | 3.487 ms | 19.902 s |
| Boundary fixture, rseq disabled | completed, identical 128 bytes | 174 / 174 | 3.426 ms | 1.318 s |

The rseq-disabled `ls` terminal now confirms VPTESTMB completed and then
refuses `KMOVQ RAX,K0`, bytes `c4 e1 fb 93 c0`, code 1933. Equal admission
counts do not imply that the stopping instruction stayed unchanged. The
completed `true` runs have first admission service times of 78.448 and
79.580 microseconds, and median services over 16 revisits of 78.3025 and
82.8095 microseconds, respectively. These remain admission-service samples,
not full first-touch latency or steady-state application throughput.
This successor supports claims 2 and 4; selected source patches remain zero
and neither `ls` failure becomes a completion result. The earlier receipts
and their original outcomes follow unchanged.

The opt-in release bridge is built by
`tools/page-entry/selected/build-native-pages.sh`: C at `-O2`, Rust decoder
with `--release`. The live owner verifies the complete page, executable
14-byte halos, sealed backing, aliases, generation and actual permissions.
It closes every admitted page before handing execution to another owner or
performing a selected syscall. An exact seccomp gateway filter closes the
legacy-vsyscall escape that SUD alone leaves open. The existing cooperative
singleton contract, reserved signals, no debugger and no application entry
into private runtime code remain required. Every actual executable mapping must
be at or above 8 GiB before native admission, so compatibility-mode entry
faults before executing an instruction. Registered rseq disables native
page admission, including when its current critical-section pointer is zero.

The [five-case real-program receipt](results/native-pages-45d8e92.json)
is from code revision `45d8e921f0df823edd26fa3d40208e6ff0b21ed7`, which
contains main `690cb9c4677ea4eb5401946c383c536f821295ad` and the earlier
requested `7ab79270` merge. Source, tool, artifact and input checks remained
unchanged with no finalization errors. The bridge SHA256 is
`db188011acd184c7f534e2fcf7928231d912ce83700d8e4a664b42b7440a096f`.
Execution used one reserved AMD EPYC 9D85 CPU and the receipt's exact
kernel, compiler, program and dependency identities. Native and gated
programs receive the same declared application environment; gated launch adds
the sealed-namespace library and dependency variables.

| Case | Result | Admitted / verified closed | Native command | Gated command |
| --- | --- | ---: | ---: | ---: |
| Dynamically linked `true`, default rseq | completed, identical empty output | 415 / 415 | 3.146 ms | 10.895 s |
| Dynamically linked `true`, rseq disabled | completed, identical empty output | 1,389 / 1,389 | 3.638 ms | 7.737 s |
| `ls -d .`, default rseq | SIGKILL; no terminal report | unavailable | 4.716 ms | 30.257 s |
| `ls -d .`, rseq disabled | exit 125, failure 100 | 4,928 / 4,928 | 3.549 ms | 20.208 s |
| Real-interpreter boundary fixture, rseq disabled | completed, identical 128 bytes | 174 / 174 | 3.475 ms | 1.368 s |

**The five-case matrix remains failed, with three passing cases.** Every
gated command retains the same 30 CPU-second, 60 wall-second, 512 MiB
address-space and 16 MiB file limits. The default `ls` outcome has no report
from which to infer a stopping instruction. The rseq-disabled failure reaches
unsupported `VPTESTMB`, bytes `62 b2 75 41 26 c1`, decoder code 2785.
Neither failed run supplies a completed-program performance result.
Whole gated-command times include namespace preparation; these are single
observations on a shared host, not instrumentation-only overhead estimates.

| Completed `true` configuration | First admission service | Median of 16 revisits | Revisit range |
| --- | ---: | ---: | ---: |
| Default rseq | 81.081 microseconds | 84.247 microseconds | 79.920–90.476 microseconds |
| Rseq disabled | 82.633 microseconds | 82.629 microseconds | 78.198–94.592 microseconds |

The JSON retains all raw integer nanosecond samples. Each interval uses
`CLOCK_MONOTONIC_RAW` from admission-owner entry through live bytes, backing,
halo, permissions and post-publication verification. Revisits identify the
same page address, allocation and generation. These measurements exclude
signal delivery and measure repeated admission service, not steady-state
instruction throughput or the full first-touch fault.

The boundary fixture executes a genuine CALL ending at a page boundary and
checks its original return word on a never-executed next page. That page stays
NX until its first fetch. It also exercises a split MOVABS: the owner retains
the genuine first fault, closes the old page, and returns the frame unchanged
for a second actual NX fault at the same RIP. Four main-page admissions and
one main refault complete with exact native output. This implements the
qualified boundary rule rather than assuming an unexecuted page cannot hold
a return address.

The [integrated vsyscall negative](results/native-pages-negative-45d8e92.json)
joins the same revision and exact bridge. All seven bounded commands satisfy
their expectations. The native legacy-time baseline completes with 48 output
bytes. The gated program publishes one main page, reaches the real CALL,
then refuses with exit 125/failure 602, emits only the 16-byte pre-call marker,
and verifies all 171 admissions closed. The prohibited operation remains
failed. Its runtime report does not contain raw SIGSYS metadata; the separate
exact-filter component below establishes the kernel mechanism. This negative
runner retains exits and reaping but did not retain the launcher PID, so its
reported owner PID has no independent saved launcher-PID join. The five-case
matrix does retain and compare its actual launcher PIDs.

Additional finite evidence supports claims 2 and 4:

- [Raw policy](results/native-policy-45d8e921f0df.json): 750,794 checks,
  including prefixed opcode and HLE patterns, all ModRM values for three
  excluded groups at 12 seams, allowed forms and 69 actual inaccessible
  neighbors. This qualifies the finite byte policy, not whole-program mode,
  mapping or rseq behavior.
- [RF component](results/native-rf-38224a8.json): 48 actual native/NX pairs
  over SYSCALL and CPUID, RF clear/set, six flag patterns including DF, and
  a preceding ordinary arithmetic epoch. All 16 GPRs, complete flags and
  512-byte legacy FXSAVE agree. This is not a full-XSAVE production-owner test.
- [Gateway component](results/native-gateway-38224a8.json): 28 real children,
  186 predicates and 17 supplied header controls. Native and SUD-alone lanes
  complete all three legacy vsyscalls; seccomp lanes trap all three. The
  trusted gateway works, and compatibility/x32 paths are refused. The two
  component receipts bind revision `38224a816ec03bc62907f88197a8c9bbceeab653`;
  their scripts, probes and filter are byte-identical at the final code revision.
- [Canonical VPCMPB](results/20261028T062256.587516Z-page-selected-vpcmpb-45d8e921f0df.json):
  nine actual native cohorts, 189 state pairs, 1,080 TF refusals, 360
  actual-before write-footprint queries and 657 unsupported-query controls.
  The admitted register-only 512-bit forms cover all vector/mask registers
  and signed predicates, with exact GPR/flags/kernel and live XSAVE checks.
- [Fast-reset composition](results/20261028T062334.948984Z-page-selected-fast-zero-45d8e921f0df.json):
  47 native processes across the unchanged generic, TRACE, register-cache,
  failure and REP cohorts. All 112 commands complete and preserve required
  failed operations. The actual bridge's 15-byte CLD/REP-STOSB reset is bound
  to SHA256 `9b0962fabb10968cfa175213396b8a63e6e8b81cce83547aea6e90223d21ec9f`.

All six checks passed at `45d8e921`: 350 recorder tests (42.64 s),
formatting (6.08 s), clippy with warnings denied (4.31 s), workspace tests
(350.10 s: 2,683 passed, zero failed, 11 ignored across 101 harnesses),
workspace all-feature/all-target check (3.12 s), and serial launch
(131.25 s: 1,039 passed across 27 harnesses). Strict precontext and both
backing-cleanup protocols qualified. Source and configuration stayed unchanged;
all commands completed cleanup. All six saved log hashes were verified and
the original evidence parsers and qualification gate replayed exactly.
[Required-check receipt](results/20261028T062238.221729Z-checks-45d8e921f0df.json).

The earlier [real-program run](results/native-pages-e0d94eb.json) retains its
failed three-of-five outcome and all raw timing samples. The earlier
[required-check preflight](results/20261028T061044.600310Z-checks-e0d94eb766db.json)
rejected the stale source inventory before running any command. The reviewed
inventory successor accounts for exactly 16 added rapid-profiler tests,
retains every old test and assertion, and agrees with actual test listings.
No failed result is relabelled. Earlier [raw-policy](results/native-policy-e0d94eb766db.json)
and [vsyscall-negative](results/native-pages-negative-e0d94eb.json) runs also
retain their original successful results at `e0d94eb`. The [prior finite projection](results/20261028-native-prior-finite-e0d94eb.json) retains both successful earlier VPCMPB and fast-reset runs with their original receipt hashes, exact revision, hardware, commands and numeric counts; it adds no new execution qualification.

Reproduce at each receipt's exact revision using its argument vector,
environment and limits; reserve one CPU for native runners and four for the
required-check suite. The production recipe and all evaluators are tracked.
Raw numeric results and hashes are public JSON; process logs remain private.
This is partial evidence for first-instruction coverage and systematic
validation (claims 2 and 4). It does not complete B2/B3/B4, establish selected
source patching, complete `ls`, or measure steady-state application throughput.
