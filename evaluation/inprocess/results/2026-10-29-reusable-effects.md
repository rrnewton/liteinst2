# Reusable in-process effects

ADDS real `/bin/ls -d .` completion with in-process CPUID, SYSCALL and RDTSC
patching, plus trusted linked Native/Scripted callbacks for all seven selected
instruction classes. The Linux x86-64 gate requires no ptrace supervisor.

The release run at `54cfe04f8c81e11faa7113edf3e0e8cf9b3a3631` preserved default
inactive rseq registration. Native and gated processes both exited zero with
identical output. All 148 temporary patches were restored: 38 CPUID, 100 SYSCALL
and 10 RDTSC. There were 147 returned effects; the final nonreturning exit is
explicitly unreturned, uncommitted and unretired. All 5,728 native admissions
closed.

On the recorded AMD EPYC 9D85, first admission took 84,277 ns. All 16 retained
revisit measurements were 79,469–90,076 ns. These measure admission work only.
The single whole-process intervals were 13,386,414,070 ns gated and 4,180,993 ns
native; they include launch/capture overhead, and gated namespace sealing.
They establish neither steady application throughput nor a causal speedup.
Exact hardware, binary identities, commands and individual measurements are in
[the release receipt](20261029T112406.460474Z-page-selected-effect-ls-54cfe04f8c81.json).

Eleven focused evaluators passed at product source
`9d52dc39ea1d63e48140a74fb85ffd90f3e8646c`. Both callback policies matched full
architectural/XSAVE references for 17 effects spanning all seven classes;
five actual registered-word query overlaps refused before issue. The register,
vector and repeated-store instruction oracles include boundary and actual
memory-fault cases. The [compact numerical results](effect-integration-9d52dc39ea1d.json)
retain every evaluator's reproduction command and complete aggregate counts.
Only the real-ls evaluator/documentation changed between that source and
`54cfe04`; runtime source did not change.

The normal main/DSO application cohort still **fails** at unsupported iced
Code 1604 (`VMOVDQU64` with a 256-bit destination). Its later state/stress lanes
remain unexecuted. Real-ls completion does not establish full B2, unrestricted
program coverage, signals/threads, B3/B4, or application reuse-stress coverage.

At `54cfe04`, all [required checks](20261029T112539.823570Z-checks-54cfe04f8c81.json)
passed: recorder 350; formatting; strict Clippy; workspace 3,196 passed,
0 failed, 36 ignored across 103 harnesses; all-target/all-feature check;
serial launch 1,039 passed across 27 harnesses. The
[earlier failed attempt](20261029T112408.028249Z-checks-54cfe04f8c81.json)
remains failed: its search path selected an unusable C++ wrapper. The passing
run selected system `g++`, stable Rust 1.97.1 and Python 3.12.15; source, tests,
comparators and time limits were unchanged.

These bounded results support claims 1, 2 and 4 from the evaluation plan.
The subsequent publication commit adds these receipts and this summary only.
