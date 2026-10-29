# Full-state selected-effect fixture

The five fixed reference trajectories cover all seven selected classes in 17
operations. Native + post-native execution remains mandatory: it records the
real hardware/syscall result before applying the original reference reply,
including both actual masked CPUID samples. A separate explicit `scripted`
policy supplies the same replies before the effect and binds no post callback.
The Scripted lane requires zero selected native attempts, returned native
results and raw kernel issues. Initialization observations remain literal;
CPUID hardware setup is not misrepresented as a selected instruction sample.

Both policies retain complete source, memory, signal mask, GPR, raw context and
architectural XSTATE comparisons against fresh same-CPU raw/model/trap native
references and the independent format probe. Seven canonical CPUID/RDTSC/SYSCALL
sites must genuinely publish, restore and retire through UD2; the other ten use
the exact direct NX path. Completion is the next unexecuted NX boundary, not
whole-program termination. This finite profile disables libc rseq; real normal
loader/default-rseq application qualification is a separate required cohort.

`prepare.prepare(..., policy='native-post')` and `read.record(...,
policy='native-post')` preserve the original default. For the distinct Scripted
lane, pass `policy='scripted'`, compile the resulting `be_policy.c` with the same
18-TU/17-macro recipe, and run actual DWARF through `scripted_layout.py`. The
layout contains no post-callback symbol; the actual retained binding is NULL.
`read.cohort(..., policy=...)` requires all five ordered independent subjects of
that exact policy, all 17 rows and the original seven/ten ingress counts. A
Scripted result never substitutes for the mandatory Native+post-native result.

The private execution helper composes a fresh reference cohort followed by both
five-subject policies on one reserved CPU. Each process retains the original
30 CPU-second, 60 wall-second, 512 MiB and 16 MiB bounds. Failed attempted rows,
raw captures and cleanup failures remain authoritative; no retries or omitted
samples are accepted.
