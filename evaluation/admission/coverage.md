# Admission evidence scope

This ledger distinguishes implemented mechanisms, their finite validation corpus,
and remaining milestone requirements. Run `run.py` from the exact revision named
in a result JSON; expected assertions below become evidence only when that run
qualifies. Existing strict-backend negative fixtures remain required.

| Mechanism | Required evidence in this revision | Remaining scope |
| --- | --- | --- |
| Default selected policy | CPUID, RDRAND, RDSEED, RDPID, RDTSC, RDTSCP and SYSCALL dispatch; masked CPUID does not disable later callbacks | General loader/JIT/signal paths and complete per-class cost measurements |
| Random operand effects | Independent scripted model: both carry outcomes, all 16 GPRs, all three widths; raw CPU/replay/native-provider comparisons for the declared native corpus | Additional hardware and encodings outside the corpus |
| Overlapping selected starts | Default RDPID and deliberate RDSEED suffix entry; whole-instruction restoration and exact rearming | Unrestricted collateral instruction execution |
| Embedded selected bytes | MOV retains its original immediate and no extra callback; deliberate entry into the embedded instruction and continuation match the independent model | Other enclosing instructions explicitly refuse until separately qualified |
| Partial operation failures | Six private injections after real writes/protection/restoration/steps; exact held state, closed API, unexecuted continuation and pidfd-authenticated cleanup | No source-byte rollback claim after partial publication |
| Boundary publication | Cross-page selected decode and conservative CALL return into a never-executed page retain complete closure | Arbitrary saved frames and concurrent dynamic contexts |
| Declared syscall aliases | INT 0x80/SYSENTER input conventions, declaration refusals and explicit provider faults | Successful alias execution/return conventions |
| Lifecycle registry | Non-reused task/mm IDs, clone/fork/vfork/exec ordering, retained signals/resumes, invalidation and rollback on bookkeeping errors | Actual native dynamic ownership, signal delivery, exception return, mapping churn, dlopen, JIT and real applications |
| In-memory oracle chain | Exact fact reuse, immutable refusals, bounded storage, stale/poison fallback, dependency invalidation | Live integration, verified persistent metadata and sparse overlays using the core artifact contract |

B2 is still incomplete while selected aliases and broader execution coverage
remain unqualified and its required cost metrics are missing. The registry is a
B3 foundation; a held registry record alone is no native exclusion proof. The
cache is a B4 foundation; it accepts no persistent artifact and makes no offline
or sparse-overlay equivalence claim. Actual application startup, throughput,
cache hashing, overlay memory and software preemption-clock evidence remain
unmeasured by this validation protocol.
