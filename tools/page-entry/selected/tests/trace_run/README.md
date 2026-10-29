# Additive TRACE to register-run oracle

This fixed standalone oracle calls the real chain/run proof APIs. It does not
exercise `selected_register_run.inc`, registered-rseq, custody/lease retention,
real applications or performance. The old four register-run, fourteen run-control
and twenty-three chain processes are unchanged and remain separate obligations.
No case from those populations is replaced by this seven-process cohort.

After applying the reviewed product and oracle sources, use one externally
reserved CPU and a clean exact revision:

```
PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/page_selected_trace_run.py --expect-revision <40-hex-HEAD>
```

The existing fresh `Build.prepare()` owns the sealed decoder archive and its
source/package/tool closure. The fixture's exact nine-TU recipe has compiler-M
closure, actual ELF import/segment/symbol checks and file-only DWARF. Each native
process retains the old 5 CPU seconds, 15 wall seconds, 512 MiB address space,
16 MiB file/record and zero core bounds; stdout/stderr are at most 8192 bytes.
The actual complete record has a C static 16 MiB bound and an independent
ELF/DWARF-derived bound. The public projection is below 10 KiB, with hashes and
counts; raw state and command artifacts remain in the private receipt directory.

## Genuine positive

One fixed original page holds ADD RAX,1; MOV EAX,0x12345678; MOV ECX,EAX;
ADD EAX,EAX. Initial RAX is 0x7fffffffffffffff. The first ADD really retires under
TF and produces 0x8000000000000000 with flags 0xa96. Its actual TRACE closes and
releases the predecessor, then the actual OLD_STEP successor is freshly borrowed
and released. Only the opaque offer from that event can admit a new borrow into
the run owner. Two MOVs execute in a genuine private publication; the original
ADD EAX,EAX remains an NX guard and never executes. A second complete lane is a
real cache hit, with a new proof and borrow and the same retained publication.

Before either gated lane, three independent native intervals observe the ADD,
the MOV block, and their whole sequence. Each uses the original instruction
bytes and an explicitly recorded INT3 at its distinct end; all three full source
images are retained. The block's input is the actual preceding native output.
The complete original source is restored before either gated execution. This
separate ADD reference matters because the following MOV overwrites RAX and
could hide a bad predecessor in an endpoint-only comparison.

The C fixture and independent Python reader compare all sixteen GPRs, literal
whole flags/PCs, full initialized kernel FP and standard XSAVE images, six actual
live segment selectors, FS/GS bases, signal masks, the whole 8192-byte private
stack/redzone and 4096-byte data region. Raw actual ucontext/siginfo bytes retain
physical alias checks. TRACE closure permits exactly its owned TF removal;
run entry permits exactly RIP replacement. Actual trap/RF/TF distinctions are
checked at their source-defined events; no observed frame is normalized.

## Required failed operations

Six separate processes must exit 125 with the exact required prefix: null
opaque offer; supplied RAX-frame mutation; a genuinely consumed proof replay;
real fresh-source release before entry; real same-thread tgkill while armed;
and a genuine predecessor read fault with a separate native failed-operation
reference. The null/frame changes are explicitly supplied inputs, not hardware
faults. The nested signal retains actual SI_TKILL sender identity. Failed owners
retain their actual source/publication prefixes; no generated redirect, run
completion, or successful native continuation is invented. All seven processes
also execute the unchanged 47 refusal checks and genuine native/NOP startup.

Eight additional reader controls alter a passed real record only. They include
a coordinated predecessor-result mutation whose final MOV outcome is intact;
the independent ADD literal model must reject it. These are supplied parser
controls, not extra native processes or signal observations.

The broader design's different instruction bodies, two-page geometry,
preflight-SLOW/no-borrow, fresh capacity-miss release, registered-rseq and actual
runtime-controller composition remain pending. Neither successful source review
nor this fixed API cohort alone supplies those missing qualifications.
