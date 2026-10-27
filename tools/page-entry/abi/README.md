# Independent first-entry ABI check

Run the additive committed-source check on a reserved CPU:

```sh
python3 evaluation/inprocess/first_entry_abi.py --expect-revision COMMITTED_SHA
```

This correctness cohort links the current production bridge entry body unchanged.
An external assembly endpoint captures kernel-origin GPRs, PUSHFQ-visible flags,
XGETBV/XSAVE state, FS/GS bases, selectors, full initial stack VMA and PHDR bytes
before entering that body. A separate original-interpreter fixture captures the
actual post-transfer state into independent BSS. It never reads the pre record
or production save buffers. Each record is completely written to an inherited
private file before the pre endpoint restores its own state and enters the
bridge. The parent reads the sequential records only after the child is reaped.
Missing, extra, reordered or duplicate records refuse.

The comparator binds each ELF e_entry to its actual endpoint symbol and the
executed capture PC. Positive capture labels equal the entry; the two deliberate
negative prefixes are separately authenticated. Every GPR, flags value, base,
selector and stack byte must match. The only stack transformation is the unique
AT_BASE value, independently checked against each image's actual entry load
bias. The PHDR address stays unchanged; its before/after contents must be the
carrier/original table. RIP intentionally changes between those exact entries.

Both raw 64 KiB XSAVE arenas are retained privately. Comparison covers explicit
architectural x87/SSE/AVX/AVX-512/PKRU fields, including architectural initial
values for absent components; unknown active components, compacted/supervisor
formats and invalid component extents refuse. This measures actual kernel-origin
state, not separately seeded nonzero vector state. A distinct native exec checks
kernel-defined cleared GPR/base/selector fields; random ASLR state from different
execs is never compared for equality.

The positive pair must pass. Two actual interpreters deliberately change R12 or
one stack byte at RSP-8 and must fail at their precise comparator. Additional
supplied-record controls retain all original register/state/framing families,
cover every actual stack page, and reject mutated ELF entry fields. Their count
is derived from the observed stack and qualified XSAVE layout, not fixed to a
previous environment. Supplied profile controls verify unchanged old limits and
reject malformed overrides before any capture is opened or child is spawned.

The capture interpreter exits with status 23 instead of starting main. A real
sealed libc image supplies metadata to the unchanged object registry but is not
executed by this fixture. This does not measure real ld.so's entry registers or
make a performance claim. The real-loader evaluator and CPUID/RDTSC first-opcode
fixtures remain separate and unchanged.

Each native child is pinned to the capability-observation CPU with CPU 3 seconds,
address space 256 MiB, wall 10 seconds, and RLIMIT_NPROC 1 (exec without fork).
The ABI-only RLIMIT_FSIZE is 8 MiB **per file**, including stdout, stderr and the
private record file. A separate acceptance check rejects stdout or stderr over
1 MiB after capture; it is not a physical 1 MiB output cap. Record acceptance
requires exactly 2429312 bytes for native and twice that for each paired exec.
Build children retain the existing 30 CPU-second / 1 GiB / 16 MiB / 60 wall-second
profile. Existing invocation defaults are unchanged. Cleanup uses the existing
pidfd readiness, process-group kill and direct child reap, recording actual close
outcomes and preserving primary failures; escaped-descendant custody is not
claimed. Kernel RLIMIT_NPROC privilege semantics still apply.

Public receipts contain hashes, lengths, bounded metrics and comparison outcomes.
Raw records, maps, registers, compiler logs and binaries stay under target. Exact
revision, source hashes, tool identities and binary hashes are checked before and
after the complete attempt. Earlier prototype failures and results remain intact.
