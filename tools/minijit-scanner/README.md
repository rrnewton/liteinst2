# minijit-scanner

Standalone S3 prototype for classifying x86-64 instructions
without a full decode on the fast path. It is not part of the
liteinst2 workspace and is not used by `liteinst-jit` production
code.

Constraint stated upfront: **known boundaries only** — entry
points and branch targets obtained from a prior accepted scan or
full decode. The scanner never resynchronizes by guessing. When
an encoding form is not positively modelled, the result is
`needs_full_decode`.

Per instruction the table scanner reports length,
direct-relative branch/call, RIP-relative memory form,
interception target, and a conservative
`allowlisted_movable` bit. Interception follows the
`liteinst-jit` decode envelope: the syscall class (SYSCALL,
SYSENTER/SYSRET forms, INT/INTO/IRET) plus CPUID, RDTSC,
RDTSCP, RDRAND, RDSEED, RDPID, and XGETBV. The movable bit is a
scanner-proved subset of the P1a Ordinary envelope; all other
Ordinary candidates fall back to `liteinst_jit::decode`, so this
prototype does not become a second admission definition.

Run the oracle and benchmarks:

```sh
CARGO_INCREMENTAL=0 cargo run --locked --offline --release \
  --manifest-path tools/minijit-scanner/Cargo.toml -- \
  /lib64/libc.so.6 /usr/lib64/libLLVM.so.22.1
```

The driver extracts `.text`, compares scanner length and movable
classification with iced-x86 plus `liteinst-jit` admission at
every iced boundary, and exits non-zero on any length
disagreement or false movable. Speed cells are one warmup plus
exactly ten timed samples. See `RESULTS-20261105.md`.
