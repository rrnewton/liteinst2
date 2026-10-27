# Dynamic Linux page mode

This Linux x86-64 prototype runs a real dynamically linked `/bin/ls` without ptrace. It combines lazy executable-page admission with kernel traps for selected instructions. It does **not** patch instruction bytes (`source_patches=0`); the owned-region core-patching implementation in `liteinst-inprocess` is a separate backend.

Run the release comparison from a committed repository root with no tracked changes:

```sh
python3 evaluation/inprocess/dynamic.py --repeats 5
```

Required repository validation is separate:

```sh
python3 evaluation/inprocess/checks.py --expect-revision "$(git rev-parse HEAD)"
```

This runs the existing 330 recorder controls, formatting, strict all-feature/all-target Clippy, workspace tests, all-feature/all-target checking, and the full serial launcher suite. It reuses the admission corpus/parser and process cleanup. Its explicitly named new profile gives workspace tests 900 wall seconds, including build time; prior 360-second failures remain failed records. The other five bounds remain unchanged. Validation requires all source inputs committed and writes compact receipts with raw logs retained under `target/evaluation/inprocess`.

The runner builds with `tools/page-mode/build.sh`, pins each fresh child to one allowed CPU, compares reference/instrumented stdout, and records exact source revision/tree, compiler, CPU/kernel, commands, controlled environment, binary/capture hashes and numeric observations. Build products go to `target/page-mode`; exact tested copies and raw captures go to `target/evaluation/inprocess`. The typed receipt goes to `evaluation/inprocess/results`. No earlier measurement is substituted for this run.

The real commands, each in the same fixed directory containing `alpha.txt`, `beta.txt` and `subdirectory`, are:

- `/bin/ls -d .`
- `/bin/ls -ln --color=never .`
- `dynamic_probe`

Numeric `-ln` is intentional. Ordinary `ls -l` may invoke NSS socket lookup; socket/network calls are outside this profile and cause an explicit status-125 refusal. They are not emulated or silently bypassed.

The dynamically linked probe exercises actual CPUID/RDTSC/getpid and data mmap/write/mprotect/read/munmap. It warms one directory scan, then measures exactly 1,000 more real openat/getdents64/close scans, checking all five expected entries on each scan. Two clock syscalls bracket the interval. The read-only `li2_dynamic_snapshot` API exposes actual NX/syscall counters: all 4,002 interval calls must be dispatched and forwarded, and the NX count must not change. Reference backend counters are null. Formatting/exit after this interval can touch other pages; no global zero-fault steady-state claim is made.

Process-wall time includes fresh child creation through reap and harness overhead; the repeated-loop clock is reported separately. NX service clocks start inside the C handler, so they exclude kernel signal delivery/return and are not full first-touch latency. Unavailable final timing is null and cannot pass the measurement. Pairs run reference first and share host/filesystem caches; results do not establish cold-cache performance or universal overhead. Child bounds are 3 CPU seconds, 256 MiB address space, 1 MiB per capture and 10 wall seconds. The runner kills a timed-out process group and reaps its direct child; it does not claim custody of escaped descendants.

## Mechanism and coverage

Activation starts in the preload constructor. Loader activity and any earlier startup are outside coverage. Actual loaded ELF executable segments must be readable and nonwritable. The constructor removes execute permission from all collected main/DSO code pages except this runtime and the vDSO. An actual kernel instruction-fetch fault restores RX to that exact retained page once. No complete instruction-head proof is inferred from symbols or linear decoding. This is page admission, not a source-publication proof.

`ARCH_SET_CPUID`, `PR_SET_TSC` and Syscall User Dispatch trap selected execution independently of NX admission. The only syscall exemption is the private assembly gateway/restorer range; there is no mutable ALLOW selector. The handler passes all six original arguments to the genuine kernel syscall and retains raw negative errno, original-next-PC RCX and original RFLAGS in R11. CPUID/RDTSC/RDTSCP return actual hardware results with architectural zero extension; other saved registers, flags and FP state remain for kernel signal return. Only exact unprefixed encodings are supported. RDRAND/RDSEED/RDPID interception is not implemented.

Before activation returns, trapped CPUID(0) outputs are compared with native pre-activation outputs, trapped getpid with a private-gateway result and exact RCX/R11, and trapped RDTSC with native before/after bounds plus zero extension. Separate selfcheck counters prevent these probes from masquerading as application operations. Compatible kernel controls, hardware and synchronized TSC are required; unsupported activation fails closed.

## Execution contract

The constructor verifies one actual task, no active shadow stack, no user signal handlers, and unblocked SIGSEGV/SIGSYS. It installs a 512 KiB alternate stack between two PROT_NONE guards. Handler code uses raw syscalls, fixed storage and lock-free atomics, without libc, allocator, TLS or locks. A private duplicate of stderr survives coreutils exit cleanup and carries diagnostics. This changes observable descriptor/signal state and is a cooperative experiment, not a sandbox.

`ordinary_syscall` is the explicit allowlist for normal file/directory queries, data I/O, identity/time queries and selected process-local services, including read-only xattr queries. Data-only nonfixed mmap, nonexecuting mprotect and munmap have protected-range checks. New executable mappings, fixed mmap, protected mapping mutation, threads/process creation, exec, socket/network calls, signal reconfiguration and unknown syscalls terminate before the unsupported operation. Query-only signal APIs return the actual runtime-installed state. No Python/JIT/dlopen or general signal-transparency claim is made.

This backend lasts until real exit/exit_group; it does not disarm into an arbitrary caller. Default asynchronous termination and unsupported application faults are outside the demonstrated successful profile. Existing seccomp/tracing/audit or other policies must not depend on the original syscall PC, user stack or signal context: forwarding occurs at the private gateway on the handler stack. Address-insensitive seccomp is not categorically excluded. Cooperative code must not bypass the gateway policy, rewrite protected runtime storage, change PKRU/control state outside the profile, or race constructor enumeration. Neither adversarial isolation nor unchanged timing/signal-disposition observation is promised.
