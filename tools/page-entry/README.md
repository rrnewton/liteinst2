# First-entry Linux page admission

This Linux x86-64 launcher runs an original dynamic linker and application under
an in-process NX gate from the linker's first instruction. It uses a private ELF
carrier and explicit sealed copies of dependencies. No ptrace supervisor is
needed. The kernel-trap backend has `source_patches=0`; actual selected-instruction
source patches are provided separately by `liteinst-inprocess`.

The opt-in [partial selected controller](selected/README.md) adds original-address
ordinary stepping and native random/ID completion under a narrower execution profile.

Build the optimized runtime and its fixtures from the repository root:

```sh
sh tools/page-entry/build.sh
```

Run the prepared real `/bin/ls` through a fresh private dependency namespace:

```sh
python3 tools/page-entry/carrier.py exec-loader \
  --library-root /usr/lib64 --namespace target/page-entry/ls-namespace \
  target/page-entry/ls-carrier /bin/ls -- /bin/ls -ln --color=never .
```

Choose the explicit library root for the installed application; the namespace
directory must not exist. The profile does not emulate the system library cache,
RPATH/RUNPATH, audit, filter or arbitrary loader-search policies. The supplied
root and actual DT_NEEDED closure select the dependency bytes. The real linker
performs mapping, relocation, TLS setup and initializers. A generic carrier can
be prepared with `carrier.py make ORIGINAL BRIDGE OUTPUT`; unsupported runtime
operations then refuse instead of returning synthetic success.

For an explicitly authorized late dependency, add `--late-soname libplugin.so`
to `exec-loader`. This repeatable option seals the named object and its
transitive dependencies after resolving the startup closure, within the same
32-object limit. It does not preload the object or admit its pages. The
application still calls `dlopen`; actual mapping and execution remain subject
to the runtime gate. The namespace manifest records the requested names and
sealed-object indexes separately from runtime mapping identities.

Run the committed-source validation with:

```sh
python3 evaluation/inprocess/first_entry.py --expect-revision "$(git rev-parse HEAD)"
python3 evaluation/inprocess/first_entry_abi.py --expect-revision "$(git rev-parse HEAD)"
```

The evaluator uses bounded fresh children pinned to one CPU, actual native and
gated executions, first-opcode fixtures, malformed-input controls and explicit
refusal controls. Exact revision, hardware, commands, input/binary hashes and
numeric results go into a compact JSON receipt under `evaluation/inprocess/`.
Raw captures and namespace preparation records stay under `target/`. Any
recorded whole-process durations include Python dependency copying/sealing and
child creation/reaping; they are not pure instrumentation overhead or a warmed
application measurement.

The first-entry evaluator's `first_entry_dependency_files_v2` profile sets a
16 MiB per-file `RLIMIT_FSIZE` for non-build commands, matching the namespace's
existing maximum dependency size. This physical limit also covers each stdout
and stderr capture; the unchanged acceptance check rejects captures larger than
64 KiB. The 3 CPU-second, 256 MiB address-space and 10-second wall bounds remain,
and the native process-count limit stays inherited without an override so the
real thread-creation control can execute. Build limits and the separate ABI and
post-constructor profiles are unchanged. The earlier 1 MiB-profile attempt
failed while sealing a dependency (`EFBIG`) and remains a failed observation;
this resource-envelope correction does not relax any of the 65 commands or
semantic checks.

## Startup and backing identity

The carrier clears PF_X on original main PT_LOAD headers before the kernel maps
them, replaces PT_INTERP with the freestanding bridge, and retains authenticated
original headers and content hashes. The bridge reads actual sealed
`/proc/self/exe`, reconstructs and verifies the original bytes, and opens the
interpreter named by that authenticated original PT_INTERP. The interpreter's
verified bytes become a sealed memfd. Exact PT_LOAD segments are mapped into a
private reservation with execution withheld; BSS zeroing covers the complete
final page tail, including storage used by the linker's bootstrap allocator.

The kernel-created argv/environment/auxv storage stays in place. Original PHDRs
are restored at the actual AT_PHDR address under temporary RW/NX, then returned
to readonly/NX. Only AT_BASE changes to the original interpreter's new bias.
The bridge saves entry GPRs, flags and enabled user XSAVE state (or FXSAVE state),
uses its own stack, then restores state and original RSP before jumping to the
interpreter entry. The [independent ABI fixture](abi/README.md) compares actual
kernel-origin GPRs, flags, FS/GS, qualified XSAVE state, full initial stack and
restored PHDRs before and after that production entry body. It uses a separate
capture interpreter; it does not observe real ld.so's entry registers. The
separate first-opcode fixture requires interpreter CPUID and main
RDTSC to be intercepted before their following instructions execute.

Every dependency is retained through an actual sealed descriptor. Private
SONAME links name inherited descriptors. The runtime independently authenticates
bounded ELF geometry, actual VMA identity, file offsets and initial executable
bytes. New pages receive mapping identities and generations; fetch faults check
the current owner and permissions before RX admission and private expedited
sync-core. Fixed loader replacements must match the same allocation's actual
PT_LOAD file or anonymous BSS segment. Partial mprotect effects are reconciled
even when the original syscall returns an error.

Pending pages can temporarily be RX inside the excluded handler while original
mapping operations and partial effects are resolved. They are revoked before
returning to application code. The guarantee within this profile is no
application fetch before admission, not literal NX at every instant of mapping
creation or a source-patch publication proof. There are 8,192 lifetime page
records and at most 32 dependency objects plus the two initial images; bounds
refuse rather than recycle live evidence.

## Execution contract

This is a fresh singleton process with compatible kernel CPUID/TSC faulting and
Syscall User Dispatch, no active CET, and reserved default/unblocked SIGSYS and
SIGSEGV. The runtime uses a guarded 512 KiB alternate stack, raw syscalls and
fixed storage; it does not depend on target libc, TLS, an allocator or locks.
Handlers do not use floating/vector instructions. The trusted bridge, handlers,
gateway, alternate stack and retained source buffers are protected.

The actual kernel vDSO is bound through original AT_SYSINFO_EHDR, bounded ELF
headers and its actual RX mapping. Its selected traps are handled, while its
pages remain outside NX gating. Unknown code origins and unsupported faults
refuse. CPUID/RDTSC/RDTSCP use actual hardware outcomes; syscall forwarding
retains original arguments, raw results and saved RCX/R11 semantics. Exact
unprefixed encodings are supported. RDRAND/RDSEED/RDPID are not intercepted by
this backend.

Policies whose results or observations depend on the original syscall PC or
handler context, including such seccomp, tracing or audit policies, are outside
this profile. Forwarded syscalls execute through the private gateway.

The finite syscall profile permits ordinary file/directory/data/identity/time
queries, real TLS/tid-address/robust-list/rseq setup, and the reviewed mapping
lifecycle. The default profile refuses thread/process creation, exec, network
operations, unknown syscalls, protected mapping mutation and externally writable executable
objects. Signal mask and alternate-stack operations, including queries, refuse;
the handler's temporary state is not substituted for interrupted application
state. Signal action changes and reserved-signal queries also refuse. Other
action queries retain actual kernel results. Generic asynchronous signal and
rseq-critical-section transparency remain unsupported.

The explicit launch environment uses C locale, UTC, eager binding and the private
dependency namespace. File/device/inode identities, DSO paths, `/proc/self/exe`,
AT_EXECFN, descriptors, mapping layout and signal state therefore differ from
an ordinary exec. Hashes authenticate trusted local preparation; they are not
signatures or an external trust root. Cooperative code must not bypass the
private syscall gateway, overwrite runtime storage or alter unsupported control
state. This is not an adversarial sandbox, filesystem-transparent loader,
arbitrary-application launcher or complete B2/B3/B4 implementation.

## Opt-in raw fork and wait

`carrier.py exec-fork` adds a closed process-creation profile to the same sealed
namespace runtime. It accepts one actual raw `SYS_fork` attempt from the original
singleton parent and at most eight `wait4` calls for that actual child, with
options zero or `WNOHANG`. Original syscall arguments and kernel results are
preserved. A failed wait can already have reaped the child: `EFAULT` is neither
retried nor treated as proof that no effect occurred. Ordinary `exec-loader`
continues to refuse fork. libc `fork`/atfork, clone, vfork, child forks, threads,
exec and general asynchronous signal handling are outside this profile.

The child initially runs inside the copied private signal frame. Before it
returns to the original application PC/RSP, the runtime checks the actual child
identity, inherited protected mappings and sealed owners, signal/alternate-stack
state and CPUID/TSC configuration, registers sync-core and re-arms Syscall User
Dispatch. Parent success remains the actual child PID even if child setup fails;
that child reports its failure and exits 125. Parent and child retain their own
COW copies of the mapping history and cumulative counters. Identical inherited
history is not counted as fresh execution in both processes.

The caller must provide `--report-parent FD --report-child FD`: distinct actual
blocking write-only FIFO owners, inherited across exec and retained through
process exit. These report owners are protected against close and flag changes.
The optional `--child-failure 1..4` fixture control explicitly stops before a
child setup phase; it is not an injected kernel return or permission to execute
an incompletely restored child. The evaluator provisions and supervises these
resources:

```sh
python3 evaluation/inprocess/fork.py --expect-revision "$(git rev-parse HEAD)"
```

The 39-command cohort preserves the nine semantic native/gated pairs, child
setup failures and default refusal. Separate assembly observations compare full
parent/child GPRs, flags, original RSP/redzone, FS/GS and qualified architectural
XSTATE against each process's actual pre-fork state. Real R12/redzone corruption
variants must be rejected; supplied-record mutations are separate controls.
Actual XINUSE and XSTATE_BV values are reported without asserting bitmap equality.
Supervisor controls exercise timeout, SIGINT, an exited leader with a live
child, malformed reports and real close/reap errors. Expected control failures
remain failed command rows; unknown cleanup stops further ordinary commands.

This cohort uses one CPU, 5 CPU seconds and 512 MiB address space per command,
15 seconds wall time and one 2-second cleanup bound. Its 16 MiB per-file bound
covers sealed dependency preparation; accepted stdout/stderr remain at most
64 KiB, runtime reports 4 KiB, and each continuation record exactly 135,936 bytes.
These are explicit fork-cohort bounds. The existing first-entry, ABI and other
profiles keep their own commands, limits and qualification requirements.
