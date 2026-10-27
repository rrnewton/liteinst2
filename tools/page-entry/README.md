# First-entry Linux page admission

This Linux x86-64 launcher runs an original dynamic linker and application under
an in-process NX gate from the linker's first instruction. It uses a private ELF
carrier and explicit sealed copies of dependencies. No ptrace supervisor is
needed. The kernel-trap backend has `source_patches=0`; actual selected-instruction
source patches are provided separately by `liteinst-inprocess`.

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
lifecycle. It refuses thread/process creation, exec, network operations,
unknown syscalls, protected mapping mutation and externally writable executable
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
