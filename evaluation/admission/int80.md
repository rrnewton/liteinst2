# Long-mode Linux INT80 evidence boundary

The explicit `execute_linux_int80_getid` operation and corresponding declared
page-gate path cover Linux i386 getpid (20) and gettid (224) from native CS 0x33.
They require ordinary TF/RF-clear user flags. The syscall number and semantic
arguments use the low 32 bits; kernel entry authentication also checks the full
saved argument registers. The ordinary owner's x86-64 syscall parser and
allowlist are unchanged. Other INT80 operations and successful SYSENTER remain
outside this profile, as do compatibility-mode applications.

`native_int80.rs` declares six bridge rows and six native page-gate rows:
two numbers times `CD 80`, `66 CD 80` and `48 CD 80`. Two additional literal
page-gate rows use typed scripted results. These are rows inside six test
functions, not additional libtest cases or additions to the separate 50-case
`native_selected` telemetry catalog. Three additive pure-semantics tests cover
full replacement state, invalid requests/results/flags, ABI mismatches and
non-consumption of rejected provider rows.

The independent native oracle executes a hand-encoded original ELF through
raw ptrace, without the production checkpoint, gate, island or return bridge.
It seeds high halves of GPRs, RCX/R11, arithmetic flags and DF, x87/SIMD state,
a fixed stack and data memory. Comparisons cover every register field, flags,
segments, kernel `orig_rax`, complete captured XSTATE, stack and data bytes at
entry, completion and original continuation. A successor write must remain
unexecuted until explicit resume. Twelve deliberate corruptions exercise the
comparison. Cross-run native comparisons first assert each run's exact known
PID result; only that verified RAX identity is substituted for comparison.

Native kernel entry changes `orig_rax` to the zero-extended low32 syscall
number. The typed replacement does not enter the kernel and preserves its
original bookkeeping instead. These are distinct expected transitions. The
actual native exit state is checked before the existing private INT3 return
bridge can establish an owned injection stop. Rearming then preserves that
complete state. Unsupported requests and flags refuse before execution;
undeclared, mismatched and faulting alias fixtures remain required.

Run the full `evaluation/admission/run.py` protocol at its recorded exact
revision to qualify these assertions. Its JSON records source hashes, hardware,
toolchain, all commands and exact harness counts. An incomplete or failed run
does not qualify this profile; these counts are validation observations rather
than performance measurements or complete claims 1, 2 or 4.

The reviewed kernel source is Linux v7.1.3
[`arch/x86/entry/syscall_32.c`](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/entry/syscall_32.c),
SHA-256 `db3cbd57909d81fa4a487500bbb42859dd8c50fe62c78c61c067fdf4698d5268`.
`do_int80_emulation` records the truncated number and the ENOSYS entry sentinel;
the SYSENTER path instead reconstructs a compatibility stack and vDSO return
address. That different return convention is not supplied by this INT80 path.
Matching an upstream version does not authenticate a vendor kernel; native
tests must independently pass on the recorded running system.

Retrieve the reviewed source without adding it to the repository:

```sh
mkdir -p target/review-linux
curl --fail --silent --show-error --location --max-time 30 \
    --output target/review-linux/syscall_32.c \
    https://raw.githubusercontent.com/gregkh/linux/v7.1.3/arch/x86/entry/syscall_32.c
sha256sum target/review-linux/syscall_32.c
```
