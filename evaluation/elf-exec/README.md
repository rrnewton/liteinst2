# Normal kernel-exec artifact check

Run from a clean committed checkout on Linux x86-64 with ptrace access, GNU
assembler/linker/binutils and the locked Rust dependencies already cached:

```sh
python3.9 -B evaluation/elf-exec/reproduce.py \
  --raw "$PWD/ignored/elf-exec-RUN" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_CACHE"
```

The toolchain argument is the canonical Rust toolchain directory containing
`bin/cargo` and `bin/rustc`; the other two arguments are canonical existing
home/cache directories. `RAW` must be a new directory beneath this checkout's
`ignored/`. The recipe records the exact Git revision, all tracked file hashes,
CPU model/kernel/tool versions, command arguments/environments, bounded-command
receipts and raw captures. It keeps one Cargo target directory, four jobs and
incremental compilation disabled. Raw paths and captures remain private; publish
only sanitized JSON/CSV observations and their revision/command alongside a
summary under `evaluation/`.

The first four operations are the unchanged required workspace gates. Then the
recipe runs the retained 3/24 site-comparison controls, builds authenticated
Cargo artifacts, assembles the fixed fixture, and emits four candidates:
unstripped/stripped crossed with null/recording hooks. It checks COMPLETE, every
index hash and exact file set, then decodes actual metadata and sparse sidecars
and compares their source edits/image against the executable file.

The driver uses `fexecve` on a retained descriptor. Kernel startup reaches an
authored CALL before a single register/XSAVE seed; it never redirects RIP or maps
a LOAD itself. Two heads and two seeds give eight original and sixteen rewritten
traces, with 72 complete state comparisons, 24 application CALL/RET witnesses,
eight hook CALL/RET witnesses and four exact recording-hook journal rows.
The fixed trace inventory is 1,230 files, including six executable copies, their held-descriptor mount
records and the mapping-file links at each traced phase. Those
copies additionally run as ordinary processes and must print exactly
`elf exec ok` plus a newline and exit successfully. Every phase must pass in
order; failed attempts retain their logs and do not qualify later phases.

This is an authored ET_EXEC fixture with fixed application addresses. There is
no dynamic loader, PIE/DSO, unwind, CET, SIGILL-router or arbitrary-program
qualification here. All emitted products retain `qualification_complete=false`;
the explicit runtime requirements are not discharged generically by this check.
The source recipes are prospective until accompanied by exact-revision results.

For constrained disk space, pass `--build-profile dev-debug0-v1` to both
`reproduce.py` and `reproduce_tactics.py`. This explicit profile disables debug
information, retains optimization level 0, debug assertions and overflow checks,
and authenticates the exact Cargo artifact profiles. The default `legacy`
profile keeps its original debug information. A tactics run requires its closed
B1 prerequisite to use the same profile. Neither profile supplies performance
measurements.

The complete sequence runs the 27 B1 stages, then the 93 additional tactic
stages after the first parent has exited and all descendants have been reaped:

```sh
python3.9 -B evaluation/elf-exec/reproduce.py \
  --raw "$PWD/ignored/elf-b1-RUN" --build-profile dev-debug0-v1 \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_CACHE"
python3.9 -B evaluation/elf-exec/reproduce_tactics.py \
  --raw "$PWD/ignored/elf-tactics-RUN" --build-profile dev-debug0-v1 \
  --b1-raw "$PWD/ignored/elf-b1-RUN" --b1-closed-and-reaped \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_CACHE"
```

The full sequence requires 748 state comparisons across 76 original and 152
rewritten traces, plus 30 ordinary process executions. It covers B1, B2, T1, T2
and T3 with stripped/unstripped files and null/recording hooks. These counts
remain prospective until exact-revision results are published.

Pure controls for the profile admission guards accept two complete records and
require 28 malformed or mismatched records to be rejected. They extract the
literal guards without executing either recipe or any subject:

```sh
python3.9 -B evaluation/elf-exec/profile_controls.py --repo "$PWD" \
  --sources "$PWD/evaluation/elf-exec" --out "$PWD/ignored/elf-profile-controls-RUN"
```
