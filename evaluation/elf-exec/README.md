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
The fixed trace inventory is 1,176 files, including six executable copies. Those
copies additionally run as ordinary processes and must print exactly
`elf exec ok` plus a newline and exit successfully. Every phase must pass in
order; failed attempts retain their logs and do not qualify later phases.

This is an authored ET_EXEC fixture with fixed application addresses. There is
no dynamic loader, PIE/DSO, unwind, CET, SIGILL-router or arbitrary-program
qualification here. All emitted products retain `qualification_complete=false`;
the explicit runtime requirements are not discharged generically by this check.
The source recipes are prospective until accompanied by exact-revision results.
