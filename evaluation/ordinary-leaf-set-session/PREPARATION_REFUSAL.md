# One preparation-refusal control

`preparation_refusal.py` builds or reuses a source-bound release `ordinary-interval` and a separate
four-byte assembly DSO. Its selected LOCAL FUNC is exactly `48 89 f0 c3`
(`mov rax,rsi; ret`). The complete function is explicitly selected as `certified`;
the existing short-role refusal must occur before publication or a target call.
There is one application attempt, with no retry or alternate fixture.

From a clean, reviewed exact revision containing the diagnostic and this recipe,
use an external hard **two-CPU** reservation and the existing bounded process
owner with **1200 seconds / 8 MiB**. The caller must supply the actual reserved
pair; an affinity mask or reservation tag alone is not reservation evidence.
Use absolute directories and a fresh path below the checkout's `ignored/`:

```text
python3 -B evaluation/ordinary-leaf-set-session/preparation_refusal.py \
  --revision <exact-40-hex-commit> --reservation-tag <external-tag> \
  --raw <absolute-fresh-ignored-directory> \
  --toolchain <absolute-rust-toolchain-directory> \
  --user-home <absolute-user-home-directory> --cargo-home <absolute-cargo-home-directory>
```

The recipe authenticates source against Git before importing shared helpers,
pins compiler/linker subtools, and builds with opt-level 3, debug 0, assertions
and overflow checks enabled, four Cargo jobs and no incremental compilation.
Cargo uses the single shared checkout `target/` directory; its fixed build bound
is 120 CPU seconds / 180 wall seconds / 128 MiB per file. The existing native
artifact checker requires the exact release metadata and a boolean `fresh`, whose
actual value is retained. The completed Cargo product keeps its first content
pin. A separate exclusive executable copy in the private output must have identical
bytes, a different inode, mode 0500, and owned one-link identity through acceptance.
The recipe executes only that retained copy; it does not claim fresh compilation. Other stages use 20 CPU seconds / 30 wall
seconds / 1 MiB, including the application driver and its one child. The existing
bounded helper and process owner retain descendant cleanup and ECHILD checks.

The inner mode reuses the authenticated owner’s single-thread/no-child preflight
and subreaper/ECHILD helpers, then forks once and calls `waitpid` directly. It retains the actual raw
wait status and core-dump bit, then requires normal reap/ECHILD, SIGABRT, empty
application stdout, and this exact application stderr:

```text
normal-leaf-set-session PREPARATION_FAILED stage=site class=core reason=no_patch_window
```

Both core-bit values are retained; `RLIMIT_CORE=0` is not a claim that the bit is
zero. The writable application files are separate from the inner driver's and
bounded helper's streams. Outer acceptance additionally requires complete normal
helper/owner closure and unchanged first source/tool/artifact/evidence pins. Any
failure remains FAILED; unstarted stages remain UNRUN. Raw command, hardware,
source, build, file-identity, wait and closure records stay in the private output
and existing `target/evaluation/` log directory. No failed file is deleted.

The four fabricated Python guard controls run first; they exercise the ELF,
raw-status/stream joins, exact Cargo metadata and actual file/copy custody helpers without loading code or
launching the application. They do not replace existing Rust controls or gates.

This is diagnostic refusal coverage only. It gives no scalar, full architectural
state, Schedule/deadline, performance, successful publication or full-campaign
credit. The ordinary loader's source/mapping and no-CET/single-main/no-signal
contracts remain required; this receipt is not a universal destructor proof.
