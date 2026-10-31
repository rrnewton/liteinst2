# Finite offline corpus comparison

This packet adds two whole programs to the existing heap-sort application:
`checksum.S` computes the byte sum, FNV-1a checksum and input length;
`rle-roundtrip.S` encodes runs (maximum count 255), decodes them into a separate
buffer, checks every decoded byte against the original, and emits both the
encoded and decoded streams. Both are freestanding Linux x86-64 ET_EXEC
programs with bounded file I/O, no libc/interpreter, fixed static storage and a
separate null hook. They are an explicitly authored finite corpus, not samples
from SPEC, coreutils, or a general loader qualification.

The ten mandatory datasets cover empty, singleton zero/255, all byte values,
255/256 run splitting, mixed run boundaries, mixed 4 KiB, maximum 64 KiB run,
and maximum 64 KiB alternating expansion. The Python model checks complete
stdout and empty stderr with exit zero. Native, LiteInst, stock E9 and the
disclosed bootstrap-patched E9 lane yield 80 comparison rows. Each successful
rewritten output must also equal the successful original output. A signal,
nonzero command, witness mismatch, or changed byte is FAILED. A complete
selected-site planner refusal is UNSUPPORTED and preserves its whole report;
it is not a passing comparison. A missing pinned prerequisite is UNAVAILABLE.
Following a campaign interruption, all remaining mandatory rows are UNRUN.

`corpus.py` declares the complete machine-code instruction tables. The checksum
has 18 heads and two branches; RLE has 45 heads and 12 branches. Every kernel
jump is selected, including paths never taken by valid inputs. No successful
subset is substituted. The kernel contains no indirect transfers or CALLs;
all targets are in its authenticated complete head set. The source programs
and independent output models have different implementations. Selection uses
the unchanged strict LI2TOOL schema, source-relative byte identity, complete
entries, exact instruction/block/function extents, disjoint prospective
allocations, forced B1 and a finite fresh target-state record. It does not
manufacture entries for arbitrary compiled code.

`adapter.py` requires the complete indexed LiteInst directory, every selected
report row, exact source detours and original-relative whole-file overlay,
image ownership, the complete source-derived save/call/restore helper, exact
logical-PC and hook-target fields, restored instruction boundaries, original branch conditions
and destinations, and Jcc fall-through. E9 runs the unchanged public
`tools/elf-rewrite/e9-sites.py` first, retaining its full original/RPC/site,
loader, mapping, debug, statistic and strict-receipt checks. The added finite
branch witness checks every complete passthru body and continuation. It accepts
no trap, repair, omitted branch or unsupported opcode shape.

These byte and end-to-end witnesses are **not** a new full GPR/flags/XSAVE and
64 KiB application-stack replay oracle. The existing full-state comparators
remain mandatory for their original cohorts. There is no existing generic ELF
full-state entrypoint: `verify_elf_exec`/`elf-exec-oracle run` are fixed MOV/RET
fixtures, while `run_core_pairs.py`, `run_e9_pairs.py` and `e9-null-witness.py`
are fixed heap-sort contracts. Generalizing those contracts is separate work;
this packet neither edits nor claims their authority.

## Existing corpus inventory and unchanged entrypoints

| Corpus | Actual programs/fixtures | Entry point and scope |
| --- | --- | --- |
| Full authored Rust offline/tactic corpus | Complete workspace, including all `liteinst-rewrite` targets | `cargo test --workspace`; the closed `c66ea06` inventory is 2,293 PASS and four ignored, with nested observations kept separate |
| Authored normal-exec fixture | One MOV5/RET executable, stripped/unstripped, null/journal | `evaluation/elf-exec/reproduce.py`; complete native state and ordinary-output checks remain literal |
| Authored tactic fixtures | Fixed assembly/placement puzzle corpus | `evaluation/elf-exec/reproduce_tactics.py`; no reduction of forced tactics or refusal controls |
| Common application | One `heap_sort.c`; eight hook/style/stripping cells, not eight programs | Existing preparation/build/produce/original observation/192 ordinary cases/core+E9 paired recipes; carry all historical failures and unrun obligations |
| Pinned PLDI2020 E9 test | Two real programs: `e9tool`, `e9patch`; five actions | `ignored/a3/upstream/e9patch-pldi2020/e9test.sh`; two-generation whole-output binary equality, ten terminal rows |
| New finite expansion | Checksum and RLE roundtrip | This packet: all 14 kernel jumps, 20 program/dataset pairs, four lanes, 80 required comparison rows |

The later [complete common-corpus run](../e9-common-e8a8b6d/) at
`e8a8b6d447673aa7b98e00ff18df2eedf5e07d82` completed the previously outstanding
**704 core-null, 2,112 recording and 1,408 E9-null pairs**: 24 cells, 4,224
pairs, 8,448 children and 12,672 live state comparisons, with zero mismatches.
Its earlier failures and partial populations remain in that report. The
separate [checksum/RLE run](../offline-corpus-e8a8b6d/) passed all 80 complete
output cases and 96 saved-artifact controls. Neither cohort establishes
arbitrary-program support or full A3 qualification. The newer
[whole-program pending-selection attempt](../pending-selected-eff2f47/)
retains all 187 instruction heads and 42 jumps but refuses both candidates;
those startup-inclusive failures do not replace the successful kernel cohorts.

The later [full-program startup run](../offline-router-corpus/runtime-6ed5f2d/)
at `6ed5f2d24293d414169ff4e7688671b230a35775` executes both complete programs
through the production bootstrap and router. All 40 original/candidate
invocations passed over the ten datasets. Its [matched E9 comparison](../offline-router-corpus/e9-6ed5f2d/)
passed all 80 application rows across the four lanes, retaining all 187 original
heads and 42 selected jumps, with zero lost E9 trampoline sites and zero traps.
This adds full-output correctness for these two authored programs; dynamic
route coverage, full architectural-state/ABI/unwind equivalence and complete
A3 qualification remain open. Earlier refused attempts remain separate.

The newer upstream tree at `5e098f7920b5b5535f553de599c94ee980e97e29`
also has `test/regtest` and a ten-action two-program `test/stresstest`.
It is a different E9 version and is not silently substituted for the pinned
PLDI2020 comparison. No external benchmark corpus was found in the inspected
tracked offline/application sources. The E9 examples are instrumentation
payloads, not additional whole-program test subjects.

The PLDI script is run from its own source root with `bash ./e9test.sh` under
the existing bounded helper. It prints `FAILED` without necessarily returning
nonzero. Root must therefore require exactly all ten expected PASS rows and
zero FAILED rows, as well as the real strict receipt. Do not call a zero shell
exit alone success, do not run it concurrently against its fixed `tmp` files,
and retain original script/producer identities. The script exercises E9, not
LiteInst; there is no authenticated LiteInst selection for those two arbitrary
tool binaries yet.

## Reproduction and admission

Use [reproduce.py](reproduce.py) and its [argument and build contract](REPRODUCE.md) to build fresh release products, capture the current target and run the complete comparison. The manual catalog interface below documents what that wrapper constructs.

The initial comparison at `2cf9a6e` passed all 80 output cases. The subsequent
[1345b10 comparison](../offline-corpus-1345b10/README.md) also passed all 80
with the stronger helper-prefix witness; its 96 saved-artifact controls include
68 expected refusals. The receipt distinguishes valid positive controls from
20 historical-witness gap acceptances, which supply no qualification credit. The unchanged bounded command helper
provides strict ECHILD cleanup. The new driver records each complete request,
helper receipt and enclosing wait, with 60 CPU/90 wall/128 MiB per assembler or
linker stage and 20 CPU/30 wall/16 MiB per other command, plus the established
100/40 second timeout wrapper, 10 second kill grace, and bounded 115/55+10
second parent waits. These are operational limits, not a memory sandbox.

Root first makes a fresh release frontend build, preserving assertions and
overflow checking, using the existing strict helper and exact source revision:

```text
CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true
CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true
cargo build --release --locked --offline --package liteinst-rewrite
    --bin liteinst-rewrite --message-format=json
```

The input catalog supplies its actual complete command/env, Cargo messages,
strict receipt, outer wait and executable owner; a caller-selected PASS label
alone is insufficient. The profile is exactly opt-level 3, debug 0, assertions
and overflow checks enabled. Old debug builds/results cannot satisfy it. Root
also supplies pinned assembler/linker/Python/timeout, both existing exact E9
lanes, the native target driver and its actual target request/receipt/record.
The driver rechecks the target by running that same `target` command and
requires its complete XSAVE extent to be at most 16 KiB, leaving room in the
authored 64 KiB stack for register saves, red zone, alignment and the null call.
All
catalog tuples include path, bytes, SHA-256 and six stat fields and remain
unchanged throughout the campaign; no historical tuple is refreshed.

Use the source schema in `compare.py` to create the compact caller catalog.
`release_build` is a file path in `files`, containing status/revision/profile,
product owner, exact argv/env, and command/receipt/parent_closed/cargo_messages
paths. `target` is a pinned file containing driver owner plus record/request/
receipt paths. `retained_heap_evidence` is the complete explicitly selected
existing cohort summary/review list; the driver carries its exact original
bytes and outcomes without claiming a fresh heap-sort run. All paths in those
records must be in the caller's exact owner catalog. No synthetic example hashes
or guessed future revision are supplied. The driver authenticates the supplied
catalog, saved build command/receipt/Cargo artifact and product owner; it does
not establish catalog completeness or derive build-time source identity from
a revision label. Fresh external root admission must separately verify the
complete source before/after maps, clean exact revision, current product,
profile and pinned Git tool. Preserve that private admission as evidence.

The driver writes all 80 planned rows before its first target/producer/native
command. A case becomes FAILED before command preparation and becomes attempted
only after Popen succeeds. Interruptions and command/receipt/postcheck failures
retain those rows, actual parent closure and the original failure; only untouched
rows remain UNRUN. A bounded cleanup failure does not become ECHILD or success.

```text
python3 -B compare.py --repo CHECKOUT --inputs CALLER.json
    --inputs-sha256 ACTUAL_SHA256 --out CHECKOUT/ignored/NEW_RUN
```

The short final artifacts are `summary.json`, `cases.json`, `cases.csv` and
`commands.json`; command logs and original producer artifacts stay private.
No repeated command observation is reported as a unique test. Report release
timings only for rows whose complete correctness and byte witnesses pass.
The recorded elapsed value includes exec, helper and file I/O overhead; it is
not an isolated kernel timing, nanosecond probe overhead, or statistically
qualified benchmark. There are no performance thresholds or tolerance tests.

Before execution, independently review the authored instruction encodings,
linker layout, startup bounds and both branch witnesses. Prospective violating
controls should alter one original kernel byte, remove/reorder a selected
branch, alter a complete entry, change a relocated condition/destination,
change an unselected original byte, truncate a producer index, mutate an input
owner, substitute a debug product, and alter one output byte. Each must refuse
at its real consuming check. The recorded runs and saved-artifact controls are
linked above; they do not validate a different source revision. The fixed
source programs and assertions are additive; prior comparators, test identities,
budgets and failures remain untouched.

## Saved-artifact witness controls

After `reproduce.py` completes all four phases with 80 output matches using the
strengthened adapter, run the separately bounded pure controls against that closed
output directory:

```sh
python3 -B evaluation/offline-corpus/controls.py \
  --repo "$PWD" --raw "$PWD/ignored/offline-new" \
  --out "$PWD/ignored/offline-controls-new"
```

The script checks the closed saved envelope and exact current source pins, then
loads the historical adapter from Git commit `2cf9a6e` with a 15-second bound and
an exact SHA check. It runs 96 saved-copy observations: eight valid positives,
20 expected historical guard-gap acceptances, and 68 expected refusals. This
includes both unconditional-JMP terminal-tail mutations. The source-derived
prefix witness requires the complete save/CALL/restore sequence, exact logical
PC and hook target, and complete terminal return. All original branch/output
comparisons remain.

These controls execute no native program, ELF, producer or compiler and never
reopen external tool or target products. They do not renew runtime/source owner
authority or constitute another native campaign. Raw copies and detailed
assertion results remain under `ignored`; `results.json` contains compact source
pins, counts and named assertion origins. The caller supplies the same bounded
10-CPU-second/15-wall-second/16-MiB-file control envelope, with a 25-second outer
timeout, ten-second kill grace and bounded parent cleanup. Reported expected
historical acceptances demonstrate missing guards, not new validation passes.
