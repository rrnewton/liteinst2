# Normal kernel execution of the four additional tactics

This recipe adds B2 generalized punning, T1 prefixed punning, T2 successor
eviction and T3 neighbor eviction to the separate B1 MOV5/RET fixture. It
prepares actual ELF candidates through `liteinst-rewrite`, authenticates their
metadata and byte ownership, and executes each file through the kernel loader.
It does not mark an artifact qualified for general use.

Run the unchanged B1 recipe first at the same clean source revision, with a
fresh absolute output path under `ignored/`. It runs the four required
workspace gates, builds and archives the frontend and native driver, and checks
the original B1 fixture. Wait for that recipe's parent to exit and be reaped
before supplying `--b1-closed-and-reaped` to this recipe:

```sh
python3 -B evaluation/elf-exec/reproduce.py \
  --raw "$B1_RAW" --toolchain "$RUST_TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_CACHE"
python3 -B evaluation/elf-exec/reproduce_tactics.py \
  --raw "$TACTICS_RAW" --b1-raw "$B1_RAW" --b1-closed-and-reaped \
  --toolchain "$RUST_TOOLCHAIN" --user-home "$USER_HOME" \
  --cargo-home "$CARGO_CACHE"
```

All path arguments must be absolute and canonical; both output directories
must be new. The tactic recipe requires the B1 source hashes and revision to
match its own. It reuses the archived binaries and target record and checks
that consumed prerequisite bytes remain unchanged. Do not wrap either recipe
in another timeout process. The required workspace gates keep their original
runner limits; the remaining B1 stages and all tactic stages use the existing
bounded helper’s process-group and descendant-cleanup checks. The prerequisite flag records a caller
observation; the stored result files cannot prove their parent has exited.

The new recipe has 93 bounded stages. It compiles two read-only examples, then
assembles, links and strips each authored fixture. Each family has four
prepared candidates (unstripped/stripped times null/journal hook), exact artifact
verification, one refusal-control invocation, one native invocation and six
ordinary process executions. Failed attempts remain in their original output
directory, and subsequent stages are not run.

| Family | Original entry offsets | Original traces | Rewritten traces | Full-state comparisons |
| --- | --- | ---: | ---: | ---: |
| B2 | 0, 3, 8 | 12 | 24 | 120 |
| T1 | 0, 2, 7 | 12 | 24 | 120 |
| T2 | 0, 3, 11, 16, 64, 74 | 24 | 48 | 248 |
| T3 | 0, 2, 3, 64, 74 | 20 | 40 | 188 |

These are required counts, not a report of an executed campaign. The two state
seeds give T3 both ZF outcomes and give T1 nonzero upper RAX bits. Every original
entry runs, including unaffected entries and the displaced victim. Comparisons
cover the before/after application CALL and every authored instruction boundary
through RET. The inherited comparator checks registers, flags apart from the
existing debugger bits, architectural XSAVE state, application data and stack.
Hook scratch memory has the same separately checked private-memory contract as
B1. Both hook variants must preserve application state; the journal hook must
record the selected logical PC exactly once when that site is reached.

The native driver observes gateway and relay edges and authenticates the actual
LOAD owners. It keeps the existing 20,000-step and 15-second whole-child bounds.
The recipe derives the complete capture filename set independently before
launching any native child; it rounds each authenticated ELF payload extent to
its actual page coverage, allowing up to two pages per generated image within
the fixed placement permit. It compares this set with the driver's pre-exec
inventory and every resulting file. There are no manual LOAD mappings or
post-seed repairs.

The 18 refusal cases require exact error contracts for unknown entries, stale
source identity, stale hook identity after rebinding source identity, an
unavailable selected placement, and (for T2/T3) a one-image budget. They produce
no executable candidate and do not replace any positive or native case.

Raw logs, ELFs, memory captures and host paths belong under `ignored/`.
Published results belong under `evaluation/` as CSV/JSON summaries with the
exact tested revision, hardware and commands. This finite fixture supports
claim 4 (systematic tactic validation) only in its stated scope. PIE/DSO,
unwind and early-loader behavior, E9 comparison, cross-vendor execution and
complete qualification remain separate obligations.
