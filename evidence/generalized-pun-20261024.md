# Generalized install-once puns — 2026-10-24

Historical measurement revisions below refer to the original local history,
before public-evidence sanitization. Production source and test bytes were
preserved; raw receipts and the revision mapping remain private under
`ignored/`. Validation of the rewritten revisions is recorded separately.


The owner's clarification changes the install-once default to generalized
instruction punning before relocation. This extends A1 from base
`ad5a938fa2fe2913a292989026b9e4ac44e93eeb`; the exact committed-head receipt is
recorded by [run-checks.py](a1/run-checks.py) in `ignored/a1/commands.json`,
with immutable timestamped logs and source hashes alongside it.

## Contract and behavior

Contract version 2 adds `PlanParts.kind`: `Relocation` or
`GeneralizedPun(GeneralizedPun)`. Existing admission/mock constructors add
`kind: PlanKind::Relocation`. A generalized pun replaces the entire original
instruction of length L=1–4 with E9 and L−1 free low displacement bytes.
Successor bytes supply only the fixed high displacement bytes and stay unchanged.
The resulting windows contain 1 / 256 / 65,536 / 16,777,216 consecutive target
addresses. Signed negative displacements follow the same rule.

The plan records the five-byte consumed range, target window, L-byte semantic
edit and actual byte/word/dword store. Three-byte instructions use a four-byte
MOV preserving one authenticated padding byte. At cache-line offset 61, that
padding comes from the preceding byte; otherwise it comes from the successor.
Padding, consumed successors and all source bytes remain checked and leased.
Both installation and retirement use one explicit MOV. A line-crossing original
instruction or missing source evidence refuses the pun, allowing the default
policy to try relocation. All five fetched bytes must be executable after
finalization, including when the fetch spans two pages. Existing quiescence and
sync-core requirements remain in force.

The exact-instruction emitter observes/replaces only that original instruction
and resumes at PC+L. Successor entries stay at their original addresses, with no
SIGILL routes. `RapidProbe` and its exact opcode-byte toggles are unchanged.
`TacticPolicy` exposes the preferred order and forced modes; every attempt names
its tactic. Allocation obeys existing non-clobbering mapping and search budgets.

## Required coverage

The generalized contract corpus requires **200 successful installations**:
193 generalized puns and seven relocation fallbacks. Three declared heads per
installation execute before publication, while installed and after retirement:
600 entry cases, 1,800 calls, exact callback counts and zero mismatches.

- All 64 cache-line offsets for L2/L3/L4: 186 puns and six required crossing-line
  relocation fallbacks. L3 at offset 61 must use the shifted four-byte store.
- One L1 exact-destination case and three cases whose five-byte E9 fetch spans
  two executable pages.
- Twelve required planning refusals: six crossing-line puns, one unavailable
  preceding padding byte, three truncated consumed ranges, one occupied target
  window and one zero-candidate budget. Occupied-window fallback must execute.
- Three prewrite publication refusals: stale right/left padding and a mapping
  collision. All preserve the complete source snapshot; restoring the prerequisite
  permits the same immutable plan to publish and execute.
- Contract-construction mutants forge padding, store width, destination window,
  encoded target, application profile or consumed length. Every mutant is refused.
  A synthetic address in the final u64 cache line refuses without overflow.

Three new emitter tests cover lengths 1–4, observing/replacement semantics,
entry/boundary maps, exact continuation, unavailable heads and the preserved
minimum size of the relocation-window constructor.

The independent native oracle adds four required generalized-pun fixtures,
12 original heads and two fixed seeds: **24 installed comparisons plus 24 retired
comparisons**, with unchanged GPR/flags/xstate/memory comparators. Every fixture
also proves a same-site relocation plan is feasible, then requires the default
policy to choose the pun. A separate three-byte null-load pun compares full fault
state, signal, si_code, address and logical/physical fault location for two seeds,
both installed and retired. Existing 160 relocation comparisons, two relocation
fault seeds and six negative calibrations remain required with explicit
`RelocationOnly` selection. No comparator or support-harness byte changed.

## Validation

The complete implementation tree passed all checks starting 2026-10-25
01:41:07 UTC (2026-10-24 Eastern time). Receipt:
`ignored/a1/20261025T014107.534581Z/commands.json`.

| Check | Result | Elapsed |
| --- | --- | --- |
| `cargo fmt --check` | pass | 0.314 s |
| Workspace all-target/all-feature Clippy, warnings denied | pass | 1.667 s |
| `cargo test --workspace` | 191 passed, 0 failed, 4 existing ignores | 13.439 s |
| Workspace all-feature/all-target `cargo check` | pass | 1.166 s |
| Original quiescent contract corpus | pass | 0.315 s |
| Generalized-pun contract corpus | pass | 0.315 s |
| Native oracle | 10 passed | 7.579 s |

Checks run serially with four Cargo jobs, incremental compilation disabled,
one target directory and bounded child lifetimes. The final committed-head run
and reviews are linked in the coordinator status file. Evidence remains a finite
Linux/AMD-host corpus under the documented ABI and signal envelope. This change
does not qualify live generalized-pun toggling, all ISA instructions, Intel/CET,
or a universal allocator; bounded placement can still refuse.
