# Cyclic guarded-store execution and frontier census

Revision `6d0cbd68d20ebe74c594bc14c497d3022e1b1830` adds a registered generated epoch spanning two source pages, including direct and back edges and four guarded scalar MOV-store forms. The fixed-entry loop runs without interior signals. Recovery preserves precise state on a late store fault; protected runtime intervals are excluded before any store. This is a configured-entry primitive. Dynamic whole-program selection and the target of at most ten times DynamoRIO remain open.

The same revision adds a bounded diagnostic counter for actual page-cut planner refusals and completed exits. Counter collection does not change planning, opcode eligibility, publication or replacement. The normal build excludes the counters.

## Reproduction and machine

Run from the exact revision with one externally reserved CPU and the original runner bounds:

```sh
python3 -B evaluation/inprocess/persistent_epoch.py --expect-revision 6d0cbd68d20ebe74c594bc14c497d3022e1b1830
python3 -B evaluation/inprocess/linked_frontier_census.py --revision 6d0cbd68d20ebe74c594bc14c497d3022e1b1830 --output target/page-region-next/frontier-reproduction
```

The second output directory must be new. Both scripts build release artifacts and record source, toolchain, input and artifact identities. Actual runs used reserved CPU 1 on AMD EPYC 9D85, x86-64 family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3, with no effective capabilities. Public receipts include the exact commands and hardware identities; full command captures remain private. Each program retains its 30 CPU-second, 60 wall-second, 512 MiB and 16 MiB output limits.

## Persistent primitive

[JSON](results/20261031T004703.496428Z-persistent-epoch-6d0cbd68d20e.json) and [CSV](results/20261031T004703.496428Z-persistent-epoch-6d0cbd68d20e.csv) record 71 commands and five qualified subjects:

| Subject | Required outcome | Result |
|---|---|---|
| Native success | Complete the four-store loop | Passed |
| Generated success | Match native state | Passed |
| Native late fault | Fault on the third store | Passed |
| Generated late fault | Match native fault state; preserve the first two stores | Passed |
| Generated protected-word rejection | Reject before any store | Passed |

Each generated subject records one entry event, one terminal event and zero interior signals. Both pure component oracles pass before native execution. The readers retain 32 application, 60 owner, 8 pair, 102 terminal and 18 registry rejection controls. Source and cleanup closure pass. The preceding [55b9606 run](results/20261031T004151.281892Z-persistent-epoch-55b960678bee.json) also passed and received an independent extraction of both complete native state pairs, all 1,296 descriptor slots and the startup/entry/terminal registry joins.

Earlier failures remain recorded: strict release compilation at `5cc84af`, bounded debugger allocation at `753539d`, registry snapshot timing at `d9c0d5e`, and the scalar-span descriptor oracle at `803e93b`. The registry correction retains the full startup prefix and requires whole-registry equality over the actual epoch. The descriptor correction models the existing operand refusal code 5 for `MOV [RDI],RAX`; all other descriptor bytes and the whole-record comparator remain unchanged. These changes do not relax process bounds or reclassify failed runs.

## Actual whole-program frontiers

The [diagnostic JSON](results/20261031T004604.928403Z-linked-frontier-census-6d0cbd68d20e.json), [event CSV](results/20261031T004604.928403Z-linked-frontier-census-6d0cbd68d20e.csv) and [opcode CSV](results/20261031T004604.928403Z-linked-frontier-census-6d0cbd68d20e-histogram.csv) record one `/bin/ls -d .` execution. It exits zero with the expected output. All 33 commands, source closure and cleanup pass; counter overflow is zero.

| Observation | Value |
|---|---:|
| Whole-process time | 12.711151872 s |
| Events / traps | 117,862 / 74,001 |
| Generated entries and completions | 34,393 |
| Completed unsupported / page-cut exits | 31,696 / 2,697 |
| Maps queries / cached hits / fresh acquisitions | 1,518,213 / 1,506,580 / 11,633 |
| Cold planner calls | 38,188 |
| Cyclic-graph / exit-capacity / queue-capacity refusals | 5,896 / 1,898 / 8 |
| Completed unsupported `Mov_rm64_r64` exits | 10,702 |

This is a single instrumented diagnostic observation, with no aggregate timing or speedup credit. Opcode families include different operand forms; the MOV count is not a proved count of eligible guarded memory stores. Cold candidate frontiers, root refusals and completed exits are distinct populations. Cycle counts do not measure loop iterations or predict saved traps.

## Page-cut qualification and failed comparison

The earlier `2ad2193b8e5f87c205f3ed2ddf11cb03f9651a38` page-cut implementation passes [primitive nine](results/20261030T231847.172776Z-linked-preedge-2ad2193b8e5f.json), [cut-failure three](results/20261030T232044.435664Z-linked-preedge-cut-failure-2ad2193b8e5f.json) and [full 26](results/20261030T232158.949739Z-linked-preedge-full-2ad2193b8e5f.json), including all 65 replacement entries and the original cold/warm reuse pattern. General aging based on actual completed executions fixes the observed eviction of useful graphs; no slot, case or retirement invariant changed.

Its [62-case comparison](results/20261031T000448.154160Z-linked-preedge-performance-2ad2193b8e5f.json) remains failed at 61/62. All 60 ordinary native/gated/DynamoRIO runs and differential TRUE pass. Differential LS is killed at the unchanged 30 CPU-second bound. Its 30.179558992-second process observation includes 29.992950 CPU seconds. No aggregate medians, speedup or full comparison qualification is claimed. The ordinary first LS observation is 12.786042317 seconds, with 118,115 events, 74,103 traps and 11,633 fresh maps reads. The record contains the exact reproduction command and all per-run rows.

## Required checks

The first required-check run at `6d0cbd6` [failed](results/20261031T004814.279938Z-checks-6d0cbd68d20e.json) in recorder validation after 147.501 seconds; no Cargo command started. One historical test compared the newer `reproduce.py` blob directly to a historical hash. Successor `b631939` applies the existing exact source inverse before that comparison and binds the test edit with its own exact inverse. All 1,332 assertions, raw corruption controls, counts and deadlines remain. Runtime sources are unchanged.

The fresh [six-check receipt](results/20261031T005338.717147Z-checks-b63193985340.json) at `b63193985340a1b1a0decd65740dfc0d5e3709ec` passes recorder validation (360 tests, 167.982 s), formatting (10.079 s), strict Clippy (20.154 s), workspace tests (4,048 passed, 37 ignored, 109 complete harnesses, 744.915 s), all-features/all-targets checking (10.449 s), and serial launch validation (1,039 passed in 27 harnesses, 151.360 s). Source, configuration and process cleanup remain closed. Original deadlines and fixture inventories are unchanged.

A fresh [native/generated JSON](results/20261031T011216.849587Z-persistent-epoch-b63193985340.json) and [CSV](results/20261031T011216.849587Z-persistent-epoch-b63193985340.csv) at the same `b631939` successor pass all five subjects, both pure component oracles, and all original reader controls. The run used reserved CPU 3 on the same hardware, closed 71 commands, and retained complete source and cleanup closure. Reproduce with the persistent command above, replacing its revision argument with the full `b631939` revision.

Main `20cbe068487f10b47c08b02505ba0dcda7248f54` is merged in `357ae877e6e296c53da279b197dd364971352c7a`. Successor `f9d969b37252566add54bff42621375c8fa5b7ff` binds its exact incoming source and test inventory while preserving historical source inverses, rejection controls and deadlines. Its [merged six-check receipt](results/20261031T012022.588641Z-checks-f9d969b37252.json) passes recorder validation (361 tests, 138.607 s), formatting (9.761 s), strict Clippy (29.102 s), workspace tests (4,062 passed, 37 ignored, 109 complete harnesses, 607.646 s), all-features/all-targets checking (20.077 s), and serial launch validation (1,039 passed in 27 harnesses, 137.825 s). The run used four reserved CPUs; source, configuration and process cleanup remain closed.

Fresh [merged native/generated JSON](results/20261031T013614.085032Z-persistent-epoch-f9d969b37252.json) and [CSV](results/20261031T013614.085032Z-persistent-epoch-f9d969b37252.csv) at the same `f9d969b` revision pass all five subjects, both pure component oracles and every original reader control. All 71 commands close with unchanged source and complete cleanup on reserved CPU 3. Reproduce with the persistent command above using the full `f9d969b` revision; the checks receipt records its exact reproduction command and machine. These results qualify the configured-entry primitive on the merged source. Dynamic selection and whole-program speedup remain unqualified.
