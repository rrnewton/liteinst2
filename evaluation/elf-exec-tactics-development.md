# Four-tactic development attempts

The [attempt CSV](results/elf-exec-tactics-history-20261026/attempts.csv),
[all planned stages](results/elf-exec-tactics-history-20261026/stages.csv),
[complete command records](results/elf-exec-tactics-history-20261026/commands.json)
and [history JSON](results/elf-exec-tactics-history-20261026/history.json)
preserve four distinct completed attempts on an **AMD EPYC Zen 5 dev host**.

| Source | Campaign | Outcome |
| --- | --- | --- |
| `2e39169b5b54982c6f49f06772c7331660dfc277` | B1 prerequisite | Formatting passed; Clippy failed because a shared test consumer lacked the decoder dependency. Later gates and recipe stages did not run. |
| `fe75ab9dfb9b639938f256b86545ed888ede498b` | B1 prerequisite | Formatting passed; Clippy rejected two shared-helper expressions. Later gates and recipe stages did not run. |
| `377a649dd8d4aedcdd5bdd7831b61d26bfbd47ba` | B1 prerequisite | All 27 stages passed: 24 traces, 72 state comparisons, 1,230 captures and six ordinary executions. |
| `377a649dd8d4aedcdd5bdd7831b61d26bfbd47ba` | Four tactics | Seventeen stages passed; native B2 setup failed before tracing because it looked for an ELF carrier row in the plan-only ledger. Seventy-five later stages did not run. |

The last attempt verified four B2 artifacts and four required refusals, but
produced zero native traces. Its seven files were captured before tracing.
The successful B1 prerequisite does not turn that failed tactic campaign into
a native pass. There are 174 planned recipe-stage rows: 44 passes, three
failures and 127 unrun stages. Nested required gates retain their own statuses
and are not extra recipe stages.

The corrections authenticated the finite JNE encodings directly, used
equivalent expressions accepted by all shared consumers' lint policies, and
read carrier ownership from the complete ELF ledger while retaining its exact
plan prefix. No old assertion, tolerance, comparison, refusal or execution cap
was removed or relaxed. The later successful source and evidence are recorded
[separately](elf-exec-tactics-e6243a8.md).

The [historical renderer](reproductions/elf-exec-tactics-history-v1/README.md)
reproduced all five published data files byte for byte from its frozen input
archive. It executes no workload and grants no independent architectural-state
qualification. Original launch records keep their pending parent fields;
separate root tool observations establish the actual closed/reaped outcomes.
The records identify this distinction explicitly. Raw logs and captures remain
private; commands use reversible symbolic path roles. Timings are individual
operational observations, never sums of overlapping intervals or benchmarks.
