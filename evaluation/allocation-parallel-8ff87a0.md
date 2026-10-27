# Allocation-sensitive tests under default parallelism

The two staged-trampoline ownership tests and the prefixed-pun native oracle
now execute their complete allocation-sensitive bodies in fresh, exact-name
child processes. This gives each body its own address space while the enclosing
test targets retain default libtest parallelism. Original assertions and
allocation requirements remain intact. The prefixed oracle still requires all
six geometries, 18 heads, both seeds, 36 installed comparisons and 36 retired
comparisons. Panic, timeout, an empty child filter or incomplete child cleanup
fails the parent test.

The tested revision is `8ff87a0a14c9348610c843063516c79190f6dede`, which includes
coordinator main `e571dfbce8d0eba0cb37aa4c11e1aa793bc6445c`. The saved-record
collector was subsequently added at
`f1a4880ff4bce5ccd321eb1f9a231ba8882099ea`; it changes no tested source bytes.
These results support claim 4's finite regression coverage. They do not
establish general allocator concurrency or complete milestone A4.

All seven unfiltered commands passed on the **AMD EPYC Zen 5 dev host**
(AMD EPYC 9D85 158-Core Processor, 316 logical CPUs, x86-64, glibc 2.34),
using Rust 1.97.1, four Cargo build jobs, one target directory and disabled
incremental compilation. No default-parallel command sets `RUST_TEST_THREADS`.

| Full target | Invocations | Passed per invocation | Ignored per invocation |
| --- | ---: | ---: | ---: |
| liteinst2 library | 3 | 207 | 1 |
| prefixed_pun_oracle | 3 | 27 | 0 |
| Workspace | 1 | 1,671 | 4 |

The workspace retains all 90 outer groups and all 1,675 case/status identities
from the separate same-revision required-gate run. The three named regression
cases passed in their full targets and in the workspace. Nested child summaries
are not additional tests. Ignored cases are unchanged.

The four separate required gates also passed: formatting, warnings-denied
workspace Clippy, workspace tests and the all-feature/all-target workspace
check. Those gates use the existing four-thread test setting; they do not
substitute for the seven default-parallel commands. Each default command keeps
the original 360-second limit. The complete default sequence took 361.092 s;
its workspace command took 338.393 s. The required workspace test took 350.314 s.
These are shared-host operational durations, not performance measurements.

The normalized [JSON/CSV records](results/allocation-parallel-8ff87a0-20261026/summary.json)
retain the exact command arguments, explicit environments, hardware, source and
tool hashes, individual durations, command outcomes and terminal observations.
Terminal observations remain unclassified and unaggregated in the machine data;
the outer counts above come from the independently checked case inventories.
Private raw logs, process captures and path coordinates remain under ignored/.
Source/tool observations stayed equal across every command. Configuration
lookup denials are retained; full configuration, dependency and runtime-loader
closure is not claimed. Failure and UNRUN rows would remain visible.

To reproduce the default-parallel sequence at the tested revision, supply
canonical absolute paths for the checkout and installed toolchain:

```sh
python3 -B evaluation/trampoline-parallel.py \
  --repo "$REPO" --output "$REPO/ignored/allocation-parallel-new" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The four-check recipe is `evaluation/required-gates.py`. This recorded run
invoked it as the first stage of the [complete build recipe](e9-common-app/BUILD.md).
The [collector](collect-trampoline-parallel.py) reads closed saved records and
caller-supplied parent-closure/review references; it never launches workloads.
It checks complete decoded command inverses, exact Git source objects and
private-text exclusions before producing the six public files. Collector and
tested revisions are recorded separately. Original-only build/inventory work,
older results and unfinished A2–A5 gates receive no new qualification here.
