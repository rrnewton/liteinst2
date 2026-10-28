# Fixed ordinary call tree

`tree_work.S` contains a protected 23-byte root and the existing 39-byte
linked-memory child at root+32. Its original E8 at root+9 pushes root+14;
the root adds one to the child's result. Both functions execute ordinary RET.
The closed input population is the two existing seeds crossed with `fit2`
and `conflict3`, each with 64 iterations. This fixture does not exercise
recursion, tail calls, unwind, signals or arbitrary application call graphs.

`truth.rs` independently describes the literal instructions, uses the existing
child interpreter, and joins it to a separate cycle/stack operand formula.
Each invocation has six root and 326 child instructions, 129 input reads,
two RET reads and one CALL store. Predictions alone do not establish native
execution. The native adapter must witness the source E8 and both physical
C3 successors before destination callbacks execute, then the real outer RET
and normal postflight. All original state comparisons remain required.

`model.rs` starts one cache at root entry: 64-byte lines, four sets, two ways,
true LRU, write allocate and write back. It uses actual virtual addresses,
input base in set2 and both return slots in one set3 stack line. The CALL
allocates that line before either RET. Every event is checked against both
reuse distance and a literal miss vector. Fit2 has three misses; conflict3
has 65. Exclusive attribution uses the instruction's function identity;
inclusive totals come from the same continuous simulation. The sole dirty
line is never evicted here. These are demand-cache model results, without
hardware-miss, timing-accuracy or performance claims.

Run the finite truth and output-protocol controls with:

```sh
cargo test --locked --offline --release -p liteinst2 --test call_tree_truth
python3 -B tools/rapid-profiler/tree-work/test_recipe.py
```

The release reproduction uses the existing ordinary-interval runner with
`--call-tree`, retaining the inherited populations. From a clean exact revision,
use a fresh directory under `ignored/` and absolute toolchain/cargo-home paths:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$(git rev-parse HEAD)" --raw "$PWD/ignored/tree-run" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work \
  --counter-probe --call-tree
```

The required tree state population is four pairs/eight children, 1,372 complete
boundary comparisons, 24 immediate application-transfer witnesses and eight
real outer returns. The 1,328 original instructions produce 528 model events,
392 hits and 136 misses. A run earns those counts only after exact source,
input, stack, register, flag, XSAVE, row, journal, Report and child-reap checks.
The original 15-second and 20,000-step child limits and 90-second/1MiB state
stage limit apply. Failed witnesses or limits remain failures.

Raw logs and capture state remain in `ignored/`. A paper-facing receipt records
the exact source revision, release profile, command, sanitized hardware and
the four-row CSV; it must describe the actual completed run. This document
states the fixed contract, not an execution result. Concurrent epoch ownership
requires its separate real-call control and cannot be inferred from these
single-epoch pairs.

The required owner control pauses the actual root entry under epoch A, replaces
it with B before child entry, and replaces B with C at the child's pre-RET
pause. It checks that B stays pending until the original caller continuation
and A stays pending until the actual outer return and source postflight. The
caller retains its local loader and attachment; only the controller moves to
the joined helper thread.

A separate malformed-word child authenticates the original E8, changes only
its eight-byte saved return word, and requires bounded normal exit 123 plus
exact reaping. Its one-row `EXPECTED_REFUSAL` result is separate from the four
successful pairs. Exit 123 is the existing undifferentiated fatal policy; the
receipt makes no claim to have decoded the internal runtime error.
