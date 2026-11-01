# Three resident regions: finite architecture experiment

This opt-in page-mode profile tests one shared lifetime for three separately
published regions. It uses an in-process signal gate, sealed code/proof objects,
and a maintained source view. The original two-region owner is unchanged.

The fixed application makes four cycles through three regions. Native execution
provides the reference register, flags, floating-point, signal-context and stack
state. The generated execution must finish with zero signals inside the admitted
graph and one terminal signal. A completed process alone does not pass: the
independent application, owner and pair readers must all accept the actual
records and reject their supplied corruptions.

The runtime also has two narrowly scoped routes needed before this graph:

* PUSHFQ and POPFQ use sealed one-instruction tiles on the original stack with TF
  clear, followed by a flag-neutral jump to the original next address. Unsupported
  post-state is refused before continuation.
* Explicit POP-memory, segment-register store, x87 and KMOVQ forms execute at
  their original addresses under TF. The memory-write guard uses the decoded
  instruction and original register state without reading the operand.

Both routes are disabled by default. Their native observations retain complete
FP state and real memory faults. Standalone SIGFPE/SIGBUS observations do not
establish production fault-capture or drain support; those signals remain fatal.

This experiment does not establish arbitrary-program coverage or a whole-process
speedup. The unchanged original qualification cohorts and matched native/page/
DynamoRIO comparison are required before making those claims. All performance
runs use release builds; a validation duration is not a throughput measurement.

From a clean checkout, reserve one CPU externally and run the entire process
tree on it. Set `LI2_CPU` to that CPU number, then run:

```sh
python3 -B evaluation/inprocess/reproduce_resident_three.py \
  --expect-revision "$(git rev-parse HEAD)" --cpu "$LI2_CPU" \
  --output target/evaluation/inprocess/resident-three
```

The fixed sequence builds the decoder archive, runs both native instruction
cohorts, builds and runs the native/generated graph, and audits the full
records. It creates five fresh sibling directories beside the cohort output.
It stops on failure and never retries or substitutes a result. Native subjects
retain the 5 CPU-second / 15 wall-second limit; the gated subject retains
30 CPU seconds / 60 wall seconds. Both use 512 MiB and a 16 MiB output bound.
The offline audit requires all 80 native application, 80 gated application,
231 owner and 44 pair corruption controls in addition to the full state checks.
Raw process captures stay in `target/`; publish compact JSON/CSV summaries with
the exact revision, hardware, command and receipt hashes under `evaluation/`.
