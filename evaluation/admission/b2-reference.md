# Finite comparison of execution modes

The `b2_mode_reference` integration harness compares five immutable fixtures
through dynamic page admission, explicit static traps, a handwritten interpreter
and a test-only controlled block runner. Six outer tests cover those positive
fixtures and strict negative controls. The positive fixtures declare 17 selected
transitions in each lane: 51 scripted applications across three real process
lanes, plus 17 pure-model transitions. They are not 68 native selected samples.

Every process receives the same fixed ELF bytes, complete instruction-head and
block-entry census, private data/stack and literal setup. The raw runner obtains
an independent checkpoint after native setup. It checks all literal GPR seeds,
flags, segment state, x87/SSE fields, exact mask and initialized memory before
using its complete state as the reference baseline. Production initial-state or
completion helpers do not supply that baseline.

The handwritten finite decoder recognizes only the declared fixture forms.
Every ordinary instruction executes under actual raw-ptrace SINGLESTEP and
requires an owned TRAP_TRACE and exact full-state agreement. At a selected head,
the controlled runner checks the original bytes and intercepts before resume;
its scripted effect is applied while stopped. It never single-steps an original
selected syscall. The interpreter and raw selected emulation share handwritten
selected semantics, so they are one independent selected-effect reference.
Actual ordinary execution independently checks the model's ordinary effects.
This runner is not a production BlockGate or general block translator.

Both production paths must match the complete callback trajectory and each
before/after GPR, flags, kernel metadata, XSTATE, mask and data/stack snapshot.
There is no flag clearing, field removal, XSTATE mask or comparison tolerance.
The fixtures cover masked CPUID followed by deliberate random instructions,
timestamps, RDPID, scripted getpid, prefixed operands, declared alternate entries,
an embedded selected suffix in MOV, and a page-boundary CALL/RET. The latter
returns into a never-executed NX page; potential return obligations remain
independent of which pages previously executed. Exactly one collateral MOV in
the embedded fixture contributes no selected callback.

Strict RDPID overlap refusal remains a refusal in both production paths, with
zero callbacks and physical cleanup. The static path checks the exact typed
embedded-candidate address. The dynamic path checks source/NX before its closing
error and does not invent a post-error inspection. Separate raw controls reject
unknown heads, changed bytes, wrong scripts and exhausted step budget while
held state remains unchanged. Unsupported INT80/SYSENTER refuse. Corruption
controls cover register, flag, metadata, mask, XSTATE and memory comparisons.

Each lane retains ownership through assertion failure and physical cleanup.
The raw tracer uses its original retained identity and bounded cleanup on the
same tracer thread. If it cannot prove physical removal, the entire test command
fails; no detached reaper or cleanup exemption makes the case pass. The normal
evaluation protocol additionally requires zero supervisor-adopted descendants.

The six exact named outcomes are recorded separately from static native samples,
dynamic fixture outcomes and dynamic operand telemetry. They require terminal
`ok`, command success and every unchanged whole-run gate. The catalog is an
expected inventory until a receipt qualifies execution. This is claim-4 evidence
for these finite trajectories, with no bootstrap, native selected-output,
production block backend, hook-cost or complete B2 claim.
