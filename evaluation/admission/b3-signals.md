# Native signal-admission evidence

The signal cohort compares one original asynchronous signal transaction in two
fresh processes: a pristine native reference and the explicitly selected
dynamic signal-admission profile. These are named fixture outcomes, separate
from the existing instruction samples and timing experiments. The cohort does
not establish the complete B3 application envelope.

The ordinary-stack and alternate-stack trajectories compare the complete
interrupted, handler-entry and returned state, the initialized stack and data
regions, native signal information, and the complete signal frame including its
floating-point payload. The edited-frame trajectory also requires a genuine
`rt_sigreturn` to the declared, previously untouched NX landing page. Its
restored RAX resembles a Linux error value and must retain its actual register
meaning at the return boundary.

Instrumentation can change Linux's saved exception metadata. The production
path retains the actual kernel frame and separately projects only its
trap/error/CR2 fields from an authenticated original metadata receipt. The
application-visible frame must exactly match the genuine pristine kernel frame,
parsed independently of production. The reference executes no NX fault, INT3 or single step before
that frame is constructed. A separate controlled predecessor establishes a
nonzero inherited metadata input before either application starts; both lanes
authenticate it independently. Neither an assumed zero nor a copied expected
tuple qualifies.

The pristine bootstrap establishes kernel-reset rseq before its first user
instruction. A later observation of a zero critical-section pointer cannot
prove that no inherited rseq redirection occurred earlier. Production and
reference use independently authored launch mechanisms; neither may substitute
the other's metadata receipt for its own observation. The separately isolated
nonzero-history test also requires a bounded typed completion receipt emitted
after its actual inner assertions and physical cleanups. Child exit zero alone
cannot qualify that trajectory.

The prospective named integration fixtures are:

| Test | Required observation |
| --- | --- |
| `ordinary_stack_frame_matches_pristine_original` | Native original setup, actual delivery, first handler fetch, exact projected frame and actual return on the normal stack. |
| `configured_altstack_frame_matches_pristine_original` | The same complete transaction on the application's configured alternate stack. |
| `edited_frame_returns_to_untouched_nx_landing` | Exact declared frame edits, genuine return semantics and gated entry to the untouched landing. |
| `inherited_nonzero_exception_metadata_matches_pristine_original` | Independently established nonzero inherited metadata survives the launch anchor and application-visible projection. |
| `pristine_comparator_rejects_metadata_and_unrelated_state_corruption` | The independent comparator rejects hidden-field and unrelated-state corruptions; this is a comparator control, not an additional native instruction sample. |

The exact final catalog also includes the production native failure controls.
Unknown signal/frame/route identities, unsupported inherited state, stale
versions, undeclared frame edits and resource exhaustion remain refusals. A
failed test, ignored test, incomplete named result or missing native path does
not count as a passed trajectory. Existing uninstrumented signal tests and
all other correctness fixtures remain required.

The separate reset-launch unit cohort exercises actual helper ownership before
any application is released. Its eight source-authored cases require:

| Control | Required observation |
| --- | --- |
| Packet-send failure | The actual failed send return, retained reaper ownership and physical cleanup. |
| Transient helper killed before clone | Its actual SIGKILL terminal and an empty exact parent wait domain. |
| Transient helper killed after clone | Both helper identities remain owned through physical cleanup. |
| Absent PID publication | A missing numeric handoff does not erase the real child or its wait ownership. |
| Reaper before its first stop | Live/no-status parent eligibility and recovery through the bounded procfs fallback. |
| Original launch deadline | The original deadline expires; cleanup is independently proved under its existing bound. |
| Injected pin-allocation refusal | The failure remains an error while retained parent wait authority permits cleanup. This is not an operating-system descriptor-exhaustion measurement. |
| Abort before START | The actual empty Done receipt and terminal/HUP/wait evidence establish that no application was created. |

The reset cohort has its own closed test namespace and typed outcomes. It does
not contribute application signal-frame or selected-instruction sample counts.
An inability to establish bounded completion of a test's helper owner aborts
the validation command; a detached live owner cannot supply a test outcome.

Eleven separate synthetic frame-parser controls cover exact three-word
projection, complete-read coherence, malformed bounds, every undeclared byte,
all 32 declared-edit subsets, torn fields and exact final return policy. They
provide no process, frame-construction, publication or native-execution credit.
Their expected byte images use literal ABI offsets, and the actual native
trajectories retain the complete independent state comparator.

Seventeen pure census controls test complete original/prospective frame roles,
session and generation binding, exact immutable history, explicit return
witnesses and storage refusal without refunds. Ten pure configuration controls
test singleton scope, signal and mask eligibility, bounded disjoint stacks,
exact opcode/head source binding and the fixed pre-launch evidence threshold.
These controls provide no native execution or cleanup credit. Their source
review does not substitute for their later recorded test results.

Seven pure journal controls retain independent register, XSTATE, mask and
syscall-information outcomes, including initialized buffers from failed reads.
The first failure remains separate from physical cleanup. Internally, one
bounded record groups each raw stop with its information and state observations;
public snapshots expand the same complete facts in their original order.
The fixed record, state and frame limits remain 64, 16 and 32.

Signal sessions authenticate the native XSTATE export extent using a successful
maximum-size request at an owned bootstrap stop. Linux initializes the regset
extent from its maximum user state size; later dynamic component use does not
shorten or enlarge that export. Subsequent state acceptance requires the exact
certified size and native task identity. This tightens logical retained-state
reservations under the existing 64 MiB lifetime limit. All raw failure buffers
remain reserved at 64 KiB, unused reservations are not refunded, and complete
state comparisons stay exact. The reservation is not an allocator-capacity or
resident-memory measurement.

Run the same complete validation protocol from the exact clean source revision:

```sh
python3 evaluation/admission/run.py --expect-revision REVISION
```

The runner records the four repository checks, recorder calibration and serial
native oracles, with the existing command deadlines, output bounds, four build
jobs and disabled incremental compilation. It publishes typed JSON summaries
under `evaluation/admission/results/`; raw captures remain private. Each result
records the exact revision/source manifest, hardware and toolchain identities,
command arguments, capture hashes and physical cleanup. The named signal
outcomes qualify only when every required command succeeds and source and
configuration remain unchanged. Runtime failure and partial observations are
retained without success labels or automatic retries.

The cohort contributes finite evidence for page publication, selected
instruction interception and systematic validation (claims 1, 2 and 4). It
does not evaluate the preemption clock, signal throughput, nested frames,
arbitrary frame writers, syscall restart, synchronous exception semantics,
general mapping churn or browser/JIT/process coverage. Those B3/B4 requirements
remain independent release gates.
