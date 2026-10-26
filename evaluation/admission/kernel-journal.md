# Retained partial kernel progress

`DynamicAdmissionSession::kernel_progress()` returns a cloneable read-only
`KernelProgressReader`. Its `snapshot()` returns diagnostic facts without sending
a tracer command, so a caller can retain it across an operation error or session
drop. The archive belongs to the native owner independently of the temporarily
taken admission state. It exposes historical identities, never a stop token or
permission to resume, repeat or complete an invocation.

Before restoring an original selected syscall, the owner prepares 32 fact slots
and eight 64 KiB state buffers. The exact pending invocation, source generation
and plan, full input state, task and absolute deadline bind this storage to its
owner. The existing census reserves and debits the complete retained allocation
before attachment or release. Original effect accounting remains separate and
the 64 MiB lifetime limit remains nonrefundable. CPU and scripted completions do
not create kernel attempts.

The journal distinguishes release attempts from successful ptrace requests,
raw stops from validated lifecycle transitions, and native transport completion
from admission completion. A successful resume request alone proves no syscall
result. Raw capture starts after successful pinned wait delivery and precedes
lifecycle interpretation. It commits the raw header before reading syscall info,
event payloads or full state. Partial reads retain an explicit incomplete state;
they never expose a partially initialized complete snapshot. Earlier WNOWAIT
observations that fail pin acquisition or consumption are outside this capture
boundary and remain ordinary failures.

Actual syscall ENTRY, parent CLONE, automatic newborn return-ready and parent
EXIT have separate raw records and state slots. A raw newborn has no invented
logical task identity before creation joining. A later validation fact links the
original records without rewriting their collection order. Queued logical events
do not create another raw observation, and a newborn is never assigned an
unobserved syscall EXIT.

Each neutral return bridge retains its start and actual completed full state.
Completion requires exact GPR, XSTATE and signal-mask equality with the original
EXIT or newborn state. Transport completion follows all required bridges.
Admission completion follows census checks, generation rebinding, source rearm,
final-state checks and accounting. A later error therefore preserves the
successful prefix without turning it into an admission result. The first failure
survives subsequent errors, cancellation and panic while admission state is
temporarily moved out of the owner.

Reader snapshots copy retained data under a mutex. No ptrace, wait, provider or
client callback runs while that mutex is held, and reading never renews a native
deadline. `archive_poisoned` reports an interrupted critical section. Writer
status reports cleanup separately from invocation progress. A `Cleaned` status
is diagnostic; physical cleanup still requires the native owner's terminal waits
and independently retained pidfd/natural-parent evidence. The in-memory archive
does not survive process death and is not a crash-durable journal.

## Validation boundaries

Twelve pure tests exercise archive transactions and actual census accounting.
Their synthetic states do not establish native stop or cleanup behavior. Native
fixtures separately compare retained states with a raw-ptrace execution of the
same fixed ELF. They preserve all GPRs, flags, orig_rax, complete XSTATE, the exact
signal mask, initialized stack/data and original source bytes. Only a known
PID/TID result is substituted across runs, after independently checking each
run's actual identity. TRACEME's newborn SIGSTOP and the seized owner's newborn
EVENT_STOP/SIGTRAP are checked as distinct kernel facts.

Per-owner test-only hooks fail at raw/validated ENTRY, actual EXIT, raw newborn,
each bridge, transport and rebind boundaries. Bounded channels witness the real
phase before an exact error, panic or deadline expiry. Native operation expiry
and client response expiry retain different exact errors. A repeated request
must refuse without another original release or completion. Successful getpid
and gettid cases additionally require exact source rearming.

The held-native capacity fixture retains the default 64 MiB limit. It consumes
explicit unused, nonrefundable setup reservations until the unchanged ordinary
completion envelope fits but the additional journal allocation is one byte
short. The actual production completion must refuse before attachment,
restoration or release, with unchanged full native state, source, pending input,
census, retained-byte usage and charged budget. The setup reservations are
lifetime charges, not fabricated retained payloads or a reduced default limit.

Two separate tests collect and journal genuine CLONE/newborn stops in actual
wait order, then force each lifecycle processing order. They qualify processing
of held observations; they do not force chronological kernel wait order. Both
retain the prefix through duplicate-dispatch rejection, with no child EXIT or
admission completion invented.

The independent raw tracer blocks all catchable signals across its exclusive
wait domain, acquires the first pidfd atomically and pins unknown waitable tasks
before consuming statuses. It installs the exact application mask at the held
exec stop. Cleanup retains ownership until the wait domain is empty and retained
pidfds show physical removal. Native owner cases retain the existing production
cleanup rules. A caller timeout is never a successful cleanup result.

Exact named outcomes appear in `native_validation_fixtures` only under their
declared unit harness. They qualify only with the complete unchanged evaluation
protocol. Counts and results come from that revision's corpus and receipt.
These checks support claim 4 and admission prerequisites for claims 1 and 2.
They add no accepted syscall, signal, mapping or exec profile, no performance
result, and no full B3 or crash-durability claim.
