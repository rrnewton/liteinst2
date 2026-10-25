# A2 mandatory-prefix move qualification

Five four-byte legacy SSE/SSE2 move forms now have forced native evidence on an
**AMD EPYC Zen 5 dev host**: MOVSS and MOVSD register copies, MOVDQA register
copies, and MOVDQU memory loads and stores. The planner recognizes the exact
instruction codes, lengths and operand shapes. The ordinary GPR qualifier and
all earlier tests remain unchanged.

The admitted register forms use XMM0–XMM7. The memory forms pair a low XMM
register with plain RAX, RCX, RDX, RBX, RSI or RDI addressing, without an index
or displacement. Extra prefixes, REX/VEX/EVEX forms, arithmetic SIMD, string
MOVSD, other memory/register forms, and wider addressing remain refused. Native
tests use the five literal operands below; they do not test every admitted
register substitution.

| Original bytes | Required instruction |
|---|---|
| `f3 0f 10 c1` | MOVSS xmm0,xmm1 |
| `f2 0f 10 c1` | MOVSD xmm0,xmm1 |
| `66 0f 6f c1` | MOVDQA xmm0,xmm1 |
| `f3 0f 6f 07` | MOVDQU xmm0,[rdi] |
| `f3 0f 7f 07` | MOVDQU [rdi],xmm0 |

Each instruction precedes MOV EAX,0x64534231 and RET. All three original heads
execute with both established state seeds through B1 relocation, B2 generalized
punning, and T1 with one, two and three prefixes. All 25 cycles must install and
retire at their exact prescribed addresses. Each pun geometry has one candidate.
B1 has 12 prospectively fixed candidate slots; only the 0x60 slot fits the sole
permitted page. No upstream search or alternative tactic can satisfy a case.

The normal matrix requires 150 original traces, 150 installed and 150 retired
comparisons, 50 authenticated selected-site callback events, and all 10 routed
B1 successor entries. Every cycle separately refuses a declared entry in the
middle of its mandatory-prefix instruction with `NotInstructionHead`; the 25
refusals preserve all source bytes and another 150 native state comparisons.

Both MOVDQU memory directions also execute from a null-address prefix through
all five tactic geometries. These 10 cycles require 20 original, 20 installed
and 20 retired synchronous-fault comparisons, with SIGSEGV, SEGV_MAPERR, address
zero and the original logical fault PC. Fault callback counts are not measured
by the existing fault API and are excluded from the 50 normal events.

The existing comparator checks GPRs, defined flags, extended state, application
memory and stack/redzone. Callbacks deliberately clobber caller-saved state.
Complete source and generated-image bytes are checked independently. No mask,
15-second trace deadline, 20,000-step limit or earlier calibration is changed.
Normal and fault cohorts have separate bounded exec wrappers.

The unchanged core first failed the required MOVSS positive with
`UnsupportedSemantics`. The corrected private core then passed all 25 normal
and 10 fault cycles and warnings-denied Clippy. Four additive unit tests also
check the five exact positives, 17 valid nearby negatives, invalid LOCK and
constructed operand-shape negatives, plus unchanged ordinary GPR outcomes.
Initial test compilation and private-package setup failures remain archived
with the successful receipts in ignored private evidence.

This is a bounded mandatory-prefix qualification. It does not qualify general
SIMD, relocated CALLs, exception landing pads, asynchronous signal/unwind
recovery, active CET or Intel hardware. Those and the remaining full A2 gates
stay open.
