# Canonical unmasked VMOVDQU64 load/register family

This extends Code1605 to canonical EVEX.512.W1/F3/0F/6F with reserved vvvv
and V', no writemask, zeroing, broadcast or leading prefix. It admits ZMM0–31
and original 64-bit ModRM/SIB/RIP memory operands, including signed compressed
disp8 multiplied by64. Store opcode7F, other widths, W0 and masked forms remain
outside this family. The existing write-footprint rule remains NONE.

The fixed160 native/TF pairs run as ten16-case cohorts, each with the original
startup self-test. They cover all32 source and destination registers,32 self
copies, all16 GPR bases, all15 usable indices/scales, the actual libc encoding
`62e1fe486f5701` (ZMM18 from RDI+64), ordinary signed disp8/disp32, RSP,
RIP-relative and guarded absolute-SIB operands. Every tail of every supported
length (6,7,8,10,11) is present:42 combinations, with37 crossing and123 ending
pairs overall. This is structural coverage, not1024 register pairs or every
numeric address. The literal tables are hash-bound and independently decoded
by the evaluator, including disp8 scaling and ignored address-extension bits.

The shared `tests/vmovdqu64/fixture.S` and `tests/generic/fixture.c` remain
unchanged. All32 ZMM registers and eight opmasks have independent nonzero seeds.
The C oracle compares complete actual native/TF GPRs, flags, selectors, bases,
initialized kernel FP state, live XSAVE, source, data and private stack. It
checks all512 destination bits against the independent source literal and
every other initialized state byte for equality. No additional masks or
normalizations are introduced. Four real failed reads cover ordinary/indexed
fully inaccessible operands and32+32-byte page crossings; required exit125,
trap14/ERR4/CR2, zero TRACE/completion and full unchanged state are mandatory.

The original33 VMOVDQU64 neighbor bytes are retained unchanged. Seven exact
rows0–6 retain mandatory positive Code1605/FALLTHROUGH/SIMD and supplied
NONE-footprint checks, plus a native pair each. The25 remaining rows stay
negative; original index12 (`62e1fe286f0f`) now has a separate mandatory
Code1604/NONE promotion and native coverage in the256 cohort. All47 common
refusals remain. The original2080-byte seven-row trailer is unchanged; a
separate352-byte trailer retains the exact Code1604 observation.
The seven older fixtures containing these seven rows receive the same explicit
promotion checks and trailer. Their native cases, failures, old catalog bytes,
all other assertions and process limits remain intact. Counts distinguish
negative rows from qualified positives; no failed subject becomes a pass.

Run `evaluation/inprocess/page_selected_vmovdqu64_family.py --expect-revision`
with the exact committed revision and one reserved CPU. The evaluator reuses
the original build/header/ELF/capture/source closure. Each fixture build and
native process keeps5 CPU seconds,15 wall seconds,512MiB and16MiB, including
the complete new trailer. The source packet alone grants no native,
application-completion, performance or full-B2 qualification.


The explicit `--vector-bits 256` mode uses `build256.sh` and literal
`cases256.json`/`cases256.inc`; default512 keeps the original catalogue/build
invocation. Shared C code selects only operand bytes, Code, exact profile
identity, displacement/fault geometry and the additional AVX512VL prerequisite.
For256 every destination bit is checked: the low32 bytes equal the original
source and the upper32 bytes are zero, including all32 self-copy cases.
All other state remains exact, and failed reads preserve even the upper bits.
Ten16-case groups retain170 positive pairs including startup; four required
faults retain their separate startup pairs and failed outcomes. All42 fetch
tails, all32 register roles, all bases/indices/scales, RIP/absolute operands,
the actual libc RSI load and its +32/+64/+96 forms are literal rows. Four
read faults use fully inaccessible and16+16-byte crossing operands. All25
additional VL256 negative neighbors must refuse, alongside the72 old negative
controls after the explicit one-row promotion. A passed512 result does not
stand in for256; both complete profiles and affected old companions are
required before promoting the production width addition. Limits remain exact.
