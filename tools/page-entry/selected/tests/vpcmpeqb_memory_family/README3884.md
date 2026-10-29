# VPCMPNEQUB256 memory oracle

The explicit `VPCM_PROFILE=3884` / `--comparison neq256` profile covers only
canonical unmasked EVEX.256.W0 VPCMPUB with immediate 4 (unsigned byte NEQ).
The original Code1720 EQ512 build, catalogue, protocol, and evaluator default
remain available with their original population and bounds.

Run at an exact committed revision on one externally reserved CPU:

```
PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/page_selected_vpcmpeqb_memory_family.py --expect-revision <40-hex revision> --comparison neq256
```

The evaluator builds its authenticated decoder archive and five fixture images
from current source. Each positive image runs one original startup pair and 18
native/TF instruction pairs. Four additional processes require actual failed
reads: ordinary and indexed addressing, each wholly inaccessible and 16+16-byte
page crossing. They must exit 125 with no TRACE or instruction completion;
the completed startup prefix is kept separately. No failed operation becomes a
completed comparison. Native subjects retain the original 5 CPU seconds,
15 wall seconds, 512 MiB address space and 16 MiB file/record limits.

The 90 literal cases combine all 32 YMM source roles, all 8 K destinations,
all 16 GPR bases, all 15 usable index roles, scales 1/2/4/8, RIP-relative and
absolute addressing, unaligned/data-page edges, disp8*32 extrema, and every
fetch tail for instruction lengths 7/8/9/11/12. Eight exact retained libc
encodings are included. This finite structural population is not an exhaustive
encoding census or an application-completion claim. The four fault instructions
also occur in the successful population.

The fixture computes NEQ from the actual captured low 32 source bytes and
actual retained operand, then joins a separate literal zero/full/mixed mask.
All K registers begin with nonzero high halves. The full selected 64-bit K
result must equal the zero-extended mask; every other K byte and all 32 complete
ZMM registers remain byte-exact. The original native/TF full GPR, logical flags,
initialized kernel FP, live XSAVE, selectors/bases, signal mask, source image,
private stack, data, actual continuation and revoke checks still apply. No
architectural state is normalized. RIP-relative operands are joined to the
complete immutable source image; other operands to captured stack/data bytes.

The independent Python leaf binds the entire literal C/JSON catalogue, decodes
its EVEX/ModRM/SIB address fields, and joins all 188 actual-before GPR/FS/GS,
NONE and effective-address observations. It does not claim to repeat the full
C architectural oracle. Every process retains all 108 old refusals, all 14 old
typed/NONE promotions, and 33 additional mandatory forbidden neighbors. Those
neighbors include all seven other low immediate predicates; none is promoted.
Old promotion records remain complete and separate. The new query trailer is
10,304 bytes; the complete ELF-sized record must still fit below 16 MiB.

This source profile grants no execution or qualification credit until its
fresh native processes and complete consumers pass at the claimed revision.
