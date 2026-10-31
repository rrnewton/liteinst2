This fixture embeds both complete, unchanged executable pages from the pinned
reference interpreter. It enters the relocation loop at ELF offset `0x102c8`,
executes two real RELA rows, and follows the original tail and POP/RET sequence.
The native oracle checks all 52 next PCs and retains 12 complete signal frames.
The full data, stack, integer, flags, vector, mask and TLS comparisons remain.

Mode 0 registers rseq before the loop. Mode 2 runs the loop and collects its
complete state before making the real register/unregister calls. Its prefix
explicitly marks registration as unattempted; it does not report a successful
zero result or an observed zero publication word.

The startup capture observes one compiled activation from `0x102c8` to the
genuine `0x100a0` frontier. It retains the whole source/certificate/code,
predecessor and successor frames, mapping and lifetime observations, and
closure of all 17 generated pages. A completed run can establish this one
activation only. Warm entry, two-member activation, faults and performance
need their own evidence.

`evaluation/inprocess/startup_build.py --expect-revision REV` builds both
maintained and differential release bridges with strict source and compiler
closure. It checks their emitted layout against independent source arithmetic.
This script does not execute the guest or confer runtime qualification.
