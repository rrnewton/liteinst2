# FreeBSD strnlen source and structural provenance

`strnlen.c` is byte-exact FreeBSD source at commit
`10e31f0946d820d53adc58b7d013b969e4a9a8ed`, path
`lib/libc/string/strnlen.c`, blob `b44f8ab2194710a91dfde4be07384f1fbdeec79a`.
Its SHA256 is `969eb826cd618ff799cdc4fcc9d61edd044a314bd39208479787eda622c4f336`.
`UPSTREAM.json` preserves the fetched source record, including its historical
pending build/header status and lack of Git signature validation. It is source
provenance, not a current build or execution receipt.

The original BSD-2-Clause copyright, conditions and disclaimer remain in the
source. Source redistributions must retain that notice; binary distributions
must reproduce it in their documentation or other supplied materials. This
controlled translation unit does not represent the deployed FreeBSD libc.

The fixed anonymous `localize.map` localizes all definitions. The wrapper calls
the existing selected-work geometry validator through its closed strnlen
profile: symbol `strnlen`, label `freebsd-strnlen-14.1-v1`. The checksum profile,
default API/CLI, bounds and geometry predicates remain unchanged. Both entry
points refuse optimized Python before work. Readelf symbol-table headers must
use `1 entry:` or a non-one count followed by `entries:`; the actual row/table
counts must still match the ELF. The strnlen profile additionally requires the
sole null dynamic symbol in both files, matching its all-local script; checksum
dynamic-symbol rules are unchanged.

The CLI retains the existing arguments:

```
python3 -B tools/rapid-profiler/strnlen-work/provenance.py \
  --prestrip PRESTRIP --final FINAL \
  --pre-symbols PRE_SYMBOLS --final-symbols FINAL_SYMBOLS --output NEW_MANIFEST
```

The caller must independently bind the exact upstream source, compiler flags,
Linux LP64 header/preprocessor closure, tools and commands. It must freeze the
complete final-file authority before candidate copying. This helper checks
selected code and full RX equality, final symbol/debug stripping, and unchanged
ELF/LOAD geometry. It does not establish compilation, correct C semantics,
loader/CFG eligibility, patchable entry/returns or native fit. No compiler flags,
runner, SDK or native route are changed here; short-return support remains a
separate prerequisite, with zero-bound and early-NUL paths retained.

Run the existing six checksum controls and the eight new structural controls
separately. The new synthetic ELF buffers and symbol text are never loaded or
executed and are not a substitute for real compiler/strip qualification.

```
python3 -B tools/rapid-profiler/selected-work/test_provenance.py
python3 -B tools/rapid-profiler/strnlen-work/test_provenance.py
```
