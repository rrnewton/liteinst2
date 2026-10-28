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

## Fresh unchanged-source qualification

The additive recipe keeps the named and selected qualification recipes as
fresh mandatory prerequisites, including the old named short-return refusal.
Run it from a clean exact revision with an existing ignored parent directory:

```
python3 -B tools/rapid-profiler/verify_strnlen_interval.py \
  --revision FULL_40_HEX_REVISION --raw /absolute/repo/ignored/NEW_ATTEMPT \
  --toolchain /absolute/toolchain --user-home /absolute/user-home \
  --cargo-home /absolute/cargo-home
```

The recipe uses the unchanged shared C flags and all-local script, binds the
complete GCC header closure before preprocessing/build, checks the exact
preprocessed strnlen body and Linux LP64 ABI, and compares the actual `-MD`
dependency closure after compilation. Compiler, header and source changes stop
the attempt. The prestrip/final complete ELF authority, full RX equality and
load geometry are fixed before distinct-inode candidate and mutated copies.
The source and its BSD license are never edited or replaced.

After the fresh old prerequisites, 24 direct stages require the eight
provenance and nine protocol controls, exact release control groups (7 core,
6 frontend, 6 state, 7 work), seven compiler/metadata stages, and the three
refusal/state/work executions. Compiled test inventories authenticate exact
filtered counts. All C stages use 20 CPU seconds, 30 wall seconds and 1 MiB;
state uses 90/90/1 MiB and unchanged per-pair 15-second/20K bounds; work and
refusals use 20/30/1 MiB. No retries, reduced population or alternative compiler
flags are available after failure.

The native state population is two seeds times eight cases: zero bound,
single-byte empty/nonzero, last-of-two, interior NUL, long empty, long last NUL
and full bound. All 16 original/installed pairs retain the full state comparator,
actual subject and outer returns, complete reachable head/edge/RET union and
input operand containment. The finite consumer separately performs eight
originals and eight installed calls: four sampled, three FunctionClosed and
one Removed, retaining both two-record Reports, four history actions, sixteen
events, all 512 journal words and actual detach/thread join. The three preload
refusals retain named-final, wrong whole-file and changed-selected-byte errors.

`strnlen-pairs.csv`, `strnlen-rows.csv` and path-redacted `result.json` are compact
outputs with exact command/source/tool/release/closure joins. Raw streams,
headers and detailed manifests remain ignored. Scalar rows do not independently
replay full state, complete journals or Reports. Raw callback ticks are
uncalibrated; this recipe establishes no timing accuracy, performance,
cache-hardware, deployed-libc or full-A5 claim. A source proposal or successful
parser control does not establish compiler fit or a successful native campaign.
