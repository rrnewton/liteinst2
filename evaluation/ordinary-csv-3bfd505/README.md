# Ordinary CSV: retained failed qualification

At `3bfd505852069856f56490271a07af9169a9fc24`, the single planned release
qualification failed before any CSV call. The static ELF loader refused `Format`: the
DSO link recipe omitted `-z now`, while the unchanged loader requires an eager-binding
NOW tag or flag. The compiled function was 126 bytes with two RETs. All 16 original
and 16 installed calls are **UNRUN**; there are zero functional result rows.

The caller disassembly contained a 20-byte straight-line function, an indirect CALL,
and an immediate result store at offset 15. This is only static shape evidence; no
runtime return-word join occurred. The child exited 101, with normal ECHILD closure
and no rescued descendants. One CPU (118) was reserved through cpuset-alloc; the
one-minute load average was 81.63 before and 83.91 after. This is not a quiet-host claim.

All seven source checks passed at this revision: workspace default parallelism
3,134 passed / 0 failed / 36 ignored, serial launch 1,039 passed, staged allocation
3 passed, and prefixed-pun oracle 36 passed; fmt, strict Clippy and check passed.
The receipt also preserves the preceding `82671a6` Clippy failure. No performance
number is reported: wall durations describe command execution only.

`receipt.json` records exact revision, commands, tools, hardware, resource bounds,
reservation, numerical outcomes and hashes. `outcomes.csv` is the complete one-attempt
population. Raw logs and ELF captures remain under ignored/. To reproduce this
failure, check out the recorded revision and use the receipt command with fresh
local directories. The tracked script is `evaluation/ordinary-csv/reproduce.py`.

The prospective correction adds only `-z now` to satisfy the loader contract; the
loader, C source, 16-case corpus, checks and bounds stay unchanged. A corrected
build has a separate frozen one-attempt qualification. It does not replace this
failure. Claim 4 receives a bounded refusal result; functional success, full native
state and full A5 completion remain unproved here.
