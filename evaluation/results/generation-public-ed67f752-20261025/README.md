# Public generation metadata qualification at ed67f752

The complete v6 campaign passed seven main commands at
`ed67f7528184bf9ba33c05946ed8b07bef1bf41d`: normal-library build, test compile
without execution, exact list, 17 model tests, Clippy, two ownership compile-fail
documentation examples, and Rust 1.85 check. Sixteen separate preparation and
before/after verifier steps also passed. `commands.csv` has all 23 rows;
`cases.csv` has exactly 17 model cases and two documentation cases. Listing
those model names is not another 17 cases. The models reported zero failures,
zero ignores and seven filtered legacy profiler tests. The separate required
workspace campaign retains those old tests; its results are not added here.
The documentation diagnostics are exactly E0599 and E0382.

The seventh main command makes the ordinary library prerequisite explicit.
It was added before this v6 run. All six original command caps remain intact:
compiler/Clippy/MSRV 60 CPU seconds / 90 wall seconds / 128 MiB per-file cap;
list/models/docs 20 / 30 / 1 MiB. The library prerequisite uses the same compiler
cap. Preparation and each verifier use 20 / 30 / 16 MiB; model-request
preparation uses 20 / 30 / 128 MiB to copy the admitted binary. Documentation
used the prebuilt, independently admitted normal library, unchanged before and
after the command. This is **not** a cold documentation build under 1 MiB.

Cargo reported library 1 new / 16 reused artifacts; test compilation 0 new /
17 reused; Clippy 17 new / 4 reused; MSRV 21 new / 0 reused. The model executable
was separately admitted and archived from the actual compilation records,
then its full hash was required for list and models. Reuse is not relabelled as
recompilation. The earlier C fixture's missing historical Clang identity remains
a provenance limit; observing current tools cannot fill that historical gap.

The saved verifier commands directly checked 189 source files, nine executable
roles, the helper source, and 16 Cargo configuration observations. Two ancestor
configuration `exists` calls returned EPERM; that operation/errno is recorded,
not called absence or evidence of hidden contents. The 206 enumerated runtime
paths are separate before-campaign and current post-campaign observations,
not an exhaustive runtime/tool closure and not timestamped per-command captures.
Root's historical pre/post assertions are invocation history, not extra saved
verifier evidence. The hardware record is a before-campaign observation on the
AMD EPYC Zen 5 dev host, without continuous attestation. No tool version banner
was executed in these 23 steps; exact hashes and role identities are recorded.

The prior v3 attempt stays `PARTIAL_QUALIFICATION_HELD_BEFORE_MODEL_REQUEST_PREPARATION`:
its compile passed, but its canonical Cargo package-ID predicate was wrong.
Models and the remaining gates did not execute there, and no result was
transferred into this campaign. Two later post-observation review errors also
remain preserved: using lstat instead of the original stat method produced
24 symlink-metadata mismatches, followed by an incorrect mixed-method narrative.
The final current observation matches all 206 original stat rows. Those were
metadata-checker errors, not failed application or compiler commands.

All four paper claims remain unqualified. These are generation-bookkeeping
models and ownership API checks, not frontend activation, physical probe
publication, a software/preemption clock, or full A5. Internal comparator
calibrations are already included in the 17 models. The historical standalone
report and required-workspace report remain separate source/result records.
Elapsed values are operational diagnostics from a shared host, not benchmarks.

## Reproduction and identities

Use [the exact v6 request generator and instructions](../../generation-public.md).
Keep `REPO` checked out at the tested revision and `REPORT` at the later checkout
containing these evaluation materials. `RAW` is a fresh directory below
`REPO/ignored`. The nine recipe/material files are shipped once; their snapshot
source ID retains `tested_revision: null` because the generator ran from the
private proposal, while the seven main commands name the actual ed67 revision.
A later data commit does not change the tested revision.

`summary.json` records each actual command's sanitized argv/environment, request
and receipt hashes, output hashes, helper limits and outer invocation. These
are role substitutions, not a claim that literal placeholder strings executed.
The exact outer wrapper used timeout with TERM and kill-after 10 seconds:
40-second outer timeout plus finite 55-second parent wait for 30-second helper
requests; 100 seconds plus finite 115-second parent wait for 90-second requests.
The existing helper's zero-exit, unchanged-input and clean ECHILD receipts are
required; the wrapper does not introduce a new supervisor or retry. Before
launching any new attempt, review actual local source/config/tool admission and
the fresh compiler/dependency/binary binding as the v6 instructions require.

JSON is authoritative; CSV stores nested argv/environment as JSON cells.
`files.json` hashes this public result directory. `source-files.json` preserves
all 189 source hashes plus the nine recipe hashes. `runtime-observations.json`
exports only ordinal/path-digest IDs, sizes and full-byte hashes for the 206
explicit observations; raw paths, inode/device records, environments, logs and
artifact bytes remain private. The source-tree digest uses sorted compact JSON
without a trailing newline. The private capture inventory is represented by
its SHA-256, not by published raw paths.
