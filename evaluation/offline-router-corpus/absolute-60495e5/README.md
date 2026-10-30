# Absolute-prerequisite startup attempt

Revision `60495e5b69fd0d48a15d6a22c7e2bfe73a7b73b0`, AMD EPYC Zen 5 dev host.
This claim-4 result covers both complete authored programs: 187 instruction
heads and 42 selected jumps. Preparation, independent main verification, both
release bootstrap builds, observer build and final dependency-fact preparation
passed. Both five-object graphs were independently reviewed. These checks do
not establish native correctness.

The single observer attempt **failed**: its checksum child exceeded the fixed
30-second wall limit (30.493851 seconds, SIGKILL, ECHILD cleanup). RLE remained
UNRUN. No ordinary N01 invocation was made; all 20 pairs / 40 invocations remain
outstanding. Empty observer output does not prove whether its native exec was
reached. The failed attempt is retained without a retry or wider deadline.

One separately instrumented, read-only preflight completed. It made 668 Git
`check_output` calls, including 605 across eleven native-source checks. Its
45.686744-second owner duration includes instrumentation and final cleanup;
these are diagnostic timings, not release performance measurements. That
diagnostic dispatched no observer or application.

Matched E9 preparation and all sixteen new executor controls passed. The first
actual transport command exited zero, but the executor then rejected the exact
directory-membership check. The command row remains FAILED, seven commands and
all four structural products remain UNRUN, and all eighty application rows
remain UNRUN. Both a small repeated-listing diagnostic and a later reread of
the actual closed command passed. The cause remains unresolved; no directory
reader change is justified by these observations.

`results.json` contains the measured numbers, exact source and input hashes,
commands, reserved CPUs, load averages, limits and raw-log hashes. Paths use
`$ROOT`, `$TOOLCHAIN`, `$CARGO_HOME` and `$USER_HOME` substitutions. Raw logs and
captures stay in ignored storage. Every recorded command ran once against the
clean stated revision with four reserved CPUs and the existing process owner.

Reproduction uses `../reproduce_preparation.py` for each explicitly selected
preparation/observe stage, `../profile_preflight.py` for the diagnostic, and
`../../offline-corpus/full_startup_e9.py` for matched E9 preparation. Their
recorded argv and external input hashes are in `stages`. Fresh local source,
platform, build and whole-fact records must be generated; the platform contract
and final profile require the caller's explicit review. Historical private
paths and statuses cannot substitute for those actual inputs. No script
automatically proceeds from preparation to native execution.

The separately pinned E9 executor and its controls were run as private source
and are published byte-for-byte in `../../offline-corpus/full_startup_e9_execute.py`
and `full_startup_e9_execute_controls.py`. Their bytes were **not** in the frozen
60495e5 source inventory. Commit `d32f705` preserves those exact historical
executor bytes; later changes do not reinterpret this result. The executor accepts the recorded plan hash and its
own source hash, and pins its seven dependencies to that revision. To reproduce
this historical attempt, use those exact dependencies and executor bytes with
fresh outputs. Its `outputs` phase requires a separately completed N01 result
and was not invoked here.

No full-A3, route-coverage, qualification or performance claim is made. Earlier
16 MiB corpus failures, cache-identity refusal, workspace timeout and the strict
2 ms clock campaign (one pass, four failures) remain unchanged.
