# Source-certified normal backtrace witnesses

This opt-in adapter builds the active library and eight authored fixture sources.
It checks a normal callback backtrace through generated code for two original
frame profiles and two fixed states. It does not admit exceptions escaping a
callback, arbitrary asynchronous unwind points, arbitrary source CFI, module
unload, fork after registration, or general A2 completion.

`publish_with_unwind` retains source, consumer, code and CFI owners before the
real libgcc registration call and before a reachable source redirect. Registration
has process-lifetime ownership. Existing publication paths remain unchanged.
The native witnesses check real source `.eh_frame` rows, caller RBX distinct from
live hook RBX, actual call-site RSP/CFA observations, real libgcc walks, and the
unchanged strict architectural comparator. PC translation is not unwind evidence.
The fixture requests the authenticated ELF load bias minus 64 MiB as its explicit
preferred image address and requires that exact address in one allocation attempt.
Its original rel32 ranges, 256-candidate cap, 8 KiB allowance and occupancy checks
remain intact. This qualifies that declared placement, not default-allocator
success. Earlier private default-placement and metadata-identity failures remain
failed evidence; they do not contribute passes to this public cohort.

The adapter requires Linux x86-64, the already qualified ptrace/signal envelope,
the pinned GCC/libgcc consumer, and an explicitly reviewed local toolchain map.
All output, input snapshots and host captures belong in a new ignored directory.
The public source never embeds captured ELF tables, host maps or private paths.

## Reproduction phases

Run phases serially. Every output directory is new; failures stay in place.
There is no retry, skipped case or dynamic budget adjustment. The supplied
`bounded_command.py` is the sole descendant-cleanup helper. The adapter uses the
existing `timeout` wrapper around it, never a new process supervisor.

1. Prepare a reviewed source-admission JSON and toolchain JSON. The admission
   binds the complete selected public source map, canonical source-map digest,
   revision/tracked-diff identity, and independent review token. A dirty build
   uses `tested_revision: null`; a later commit cannot relabel that build.
2. Create a phase parameter file from `aggregate-parameters.json`, replacing
   every placeholder with an actual reviewed path or digest. Generate a fresh
   outer request outside the build/runtime tree with the selected Python:
   `"${PYTHON}" -B tools/unwind-oracle/aggregate.py prepare --parameters
   ${PARAMETERS} --parameters-sha256 ${PARAMETERS_SHA} --output ${NEW_OUTER}`.
   Preparation writes only `request.json` and `binding.json`; it launches nothing.
3. Review the actual request/binding, then launch the exact existing helper:
   `"${PYTHON}" -B tools/unwind-oracle/aggregate.py launch --binding
   ${NEW_OUTER}/binding.json --binding-sha256 ${ACTUAL_BINDING_SHA}`.
   This authenticates the recorded Python, helper, source and inputs, then uses
   `execve` to replace the launcher with `bounded_command.py` in an explicit
   environment. There are no new process-supervisor or cleanup algorithms.
   The helper owns the complete phase and descendants, including interruption
   paths. Its receipt and stdout/stderr remain in `${NEW_OUTER}`, outside the
   closed build/runtime inventory. Require exit zero, unchanged inputs, ECHILD,
   zero descendants/cleanup events, exact request/output hashes and the literal
   successful helper summary before proceeding.
4. Run `freeze`, then `build`, each using its own fresh outer request. Freeze
   returns its actual digest; build retains the unchanged mapping controls,
   Cargo library/unit build, assembly/C++ objects and three fixture compiles.
   Independently review the closed build audit, depfiles, immutable archives,
   header identities, complete linker captures and four binaries.
5. Generate `runtime_generation` parameters using that actual build review and
   an exact committed source admission whose compiled inputs match the build.
   Launch its fresh outer request. This binds actual files and an explicit
   loader epoch without running tests or native modes. Independently review the
   resulting manifest, source index and eleven inner request rows.
6. Generate and launch the fresh `qualification` outer request with those
   actual digests. All ten commands and the separate final audit remain
   mandatory. There is one outer wall backstop for the complete phase, with
   unchanged inner command, child, trace and cleanup bounds. A breach fails;
   there is no retry or automatic budget extension.
7. Generate `closed_export` parameters only from actual closed captures and
   the closed qualification outer binding plus reviewed schema/metadata digests,
   then launch its separate outer request.
   Review the five resulting sanitized files before public publication.
8. Run the fixed fresh 72-row ordinary-emission parity gate and required
   exact-head workspace gates separately. Neither is replaced by this cohort.

The phase parameters are an exact schema: the common keys are `phase`, `python`,
`home`, and `raw`; each phase's remaining required keys are in
`aggregate-parameters.json`. Output folders and every actual hash are supplied
explicitly. The generator verifies current inputs, creates no future hash, and
refuses an existing outer-output directory. Existing failed directories stay
in place. The unchanged controllers are the helper's child commands; public
reproduction enters them through these generated outer requests.

The toolchain JSON has exactly `tools` and `files`. Required tool roles are
`cargo`, `rustc`, `gcc`, `cxx`, `linker`, `assembler`, `helper_python`, `timeout`,
`libgcc`, and `libstdcxx`; the helper is bound separately to its literal digest.
The files inventory must contain every resolved role, compiler runtime, linker,
start file and C++/system header actually consumed. Every tool target is hashed
before and after each command. Cargo package IDs, versions, source ownership and
depfile targets must match the complete root dependency closure in Cargo.lock.
The existing shared Cargo target and four jobs are retained. Archives are copied
before later target writes; a reused Cargo artifact is explicitly recorded as
reused, not relabelled as a fresh compiler invocation.

The source-admission schema is `unwind-source-admission-v1` with status
`REVIEWED_SOURCE_FOR_NEW_BUILD`, `source_files`, `source_kind`, `tested_revision`,
`base_revision`, `git_tree`, `clean_tracked`, `tracked_diff_sha256`,
`source_tree_sha256`, and `review: {path, sha256}`. The source-tree digest is the
SHA-256 of sorted compact ASCII JSON plus one newline. Both build and runtime
admissions remain separate, immutable records.

The explicit runtime epoch pins the interpreter, libgcc alias and canonical
file, six decoded dynamic function symbols, a byte-equal separately owned libgcc
snapshot, loader cache, enumerated system configuration files and inactive global
preload. This is not a claim of general loader dependency-graph qualification. The native
fixture retains file descriptors, authenticates full bytes and both stat and
mount-device identity domains, and checks actual mappings. A later inode or
configuration change refuses readmission; it never refreshes a frozen epoch.
An unreadable Cargo configuration observation records the exact operation and
EPERM/EACCES value. It proves only stable inability to inspect, never absence or
hidden contents. Other failures are not absorbed.

## Fixed inventory and bounds

The mapping-admission step retains two identity acceptances/seventeen required
refusals and two record acceptances/eighteen required refusals. The qualification
then requires these ten commands, followed by a separate final receipt audit:

- Exact listing of all 32 launcher tests, preserving the original 25 names.
- Six consumer models and the entire 190-name library inventory: 189 pass and
  one pre-existing ignore, with three nested guard invocations counted separately.
- All 26 shared calibrations, preserving the original 19 and requiring all seven
  Word additions; the exact should-panic name set remains mandatory.
- Six separately bounded native modes: frameless, frame-pointer, both no-FDE
  controls, and both postwrite KeepGated controls.

The two positive modes require 12 subject calls, 16 real backtraces and four
generated crossings; four original, four installed and four retired strict
comparisons; and six required prewrite refusals. The two no-FDE controls require
their own 12 calls/16 walks/four missing crossings and strict comparisons. The
KeepGated controls require four original calls/walks and two retained postwrite
failures, with zero installed subject calls. Negative controls are never counted
as positive unwind qualification.

Outer build and qualification requests use 120 CPU seconds / 180 wall seconds,
with file caps of 128 MiB and 16 MiB respectively. Preparation and export use
20/30/16 MiB. The existing helper uses per-process CPU rlimits and an outer wall
backstop; these values do not claim cgroup-wide summed CPU accounting.

Compiler commands retain 60 CPU seconds / 90 wall seconds / 128 MiB per-file cap.
The pure mapping command and list/model/calibration/audit commands use 20 CPU
seconds / 30 wall seconds / 16 MiB. Each native parent uses 30/45/16 MiB; its
single ordinary main-thread child retains 20/30/16 MiB, two-second owned-group
cleanup, 15-second/20,000-step traces and 32 frames per real walk. A breach fails
the fixed cohort. Bounds are not enlarged after a failure.

## Sanitized result export

`export.py` consumes the closed terminal digest, all exact captures, the actual
hash of `evaluation/schema-v1.json`, and reviewed hardware/tool metadata. It
writes a new directory with `summary.json`, `commands.csv`, `cases.csv`,
`source-files.json` and `files.json`. It uses the frozen common field names; no
private reporting framework or executable evaluation module is required.

Run the exporter from the tested public source with `--runtime`,
`--manifest-sha256`, `--terminal`, `--terminal-sha256`, `--aggregate-binding`,
`--aggregate-binding-sha256`, `--schema`,
`--schema-sha256`, `--metadata`, `--metadata-sha256`, `--output`, and `--run-id`.
Keep its output private until independent result/privacy review, then copy only
those five files into `evaluation/results/<run_id>/`. Commit source as C, test C,
then publish the result files in a later data commit that still names C.

Build and runtime source epochs stay distinct. Commands have actual receipt
status and separate CPU/wall/file limits. Cases keep ordered command/name/kind/
expected/observed fields. If a failed cohort has no receipt for a planned
command, that command stays in `planned_commands` and `unexecuted_commands`,
with its cases marked `not_run`; no fictitious command receipt or pass is made.
The complete fixed denominator remains visible. Repeated calibrations, metadata
listings, nested tests, compile outputs, native positives and native controls
remain separate. The exporter uses a separate authenticated `verify_records`/`audit_closed`
path. It rehashes retained source/build snapshots and checks the same receipts,
request inventory and captured identity/state evidence, without reauthenticating
today's loader cache, canonical libraries, tools or source tree. The live
`verify`/`audit_through` launch paths remain unchanged. No completed run is
readmitted or rerun during export. All four roadmap claims remain unqualified.
Elapsed times are operational diagnostics, not performance benchmarks.

The exporter also authenticates the exact closed qualification outer request,
seven-file capture inventory, helper receipt and literal helper summary. These
remain a separate aggregate-boundary observation, not extra native case credit.
An inner completion marker with a failed outer timeout or cleanup cannot produce
a passing report. Missing or malformed outer records refuse export rather than
manufacture containment evidence. Preserve the reviewed parameter file alongside
its immutable outer request and captures.

Export metadata supplies exactly `hardware`, `tools`, `tool_version_evidence`,
`command_tools`, `private_tokens`, and `path_substitutions`. Tool rows name a role,
exact SHA, version, version basis and version-capture SHA. A captured version
requires its actual immutable evidence; an unrecorded version must be null and
explicitly labelled as unrecorded. Each command-tool role authenticates its
actual first argv executable. Hardware uses the fixed sanitized label
`AMD EPYC Zen 5 dev host` and observed architecture/vendor/family/model/stepping/
kernel fields, with observation phase/digest. Raw host names and paths remain
private. Explicit `${RAW}`, `${REPO}`, `${TOOLCHAIN}` or caller-declared role
substitutions are applied to argv and selected environment fields; unknown
absolute paths and known private tokens refuse export. Do not invent version
outputs or label a precommit compiler result with a later tested revision.
