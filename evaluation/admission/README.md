# Admission evaluation

Run the admission validation protocol from a clean checkout of an exact commit:

```sh
python3 evaluation/admission/run.py --expect-revision "$(/usr/bin/git rev-parse HEAD)"
```

The recorded `reproduce` argument vector contains the concrete 40-hex revision.
Check out that revision and use its recorded Rust/Cargo versions and Linux
x86-64 hardware to reproduce the experiment. The dependency cache must already
contain Cargo.lock's dependencies: resolution is offline. The protocol uses
`/usr/bin/git` explicitly for source authentication and the isolated Git fixture,
recording its version and hash. This avoids ambient Git wrappers that start
background processes. Automatic Git maintenance runs in the foreground; the isolated
fixture excludes ambient Git configuration and hooks. The same descendant
cleanup and hidden-source-edit assertions still apply. Child ptrace and
child-mm membarrier sync-core must be available; tests fail if requirements are
missing. Do not use root to turn a failed unprivileged run into a claimed
unprivileged success. The result records effective-root status, relevant
capabilities and Yama ptrace policy explicitly. An absent or unreadable policy
interface is recorded as unknown, never inferred to mean policy zero; the
actual child ptrace assertions still must pass.

The runner checks its recorder regressions, the four required workspace
commands, then all launch tests serially with explicit native-case telemetry.
It fixes four build jobs, four workspace test threads, no incremental builds
and one `target/` directory. Workspace tests have a declared 360-second deadline;
other commands have 180 seconds. Each command has an 8 MiB private output cap and up to three further seconds
for owned-child cleanup. The Linux supervisor must be single-threaded, have no
pre-existing children and exclusively own child reaping. It uses subreaper
adoption and pidfds to clean up descendants that change process groups or
sessions; violations, incomplete cleanup or descendants left behind by an otherwise
successful command fail the command. SIGINT is deferred across ownership
transfers and triggers bounded cleanup. If per-task child listings are absent,
a bounded, one-level process enumeration supplies candidates only; pidfd waits
authenticate owned children, and an `ECHILD` result proves final emptiness. The
chosen discovery strategy is recorded per command.
Failure, output exhaustion or timeout does not become a pass. These are serial
validation commands, not a benchmark or a contained seed sweep.

The separate `diagnose_cleanup.py` reproduces the two private fork-cleanup
fixtures individually with the same command supervisor, source authentication,
environment and output bounds. Run it with `--expect-revision` and an exact
40-hex commit. Its receipts identify the filtered case and complete filtered
denominator, and an otherwise successful test with leftover descendants still
fails. This diagnostic attributes failures; it does not replace any command in
the full qualification protocol or establish a complete claim.

The [original anonymous mapping result](mapping-lifecycle-7022e137.md) records
the finite original-syscall and runtime-source lifecycle qualification.

## Public result format

Each invocation creates an append-only run identity under `results/`. Its JSON
records exact revision/tree, tracked-source hashes, runner/corpus hashes,
hardware/ISA facts, tool versions, command arguments, environment controls,
per-command wall times and exit/termination status. Source bytes and executable
modes are authenticated directly against HEAD blobs, including files hidden by
Git index optimization flags. Valid invocations refused during preflight retain
a result with every command marked `not_run`. Per-harness summaries retain
the complete passed/failed/ignored/measured/filtered counts. Native CPU records
retain each case's parameters, actual random carry outcomes and explicit native,
scripted or fault counts. The command and result schema version is 1. Native-case telemetry uses version 2,
which adds exact instruction bytes and the selected coverage backend. Historical
receipts retain the format of their recorded source revision.

These JSON files are the numerical observations for analysis. Commit them after
review, including failed attempts; reruns create new files instead of overwriting
the earlier result. Command durations measure validation overhead, not hook
latency or application speed. Missing measurements are not inferred. A result at a
source revision precedes the later commit that adds that result file; its source
identity remains the tested revision. Historical development captures, when
imported, explicitly record dirty-source equivalence and are not clean-checkout
qualification runs.

Raw combined output stays in ignored `target/evaluation/admission/<run-id>/`;
only its digest enters the public JSON. No raw stderr, environment dump,
hostname, user name, absolute working path, kernel vendor suffix or failure
message is exported. Kernel upstream version plus a hash of the complete kernel
release identify the kernel without publishing private build labels. Source and
command paths are repository-relative. The runner excludes inherited campaign, libtest, compiler and dynamic-loader
overrides. Only absolute PATH, HOME, CARGO_HOME and RUSTUP_HOME locations are
inherited privately; tool versions and launcher hashes identify their tools.
Readable Cargo configurations must contain only network/HTTP tables, and their
hashes are checked before and after execution; inaccessible ancestors are
explicitly recorded. Cargo runs offline. Toolchain/dependency installation and
ambient host scheduling are not hermetic; no cross-machine performance
equivalence is inferred from matching this protocol.

## Evidence accounting

`corpus.json` declares the expected outer harness cohort, 50 static native cases
and separate named dynamic admission and per-invocation matrix cohorts.
Update it explicitly when adding/removing tests, and review denominator changes.
The parser requires exactly one final unfiltered outer summary matching each
declared cohort. Nested child summaries are separate observations and never
added to outer totals. Two exact existing child-start fixtures are declared: `unit/liteinst2/lib`
(184 outer tests, plus the historical 176-test cohort for replay) and `test/stress`
(seven outer tests), each with one unreported single-test child. Their reviewed children exit
without libtest summaries and the parent assertions check those exit statuses.
Other unmatched child starts refuse; these starts never increase passed totals. Missing, duplicate,
ambiguous or changed outer cohorts invalidate the evidence.

The published coverage increment at `2de30a88c109fd4c9e29669fcc56ef8cdeb33c57`
extended baseline `b6f23bf243baaa6d576c3d8754d701bb718757ad` with 85 outer
instances: 16 pure guard-closure tests, 16 pure lifecycle tests,
21 cache tests plus one poison unit test, two return-ledger tests, six scripted
coverage tests, 17 native coverage cases and six injected-failure unit fixtures.
That revision declared 63 workspace harnesses and 1018 outer tests, including
four existing ignores: 1014 possible outer
passes. The five nested child passes remain separate. Its serial launch cohort
had 180 tests in 11 harnesses, with 50 native cases. These are expected
cohorts, not results; each run must satisfy them independently.

The current corpus additionally covers live oracle reuse, native controller
ownership and signals, physical-reaping failures, and the explicit INT80
profile, plus the bounded opt-in native fork lifecycle. The fork increment adds
23 outer tests: seven public native fixtures, five private native event-order
and refusal fixtures, and eleven pure registry regressions. These include
an explicit newborn return-ready phase and an independent first-user fault
oracle; a child fork syscall-exit event is not invented. Its independent native
oracle runs in a separate natural-parent reaping domain; the outer fixture
checks each positive-oracle and intentional-unwind subprocess's one-test
summary and cleanup witness without adding it to outer totals. Exact current harness denominators are declared in `corpus.json` and
independently asserted by `test_parsing.py`. These additions do not change the
separate 50-case native telemetry denominator or the four existing ignores.

The later-exec increment adds 21 outer tests: eight public native cases, seven
private event-order/refusal/cleanup cases and six pure phase/identity cases.
Its three state oracles, three failure oracles and one explicit output-unwind
control run as seven captured single-test subprocesses with exact one-test
summaries and physical-cleanup witnesses; they do not increase outer or
parser-nested pass totals. Event, actual syscall exit
and first-user phases remain distinct. Failed exec refuses continuation,
including the independently observed post-point-of-no-return case. The original
workspace, serial, telemetry, cleanup and recorder gates remain unchanged.

The bounded native thread increment adds 39 outer tests: twelve public native
cases, five private actual-order/refusal/exit cases, eight private CET-certificate
control/refusal cases, six private deadline controls, five pure shared-mm cases
and three pure Exiting-phase cases. Four captured single-test oracle/control
invocations cover first-user state, shared writes and alternate-stack effects,
leader-first exit statuses and output-pressure unwind. Each requires one exact
summary and physical-cleanup witness, without adding outer or parser-nested
passes. Actual failed-clone retries preserve state and do not invent tasks.
The explicit Exiting notification retains worker control without promising a
terminal wait or physical process removal. All prior tests, ignores, native
telemetry counts, deadlines and zero-adoptee gates remain required.
The deadline fixture now requests a 100 ms native event deadline and an
explicit three-second total response bound. The existing one-budget API retains
its end-to-end deadline; an additive control requires its exact response-timeout
error while withholding the real owner's reply. Both deadlines begin before
enqueueing. Native expiry, expired dispatch and response expiry retain distinct
error labels; the fixture accepts only native expiry. See `native-thread.md`.

The dynamic admission increment adds 72 outer tests: 14 pending-plan puzzles,
17 resume-census bookkeeping tests, 16 client/owner protocol tests, ten resource
bound regressions, seven baseline native integration fixtures, seven dynamic
matrix fixtures and one CALL-return fixture. The expected launcher unit cohort
was 109 before the kernel journal increment. The journal adds twelve pure tests,
fifteen native fault/oracle/capacity tests and two native forced-dispatch tests;
the B2 finite comparator adds six integration tests. Expected launcher unit
count before the signal increment is 138. The signal increment adds 56 pure
frame/census/profile/journal/extent/sizing controls, eight native reset controls
and five native integration fixtures, reaching 202 launcher unit tests.
The [retained source census](source-history.md) adds eighteen pure controls and
one native refusal fixture with three subcases, reaching 221 launcher unit tests.
Workspace expectations are 1341 outer tests in 77 harnesses (1337 possible passes
and four existing ignores); serial launch expects 503 tests in 25 harnesses.
The recorder catalog expects 213 controls, including eight signal/reset and five
source-census cohort checks. These are source-derived expected cohorts, not reported execution
results.

The serial command exports four distinct evidence collections. The existing
`native_cases` collection retains its separate 50-case static oracle denominator.
`dynamic_admission_fixtures` has exactly one row for each of the 15 declared
fixtures, including the original seven in their original order. Exact Rust module
segments identify the seven `matrix::` tests and one `call_boundary::` test; a
matching suffix or an unregistered name is insufficient. Every named result
requires the announced harness and an explicit terminal `ok`. The independent
aggregate harness parser remains required. Expected-panic diagnostics do not
supply that terminal result.

`dynamic_matrix_cases` records 388 declared completion invocations from seven of
those fixtures and 385 sessions. The source inventory expects 144 native and 244
scripted invocations. These expectations are not execution results or additional
outer tests. Each `LITEINST_EVALUATION_DYNAMIC_MATRIX ` JSON row must occur once
under its exact owning fixture and match the declared case ID, class, width,
destination, execution path and flag-input predicate. Seeded flags are exact;
the 12 literal-first inputs retain their actual numeric checkpoint flags under
the existing TF/RF-clear contract. They do not acquire an invented fixed input.
Only random rows carry numeric actual CF; native CF is an observed zero or one,
scripted CF must equal its declared value, and other classes require null. A
missing row has no observed CF or completion value. Integer `completed=1`, boolean
`cleanup=true`, the fixture's terminal `ok` and command success are all required.
The schema rejects extra fields, malformed or duplicate keys, wrong contexts and
unknown identities. No raw addresses, output values or private diagnostics are
exported.

`native_validation_fixtures` separately retains 37 exact named outcomes: the
seventeen native journal/capacity/dispatch cases under their declared unit-module
prefixes, six B2 reference integration cases, eight native reset controls and
five signal integration cases, plus the original-EXEC/EXIT source-census refusal
control. The source-census control requires its full exact identity; its three
mutations remain one named test outcome. The reset, signal and source-census
cohorts have distinct closed namespaces. These are test outcomes, not
instruction samples, event counts or performance measurements. A case requires
its exact harness and an explicit terminal `ok` within one announced libtest run.
Missing, duplicate, skipped, failed, misattributed or unlisted cohort names refuse.
Other unit tests are structurally checked without exporting their diagnostics.
The independent aggregate harness parser remains mandatory. An explicit empty
catalog is used only by historical synthetic protocol tests, never as a default
for a missing current catalog.

The [kernel progress journal](kernel-journal.md) keeps raw and validated phases
separate across actual failures, panic, native expiry and client response expiry.
Its pure-model accounting tests remain separate from held-native capacity and
full-state oracle evidence. The [finite B2 mode comparison](b2-reference.md)
checks shared trajectories through three process lanes and a handwritten model;
it supplies no production block backend or native selected-effect measurement.
The [finite signal comparison](b3-signals.md) requires ordinary and alternate
stacks, a genuine edited return, independently established nonzero inherited
exception metadata and a strict corruption control. The separate reset cohort
requires physical helper cleanup before any application is released.
The [recorded signal result](b3-signals-e4d1322.md) binds the complete successful
protocol to source `e4d13229` and retains the seven earlier failed attempts.
The [retained-source result](source-history-a9d7f66.md) binds the subsequent
complete protocol to `a9d7f66a` and preserves its earlier catalog-invalid attempt.

The seven original named fixtures cover first CPUID entry, interpreter entry,
native clone return boundaries, scripted default-policy RDPID coverage,
mapping-policy refusal and provider panic/timeout cleanup. The matrix adds the
finite CPU instruction shapes in its exact inventory: all random widths and GPR
destinations, scripted carry outcomes, sampled native carry outcomes, CPUID and
timestamps, explicit default-policy RDPID coverage, a masked-CPUID chain, and 12
literal-first native/scripted cases. Its unchanged-state baseline is the actual
initial checkpoint where documented; it is not an independent bootstrap oracle.
It neither forces native random CF=0 nor claims that outcome when absent. The
CALL fixture separately checks the native return into a previously NX page and
retention of the original generation's potential return obligation. It supplies
one named outcome, not matrix telemetry or a new static sample.

A row alone never qualifies an experiment. Partial and failed observations stay
unqualified; source/configuration drift, another failed command, a cleanup
failure or a recorder exception disqualifies all four collections. The existing
revision/tree/source-manifest, command, hardware and log-digest fields bind the
observations. No command, deadline, ignore allowance, comparator, native50 parser
or descendant-cleanup rule changes. None of these finite cohorts establishes a
complete B3/B4 exit gate, real-application coverage or performance.

The separate static-gate scripted random matrix forces 192 invocations covering both classes,
all 16 GPR destinations, 16/32/64-bit widths and both carry outcomes. Native
coverage adds 14 prefixed random cases and three default-policy RDPID cases to
the original 33. Native carry values remain observations, never forced evidence
for both outcomes. The original strict-backend refusal tests remain present.

Native receipts are emitted only after existing original/replay/native checks
and owned-child cleanup succeed. `LITEINST_EVALUATION=1` enables their fixed
numeric schema. The exporter requires every declared case exactly once, the
matching named test cohort and terminal `ok` for each case, a successful command
and consistent outcome fields. Run qualification is assigned only after every
command passes and source/configuration remain unchanged. Recorder regressions
must finish with an unqualified unittest `OK`; skipped or expected-failing
regressions invalidate that evidence even when the test count is unchanged.
A capability fault stays a fault. Absence of a fault diagnostic cannot establish
a positive. Passing tests and instruction invocations have separate denominators.

This trusts the reviewed, hashed test source and its assertions. Mixed Cargo
and test output cannot authenticate itself against malicious test code; the
strict parser is not a sandbox for hostile test programs. A changed source tree,
nonzero command, timeout or invalid record disqualifies the run. Previously
completed command observations remain in the failed result, and commands not
attempted are explicitly `not_run`.

[Native controller ownership](native-control.md) records the physical-reaping
argument and the private helper's observable parent relationship.
[INT80 evidence](int80.md) records the separate finite getpid/gettid profile,
raw native oracle and exact distinction between native and scripted bookkeeping.
[Bounded native fork](native-fork.md) records the separate lifetime-two-task
profile, independent original-state comparison, actual stop-order fixtures and
physical-reaping distinction. It does not extend the 50 selected-instruction
telemetry cases.
[Bounded native exec](native-exec.md) records separate physical-process and
logical-incarnation budgets, authenticated image replacement and actual syscall
exit, independent original first-user state, and conservative failed-exec
refusal. These uninstrumented ownership fixtures also remain separate from the
selected-instruction telemetry cohort.
[Bounded native threads](native-thread.md) records the exact clone profile,
per-task CET observation, full-state acceptance predicate, shared process/mm
identities, and distinct nonleader removal and delayed leader exit.

[Reset-launch deadline isolation](reset-deadline.md) explains the controlled
live-reaper timeout and the separate recorded default-parallelism recipe.

## Claim mapping

These identifiers match the owner's candidate claims; they are evaluation
targets, not statements that the full claims have been established.

| Claim | Admission evidence supports | Remaining limits |
| --- | --- | --- |
| 1: cross-modification-free publication via page admission | NX admission, actual held-task leases, source reauthentication, exact stores, synchronization, one publication for competing faults | Immutable/private ownership certifications; fixed cooperative group; aliases, readers/writers, arbitrary saved contexts and lifecycle remain open |
| 2: sound unprivileged selected coverage from instruction one | Finite all-start puzzles; executable/interpreter first-instruction fixtures; exact typed/native/scripted effects; masked-CPUID callbacks; explicit positive/fault receipts | Actual privilege metadata must qualify the run; coverage is limited to qualified selected encodings and MOV-immediate collateral; aliases, loaders/signals/JIT, full-class concurrency and broader hardware remain open |
| 3: in-place software preemption clock | No evidence from this protocol | Not implemented/evaluated here; wall-clock timeouts are not a preemption clock |
| 4: systematic validation of every tactic | Workspace core regressions plus B's trap/interpreter and CPUID generalized-pun integration | A passing workspace is not an all-tactic coverage matrix; forced tactics/composition, generated/sampled campaigns and full core claims need their own manifests |

The four-worker race fixture requires four callbacks, one publication and at
least two collected faults. Do not turn that into a claim of four simultaneous
faults. The default-policy native RDPID cases separately qualify their finite encodings.
Pure all-width semantics do not establish live admission of every encoding.
The pure lifecycle registry does not establish native event ownership; the
in-memory cache does not establish persistent-artifact verification. Errors
close execution; source-byte rollback after partial publication is not claimed.
No performance, preemption-clock or unrestricted release claim is made here.
