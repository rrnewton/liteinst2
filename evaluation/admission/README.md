# Admission evaluation

Run the admission validation protocol from a clean checkout of an exact commit:

```sh
python3 evaluation/admission/run.py --expect-revision "$(git rev-parse HEAD)"
```

The recorded `reproduce` argument vector contains the concrete 40-hex revision.
Check out that revision and use its recorded Rust/Cargo versions and Linux
x86-64 hardware to reproduce the experiment. The dependency cache must already
contain Cargo.lock's dependencies: resolution is offline. The protocol uses
`/usr/bin/git` explicitly for source authentication and the isolated Git fixture,
recording its version and hash. This avoids ambient Git wrappers that start
background processes; the same descendant-cleanup requirement still applies. Child ptrace and
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
scripted or fault counts. The command and result schema version is 1.

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

`corpus.json` declares the expected outer harness cohort and 33 native cases.
Update it explicitly when adding/removing tests, and review denominator changes.
The parser requires exactly one final unfiltered outer summary matching each
declared cohort. Nested child summaries are separate observations and never
added to outer totals. Two exact existing child-start exceptions are declared: `unit/liteinst2/lib`
(176 outer tests, one unreported single-test child) and `test/stress` (seven
outer tests, one unreported single-test child). Their reviewed children exit
without libtest summaries and the parent assertions check those exit statuses.
Other unmatched child starts refuse; these starts never increase passed totals. Missing, duplicate,
ambiguous or changed outer cohorts invalidate the evidence.

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

## Claim mapping

These identifiers match the owner's candidate claims; they are evaluation
targets, not statements that the full claims have been established.

| Claim | Admission evidence supports | Remaining limits |
| --- | --- | --- |
| 1: cross-modification-free publication via page admission | NX admission, actual held-task leases, source reauthentication, exact stores, synchronization, one publication for competing faults | Immutable/private ownership certifications; fixed cooperative group; aliases, readers/writers, arbitrary saved contexts and lifecycle remain open |
| 2: sound unprivileged selected coverage from instruction one | Finite all-start puzzles; executable/interpreter first-instruction fixtures; exact typed/native/scripted effects; masked-CPUID callbacks; explicit positive/fault receipts | Actual privilege metadata must qualify the run; prefix/default-RDPID refusals, aliases, loaders/signals/JIT, full-class concurrency and broader hardware remain open |
| 3: in-place software preemption clock | No evidence from this protocol | Not implemented/evaluated here; wall-clock timeouts are not a preemption clock |
| 4: systematic validation of every tactic | Workspace core regressions plus B's trap/interpreter and CPUID generalized-pun integration | A passing workspace is not an all-tactic coverage matrix; forced tactics/composition, generated/sampled campaigns and full core claims need their own manifests |

The four-worker race fixture requires four callbacks, one publication and at
least two collected faults. Do not turn that into a claim of four simultaneous
faults. RDPID-only positive policy does not establish default-policy coverage.
Pure all-width semantics do not establish live admission of every encoding.
No performance, preemption-clock or unrestricted release claim is made here.
