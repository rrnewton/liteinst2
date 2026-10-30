# Saved-artifact verification and ELF startup carrier

Claim 4, source revision `6bf8041fa00476d12f14da1b52afbb9f52e08d8c`.
Hardware: AMD EPYC Zen 5 dev host. These are correctness results; command
elapsed times are not performance measurements.

The independent verifier checks saved whole-program rewrite products against
original instruction heads, selection facts, metadata, ledger, source writes,
image ownership, routes, requirements, declared fixups, instruction boundaries,
and final ELF bytes. It does not call the planner or emitter. Its instruction
checks are not an exhaustive semantic proof or independent fixup discovery.

Both saved programs completed those structural joins: 187 original heads,
42 selected instructions, 48 images and 8 routes in total. The original producer
capture still has two unread ancestor Cargo configurations. Consequently the
aggregate W01 result is **false**, despite the structural checks passing. There
was one verifier dispatch per saved program, no producer rerun and no candidate
execution. N01 remains **UNRUN**. See `saved-eb8a6b3/` for exact build and saved
artifact receipts, including the earlier build refusal and explicit schema-3
profile for inline comments in the finite allowed Cargo configuration grammar.
The older strict profile remains unchanged.

The opt-in static ELF carrier adds a loader path and one absolute bootstrap
DSO dependency to a supported static ET_EXEC. It preserves the original entry, LOAD layout and bytes outside declared edits,
checks the new read-only metadata and program headers, and
rejects unsupported existing dynamic, TLS and startup layouts. This commit
contains the carrier, not a runtime initializer or a native bootstrap claim.
Nine new carrier controls pass. `carrier-6bf8041/` retains the strict lint failure,
subsequent source repair, focused outcomes and an initial validation invocation
that supplied the wrong revision and was refused before running any checks.

Full validation at the exact source revision used 16 reserved CPUs and 316 test
threads. Workspace: **3,777 passed, 0 failed, 37 ignored**. Serial launch:
**1,039 passed, 0 failed**. Formatting, strict workspace Clippy and the all-target,
all-feature check passed. All 108 required source-derived regression pass lines were present,
including the RapidProbe identity, mapping contention and short-neighbor tests.
`validation-6bf8041/` records commands, fixed deadlines, CPU reservation, load,
raw-log digests and grouped controls. Five nested filtered child summaries are
retained separately; repeated executions are not unique test cases.

Reproduce focused verifier checks with
`./evaluation/adjacent-b2/artifact-verifier/check.sh`. Reproduce the carrier with
`cargo test -p liteinst-rewrite --lib carrier::startup_fixtures::`.
The exact full-validation invocation and environment are in
`validation-6bf8041/receipt.json`; its driver is
`evaluation/short-neighbor-parallel/validate.py`. Release verifier construction
and saved-input transport are documented in
`evaluation/adjacent-b2/artifact-verifier/README.md`. The verifier result depends
on the original closed capture and cannot repair its unknown build inputs.

`focused/` retains every closed focused verifier attempt, including failing
mutants before their repairs. Its final public check ran on the recorded base
plus a source overlay identical to the committed verifier; the receipt states
that distinction. Raw logs, input captures and detailed private audit records
remain ignored. These compact CSV/JSON receipts retain failures without adding
native or performance qualification.
