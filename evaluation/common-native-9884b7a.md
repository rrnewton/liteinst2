# Common-image validation at 9884b7a

Tested revision: `9884b7a259b4e0ea80d2cca6d726abab4594807a`.
Hardware: AMD EPYC Zen 5 dev host. Rust: 1.97.1. The recorded runs used
four CPUs. Timings below are validation diagnostics, not performance results.

The twelve build and static-inventory stages passed, including fmt, strict
all-target/all-feature workspace Clippy, workspace tests, and the
all-target/all-feature workspace check. Workspace tests reported **2,014 passed,
zero failed, four unchanged ignored cases**. All 2,006 previous test identities
and statuses remain; nine page-ownership tests and three derived-profile
verifier tests were added. All three previous allocation-contention regressions
passed. The required workspace test took 335.49 seconds; the complete build
caller took 367.45 seconds.

The finite E9 witness controls passed all 93 vectors in 24 categories. Four
normal CLI help checks passed, and eight optimized-Python checks refused with
the required exit status 1. The [build/control results](results/common-native-9884b7a/build-controls/README.md)
contain the exact normalized commands, limits, source/tool hashes and 29 command
rows; the four nested gates are identified separately from their enclosing stage.

All sixteen original application observations completed. The saved-content
auditor passed their recorded control flow, calls, stores, arrays and ordered
site streams: 35,886 steps, 2,426 calls, 2,024 stores and 4,186 jump visits.
This is evidence about the original applications and captured data. It is not
an architectural-state comparison against rewritten applications.

Four later verifier compilers returned zero, but **all four archive attempts
failed** and none is admitted for execution. The first attempt did not save its
after snapshots. Attempts two through four recorded changes only to timestamps
of an automount ancestor in the complete alias maps; source leaves, tools,
configuration and target owners remained equal. The cause of the ancestor
changes is unresolved. No owner field, equality check or limit was relaxed.

The [original and failed-archive results](results/common-native-9884b7a/originals-and-archive-failures/README.md)
retain every case, actual exit status, command and reproduction limitation.
Raw logs and captures remain private. The new 74-stage production campaign and
paired E9/native application validation have not run. Historical production
failures remain failures. These results support **claim 4 partially**; they do
not complete A3 or qualify a hardware-wide toggle or interception claim.
