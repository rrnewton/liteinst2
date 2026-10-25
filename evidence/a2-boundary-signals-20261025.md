# A2 signals at restored relocation boundaries

This additive Linux/x86-64 fixture runs on an **AMD EPYC Zen 5 dev host**.
It delivers a real kernel SIGUSR1 at every declared restored-state instruction
visit and at the owned return terminal, then witnesses actual rt_sigreturn.
The original state comparator, application-memory coverage, two established
seeds, 15-second trace deadline and 20,000-instruction limit remain unchanged.

Two fixed layouts exercise same-site relocation of a five-byte NOP and upstream
relocation of a seven-byte RIP-relative LEA followed by a two-byte MOV. Every
original head is an entry. Exact one-candidate placement, source edits, generated
bytes, alternate-entry obligations and whole-page restoration remain required.
The upstream case requires the complete nine-byte edit, including its owned
SIGILL marker and unchanged final instruction byte. Direct entry at that marker
uses the production router.

The fresh private run passed all 20 tests without filtering or ignores. The
native cohort requires 10 ordinary original baselines, followed by 10 signal-
injected original, 10 installed and 10 retired traces. Each phase completes
28 actual signal round trips, for 84 in total: eight at generated restored-state
addresses and 76 at source boundaries, including all 30 owned return terminals.
Exactly six installed hook events and two direct owned-SIGILL entries are
required. One inventory acceptance and five rejection calibrations check ordered
physical/logical locations, repeated visits and completed round-trip counts.
The other 13 tests are existing shared-helper calibrations, not new semantic
cases. Their repetition in other binaries does not add distinct coverage.

The signal helper checks the kernel's saved GPRs and flags, retains the physical
RIP, and follows the real handler RET, restorer and rt_sigreturn syscall entry
and exit. No tracer register or memory write occurs after signal capture.
Complete application registers, defined flags, supported extended state and
application memory must match after return. A separate parent assertion checks
logical-PC translation; the kernel frame is not rewritten to a logical PC.
Raw kernel XSAVE-frame bytes are not independently compared.

All prior helper methods, masks, assertions and calibration bodies remain exact.
The added loop charges four handler/restorer instructions per round trip to the
same step budget. The native cohort uses a fresh main-thread process with
20 CPU seconds, 30 wall seconds and bounded output; owned-child cleanup remains
bounded and keeps the group leader waitable until the final reap. The private
outer run used 50 CPU seconds, 75 wall seconds and a 16-MiB file limit, completed
in about 1.16 seconds and reported no leftover descendants. The active workspace
fixture also passed all 20 tests with no filtering or ignores, after formatting,
focused compilation and workspace Clippy with warnings denied. The first active
compile exposed an unused nested re-export in an existing driver; making the
module public and importing the two used items in this fixture corrected the
wiring without a lint exemption or any check change. That failed build remains
preserved. Exact committed-head workspace qualification is recorded separately.

The first required native attempt failed before completing the cohort because
the fixture expected only the five-byte redirect from an actual nine-byte
relocation edit and assumed a separate marker edit. Its sources and failure
receipts remain retained, with no partial native credit. The correction requires
one exact edit and compares its complete documented byte span, including the
marker and tail. It preserves every layout, entry, seed, state/event check and
bound. Raw manifests, addresses and process captures remain in ignored evidence.

This qualifies these restored-state boundaries only. It does not inject signals
inside generated save/restore sequences, qualify arbitrary asynchronous
interruptions, translate application-visible signal contexts automatically, or
provide unwind metadata. No real stack-unwind witness or generated CFI is
claimed. Active CET, Intel evidence, broader exception/chain qualification and
the remaining signal/unwind requirements keep full A2 open.
