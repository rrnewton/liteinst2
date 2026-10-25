# A2 successor chains with a backedge and a faulting anchor

Two additive native cohorts pass on an **AMD EPYC Zen 5 dev host**. They retain
the production planner, existing chain fixtures, strict architectural comparator,
all masks and all trace limits. This is a finite A2 increment, not full milestone
qualification. Committed-head workspace receipts are recorded separately.

The first chain contains a selected two-byte SHR, an immediate short conditional
backedge and a short LEA, followed by a long anchor. Its six original heads run
under both fixed seeds. The selected entry takes 32 and 31 iterations, requiring
63 authenticated hook events; auxiliary entries retain the original flag state
and do not revisit the selected instruction. Every loop visit and rejoin is
compared in order. The existing full flags comparator remains unchanged,
including SHR's architecturally undefined AF; this is host evidence, not an AF
portability guarantee.

The second chain contains short MOV/NOP/LEA nodes and a ten-byte absolute load
anchor. A retained read-only page supplies the exact embedded address. Every
original head runs in the readable partner, checking the loaded register and
subsequent application-memory store. The same source bytes, operand address,
plan, images and callback address then run with that page protected against
access. The four heads preceding or at the load must fault with SIGSEGV,
SEGV_ACCERR, the exact operand address and original logical fault PC. Full
register, extended-state, application-memory and stack comparisons remain
required. The untouched tail of the long anchor stays exact and locked.

Together the cohorts perform two install/retire cycles with eight images:
**32 original, 32 installed and 32 retired comparisons**, comprising 24 normal
and eight fault cases per phase. They authenticate **65 normal-path hook events**
and 12 auxiliary normal entries without a selected event. Fault hook counts
are explicitly unmeasured: the unchanged synchronous-fault helper does not
activate its event log. Only event logging is disabled during those traces;
the callback address and deliberate state clobbers stay the same. The readable
partner supplies positive execution of the later store and return.

Both cohorts require genuine dependencies: the original short-node windows miss
their permitted target ranges, and reverse anchor-first publication makes each
required target possible. There is no alternative tactic or retry after a failed
positive. Every complete source page and generated image is checked after each
installed and retired trace. Operand-page bytes are checked whenever readable.

The private package passes source preservation, compilation, warnings-denied
Clippy and all **15 tests**: two native cohorts and 13 unchanged helper
calibrations. Each cohort uses a fresh executable's sole main thread, verified
before and after. Child limits remain 20 CPU seconds, 30 wall seconds, two-second
cleanup and 16 MiB output; traces retain 15 seconds and 20,000 steps. Both
drivers exit zero with no peer processes, empty final child inventories and
leader-last cleanup. The launcher retains its existing same-group ownership
scope.

The first root binder stopped before native execution because it expected only
the integration-test and driver executables; the unfiltered compile also
produced the library's unit-test executable. The failed receipt remains
preserved. A separately reviewed binder authenticates all three exact artifacts
and executes only the required 15-test target. No compilation was repeated, no
library-test execution was credited, and no native bound or assertion changed.
The successful private native audit SHA-256 is
`0b8f02a03b20d0baa8813f3efb1419338427f89432b726285023f862e9b32082`.

The integrated package also passes formatting, workspace Clippy and all 15
focused tests. Its initial binder stopped before native execution because Cargo
emitted every ordinary fixture binary plus a test-profile copy of the explicitly
selected driver. A versioned correction identifies all six artifacts by target
and test profile, preserving both driver identities and executing only the
required integration test. Its failed receipt remains preserved; no build or
native test was retried. The integrated focused audit SHA-256 is
`4dc4b3c0b60bd418ebf6752adb4a6189f4bfebf56ef9877c63822b322867bfe8`.

Raw logs, addresses and captures remain private. Forward branches, additional
anchor/prefix families, store faults, grouped chains, generated unwind,
asynchronous partial-trampoline state, active CET and Intel execution remain
separate requirements. These results do not qualify concurrent publication or
general search completeness.
