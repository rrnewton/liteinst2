# A2 successor fixture process isolation

Host: AMD EPYC Zen 5 dev host. This is a fixture correction, with no planner,
publication, allocation-policy or architectural-comparator changes.

The workspace check at `d430b0b7772837685c8fb2db14009a25edad5c47` failed a
required RIP-relative successor case with `AllocationUnavailable`. That run
did not capture its exact address-space owners. A subsequent fixed sixteen-run
diagnostic preserved every original assertion and captured three required
positive failures in its first run; the other fifteen runs passed. The three
dictated victim pages overlapped anonymous private writable mappings. Those
owners were not authenticated as particular thread stacks. All 256 recorded
attempts remained at the victim stage; later candidates lay outside the narrow
permit. The planner's refusal was correct. The failed runs remain failed.

The four original native cohorts now each run once on the main thread of a
fresh ordinary executable. Their complete bodies, instruction bytes, entries,
seeds, target formulas, permits, candidate limits and assertions are unchanged.
Every child requires PID equal to TID and exactly one task before and after the
cohort. The thirteen existing oracle calibrations remain in the parent test.
One additional negative deliberately occupies the victim page and requires an
exact victim-stage refusal, with all source and owner-page bytes unchanged.
It supplies no positive tactic coverage.

The first isolated native run passed all eighteen parent tests. It retained
thirty installed and thirty retired normal-state comparisons, plus two
installed and two retired fault comparisons. Every required positive ran on
its first attempt. This finite result does not guarantee that an arbitrary
address-space layout admits the prescribed images; a remaining collision must
still fail the test.

Each driver retains a twenty CPU-second and thirty wall-second limit. The
existing per-trace fifteen-second and twenty-thousand-step limits are unchanged.
The parent holds the driver as a waitable zombie through cleanup, reaps owned
descendants first and releases the leader last. A successful exit with a
leftover descendant fails. Four separate lifecycle calibrations checked clean
success, exit failure despite a completion marker, timeout, and successful exit
with a leftover child. Both negative descendant cases killed and reaped the
exact child; these calibrations count as zero native tactic comparisons.

The ordinary driver permits unused shared fixture helpers at its module
boundary because calibration functions compile only in the test harness.
Warnings remain denied elsewhere, and no assertion is conditionalized or
removed. Clippy required moving the complete test-only launcher module after
the ordinary driver functions; every body remained unchanged. Both initial
lint failures are retained. A separate Cargo linking attempt hit the runtime
output-file cap before executing any test. Compilation now uses an artifact
file limit, while native limits remain unchanged; that failed build is retained.

Private evidence identifiers:

- Captured collision analysis: `d7003f1b82befab08dd87383ad13ab006a369308849d2a88f96b28567cd59251`.
- Reviewed isolation source manifest: `d6663c97d9fd47c66487c4006a560e8579ba923c9c331d57c2d2bdc435666c86`.
- First native audit: `8cd95f880a6764fa76076de694f155736107b798f62231ed8225c81ec5103ec9`.

Raw logs and captures remain ignored. Full A2 qualification remains open.
