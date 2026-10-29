# Selected-leaf release qualification

At source `7886d8b12bfb3dbe0021605a810720c658ad7c45`, all five fixed scalar
qualifications passed: 120 installed cases after 24 original-reference cases.
Each qualification processed 4,064 records and 10,160 target calls, covering
N=1..4, K=10/1000, empty input, K+1 records, and the fixed syntax-error case.
Across the five: 20,320 records, 50,800 calls, 50,124 sampled and 676 unsampled.
All 175 stages closed normally with no rescue reaps; all 2,068 retained hashes
were checked after closure. These cases did not exhaust a function budget.

This is the separately named `leaf-set-whole-session-v1` configuration: Certified
CSV plus Whole length/digit/space functions. It preserves the original Certified
profile and its failed campaign. The release build retains the strict 2 ms arm,
10 ms cadence and 2 s shutdown gates. There were exactly five qualifications,
with no replacements. The result is functional acceptance for this configuration;
it is not a general deadline guarantee, throughput measurement or full A5 pass.

| Qualification | Cases | Records | Calls | Sampled | Unsampled | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 24 | 4,064 | 10,160 | 10,026 | 134 | PASS |
| 2 | 24 | 4,064 | 10,160 | 10,025 | 135 | PASS |
| 3 | 24 | 4,064 | 10,160 | 10,024 | 136 | PASS |
| 4 | 24 | 4,064 | 10,160 | 10,023 | 137 | PASS |
| 5 | 24 | 4,064 | 10,160 | 10,026 | 134 | PASS |

The separate native qualification **FAILED** its unchanged 510-second cohort
limit. The old prerequisite completed 48 pairs and 4,490 full-state comparisons.
The new cohort retained 789 of 1,280 pair rows and 95,878 observed comparisons
before timeout, with two rescue reaps. These prefix rows remain unqualified;
491 slots lack accepted results, including interrupted work. No replacement
native run was performed. Full new-profile architectural-state qualification
therefore remains open. `native-groups.csv` aggregates the retained prefix;
original tables and complete state captures remain private.

The release preparation-refusal control passed once: the exact
`PREPARATION_FAILED stage=site class=core reason=no_patch_window` diagnostic,
empty stdout, SIGABRT/raw wait 134, one normal reap and ECHILD. It validates the
four-byte certified fixture's failure path, without attributing the earlier
uncaptured application abort exclusively to that cause.

Two earlier `baf5168d0dc05cade7003eeec3b1b24a437d3afd` qualifications remain
FAILED. The preparation fixture's linker-selected entry 4096 violated the
recipe's zero-entry grammar before application execution. The native recipe's
negative controls ended with SIGKILL at approximately 20 CPU seconds before
both cohorts. The fixes explicitly link entry zero and replace a Python
per-byte loop with an equivalent byte-class match; parser checks, all cases and
resource limits remain unchanged. The first calibration compile failure and
strict Clippy failure also remain in `development.csv` with their corrections.

Hardware: AMD EPYC Zen 5 dev host, AuthenticAMD family 26/model 17/stepping 0,
kernel 7.1.3, Rust 1.97.1. Release opt3/debug0, assertions/overflow checks enabled,
four compiler jobs, incremental compilation disabled. Scalar hard reservation:
controller CPU 19, worker 126, producer 235. Load moved from 36.38/40.03/40.67
to 28.87/34.47/38.11. Native reservation: CPUs 121/217/282, tracer and tracees
on 217. Exact commands, tool hashes, reservation transcripts' hashes, load and
closure records are in `receipt.json`. Durations are operational validation
durations, not performance results. Normal allocator return is authenticated
against its pinned source; no independent ledger readback is claimed.

Reproduce from the exact clean source revision using the tracked scripts:

```text
python3 -B evaluation/ordinary-leaf-set-session/preparation_refusal.py ...
python3 -B evaluation/ordinary-leaf-set-native/reproduce.py ...
python3 -B evaluation/ordinary-leaf-set-whole-session/reproduce.py ...
```

The complete argv/environment for each command is in `receipt.json`; variables
name local checkout, toolchain, Cargo home and allocator paths. Follow each
script's README for the external bounded process owner and hard CPU reservation:
2 CPUs/1200 s for preparation, 3 CPUs/1200 s for native, 3 CPUs/7200 s for scalar,
all with 8 MiB outer logs. Allocator revision and tool/source hashes are pinned.
All inner bounds are enforced by the scripts. Every raw capture stays under a
fresh ignored directory. The 24 reference cases, all 120 installed case outcomes,
all 255 planned stages across the five invocations and both initial failures
remain visible in the CSV/JSON summaries.

Owning closure audits authenticated original shared build products before later
builds replaced them. Summary projection rechecks archived evidence; it does
not treat today's mutable target cache as a historical artifact. No host paths,
user identities or raw logs are published. Prior failed timing campaigns remain
failed. Browser coverage, nested-call execution, original-address full-state
coverage, accuracy/perf comparisons and full A5 remain open.

All seven required checks passed at both the initial and corrected source revisions.
At 7886d8b: workspace 3,283 reported passes/0 failures/36 ignores in 347.638 s
under the unchanged 360 s bound; serial launch 1,039; staged allocation three;
prefixed pun 36. Fmt, strict Clippy and all-feature/all-target check passed.
The eight reserved check CPUs were 34/54/60/67/164/167/171/185.
Cargo totals can include nested summaries; this does not claim 316-thread coverage.
The final hand-back commit adds only these seven compact evidence files.
