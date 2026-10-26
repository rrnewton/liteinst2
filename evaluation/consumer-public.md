# Generated-unwind consumer evidence

This index separates historical source snapshots, exact-commit runtime results,
workspace regressions, reproduction controls and reporting operations. The
consumer supports `BacktraceOnly` for two authored frame profiles. These records
do not establish general CFI coverage, arbitrary asynchronous unwinding, or full
A2/A3/A4/A5 or paper-claim qualification. Timing is operational, not a performance
benchmark; raw captures remain private.

| Record | Qualified scope and reproduction |
| --- | --- |
| [Consumer build and native qualification](results/a2-generated-unwind-be782c88-20261025/summary.json) | Eight build phases plus ten fixed qualification commands and their final audit. The positive frame-pointer/frameless cohort has 12 subjects, 16 real backtraces and four generated crossings. Separate no-FDE controls require four missing crossings; KeepGated controls retain two failed publications and execute no installed calls. Original/installed/retired strict-state checks remain separate. Use the [consumer adapter](../tools/unwind-oracle/README.md). |
| [Historical ordinary planner parity](results/consumer-ordinary-parity-be782c88-20261025/summary.json) | 72 exact rows: 45 required successes, 27 refusals and 59 images per library; 334 raw pairs, 672 captures, one positive and 11 negative comparator controls. Zero callback or generated-code execution. Historical archived-library reuse is recorded, not relabelled as a fresh build. The [public reproducer](reproductions/consumer-ordinary-parity-be782c88/README.md) preserves the fixed old `6e99b849` and consumer `be782c88` source pair. |
| [Rust 1.85 and package listing](results/consumer-msrv-package-be782c8-20261025/summary.json) | Two exact-commit commands. The package command lists 148 names; it does not inspect a produced crate archive or execute native fixtures. [Exact templates and selected-tool scope](reproductions/unwind-consumer-msrv-package-be782/README.md). |
| [Preserved failed public build](results/consumer-public-build-failed-c537acdf-20261025/summary.json) | Seven inner commands passed, then the aggregate binder refused the launcher's absent environment-dependency record; the eighth compiler and runtime did not run. The snapshot has `tested_revision: null` and remains failed. [Reconstruction and strict correction controls](reproductions/unwind-consumer-env-dependency-v4/README.md). |
| [Private environment-dependency controls](results/consumer-env-dependency-controls-20261025/summary.json) | Four acceptances and 32 required refusals, separate from the original mapping controls. Portable sources are byte-equivalent copies; this row does not claim public materializer execution. |
| [Public preparation and pure controls](results/consumer-public-reproduction-v2-20261025/summary.json) | Five preparation cases: one acceptance and four expected refusals; one separate pure invocation preserves four acceptances and 32 refusals. Raw negative command exits remain nonzero. The earlier helper-output-boundary failure remains recorded. [Reproduction templates](reproductions/unwind-consumer-preparation-validation-v2/README.md). |
| [Required gates at `be782c88`](results/required-be782c88-20261025/summary.json) | 44 outer groups, 772 passes, zero failures, four preexisting ignores; five nested guard passes are separate. This is workspace regression, not additional native qualification. |
| [Required gates at merged `d6b56273`](results/required-d6b56273-20261025/summary.json) | 60 outer groups, 935 passes, zero failures and the same four ignores. All 44 inherited groups are retained; 16 new groups contribute 163 passes. Five nested guard passes remain separate. Historical be782 results keep their own source identities. |
| [Historical reporting operations](results/consumer-reporting-steps-20261025.json) | Three reporting commands at be782. Their original output hashes remain historical. [Reporting recipes and closure checks](consumer-reporting.md). |
| [Corrected required-report metadata and merged export](results/consumer-reporting-corrections-20261025.json) | Two actual exports at d6 correct reproduction coordinate/environment metadata and publish merged-gate data. Historical gate outcomes do not change. The old be782 summary hash remains explicitly preserved; output inventories bind the current two five-file reports. |

The [fresh public-reproduction prerequisite attempt](results/consumer-ordinary-parity-reproduction-attempt-20261025/summary.json)
remains failed. Its separate authority controls passed three acceptances and ten
refusals. The consumer prerequisite produced six exit-zero child receipts, but
only five adapter steps were fully accepted: the main compiler's exact
configuration post-check failed before binding. Two compilers and all eight
public parity stages remain unrun. The mismatching configuration value was not
saved, so later EPERM observations do not identify its cause. A separate earlier
launch failure before the helper is also preserved. The source-held v1 proposal
was unexecuted. None of these outcomes relabels the historical parity pass or
qualifies the complete fresh reproducer.

Builds made from a worktree snapshot keep `tested_revision: null`, even when
later runtime source matches a commit. Required-gate tools are unrecorded where
the runner captured only selection paths; selected-tool maps elsewhere are not
complete runtime closure. Permission-denied configuration observations do not
prove hidden content or absence. Hardware observations describe the AMD EPYC
Zen 5 dev host at their recorded phases, without continuous attestation.

Each result directory retains its command/case CSVs and source/file hash maps
where supplied. Counts with different units or scopes are not summed. New runs
must use fresh ignored output directories and actual inputs, receipts and
artifacts; historical hashes and outcomes are not new observations.
