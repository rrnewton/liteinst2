# Scalar generation reuse: initial qualification failed

Claims 1 and 4. Source `95883d7fedaa26c29c640648bb21aedb9136eee3`
adds completed-generation replacement within the existing 64 scalar slots and
an explicit initial-code protection transition. The initial owner cohort
**failed**. No owner, whole-program coverage, or performance credit is claimed.

The normal gated capture observed 676 publications and 2,898 completed entries,
including the selected region. Repeat mode 11 observed 677/2,923; the real
protection-transition mode 12 observed 680/2,925. These observations demonstrate
that the old slot-exhaustion barrier was crossed; they do not qualify the owner.

| Check | Closed result |
|---|---|
| Decoder | 8/8; 104 supplied refusals |
| Generated component | 11/11: five completed paths, six real read faults; 535 supplied refusals |
| Owner cohort | 43/43 launched; 13 native references qualified; zero gated cases or pairs qualified |
| Separate mapping controls | Eight required refusals; 152 supplied refusals; no owner credit |
| Shared range predicate | 754 cases: 273 allowed, 481 refused; no live-owner or rseq credit |

All 43 owner subjects exited as specified. Twenty-nine gated readers reached
their actual-state summaries, then their corruption helper raised `KeyError`
because two paths retained the old owner type name. Control 6 failed its exact
fetch-state expectation: it aborts before source validation, so validation calls
and the complete validation observation must be zero. All 140 commands and 318
captures have complete cleanup and source closure. The failed receipt records
13 qualified native references, seven completed native applications, six native
reference faults, and zero qualified generated read faults or owner refusals.

Fix `dc6c8a024c97970b2d560fd3e36b26c9d7586fa6` corrects the two type paths and
the source-causal control-6 expectation. Three additional coherent corruptions
check the zero-validation state, raising mandatory owner-reader refusals from
4,099 to 4,102. Every previous subject, control and process bound remains.
A fresh cohort is required; the closed failed result is unchanged.

Hardware: AMD EPYC 9D85, Linux 7.1.3, one reserved CPU (CPU 1), unprivileged.
The exact commands, revision, hardware, bounds and all numerical outcomes are in:

- [Decoder JSON](20261030T105505.391988Z-region-decoder-95883d7fedaa.json) and [CSV](20261030T105505.391988Z-region-decoder-95883d7fedaa.csv).
- [Component JSON](20261030T105544.594347Z-scalar-region-component-95883d7fedaa.json) and [CSV](20261030T105544.594347Z-scalar-region-component-95883d7fedaa.csv).
- [Failed owner JSON](20261030T105622.249164Z-scalar-region-reuse-owner-95883d7fedaa.json) and [CSV](20261030T105622.249164Z-scalar-region-reuse-owner-95883d7fedaa.csv).

The initial public projection was 38,700 bytes and failed the original 32 KiB
bound. The recovery script in the fix commit reproduces that exact projection
from the authenticated original source and closed receipt, then uses shared
columns and strings with a complete typed inverse. It publishes 30,858 bytes of
JSON and the unchanged 2,203-byte CSV. It reruns no qualification and preserves
the failed status. The private receipt remains 10,323,476 bytes, SHA-256
`50ffc4809f789ca1cc846f3208d2c013b773cd4e647ac30cd8ad09eea1351a46`.
Both uncompressed and published projections must pass the privacy check.
