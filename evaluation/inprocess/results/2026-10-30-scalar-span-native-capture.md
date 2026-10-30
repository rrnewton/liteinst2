The finite TRACE experiment at `5f766ea76a8433fa790b270e1f75bc14ab0e4035` **failed qualification**. All nine subjects launched and returned their required exits without timeout. Four native references qualified; none of the five gated records completed validation.

| Subjects | Actual and required exit | Wall seconds | Validation failure |
| --- | ---: | ---: | --- |
| Three normal gated modes | 0 | 17.042–18.473 | Older cache exhaustion/retirement coverage assertion |
| Generated read fault | 125 | 9.830 | Canonical unused REP-state assertion |
| Nested-signal refusal | 125 | 9.254 | Canonical unused REP-state assertion |

The fresh wire-v2 capture supplies the previously missing native counters. All 20 native terminal fields match their actual protected observations in all five records. The fault and nested cases then reach the next assertion: the old helper requires unused REP state, while the retained records show one completed REP lease with 52 traces. The three normal cases still fail the older cache coverage requirement before reaching that check. These diagnoses do not requalify any record or award mutation-control credit.

The run used reserved CPU 83, singleton affinity, on an AMD EPYC 9D85 158-Core Processor (family 26/model 17/stepping 0), Linux 7.1.3 and microcode `0xb101066`. The exact clean source tree was `5470895c05ce9960c4f2075d8d2d8d81bf5bdeab`. All 63 commands and their captures closed with unchanged source/artifact identities, complete process/descriptor cleanup and no final closure errors. Subject bounds remained 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB file/output. The mandatory actual-header byte-operation oracle passed under its separate 5-CPU-second/15-wall-second bounds.

The [JSON](20261030T161200.861251Z-scalar-span-trace-5f766ea76a84.json) and [CSV](20261030T161200.861251Z-scalar-span-trace-5f766ea76a84.csv) retain exact source, hardware, command/capture digests and all nine outcomes. Earlier failures remain failed. This cohort establishes no full native/owner pair, whole-program qualification or speedup; its expected process exits are insufficient for those claims.

Reproduce on one reserved CPU:

```sh
python3 -B evaluation/inprocess/scalar_span_trace.py --expect-revision 5f766ea76a8433fa790b270e1f75bc14ab0e4035
```
