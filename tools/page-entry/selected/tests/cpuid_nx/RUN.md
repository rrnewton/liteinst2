Run the standalone finite qualifier from a clean committed revision, under the
project's one-CPU allocator:

```sh
python3 evaluation/inprocess/page_selected_cpuid_nx_run.py --expect-revision "$REVISION"
```

The evaluator uses the existing `Build`, retained archive and bounded `invoke`
implementation. It first runs the unchanged 385-case original provider cohort
and 51-case configured callback component. Their original readers and outcomes
remain mandatory. It then runs every one of the 57 CPUID-NX controls described
in README.md, including all six programs in five lanes, real GET/SET denial
filters, genuine initial-disabled faults, and the unchanged native boundary
fixture in all five lanes. The original four configured one-shot carrier pairs
remain in their separate existing evaluator.

Every NX subject retains the 30 CPU second, 60 wall second, 512 MiB address-space
and 16 MiB file/capture bounds. Complete and partial captures, actual PIDs,
compiler tools and conditional includes, source and artifact bytes, namespace
aliases and cleanup outcomes remain in the private receipt. The public result
contains compact observations and hashes; attempted setup, actual processes,
terminal invocations, accepted controls and failed operations are separate.

The only production opt-in is `LI2_CPUID_NX_ONLY=1` with the complete existing
native-page/TF/register/maps/rseq composition. The NX bridge never queries or
sets the CPUID faulting control. It must execute genuine bootstrap/hardware
CPUID successfully before target entry. Raw sampling precedes configured
policy, which precedes the actual saved-frame commit. NX phases do not claim
enable/rearm operations. TSC, syscall, rseq, mapping and all-byte scanning guards
remain required. Existing default faulted profiles are unchanged.

One-shot publication remains explicitly incompatible at compile time. This
finite qualification cannot establish full B2, arbitrary-entry coverage,
other selected-class callback parity, old-kernel support or a performance
improvement. Actual qualification is pending; this source package grants no
execution credit.
