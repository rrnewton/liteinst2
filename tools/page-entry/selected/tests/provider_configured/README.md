# Configured selected-provider qualification

The explicit carrier option `--provider-policy mask-random-v1` selects the linked
CPUID mask and random/ID policy before the interpreter's first instruction.
The default remains native. Actual hardware admission uses raw hardware facts;
masking the application's CPUID result does not relax those requirements.

Run the combined evaluator on a clean committed checkout and one reserved CPU:

```
python3 evaluation/inprocess/page_selected_provider_configured.py --expect-revision <40-hex-HEAD>
```

It requires all 385 original native/scripted/refusal provider cases, the 51
callback controls, and four native/configured carrier pairs. Each configured
process begins with a genuine CPUID at interpreter entry, followed by one of four
main-entry selected instructions and 16 independently seeded operations. The
72 configured effects include 64 live post-return captures. Complete retained
kernel context/FP, source and data checks remain mandatory. Live captures cover
all GPRs, flags, selectors, ZMMs and opmasks; they are not an independent complete
live XSAVE image. Native physical random values are not scripted references.

The six original restored one-shot sites per configured process still require
two RDTSC and four syscalls. The nonreturning exit retains the honest restored,
effect-started prefix: 24 restored owners and 20 returned completions across the
four programs. Clock words are retained and checked for the declared shape and
ordering, rather than compared for equality across separate executions.

The evaluator uses one current release decoder build, actual compiler include
and link/loader closure, retained tools and artifacts, and the existing bounded
process supervisor. Original-provider bounds remain 3 CPU seconds/10 wall
seconds/256 MiB/1 MiB. Callback bounds are identical. Carrier runs use 30 CPU
seconds/60 wall seconds/512 MiB/16 MiB. No timeout or failed callback is labelled
completed. Failed commands, partial outputs and secondary cleanup errors remain
in the private receipt. The public result contains compact counts, outcomes and
hashes. Execution results are reported separately; this finite capability does
not establish full B2 coverage or an application performance improvement.
