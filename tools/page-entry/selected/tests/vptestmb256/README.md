# VPTESTMB256 qualification

This component tests canonical EVEX.256.W0 register VPTESTMB (Code 2784). Five processes cover 72 register/mask and fetch-boundary cases, then the retained-libc literal `62b25d2026cc` at each of its six fetch boundaries: 78 selected native/TF pairs plus five startup pairs. The retained literal is a source-consistency check, not captured runtime mapping authority. The existing 512-bit native cases, full-state comparisons and assembly remain unchanged; those fixtures also require the original row 90 as typed/NONE evidence.

The model computes 32 bytewise AND-nonzero results from the captured source vectors and original writemask, and requires the upper 32 destination-K bits to clear. Full native/TF GPR, flags, kernel FP, live XSAVE, all 32 ZMM registers, all eight K registers, source/data/stack, NX/TRACE and closure comparisons remain mandatory. AVX512VL is an additional CPUID prerequisite.

All 110 original neighbor literals remain. Row 90 requires an exact Code 2784 typed/NONE record, alongside the original Code 2785 and eleven Code 2791 promotions. A separate 37-row table adds prefix, reserved-bit, width, memory and truncation refusals. Each process requires 181 refusals and 134 unsupported footprint queries. These supplied queries do not earn native-operation credit.

Run `python3 -B evaluation/inprocess/page_selected_vptestmb256.py --expect-revision REV` on one reserved CPU. Each native subject retains five CPU seconds, 15 wall seconds, 512 MiB address space and a 16 MiB file-size limit; its complete record must fit the original bound. The build recipe is `sh tools/page-entry/selected/tests/vptestmb256/build.sh ARCHIVE OUTPUT SELECTED GROUP`, with GROUP from 0 through 4.

The new evaluator qualifies only its five processes. Same-revision runs of `page_selected_vptestmb.py`, `page_selected_vptestnmb_family.py` and `page_selected_vpcmpeqb_register.py` are also required: 14 existing processes and 266 pairs. The combined requirement is 19 processes, 349 pairs and 19 mandatory row-90 typed/NONE records. Existing regression and real-application gates remain separate. This register-only component does not establish operand-memory-fault, application, performance or full B2/B3 qualification.

The [qualified result](../../../../../evaluation/inprocess/results/2026-10-29-vptestmb256-qualification.md) records all 21 same-revision cohorts, including the unchanged late-DSO application. Its compact JSON retains the numerical results and pinned reproduction commands; the measured source remains `e03366b0b24f30df69bdcdd533d3e78d4f43d077`.
