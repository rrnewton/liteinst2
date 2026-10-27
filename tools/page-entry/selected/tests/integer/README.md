# Additional ordinary-integer native oracle

Two separately compiled cohorts add forty original-address native/TF pairs.
Group0 covers shifts/rotates, including the real loader's SHL RDX,32, register
and memory operands, CL/immediate counts and a zero count. Group1 covers signed
and unsigned multiply/divide, sign extension, conditional moves and SETcc,
byte swap, bit tests/updates, exchange, XADD and both CMPXCHG outcomes.

Each cohort includes the existing real NOP startup pair and all47 supplied
refused encodings. The complete original generic oracle (21 pairs plus its
three actual failed-operation controls) remains mandatory and unchanged.
The new fixture includes that original C source and uses its actual NX/native,
NX/TF, closed-continuation, full-frame, live-state and full-memory comparisons.
New cases have distinct IDs100..139. Their literal expected effects in CASES.json
and cases.inc are independent of the product decoder/classifier. The two files
must agree; neither is generated from observed native results.

Additional assertions require the expected values in all16 GPRs, defined flag
effects, unchanged full8KiB stack, the exact full4KiB data result, unchanged
initialized kernel FP state and live XSAVE. Full logical flags are still
compared exactly between native and TF lanes, including flags whose values the
ISA leaves undefined. The literal-effect masks assert only specified flags;
they do not relax the underlying native/TF comparator. Consequently these finite
host observations do not define portable values for undefined flags. Divide
cases use valid nonoverflowing operands; application divide-fault delivery is
outside this oracle.

Every private record uses the unchanged21-sample plus negative-slot layout
and stays below the existing16MiB file limit. The extra negative slot is unused
in these positive-only cohorts. Original negative processes are retained in
the separate original oracle. No process bound, state capacity or comparator
is widened. Source code, binaries and actual DWARF are retained for replay.
No whole-ISA, loader completion, performance or full-B2 claim follows.

Reproduce at one committed revision on one externally reserved CPU, in order:

```
python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision REVISION
python3 evaluation/inprocess/page_selected_integer.py --expect-revision REVISION --group 0
python3 evaluation/inprocess/page_selected_integer.py --expect-revision REVISION --group 1
python3 evaluation/inprocess/page_selected_generic.py --expect-revision REVISION
```
