The registered fallback profile requires three fresh successful private receipts from the same exact committed revision. Run the unchanged six-owner positive first, then the full 49-case failure profile using that positive receipt, and the original 17-case rseq application profile with the qualified fast memset option:

```sh
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REVISION"
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REVISION" --positive-receipt "$POSITIVE_RECEIPT"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REVISION" --fast-memset
python3 evaluation/inprocess/page_selected_oneshot_registered_run.py --expect-revision "$REVISION" --positive-receipt "$POSITIVE_RECEIPT" --negative-receipt "$NEGATIVE_RECEIPT" --rseq-receipt "$RSEQ_RECEIPT"
```

Use the project's one-CPU allocator for each invocation. Receipt arguments name the retained private `receipt.json`, not the compact public projection. The new evaluator authenticates exact source, inputs, tools, command order, captures and artifacts and reruns the existing complete result readers. An older revision, a subset of the 49 cases, a failed or incomplete receipt, or a missing capture cannot substitute for a prerequisite.

The new pair uses the existing Build and exact 16-TU one-shot release recipe plus explicit read-only observer adapters. Native and gated programs run under unchanged 30 CPU second / 60 wall second / 512 MiB / 16 MiB limits. A genuine successful registration remains registered/held/ACTIVE through four eligible selected sites. All four must use the ordinary fallback: zero one-shot owners/publications, unchanged complete source pages and full rseq-page comparisons. Clocks and each process's actual PID are retained and checked separately; the source/marker/registration output is compared exactly.

The public result contains only compact numeric observations and receipt hashes. Required failed operations remain failed operations, including mode 48's retained RX source permission after failed cleanup; no safe-revocation claim is added. Source/tool/artifact/capture and namespace custody is checked again on every exit. Results are reported separately; this increment does not establish full B2 or a performance improvement.
