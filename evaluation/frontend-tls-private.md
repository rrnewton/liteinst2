# Private TLS ownership records

The corrected private TLS bridge passed seven required phases, 74 unit/model cases and ten exact compile-fail examples. [Result CSV/JSON](results/frontend-tls-private-v2-20261025/summary.json) and the [source/request reproduction recipe](frontend-tls-private/README.md) retain the exact private source bytes, tools, bounds and artifact-review boundary.

The [first private attempt](results/frontend-tls-private-v1-20261025/summary.json) remains failed: 74 models passed, then warnings-denied Clippy rejected a duplicated unsafe-code attribute; docs and MSRV were not run. The correction removes only that duplicate outer attribute while preserving the inner prohibition, every assertion and all cases/caps. V2 reran all seven phases; no earlier pass was transferred.

Both private tested revisions are null. Base `9098a3d74309fd445fd6f56a6048c1ce517bb81f` identifies source ancestry; later public promotion and its exact-head workspace gates are separate. The inherited 60/eight cases and repeated attempts are not added together as unique coverage.

At public source `4c754df83b534b83f7a4725f087780e013363e4a`, the [four required workspace gates](results/required-4c754df8-20261025/summary.json) passed with 1,000 outer passes, zero failures and four existing ignores across 61 groups; five nested guard executions are separate. This includes the workspace's own 74-model/ten-doc repetition. The [existing required runner](required-gates.py) reproduces those gates. Selected-tool owner and later-hardware observation limits remain explicit in the result.

This evidence covers safe Rust TLS registration, owned tickets, synthetic slots and ordinary thread/panic teardown. Machine return-slot modification, native entry/exit, ABI/CET, asynchronous exceptions/signals, longjmp, a preemption clock, module reclamation, full A5 and claims 1–4 remain unqualified by this suite. Hardware context is the AMD EPYC Zen 5 dev host; elapsed times are operational diagnostics, not benchmarks.

Historical outer commands use two complete request-directory coordinates. See the [coordinate-role definitions](frontend-tls-private-coordinates.md); new reproductions place both request groups under `${RAW}/requests`. These definitions do not change any recorded command, result, or preparer input.

The [eight request-preparation controls](frontend-tls-preparation-controls/README.md) record two accepted preparations and six intended exit-1 refusals. No generated workload request was executed.
