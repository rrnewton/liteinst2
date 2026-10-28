# Optional backoff: control passes, timed qualification fails

Revision `398203e80d7784b3ee62c7ed84933c09e0e56b73` adds an optional backoff client that can disable observation, return through Fast, rearm sampling, and finish a Slow call with its retained owner across rearm. **All 31 prerequisite stages PASS, including the new 13-call control. The 520-epoch campaign FAILED.**

The first optional K10 trial refused `Full` while exporting a Calls packet from controller to sink (pending packet 861). Root recorded 3,441 partial physical calls: 1,839 Fast and 1,602 Slow (1,487 sampled, 115 unsampled), at generation 149. There was no Deadline diagnostic. Worker completion recorded detached=true, error=None and unexported=false. The helper exited 101 and its parent exited 1 normally, with ECHILD, complete cleanup and zero rescued descendants. K1000 is UNRUN. The pending packet prevents a complete exported population; no OS cause is established.

The separate deterministic control passed 13 original and 13 installed calls: one post-disable Fast, 12 sampled Slow, two post-rearm samples and one retained in-flight owner across rearm. Its 13 batches, 24 events, five actions, three epochs and actual worker join qualify those controlled operations, not the independently clocked schedule.

The prerequisites also passed eight optional frontend state pairs / 16 children / 1,956 comparisons (978 Fast and 978 Slow), and a separate 96-original/96-installed functional case with 32 Fast, 64 sampled Slow, three batches and 128 events. State comparisons cover actual optional gate entry through post-POP, with the real outer return after restoring each child's harness context. The 96-call and 13-call schedules do not acquire full-state coverage from those pairs. Earlier cohorts retain their separate 978/844/844 comparisons and bounds.

[receipt.json](receipt.json) and [cases.csv](cases.csv) are byte-exact wrapper outputs; failed case fields stay empty. [qualification.json](qualification.json) contains the partial failure, current prerequisite counts and scope. [commands.csv](commands.csv) gives all 31 normalized commands, limits and saved helper/parent closure facts. Its `$RAW` denotes the prerequisite raw directory. Projection checks 70 pinned CLOSED metadata files and 93 Git source descriptors, without stream/state replay or artifact reads. Input, complete journal/Report and return checks in the deterministic controls remain source-attested; timed trials check journal contents and Report counts.

The owner-specified host label is **AMD EPYC Zen 5 dev host**; recorded CPU fields are x86_64, AuthenticAMD, family 26, model 17, stepping 0. The wrapper/build uses four CPUs, with worker, controller, sink and main on distinct CPUs. Tools: Python 3.12.15, Rust/Cargo 1.97.1, GCC 11.5.0. All three artifacts report `cargo_fresh=false`, optimization 3, debug info 0, assertions/overflow checks enabled. The receipt retains hashes/profiles; closure durations are operational, not performance results.

Use a clean checkout of the exact revision and supply absolute existing tool/home paths. `RAW` must be fresh under the checkout's ignored tree; arrange four allowed CPUs for the invocation:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B \
  "$REPO/tools/rapid-profiler/backoff-work/verify.py" \
  --revision 398203e80d7784b3ee62c7ed84933c09e0e56b73 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --worker-backpressure --optional
```

The wrapper runs 31 prerequisites, then K10/K1000 in order, stopping on failure. Trials request 520 ten-millisecond periods and a 100,000-call ceiling; independent 23-call bursts retain 250 us spacing/3 ms idle gaps. Explicit worker waiting preserves controller-to-sink Full refusal, queue capacities, 2 ms arm lateness and original shutdown limits. Each trial retains 20 CPU seconds / 30 wall seconds / 64 MiB within a 55-second / 1 MiB parent; prerequisites retain their 900-second / 1 MiB parent and child bounds. Stop cannot cancel an entered call.

The metadata projection is reproducible from the pinned CLOSED input manifest and root failure summary. It produces the four data files into a fresh directory; README and projector are authored source:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B "$REPORT/project.py" \
  --repo "$REPO" --manifest "$CLOSED_MANIFEST" \
  --failure-summary "$CLOSED_FAILURE_SUMMARY" --out "$NEW_PROJECTION"
```

Separate [required gates](gates.json) and [development records](development.csv) are included below; the native metadata projection does not infer their outcomes. The [seven earlier mandatory campaigns](../backoff-independent/README.md) remain FAILED, including the campaign with a partial K10 PASS. Earlier failures also remain linked through [history-stream-4f2ddf8](../history-stream-4f2ddf8/README.md). This result gives no successful optional 520-epoch campaign, complete independent history/Report replay, timing accuracy, cost savings, throughput, indefinite-service or completed-A5 claim. The unsafe supported leaf and lifetime/normal-return obligations remain unchanged.


The seven checks passed at the same revision: default-parallel workspace
2,667 passed / 0 failed / 11 ignored in 351.113 seconds; serial launch 1,039
passed in 160.045 seconds; staged allocation 3 and prefixed-pun 36 passed;
fmt, strict workspace Clippy and all-target/all-feature check passed. The
workspace used all 316 available CPUs with no test-thread override and four
compiler jobs. Five nested libtest summaries were excluded. The new ignored
13-call control ran explicitly in the release prerequisites above. All seven
commands closed normally with complete cleanup and zero rescued descendants.
Reproduce at the exact revision with
`python3 -B evaluation/admission/check_exec_identity.py --checks-only
--toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
--output "$REPO/ignored/NEW_GATES"`; project using
`evaluation/merged-af5a1ef/summarize.py` as documented there.

The 15 development rows retain the initial Clippy initializer-style failure
and two intentional formatter mutations. The initializer correction preserves
the exact values and assertions. Dirty-tree rows identify their actual parent
and before/after source-manifest hashes; these are development records, not
additional native qualification. Adapter controls passed 37, history controls
23, docs 20, and optional/mandatory/frontend recipe controls 8/8/4. Four recipe
entrypoints also refused optimized Python with exit 1, empty stdout and exact
`assertions required` stderr. Development commands used a 180-second wall and
8-MiB output bound (optimized refusals: 20 seconds), stable Rust 1.97.1 and the
same hardware. Raw logs remain ignored.
