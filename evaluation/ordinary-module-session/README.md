# Streaming module functional campaign

This recipe checks bounded CSV/length module sessions against independently
fixed accepted records and actual original-code scalar calls. It makes no
throughput, timing-accuracy, nested-call, arbitrary-module or full-A5 claim.
The native state and deterministic pending-owner gates remain separate from
functional transcript checks.

Run the full workspace checks separately at the exact clean release revision.
An external process owner must reserve three disjoint CPUs with `cpuset-alloc`,
verify their hard allowed CPU set, retain the reservation receipt, and invoke
this script once with a **7,200-second wall and 8 MiB owner-log cap**. Do not use
affinity or the descriptive reservation tag as proof of a hard reservation.
Within that owned invocation, use absolute caller-selected paths:

```sh
python3 -B evaluation/ordinary-module-session/reproduce.py \
  --revision "$REVISION" --raw "$FRESH_IGNORED_DIRECTORY" \
  --toolchain "$TOOLCHAIN_DIRECTORY" --user-home "$USER_HOME" \
  --cargo-home "$CARGO_HOME" --reservation-tag "$RESERVATION_TAG"
```

The inherited affinity must contain exactly three sorted CPUs. The application
uses the first for its controller and the second for its worker. Its producer
inherits all three until spawning, then pins itself to the third. Each native
runner inherits only the second CPU. The original helper pins that same worker
CPU. Before/after load and actual role IDs are retained privately. These
observations do not promise scheduler silence.

The fixed order is:

1. One fresh finite native recipe (K16 then K1), then one fresh Session native
   recipe (K10 then K1000). Each keeps its original 1,200-second owner bound,
   510-second/480-CPU-second cohorts, 15-second pairs and 20,000-step walks.
   Both require all 179 calibration methods (the original 163 plus sixteen copied-Rust-body controls), the one unchanged explicit ignore,
   four caller controls and eighteen Python controls. Neither native receipt
   substitutes for the owner or functional gates.
2. A fresh release application build, exact emitted CALL/store/FUNC geometry,
   all 52 ordinary regression/control methods, and four owner controls in
   K10 CSV→length, K10 length→CSV, K1000 CSV→length, K1000 length→CSV order.
   Every owner RAW/PHASE/REPORT/SAMPLE row is checked, with actual empty stderr
   and normal exit 0. This route does not run Schedule.
3. All 26 Python controls, then an original helper build and emitted caller
   check. Eight malformed frames require the precise typed diagnostic, actual
   child exit 2 and helper/owner exit 1. A hard exit 1 cannot pass those controls.
4. Exactly 32 fresh original-code children, one for each accepted population:
   the 30 corpus cases, history, pressure. Then five fixed whole attempts, each
   K10 followed by K1000, each with those same 32 cases: **320 installed children**.
   No original call, priming or warmup is inserted into the installed app.

The original reference uses a separate immutable inode copied from the Session
native recipe's exact authenticated trusted DSO. Both functional legs use its
complete selected extents and RET geometry. Original results must match the
independent field counts and lengths; installed results must additionally match
that case's retained actual originals.

All 352 input/request/owner-command plans are frozen before the first campaign
child. The history case sends 16 records, waits for actual prefix 513, sends 32
more, and closes after prefix 520. It requires all 520 arms/521 actions and a
sample at prefix ≥513. The pressure case sends 2,048 records and withholds stdout
reads for 250 ms after READY; an actual blocked write and all 4,096 calls are required.
The existing 10 ms period, 2 ms arm deadline and 2 s shutdown are unchanged.

Each original or installed case retains the original 15-second application or
producer deadline, 20 CPU seconds/30 wall seconds/4 MiB streams, and 55-second
owner. The outer 7,200-second deadline is never renewed. A stage that cannot fit
its original bound is not granted a smaller or extended limit. Setup and
prerequisite children are distinct from the 352-child campaign.

Expected refused/incomplete inputs require their exact actual stderr, normal
application exit 1 and every accepted-prefix/result/history/Report join. Valid
EOF requires normal exit 0. Closed functional failures remain FAILED and later
independent cases continue. Missing closure, rescue, uncertain child identity,
source drift or failed prerequisites stop progress; remaining rows stay UNRUN.
There are no retries or favorable-only projections.

Private `result.json`, `summary.json` and `results.csv` preserve all 32+320 rows,
all five attempt summaries, eight malformed-control results and every gate.
`campaign_complete` means all planned slots reached an outcome with closure and
retention verified; it does not mean all qualifications passed. `attempts`
records launch authorization, not proof of completed calls. Confirmed call and
reap fields remain absent on unresolved rows. An outer termination can prevent
final files: retain the immutable initial/campaign plans, completed per-case
outcomes and the outer failure receipt, with all later entries UNRUN.

Requests, actual stdout/stderr, compiler/ELF data and all first hashes stay under
`ignored/`; owner logs stay under `target/evaluation/` and are copied only after
closure. Completed pins are rechecked, never refreshed. Public projections omit
paths, command arguments and raw diagnostics.

A separate **2 GiB retained-evidence budget** reserves the next complete stage
before authorizing it. One whole native prerequisite reserves 1,152 MiB: 870 MiB
of stream/log/DSO maxima, 175 MiB of metadata bounds, and 107 MiB of overhead.
Other stages reserve both stream caps, both owner-log copies, metadata, and any
unique generated file; an installed case additionally reserves its three APP
files. Completed original pins charge actual file lengths rounded up to 4 KiB;
copied files count separately. A 64 MiB allowance is withheld for final reports,
the outer log and bookkeeping. Missing custody or an unfinished inventory keeps
the outstanding reservation charged. A next stage that cannot fit remains UNRUN
and the overall recipe fails. Unexpected growth is retained and refuses further
work; this is a prospective guard, not a kernel filesystem quota.

Shared target binaries/intermediates/cache are not copied and are outside this
evidence budget; the external owner must preflight that build-space domain and
the total 20 GiB slot capacity. Only the three declared compiler scratch trees (`tmp/`, `<raw-name>-native-finite/tmp/`
and `<raw-name>-native-session/tmp/` under this fresh raw directory) join that separate
build-space domain. They may contain no evidence. Every other raw copy, stream,
log, request, receipt and metadata file is charged; these are exact exclusions,
not a general exemption for names containing `tmp`. No budget failure
truncates, discards or relabels retained evidence. The caller must still authenticate
the final outer closure before publishing any result. Source approval and
passing fabricated parser controls grant no native or campaign execution credit.

Caller symbol inspection retains every exact matching row from the complete
`readelf` stream through a pinned `rg` filter and `bash -o pipefail`. Paths are
positional arguments, tool failures and stderr remain failures, and the original
1 MiB stream, CPU and wall bounds are unchanged. The full unrelated Rust symbol
table is not copied into evidence. The existing symbol-count, FUNC, binding,
visibility, address and complete-size checks still apply to every retained row.

The original helper keeps the held file's `fstat` device, inode, size and bytes
as one identity. It derives the expected mapping device separately through
that held descriptor's `mnt_id` and its unique `/proc/self/mountinfo` row.
Both identities are rechecked at the existing source-custody checkpoints;
mapping permissions, inode, offset and complete page bytes remain required.
Malformed, ambiguous or excessive procfs input is a hard failure.

For a targeted original-reference check, use a fresh three-CPU reservation and
an external **1,200-second/8 MiB process owner**, then run:

```sh
python3 -B evaluation/ordinary-module-session/reference.py \
  --revision "$REVISION" --raw "$FRESH_IGNORED_DIRECTORY" \
  --reservation-tag "$RESERVATION_TAG"
```

This builds the C module and original helper, checks emitted geometry, runs six
pure mount-parser controls, then runs each of the eight malformed frames and
32 accepted populations exactly once. It retains failures and unrun cases
under the same per-child bounds and original value checks. It runs no installed
application or Schedule and grants no timing or retrospective campaign credit.

For an isolated owner qualification, use a fresh three-CPU reservation and an
external **1,200-second/8 MiB process owner**, then run:

```sh
python3 -B evaluation/ordinary-module-session/owners.py \
  --revision "$REVISION" --raw "$FRESH_IGNORED_DIRECTORY" \
  --toolchain "$TOOLCHAIN_DIRECTORY" --user-home "$USER_HOME" \
  --cargo-home "$CARGO_HOME" --reservation-tag "$RESERVATION_TAG"
```

This builds a fresh fixed C module, retains separate candidate/trusted inodes
with equal pinned bytes, checks both complete selected functions, builds the release application and
test artifact, and checks the actual emitted Rust CALL/store/FUNC geometry.
It requires all 52 ordinary Rust controls and all 26 Python controls, then runs
K10 CSV→length, K10 length→CSV, K1000 CSV→length and K1000 length→CSV exactly once.
Each retains the existing 15-second application deadline, 20 CPU seconds,
30 wall seconds, 1 MiB streams and 55-second enclosing owner. The controller
and worker use the first two reserved CPUs; the third remains available to the
owner. Affinity and load records do not establish a hard reservation.

The distinct `OWNER_QUALIFICATION_PASS` status requires all four complete owner
transcripts, normal closure and immutable source/tool/artifact retention.
Failures and later UNRUN cases remain in the initial plan and final receipt;
there are no retries. Raw CALL/RAW/PHASE/HISTORY/REPORT/SAMPLE data stay private.
This route runs no native state oracle, Schedule workload or scalar campaign.
It grants no Schedule-deadline, performance, full-campaign or retrospective
credit and leaves the full recipe's separate prerequisites unchanged.
The existing cases stage A, then B while A remains held, reclaim A at phase 4,
and reclaim B at the end. They do not restage a recycled bank or qualify native
execution after shell restaging. Pure Session controls cover that separate
storage transition without supplying native execution credit.


For native execution after reuse of a reclaimed epoch bank, run the same
isolated qualification with `--profile reuse`. The default `owner` profile
keeps its original cases and grammar. Both profiles require all previous
47 Rust controls plus five additional reuse controls; namespace matching
remains exact. Reuse additionally requires eleven independent wire controls
and four qualification-control tests, then four fresh native cases in the
same K10/K1000 and direction order, exactly once each (2,040 actual calls).

Each reuse case reclaims A while B remains pending, immediately restages the
returned bank as fresh C, then executes both functions through C. A's copied
Report must remain byte-for-byte intact; B completes on C's first entry and
C's last call completes only at the final checkpoint. The final transfer
contains four calls with exact generations, function ranks, acknowledgements
and all journal words. No original/warmup call is inserted. The separate
`REUSE_QUALIFICATION_PASS` requires all three Reports, four history actions,
fresh generations, retained A copy, exact eight phases, unchanged bounds,
normal closure, all source/tool/artifact pins and every case passing. Closed
failures remain failed while later independent cases run once; uncertain
custody stops the qualification and keeps remaining cases UNRUN. This is
functional native reuse evidence, without full architectural-state, Schedule,
performance or retrospective campaign credit.
