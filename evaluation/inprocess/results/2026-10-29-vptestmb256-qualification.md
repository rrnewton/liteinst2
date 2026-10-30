# VPTESTMB256 and successful late loading

Measured source: `e03366b0b24f30df69bdcdd533d3e78d4f43d077`.

Canonical register-form EVEX256 VPTESTMB now executes at its original PC under the in-process page gate. This admits the Code2784 instruction that stopped the previous late-DSO run. The unchanged native and gated application both complete two load/close/reload cycles, 12 effects and 24 live snapshots per lane. All 12 effect pairs and the original/restored source pages compare successfully. The gate runs in process without a ptrace supervisor.

The new opcode oracle passes 78 selected cases plus five startup pairs. It checks every vector source and mask/destination role, full 64-bit mask results including high-half zeroing, complete saved/live architectural state, 12 page-ending and 66 crossing fetches, typed/no-write-footprint queries, and unsafe-neighbor refusals. The three affected 512-bit suites retain their 14 processes and 266 pairs. Together, the four suites pass 19 processes and 349 pairs. The formerly rejected 256-bit literal remains a mandatory positive typed/NONE check in every process.

| Qualification | Observed outcome |
| --- | --- |
| New and affected mask-vector suites | 19 processes; 349 completed pairs; 660 actual-before NONE queries; 3,071 refusals; 19 mandatory 256-bit promotions |
| VPTERNLOGD256 | 147 processes; 2,250 selected cases; 2,391 completed pairs; 6 real read faults; 4,512 queries; 32,634 refusals |
| Six other instruction cohorts | 586 selected cases; 623 completed pairs; 4 real read faults |
| Zero helpers and Q/D REP | Full helper range; 6 selected pairs plus startup and 1 genuine failed store for each Q/D cohort |
| Publication and inactive rseq | 6 effects, with 5 returns and 1 nonreturning exit; 48 required failed operations plus 1 refused site; 2 completed rseq cases plus 15 required refusals |
| Native-pair | 397 commands; 16 registered and 4 boundary pairs; 22 additional profiles with 44 subjects, 11 completed pair operations and 11 required refusals; 675 supplied controls |
| REP leases | 46 subjects; 24 completed pairs; 2 native store faults; 4 signals; 34 required failed operations; 108 reader refusals and 28 supplied mutations |
| Required checks | Recorder 350; fmt; strict Clippy; workspace 3,545 passed and 37 ignored; all-feature/all-target check; serial 1,039 passed |

All results use exact committed source, reserved CPU affinity, original command bounds and complete cleanup checks. Instruction subjects retain 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB file size. Workspace and serial retain 900/180 seconds; observed durations were 365.107/130.193 seconds. The machine is an AMD EPYC 9D85, family 26/model 17/stepping 0, microcode 0xb101066. Exact CPU assignments, source tree, hardware, commands, bounds and numerical rows are in the companion JSON and pinned manifest.

These are correctness results. The application reader leaves full XSAVE, per-cycle kernel unmap, publication identity and general runtime lifecycle qualification false. The successful late-DSO lane uses the existing 19-macro release bridge; the separate 20-macro native-pair application composition is next work. Thread/signal/JIT lifecycle and full B3/B4 remain open. The earlier failed Code2784 run remains failed in its original VPTERN report. Existing performance results retain their own measured revisions.

The compact result is 35,643 bytes (34.8 KiB), SHA256 `195b1a3e15d90bffb83b0a75d21645a8ea72571b5fde4c7c8291f74869c61afd`. Schema 2 pools repeated text and table suffixes; all numerical rows and values remain in JSON. The shipped `page_qualification.expand()` reconstructs the complete ordinary projection, checked by canonical-byte equality before publication. Reading those public results needs only the compact JSON and projector; regenerating the projection also needs the pinned private receipts described below.

The sealed [manifest](2026-10-29-vptestmb256-manifest.json) binds 21 receipts and 1,925 commands: 20 passed cohorts and the original passed finite inactive-rseq profile. The [compact result](2026-10-29-vptestmb256-qualification.json) retains the numerical rows and every original cohort status. The manifest is 23,655 bytes, SHA256 `33cabe8085ec8ae6b95145f481fb8aaa7f5f66f56c330bb6317a7e5778522f77`.

All measurements bind source `e03366b0b24f30df69bdcdd533d3e78d4f43d077`; a later evidence-only commit does not change that revision. Each projected receipt retains its original public `reproduce` command, hardware and resource limits. Fresh native qualification uses those commands at that measured source revision.

To reproduce the compact JSON from the retained evidence, set `FROZEN_MANIFEST` to the shipped manifest, `MANIFEST_SHA256` to its exact hash recorded in the companion JSON, and `NEW_OUTPUT` to a path that does not exist, then run from the repository root:

```sh
python3 -B evaluation/inprocess/page_qualification.py --root . \
  --manifest "$FROZEN_MANIFEST" --manifest-sha256 "$MANIFEST_SHA256" \
  --output "$NEW_OUTPUT"
```

This data-only command requires the exact pinned public and private receipts and audit files. It authenticates the closed source, hardware, bounds, cleanup and numeric projections; it does not launch subjects or replay architectural readers. The output limit remains 40 KiB. Required failed operations and earlier failed evaluations retain their original classifications.
