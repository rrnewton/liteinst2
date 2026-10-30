# Adjacent branches with a routed successor

The explicit artifact planner and ELF frontend now handle a backward two-byte
JBE immediately before a forward two-byte JMP and an unselected MOV R12→RDI.
The upper relocation retains a separately routed MOV entry; the lower JBE uses
a generalized pun against the resulting source bytes. Original geometry selects
this family or the existing forward-Jcc pair before either outcome is known.
The full selected roster, transactional composition, pending ownership and
independent cumulative upper/lower/continuation limits remain mandatory.

The frontend can place its read-only program-header carrier in a verified gap
between original ET_EXEC LOADs. It checks complete rounded memory ownership,
including BSS, preserves original header order and bytes, and charges the full
original-plus-new address span. Existing carrier APIs retain their restrictions.
All frozen fixtures, old profiles (including 16 MiB), caps and earlier failures
remain intact.

The native fixed-fixture campaign validates 31 rows, two seeds, two hook modes
and three phases: **372 subject traces**, with real production SIGILL routing,
16 routed deliveries, 12 saved-successor signal returns and 192 hardware
CALL/RET pairs per complete campaign. It compares GPRs, defined flags, canonical
native XSAVE, memory, stack, pages and exact logs. These results cover the private
fixture; they do not establish general ELF installation or retirement.
[Native evidence](native-bba07c2/README.md) retains the initial 17 failing rows
and the observer-step correction without changing any comparator or bound.

[Frontend evidence](frontend-ccd88c3/README.md) records **250 passing Rust tests**
and **91 passing Python controls**, with every initial failure retained.
The strengthened combined fixture independently inspects its actual ELF output,
including the high original LOAD, BSS, carrier/table, full hull and four images.
Independent source reviews found no weakened assertion, fixture, cap or gate.

The release [two-program diagnostic](corpus-ccd88c3/README.md) now produces both
complete candidate files: checksum has 80 heads / 16 selected jumps / 19 images;
RLE has 107 / 26 / 29. All **187 heads and 42 selected sites** remain represented.
Each program uses one routed-JMP pair. Both outer commands retain **exit 2** and
`FAILED_OR_INCOMPLETE`: two ancestor Cargo configuration lookups were unreadable.
Independent whole-artifact verification (W01) and native execution (N01) remain
pending. Producer success does not qualify either gate or establish performance.

At source `ccd88c3`, the required full parallel workspace passes **3,768 tests,
0 failures, 37 ignored** in 880.16 seconds. Serial launch passes **1,039 tests**
in 133.39 seconds. Formatting, strict all-feature/all-target workspace Clippy
and checking pass. The workspace uses 316 test threads on 16 reserved CPUs.
Both Rapid rejection tests, all 21 short-neighbor cases, observing-control and
prefixed-pun regressions, and the new native/frontend/gap controls pass.
[Validation receipt](validation-ccd88c3/receipt.json) and
[99 exact control results](validation-ccd88c3/controls.csv) record these checks.
Five nested child summaries are excluded from the workspace total; both custom
harnesses complete separately. All command cleanup completes with no adopted
descendants.

This is claim 4 / A3 progress; A3 remains incomplete. Tests use debug builds on
an **AMD EPYC Zen 5 dev host**. Reported elapsed times are command receipts, not
performance measurements. Only the corpus capture/producer uses release builds;
no performance result is asserted. Raw logs and captures remain ignored.

The earlier [core receipt](core-7bbc027/receipt.json) and
[21 controls](core-7bbc027/controls.csv) remain unchanged: 3,670 workspace tests
passed at 7bbc027, with 37 ignored and no failures. That historical result
predates this native/frontend increment.

To reproduce the full validation at source revision
`ccd88c3aa96e7e9a590838d5d8c01cccebbca139`, use Rust 1.97.1 and Python 3.12,
reserve 16 disjoint CPUs, and run from the repository root with a fresh output
path. The driver retains 316 test threads and the recorded command bounds:

```sh
env CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
  CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
  CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
  LITEINST_EVALUATION=1 \
  python3 -B evaluation/short-neighbor-parallel/validate.py \
    --revision ccd88c3aa96e7e9a590838d5d8c01cccebbca139 \
    --output ignored/adjacent-routed-jmp-reproduction
```

Focused native, Rust/Python frontend and release producer commands are recorded
in the linked receipts. The Python control/producer commands used Python 3.9.25;
the outer process owner used Python 3.12.15. These versions are distinguished in
the evidence.
