# Bounded window placement: complete rewrites still refused

The explicit `offline-whole-authored-window-permits-v1` profile produced six
successor-eviction plans and two additional relocation plans for the two authored
programs. **Neither complete rewrite succeeded.** Seven startup branches per
program refused; all other plans were discarded atomically. This is a claim-4
structural result, with no candidate execution or performance measurement.

| Program | Original heads | Requested jumps | B1 plans discarded | T2 plans discarded | Refused sites |
| --- | ---: | ---: | ---: | ---: | ---: |
| checksum | 80 | 16 | 6 | 3 | 7 |
| rle-roundtrip | 107 | 26 | 16 | 3 | 7 |

`sites.csv` retains all 42 rows and the previous profile's tactic for comparison.
The complete source, originals, instruction rosters and ledgers are byte-identical
to the [earlier attempt](../whole-authored-1f6c043/README.md). Only the explicit
placement policy differs: permits come from the existing 16 MiB carrier arena,
excluding its 8 KiB reservation, with algebraically coordinated preferred image
addresses. One candidate and one 4096-byte mapping per role, 32 aggregate images,
all 187 legal heads, all 42 jumps and whole-program refusal remain unchanged.
The previous profile and all four failed E9 comparisons remain recorded as such.
There was one new importer call per program, both returning2, and no E9 rerun or
new comparison for this profile.

Source revision: `f59b21508c2991d13f6342da0248e44a1d2ac69f`. Hardware: **AMD EPYC
Zen 5 dev host**. The release importer remains the actual executable built at
`85e49ae297fb994555e8e742271320dd1737b290`; its Rust build inputs are unchanged.
The exact binary/profile and the earlier tool/build receipt are linked by hash
in `receipt.json`. The two READ_DENIED configuration observations remain
incomplete provenance; qualification remains false. No rebuilt result replaces
that capture.

All 17 material/head controls passed on the exact source images committed in
f59b215. Preparation preserved all 187 heads and 42 jumps. After normal process
closure, both output manifests, every listed file, their nested bundle manifests,
image hashes, selection/entry lists and all report coordinates were authenticated.
The 98 listed files remain ignored; only the compact receipt and 42-row summary
are tracked. The import used reserved CPUs 90/188/225/227, with load averages
40.88/55.94/60.90 before and after. All three outer owners closed without rescue;
the import owner retained its nonzero result. Command durations are diagnostics.

The final `NoPatchWindow` label is not an exhaustive geometric proof. Saved
site 3 diagnostics, for example, include a relocation placement stopped at its
one-candidate budget and a neighbor search with zero eligible victims. The
current neighbor tactic requires a single 10..15-byte victim. No budget was
increased and no case was removed to turn these refusals into success.

## Reproduction

Use the tracked build/material scripts and fresh ignored directories under a
bounded external owner with four disjoint reserved CPUs. The exact observed
importer argv, hashes, limits and all outcomes are in `receipt.json`; the earlier
receipt contains the unchanged build/tool details. To select this profile through
the source API, call:

```python
result = disassembly.attempt(program, inputs, expected,
                             profile=disassembly.WINDOW_PROFILE)
```

`HEAD_CAPTURE.md` and `WHOLE_DISASSEMBLY.md` in `evaluation/offline-corpus/`
describe the exact byte inputs, independent head transport and completeness
premises. Write the returned ledger and policy unchanged, freeze their hashes,
and invoke `target/release/examples/disassembly_sites` once using the receipt's
seven arguments. Do not run the full reproduction helper against the old capture
by weakening its conservative source-continuity guard. A fresh build capture is
the supported route for that helper. The helper now exposes the profile directly:

```sh
python3 -I -B evaluation/offline-corpus/build_whole.py \
  --raw "$CAPTURE" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_DIRECTORY"
python3 -I -B evaluation/offline-corpus/reproduce_whole.py \
  --capture "$CAPTURE" --capture-sha256 "$CLOSED_JSON_SHA256" --output "$OUTPUT" \
  --placement-profile offline-whole-authored-window-permits-v1
```

Its two parser/dispatch controls and CLI smoke passed; the complete workflow was
not rerun to replace these failures. The CLI source and exact check receipt are
recorded separately in `receipt.json`; they do not change the attempt revision.

Unchanged Rust validation remains recorded in
[disassembly-import-59f6550](../disassembly-import-59f6550/): targeted 160 passed;
fmt, strict workspace Clippy and check passed; workspace timed out at 360s; serial
launch 1039, staged 3 and prefixed 36 passed. This result does not establish a full
workspace pass, default 316-thread validation, full offline corpus support or
native equivalence. A3 remains open.
