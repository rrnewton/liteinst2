# Explicit whole-policy scalar recipe

This separate `leaf-set-whole-session-v1` recipe selects `CertifiedBlocks` for
CSV fields and `WholeFunction` for encoded length, ASCII digits and ASCII spaces.
The latter three complete functions must fit the existing 5..80-byte policy.
There is no fallback or policy selection based on results. The original
`ordinary-leaf-set-session` catalog and its certified scanner policies remain
unchanged; this profile cannot reinterpret their refusals.

The recipe first runs 24 independent original-reference cases. It then runs
five fixed copies of the same 24 coordinates: N=1..4, K=10/1000, and empty EOF,
K+1 accepted records, or two accepted records followed by the fixed syntax error.
Every cohort retains 4,064 accepted records and 10,160 calls across its cases.
The original and installed legs use the same explicit operation identities and
policies after ELF-address ordering. All requests freeze before reference one;
there are no retries, replacements or favorable-case selection.

From an exact clean reviewed revision, use the existing external process owner
and a hard **three-CPU** reservation with **7200 seconds / 8 MiB**:

```text
python3 -B evaluation/ordinary-leaf-set-whole-session/reproduce.py \
  --revision <exact-40-hex-commit> --reservation-tag <external-tag> \
  --raw <absolute-fresh-ignored-directory> \
  --toolchain <absolute-rust-toolchain-directory> \
  --user-home <absolute-user-home-directory> --cargo-home <absolute-cargo-home-directory>
```

The wrapper authenticates its sources and the shared runner against that revision
before importing them. Its startup time remains the campaign's original deadline
origin. Cargo uses the shared checkout `target/`, release opt3/debug0, assertions
and overflow checks, four jobs and no incremental compilation. Exact compiler,
subtool, source, original/candidate ELF, complete RET and caller geometry pins
remain required. A reservation tag, affinity and load are recorded but cannot
establish the external hard reservation.

Both profiles use the same campaign and producer lifecycle. The new producer
repeats the exact profile, catalog hash, policies and entry path; these must join
before custody release or further work. Actual APP streams, PID, normal reap,
owner closure and all original scalar comparisons remain required. Closed,
identified functional failures remain FAILED; source or custody uncertainty
withholds the rest as UNRUN. All first pins and failures remain in ignored raw
evidence. Public summaries retain every case within the existing 80,000-byte cap.

All original controls remain required: 68 ordinary Rust, 18 SDK, 55 Python and
the existing six mount/four original C controls. Six additional profile controls
run before original setup. To run just their fabricated guard checks, use the
workspace TMPDIR and `python3 -B
evaluation/ordinary-leaf-set-whole-session/profile_controls.py -v` under the
existing bounded owner. They do not launch a campaign or application.

The 520 total epochs remain distinct from three resident banks. The existing
2ms arm, 10ms interval, 2s shutdown, 15s producer, 20CPU/30s child and 55s owner
bounds are unchanged, as are stream and 2GiB evidence limits. The distinct success
label is `LEAF_SET_WHOLE_FUNCTIONAL_PASS`. It denotes scalar functional acceptance
for this configuration only; copied-caller/native state, owner reuse, timing,
pure overhead and full A5 qualification remain separate obligations.
