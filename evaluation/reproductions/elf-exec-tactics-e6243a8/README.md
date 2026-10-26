# Audit and summarize the four-tactic campaign

First run the [native recipe](../../elf-exec/tactics.md) at
`e6243a862fda2572304cccbcfe698ac9ea6212a6`, retaining its separately completed
B1 prerequisite. Copy this directory's audit and collector sources into the
environment that owns the closed raw archive. These scripts execute no native
subject, compiler or helper and read no current Cargo target artifact.

```sh
python3 -B "$REPRO/audit.py" --raw "$TACTICS_RAW"
python3 -B "$REPRO/collect.py" --repo "$REPO" \
  --tactics "$TACTICS_RAW" --b1 "$B1_RAW" \
  --audit "$TACTICS_RAW/runtime-audit-tactics-v1/audit.json" \
  --audit-sha256 "$AUDIT_SHA256" --output "$NEW_IGNORED_OUTPUT" \
  --parents-closed-and-reaped
```

All paths must be canonical and absolute. `TACTICS_RAW` and `B1_RAW` name
distinct raw directories under `REPO/ignored`; output must not exist.
`AUDIT_SHA256` is the independently computed digest of the successful audit
output. Supply the last flag only after observing successful exit and reaping
of the B1, tactic and audit parents. Stored files alone cannot prove parent
closure. Keep `private-binding.json` and the full raw audit output private.
The collector's seven public CSV/JSON files contain summarized observations
and reversible symbolic command coordinates.

The executed collector source SHA-256 is
`b36f2ae7aa95034be5223d90377ad53ad3e16f5b32ca81de21c4b55401b77532`.
It writes the seven summaries under `NEW_IGNORED_OUTPUT/public/`. Its first
invocation returned zero, but the caller's inspection failed by looking in
the output root instead of `public/`. The unchanged collector was run again
into a fresh directory; the caller completed and all seven files were byte
identical. The first caller failure retains an unknown child duration.

The executed audit source SHA-256 is
`15701346bc05e7e423b6df478ec16664367771b10f7d9a36e29708120c74c369`.
It pins `fixture.json` and `source-pins.json`, requires the complete saved source
map to equal the tested Git revision, derives expected capture names from the
fixed fixture, and compares saved architectural state independently of the
native driver's in-process comparisons. All recorded target XSAVE components
must appear at their exact sizes; additional canonical components remain part
of state equality. B1 is a separate prerequisite, not an additional result of
this four-family state audit.

The first executed audit source, SHA-256
`806336d1d0e43087c6bfcd5eef17348372703bf10ced6ddf4216b3443f1c027c`,
failed on a target-record format mismatch before its state comparisons.
`reconstruct-failed-audit-v3.patch` reconstructs that exact failed source from
the published corrected script using standard unified-diff application. Keep
the same two support files beside it. This preserves reproducibility of the
failure without changing any raw observation. The correction joins the full
target owner to its compact projection; all prior comparisons remain exact.

Actual invocations, source hashes and outcomes are in
[postprocessing.json](../../results/elf-exec-tactics-e6243a8-20261026/postprocessing.json).
These support scripts ran as separately pinned source snapshots; their tested
revision is null. The later publication commit is not relabelled as their
tested revision. Operational elapsed times are not benchmarks. Full artifact
qualification and full A3 completion remain false.

`collect_support.py` reconstructs the small postprocessing record from the
fixed retained archive, including both audit attempts and both collector
invocations. It also summarizes the independently counted required-test groups.
It launches no subprocess and reads no Cargo target file:

```sh
python3 -B "$REPRO/collect_support.py" --repo "$REPO" \
  --output "$NEW_SUPPORT_OUTPUT"
```

Its executed source SHA-256 is
`957db088ab872b2f1d554b860b6d5f300000f145bfa66baaf8fdf87db2d71940`.
It exited zero with empty streams in 0.114030143013224 seconds. The retained
raw input names are fixed to this historical cohort; fresh workload reruns
use the native recipe and audit/collector above. Keep its coordinate binding
private. `files.json` indexes the main collector's six data files;
`publication-files.json` additionally indexes the postprocessing summaries.
