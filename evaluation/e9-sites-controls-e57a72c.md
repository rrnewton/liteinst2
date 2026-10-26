# E9 site-inventory controls

At `e57a72c62fc569bd09c12815f7c9eec5162f3a50`, two independent synthetic suites
each passed three accepted cases and 24 required refusals. The adapter suite
checks producer/site ownership; the existing comparator suite checks complete
site retention and explicit trap/refusal classification. These are synthetic
controls: no E9 producer or application was executed.

The [summary](results/e9-sites-controls-e57a72c-20261026/summary.json) retains
both exact requests, environments, limits and strict receipts. The
[command rows](results/e9-sites-controls-e57a72c-20261026/commands.csv) and
[input hashes](results/e9-sites-controls-e57a72c-20261026/inputs.json) bind the
actual outputs and historical source. Independent review checked all 27 raw
files, complete expected output, empty stderr, ECHILD cleanup receipts and all
1,206 source Git blobs. Hardware was AMD EPYC Zen 5 dev host. Times are
operational diagnostics.

The [replay script](reproductions/e9-sites-controls-e57a72c/reproduce.py) is a
source-reviewed adaptation of the executed private wrapper. Preserve it outside
a clean subject checkout at the recorded revision, then run:

```sh
python3.9 -B "$SCRIPT" --repo "$REPO" --raw "$NEW_RAW"
```

`REPO` is that canonical absolute checkout. `NEW_RAW` must be a new canonical
absolute directory under its `ignored/` directory, with an existing parent.
The script SHA-256 is
`88aca300e5dfdd10764500289fc534ed9a7538045c220fbb28b146cb38365289`.
It retains the original two suites, full expected outputs, 20 CPU/30 wall-second
limits and cleanup assertions. Its new argument handling and explicit Git cwd
were reviewed but have not been executed; this is not an extra successful run.

Two failed publication drafts remain recorded in the summary: a source join
used a newer working-tree lockfile before correction to historical Git blobs,
and an attempted second path normalization was refused before correction to
one normalization pass. Neither failure changed a control result. Review also
found the prospective replay wrapper's Git calls ignored `--repo`; the corrected
wrapper binds all six calls to that directory. The actual wrapper used its cwd
as the repository, so its result was unaffected.

Raw streams and private paths remain ignored. These controls support the
structural-validation portion of claim 4; rewritten application behavior,
architectural equivalence and full A3 remain unqualified.
