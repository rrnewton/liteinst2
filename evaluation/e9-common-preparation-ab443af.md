# Compiled common-corpus original preparation

At source `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`, the compiled
ET_EXEC heap-sort fixture passed all eight dataset checks in both stripped and
unstripped form. All 30 bounded stages completed as specified: 24 returned zero
and six required refusals returned their exact usage, dataset or overwrite
status. The 16 ordinary executions produced complete expected sorted output,
empty stderr and exact 131,144-byte zero-entry journals. The overwrite refusals
preserved the existing files.

The [summary](results/e9-common-preparation-ab443af-20261026/summary.json),
[30 command rows](results/e9-common-preparation-ab443af-20261026/commands.csv),
[22 execution/refusal rows](results/e9-common-preparation-ab443af-20261026/cases.csv)
and [complete command records](results/e9-common-preparation-ab443af-20261026/commands.json)
identify the exact requests, limits, selected tools and hardware: AMD EPYC Zen 5
dev host, GCC 11.5.0 and glibc 2.34. Elapsed times are operational diagnostics.
The [artifact record](results/e9-common-preparation-ab443af-20261026/artifacts.json)
binds both binaries and 11 ELF slices. Program headers and loaded bytes agree
across stripping except the declared section-table header coordinates.

Use the [preparation recipe](e9-common-app/prepare_subject.py) at the subject
revision and follow its [instructions](e9-common-app/PREPARATION.md), retaining
the parent launch and wait result under `ignored/`. The recipe's exact SHA-256
is `79945a0bfdc7ffa9b1ea2ed265669709e278bb6d82c5676731dab547eadc278c`.
It executes the same fixed 30-stage sequence; stop on an unexpected outcome
and retain the partial result.

The [collector](e9-common-app/collect_preparation.py) ran separately at
`eac76746ceddc3a3193057dc967dda1d3f893cfb`. It consumes the closed preparation,
saved parent launch records and a pinned complete input index; it does not run
the fixture. The published collection records its own revision and source hash
separately from the subject. Its parent-closure check uses the saved launch
record plus explicit caller confirmation, not a live process observation.
Independent review verified all 276 indexed inputs, 30 strict receipts, 16
complete outputs and journals, six refusals, 11 slices and 1,204 source Git blobs.

The four selected tool hashes, compiler depfile and link map do not establish a
complete compiler or runtime dependency closure. There are zero rewrites here.
Complete disassembly, selected-site retention, hooks, architectural-state
equivalence and full A3 remain open. This supplies preparation evidence for the
claim 4 campaign. Raw logs, journals, binaries and private path inverses remain
under ignored storage; the tracked files contain sanitized CSV/JSON summaries.
