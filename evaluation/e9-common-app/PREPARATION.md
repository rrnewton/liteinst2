# Build and check the original common-corpus input

From a clean tracked checkout, choose a new canonical absolute directory under
`ignored/` and run:

```sh
python3 -B evaluation/e9-common-app/prepare_subject.py --raw "$RAW"
```

The recipe uses the existing bounded-command helper. It runs 30 fixed stages:
compiler/strip version observations, compilation and stripping, readelf/nm
observations for both files, all eight datasets on both originals, and six
required usage/dataset/overwrite refusals. Compilation uses 60 CPU seconds,
90 wall seconds and a 128 MiB file cap; other stages use 20/30 seconds and
16 MiB. Keep the recipe parent alive until it returns and is reaped; do not
wrap the whole recipe in an additional timeout.

Every positive execution must produce the complete expected sorted output,
empty stderr and the exact 131,144-byte zero-entry journal. Refusals require
their specific exit status and stderr. The overwrite case must preserve the
existing test file. The two original ELF files must have identical program
headers and loaded bytes except the declared ELF section-table coordinates.
This comparison does not mask application data or pointers.

The raw directory retains source revision/maps before and after, hardware,
selected tool hashes, compiler dependency and link maps, command/receipt
records, all output streams, journals and artifacts. A failed phase stops the
recipe; its partial results remain. `summary.json` describes original-input
preparation only. It provides no rewriting, complete disassembly, site
retention, hook-effect, architectural-state, unwind or full A3 qualification.
The [fixture contract](contract.json) fixes those later obligations.

This initial hardware profile is the AMD EPYC Zen 5 dev host. Tool hashes and
versions are fresh observations; the four selected executable hashes do not
constitute a complete compiler or loader dependency closure. Raw files remain
ignored. Publish sanitized CSV/JSON summaries with exact revisions and
commands when reporting an executed campaign.
