# Observe the original common application

`observe_originals.py` runs the admitted original observer for both stripping
forms and all eight fixed datasets. It does not compile, query a target,
rewrite an ELF or execute an E9/core candidate. The observer follows real exec
and the ordinary dynamic loader, explicitly inserts and restores one startup
breakpoint, then records the original sorting interval. This is an original
application observation, not an architectural equivalence result.

Commit the recipe and intended observer sources first. The actual admitted
build, all eight complete static inventories and this recipe must belong to
that same clean Git revision. The original application preparation remains
separately identified by revision `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`.

```sh
"$PYTHON" -B evaluation/e9-common-app/observe_originals.py \
  --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" --raw "$NEW_RAW"
```

All coordinates are absolute. File owners and parents must be canonical and
nonsymlink; the new output directory has an existing parent beneath `ignored/`.
Python assertions must be enabled. Admission happens before output creation;
a preflight failure launches no helper and leaves the proposed output absent.
The enclosing caller retains its own launch/error record in that case.

## Admission records

The input JSON has exactly `schema`, `preparation`, `build_admission`,
`runtime_admission`, `tools` and `files`, with integer schema 1. `files` maps
every consumed absolute input path to `{sha256, bytes}`. The recipe reads every
entry before launching anything, retains its six-field file identity and
rejects owner or byte changes on every subsequent read. Provide complete named
build, inventory, preparation and review dependencies in this map; an executable
hash alone does not establish build provenance.

`tools` names canonical executable paths for `python`, `helper_python`,
`timeout` and `git`. `python` is the interpreter running this recipe, and `git`
is `/usr/bin/git`. The unchanged helper at
[tools/unwind-oracle/bounded_command.py](../../tools/unwind-oracle/bounded_command.py)
must also appear in `files`. Full tracked bytes/modes must match Git at the
start, before and after every helper, and at closure.

`preparation` uses the existing producer schema: `summary`, `source`,
`source_after`, `review_binding` and `originals`. The latter names exactly
`unstripped` and `stripped`. Its closed preparation has 30 stages, 16 ordinary
original runs and six required refusals; those historical runs are not credited
to this observer. All seventeen original preparation files, including its documentation, remain exact.

`build_admission` points to a separate caller-authenticated JSON record:

| Field | Required value |
| --- | --- |
| `schema` | 1 |
| `authority` | `CALLER_AUTHENTICATED_OBSERVER_BUILD` |
| `scope` | `original-common-app-observer-build-only` |
| `source_revision` | Actual clean build/recipe Git revision |
| `source_files_sha256` | SHA-256 of sorted compact JSON relative path → `{sha256, bytes, mode}` |
| `driver` | Archived `elf-exec-oracle` executable |
| `common_sites` | Archived selector executable used by the eight inventory requests |
| `directory` | Closed build/inventory raw directory |
| `review_binding` | Actual caller-selected build/archive review binding |
| `evidence_files` | Unique complete named evidence list, including that review |

This record is an explicit caller authority, not something this recipe derives
from an arbitrary supplied binary. The production admission of `core` and
`common_sites` does not authorize the observer. The existing build already
archives the driver; no second build is needed. The recipe joins the complete
source map, actual Cargo selection/profile/source records, archive copies and
owner identities, depfile records, build closure, and all eight inventories.
It does not read the live Cargo target directory. Caller review must establish
the actual compiler and dependency provenance recorded by those archives.

All eight inventories must retain identical full instruction, memory-write,
block, padding and target tables. Each style's complete site table must match
across hooks and stripping forms. Every request, receipt, copied input, COMPLETE
index and full stdout is bound. The observer consumes the complete *null*
jump-site and heap-write inventories for each original, including zero-visit
sites; journal inventories are authenticated but do not create extra runs.
The exact layout is reconstructed from the admitted original symbol geometry.

`runtime_admission` is a separate caller-observed epoch with exactly `schema`,
`authority`, `scope`, `source_revision`, `observer_sha256`, `variants` and
`evidence_files`. Its authority is
`CALLER_AUTHENTICATED_ORIGINAL_RUNTIME_OWNERS` and scope is
`selected-original-interpreter-library-owners-only`. Its revision and driver
hash match the admitted build. `variants` has exactly `unstripped` and
`stripped`; each contains `owners_file`, `owners` and `interpreter_lookup`.
The recipe will not refresh historical metadata to make this record pass.

Each `owners` vector has 2–16 distinct file identities, with that variant's
original first, its actual resolved PT_INTERP included, and every other library
chosen explicitly by the caller. Each row is exactly:

```
path, sha256, bytes, descriptor_stat, pathname_stat, observed_path_hex, provider
```

Admitted ordinary input files use the existing 128 MiB read bound; runtime ELF
owners retain the observer's 16 MiB bound. Capture files remain capped at 64 MiB.

Both stat vectors have the observer's eight fields: device, inode, mode, size,
mtime seconds, mtime nanoseconds, ctime seconds and ctime nanoseconds. The raw
`/proc/self/fd/FD` readlink bytes equal the canonical pathname and are retained
as hex. `provider` has `mount_id`, two-element `device`, and the exact selected
`mount_record` including its final newline. The descriptor's `fdinfo` mnt_id
and inode select that mount record. Provider device need not equal fstat's
device on filesystems exposing a distinct subvolume device. No such difference
is silently normalized. All expected fields must equal the actual observation.

`owners_file` is the exact ASCII observer input: `LI2COMMONOWNERS\t1\n`, then
one canonical pathname and newline per owner in the same order. Pathnames
cannot contain whitespace. `interpreter_lookup` contains `path`, `resolved`
and `components`. Its path is the literal original PT_INTERP. Each lexical
prefix after `/` has a row `{path, stat, link}`: the same eight lstat fields and
raw symlink target, or null for a nonsymlink. The resolved owner must occur in
`owners`. Both the lookup and all descriptor/path/provider identities are
rechecked before and after each helper. The caller supplies evidence for this
epoch in `evidence_files`; this selection does not claim a complete loader,
configuration, NSS, locale or system-library dependency closure. The observer
refuses unexpected executable mappings rather than silently adding owners.

## Sixteen fixed stages

Order is unstripped followed by stripped, each with `empty`, `singleton`,
`pair-reverse`, `equal-17`, `sorted-17`, `reverse-17`, `duplicates-17`, `mixed-64`.
Every stage is mandatory and invokes exactly:

```
DRIVER observe-common-app ORIGINAL LAYOUT INSTRUCTIONS JUMP_SITES HEAP_SITES RUNTIME_OWNERS DATASET NEW_CAPTURE_DIRECTORY
```

All requests use 60 CPU seconds, 90 wall seconds and 64 MiB per file. The
unchanged helper uses the existing strict 13-field receipt and ECHILD proof;
its owned-descendant cleanup deadline remains five seconds. The observer's
own cleanup remains two seconds. Outer timeout is 100 seconds with
`--kill-after=10s`; parent wait is 115 seconds. The observer's 60-second app
deadline, prospective per-head formula, 128 bridge allowance and 1,048,576
hard step maximum remain unchanged. The old B1/tactics 20,000-step/15-second
protocols are not modified or executed here.

The request environment is explicit: `PATH=/usr/bin:/bin`, `LC_ALL=C`,
`PYTHONDONTWRITEBYTECODE=1` and a fresh per-stage TMPDIR. The observer's original
child has its existing fixed `LANG=C`, `LC_ALL=C`, `PATH=/usr/bin:/bin` environment.
Requests, outer commands, receipts, full streams, input/source snapshots,
actual hardware and capture file hashes remain private beneath the new raw
root. Durations are operational diagnostics, not benchmarks.

A receipt, cleanup, tool/input/runtime-owner drift or outer mismatch stops the
sequence. A strictly closed nonzero observer or ordinary output/schema failure
retains its failed row; the next independent dataset may run only after the
same owners and source are reconfirmed. There is no retry or cap change. Partial
capture indexes and all dependent/unlaunched rows remain explicit. Traversing
all stages does not mean success: every one of the sixteen command/schema rows
and final owners must pass.

A successful row requires exact helper and observer stdout, empty stderr,
unchanged-input and completion markers, the full expected application output
and zero journal, every static coverage row (including zero visits), event/PC
size accounting and exact saved owner/provider joins. It is labelled
`PASS_COMMAND_AND_CAPTURE_SCHEMA`. The separate actual content audit must
still check the complete trace, store/call projections, mappings and memory;
hashes or a completion marker do not establish state equivalence. Both
`capture_content_audit_required` and `qualification_complete: false` remain
explicit. The enclosing parent's closed/reaped observation is separate caller
authority and is never fabricated by this script.
