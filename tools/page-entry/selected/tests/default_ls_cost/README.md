This diagnostic observes the existing native-page handler on `/bin/ls -d .`
with default glibc rseq registration. It adds only the reviewed three writer
insertions to a generated private copy of `runtime_loader.c`. The counter
writer and strict prefix parser are unchanged: first handler, registration
transitions, then every 4096 handlers; at most 128 pairs / 256 lines of at most
2048 bytes. It reports maps acquisitions/reuses/invalidations and rseq checks
beside completed chain steps. The existing sampled CPU and wall observations
are whole-handler measurements, not stage durations or an uninstrumented
performance result. The diagnostic's own raw clock calls and writes use the
ordinary maps gateway and invalidate reuse. Counter growth and sampled handler
intervals include those observer effects; nothing is subtracted or exempted.
No new clock authority or production recipe is added.

Run the committed write-footprint oracle first at the exact same clean revision.
Then, on one externally reserved CPU:

```sh
python3 evaluation/inprocess/page_selected_write_footprint.py --expect-revision FULL_REVISION
python3 evaluation/inprocess/page_default_ls_cost.py \
  --expect-revision FULL_REVISION \
  --archive-receipt PASSED_SAME_REVISION_FOOTPRINT_RECEIPT \
  --library-root /usr/lib64 \
  --output target/default-ls-cost-UNIQUE
```

Both commands must use that one-CPU affinity. The first command performs the
existing bounded release build and full native footprint qualification. The
second reuses its retained archive after checking the exact source, all 19
commands and captures, selected tools, eight build artifacts, actual archive
dep-info, locked registry sources, ELF inspections and unchanged full native
footprint reader. No historical receipt path, namespace hash or decoder archive
is accepted as a substitute for this same-revision prerequisite.

The diagnostic performs eight commands: compiler-M, the complete 15-TU release
link, nm, objdump, carrier creation, actual interpreter `--list`, native ls and
gated ls. Each retains the original 30 CPU seconds / 60 wall seconds / 512 MiB /
16 MiB bounds. A fresh namespace plan and the real native loader listing must
name identical dependency bytes. The actual gated namespace, closed default
environment and links are checked afterward and during final custody. Optional
`--cpuid-nx` selects the existing raw NX-only recipe and its existing stricter
completion reader; it never changes the default profile or disables rseq.

Complete or partial stdout/stderr, argv, tool/header/source/artifact identities,
namespace metadata and detailed diagnostic rows remain under the requested
private output. A compact numeric result is written to
`evaluation/inprocess/results/OUTPUT-BASENAME.json`; it contains hardware,
revision, hashes, actual process exits and counts, bounded counter deltas and
integer times. It excludes PCs, host paths and raw logs.

Exit 0 requires the unchanged complete terminal report, actual gated exit 0 and
exact native-output equality. Exit -9, a missing report, valid partial pairs or
no pairs never grant operation completion; the evaluator exits 1 and retains
the failed operation and any diagnostic prefix. It does not infer the cause of
a kill. The original five-program matrix remains a separate qualification.
