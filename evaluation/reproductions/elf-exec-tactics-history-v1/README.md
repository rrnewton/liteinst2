# Reconstruct the historical summary

`collect_history.py` (SHA-256
`559b54bbd2326c501cf45a08b0238beffebcd43083be3411250468d15087ce8c`)
renders the four fixed attempts from saved records. It does not execute any
subject, compiler or audit. `frozen-inputs.json` lists hashes and sizes for
1,874 private input files; it contains no raw logs, captures or binaries.

With the matching retained archive under `REPO/ignored`, run:

```sh
python3 -B "$REPRO/collect_history.py" --repo "$REPO" \
  --inputs "$REPRO/frozen-inputs.json" --output "$NEW_IGNORED_OUTPUT"
```

Paths must be canonical and absolute, and output must not exist. `REPRO` names
this directory. Keep the generated `private-binding.json` private. The five
other outputs reproduce the [published summaries](../../results/elf-exec-tactics-history-20261026/files.json).
All frozen input hashes are checked before and after rendering.

The actual invocation exited zero in 0.6648500158917159 seconds with empty
stdout/stderr. Each of the five outputs matched its independently reviewed
specimen byte for byte. This duration is an operational diagnostic. The
renderer was executed as an exact source snapshot, with tested revision null;
its publication commit does not become a workload or renderer qualification.

For fresh workload reproduction, use `evaluation/elf-exec/reproduce.py` and
`reproduce_tactics.py` at each revision named in the
[historical command records](../../results/elf-exec-tactics-history-20261026/commands.json),
with fresh output paths and the recorded toolchain. Environment-dependent
compiler/lint failures are historical observations, not required outcomes of
a new environment. This exact-archive renderer deliberately preserves them.
