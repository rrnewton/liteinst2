Run the current unobserved effect-provider release bridge against real `/bin/ls
-d .`, with the normal dynamic loader and default rseq registration:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/page_selected_effect_ls.py \
  --expect-revision "$(git rev-parse HEAD)"
```

Use a clean committed checkout and one externally reserved CPU. The evaluator
builds a fresh decoder archive and the exact 18-translation-unit, 17-macro `-O2`
release bridge. Native loader resolution and the gated sealed namespace must
join the same original program, interpreter and dependency bytes. Both actual
children must exit zero and produce exactly `.\n`; no failed lane is omitted.
The program limits remain 30 CPU seconds, 60 wall seconds, 512 MiB address space
and 16 MiB files/captures. Existing build helpers retain their separate bounds.

The original native-page, rseq, boundary, generic/REP/cache, lease and TTY-query
completion predicates remain required. Additional checks authenticate actual
reusable publications and the selected-effect accounting. The exit report is
emitted before the nonreturning raw syscall: the last source patch is restored,
but that effect is entered, unreturned and uncommitted. It is never counted as a
returning completion or retired publication.

The compact public result records exact revision, hardware, commands and source,
archive, tool, capture and artifact hashes. Raw output and reports remain in the
private receipt directory. One native and one gated whole-process interval are
reported separately from `first_admission_ns` and every retained `revisit_ns`.
Those internal intervals measure admission work only. They do not measure
complete first-touch latency, whole-app steady throughput or a causal speedup.
The gated whole-process interval includes Python namespace sealing and exec;
both intervals also include parent capture/provenance setup and closure.

This real-program completion check does not replace the full all-seven-class,
masked-CPUID or normal-app full-state prerequisites. The separate 9,216-effect
application stress result is not inferred from `/bin/ls` completion.
