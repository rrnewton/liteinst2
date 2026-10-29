The five controls use the unchanged `query_refusal.c` with the normal dynamic
loader and its default rseq registration. They ask ARCH_GET_XCOMP_SUPP,
ARCH_GET_XCOMP_PERM, rt_sigprocmask, and each getcpu output to write into the
actual registered rseq word. Each gated child must stop before effect issue:
exit 125, empty stdout, error 1205/detail 0, exact syscall/kind and word span,
and zero Native/raw-entry/raw-return markers. Never run this fixture natively.

From a clean committed checkout, with one externally reserved CPU:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/page_selected_query_refusals.py \
  --expect-revision "$(git rev-parse HEAD)"
```

The evaluator uses the existing fresh `Build.prepare()` archive and source/tool
closure, then the exact release effect-provider recipe and the small fixture
recipe beside this file. It retains compiler dependency rules, binaries,
namespace/launch descriptions and full command captures privately. The five
children retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and
16 MiB file/capture bounds. The existing process owner uses a 3-second reap
deadline within the original 5-second cleanup ceiling. Fresh archive preparation
keeps the existing build helper's separate build/metadata/inspection bounds.

The public JSON contains counts, source/build/capture hashes and the five exact
refusal outcomes; actual addresses and raw reports stay private. This is a
finite pre-issue exclusion result, not full B2 qualification or performance.
Any separately supplied in-memory rseq controls earn no kernel-registration
credit. The earlier private attempt02 remains failed: its report reader used
the wrong `last` indices. The required write-span join here is `last[3:5]`.
