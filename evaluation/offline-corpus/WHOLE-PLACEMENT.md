# Whole-program placement profiles

`reproduce_whole.py` builds materials for every authored instruction head and
selected jump: checksum has 80 heads and 16 jumps; RLE has 107 heads and 26
jumps. It invokes the release importer once for each ready input. A refused
site prevents a complete candidate; it does not shrink the selection.

Choose one profile explicitly for both programs:

| `--placement-profile` | Virtual-span cap | Placement permissions |
| --- | ---: | --- |
| `offline-whole-authored-null-jumps-v1` (default) | 16 MiB | Original fixed pages |
| `offline-whole-authored-window-permits-v1` | 16 MiB | Pages in the existing carrier arena |
| `offline-whole-authored-broad-span-2g-v1` | 2 GiB | Same seeds and carrier exclusions, with a larger final permitted interval |

The broader profile is a separate resource contract. It preserves the old
profiles and their [fixed-page](../whole-authored-1f6c043/README.md) and
[window-permit](../whole-authored-window-f59b215/README.md) results.

The larger virtual span admits targets whose E9 displacement bytes must also
encode invalid-opcode entry routes. A legal entry at the high displacement
byte can require at least 96 MiB of positive displacement. The planner still
checks the actual target, complete image, source and occupied ranges. Each
allocation retains one candidate, one mapping and at most 4096 mapped bytes.
Aggregate limits remain 32 images, 128 new LOAD pages, 128 KiB emitted image
bytes, 2 MiB output bytes and 1 MiB added file bytes. One candidate per
allocation is not an exhaustive placement search.

Run the existing build and process-custody recipe, then select the new profile:

```text
python3 -B evaluation/offline-corpus/reproduce_whole.py \
  --capture ABSOLUTE_CLOSED_BUILD_DIRECTORY \
  --capture-sha256 EXACT_CLOSED_JSON_SHA256 \
  --output ABSOLUTE_NEW_IGNORED_DIRECTORY \
  --placement-profile offline-whole-authored-broad-span-2g-v1
```

Both directories must use canonical absolute paths under the checkout’s `ignored/`
directory; the output must not exist yet.

The capture must contain the actual current-source release build, complete
configuration and source identities, target capture, both original programs
and their independent disassembly. Existing child deadlines, output caps,
cleanup and nonzero failure returns remain in force. The wrapper never retries
with a different profile.

A virtual hull includes unmapped gaps; it does not measure physical memory or
loader reservation cost. Material or importer success alone supplies no native
execution, full-state equivalence, performance or E9 comparison result. Those
require separate complete-candidate validation; `compare.py` retains its
existing kernel-only selection.
