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
| `offline-whole-authored-short-only-2g-v1` | 2 GiB | Exact broad-profile placement; explicit ShortOnly T3 family |

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

The separate ShortOnly profile uses every BROAD_PROFILE limit, permit, seed,
search row and allocation row unchanged. It changes only the policy header to
`LI2DISASM-POLICY 2` and inserts `neighbor-victims short-only` immediately
after the ledger row. It requests the importer's explicit leading
`--short-neighbors-only` option. The first four tactic stages retain their
ordering; the final T3 stage uses only 6..9-byte victims, with no long-family
fallback, retry, extra allocation candidate or second program attempt.

Select it with
`--placement-profile offline-whole-authored-short-only-2g-v1` after a fresh
capture at the integrated source. The wrapper requires the exact importer
profile `elf-disassembly-null-jumps-short-only-v1` and
`neighbor_victims\tshort-only` metadata. An old-profile directory cannot
satisfy the new attempt. The full policy, indexed files, complete 187-head /
42-jump material population, custody, configuration and release-profile gates
remain required.

The new LI2TOOL projection retains its explicit family row. The unchanged
legacy selection parser rejects that unknown row; this profile does not strip
it for an E9 or other comparator. No comparator qualification, fit, native,
loader or performance result is established.


The separate `offline-whole-authored-short-t3-ownership-2g-v1` choice retains
all BROAD/ShortOnly limits, seeds, carrier exclusions, permits, search rows and
one-candidate/4096-byte allocation rows. It changes only the policy header to
`LI2DISASM-POLICY 3` and inserts `neighbor-ownership inherited-t3` immediately
after `neighbor-victims short-only`. Select it explicitly with
`--placement-profile offline-whole-authored-short-t3-ownership-2g-v1` after the
same current-source release capture. There is one importer invocation per ready
program, using the leading `--short-neighbors-owned` option.

The importer profile must be
`elf-disassembly-null-jumps-short-t3-ownership-v1`, with both
`neighbor_victims\tshort-only` and `neighbor_ownership\tinherited-t3` rows and
matching stdout. The complete 187-head/42-jump population, indexed files,
configuration, custody, release and refusal checks remain mandatory. An old
profile's directory cannot satisfy this mode. Existing profiles and their results
are not relabeled or retried.

Only short T3 complete-pair admission consults inherited composition ownership.
Generalized pun, ordinary relocation, prefixed pun and successor eviction can
still return a locally valid plan that fails the final append; no T3 retry follows.
Final caller append, hook/entry/aggregate/carrier checks and whole-program refusal
remain. The projection retains both mode rows and has no legacy comparator/E9
replay adapter. This profile adds no native, loader, performance or qualification
claim and does not promise that a whole-program candidate exists.
