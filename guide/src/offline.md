# Offline rewriting

Runtime patching races are avoidable entirely if you rewrite the
binary *before* it runs. LiteInst's offline path produces ELF
candidates, metadata, and sparse overlays through the same tactic
engine as the runtime patcher — so a site that is sound to patch live
is planned identically offline — while recording outstanding runtime
requirements separately from structural success.

## The pieces

* **`emission` (in `liteinst`)** — explicit target descriptions and
  symbolic same-module hooks for offline plans. Plans use bound
  virtual addresses; ELF load-bias fixups are later work, and the
  module says so.
* **`liteinst-artifact`** — content identity and format, with no
  execution authority. A valid digest proves byte identity; a
  `Rewritten` metadata outcome records the producer's structural
  decision. It does not admit hooks, entries, CPU state, or loader
  readiness, and unsurveyed original pages remain unknown. Successful
  decoding never publishes code.
* **`tools/elf-rewrite`** (`liteinst-rewrite`, not published) — the ELF
  frontend that drives emission over whole binaries and DSOs.
* **`offline-router` feature** — the opt-in startup authority that lets
  a rewritten image route its sites at load time. It is absent from
  default core builds on purpose: offline authority should be chosen,
  not ambient.

## What offline does and does not buy you

Offline rewriting trades startup work for the absence of runtime
patching races: the bytes on disk are already the instrumented bytes.
It does not solve code the binary generates later (JITs, self-modifying
code, `dlopen`ed text beyond the rewritten set), and it does not turn
LiteInst into a turnkey e9patch replacement — runtime requirements
(the router, trampoline placement, entry proofs) are recorded in the
artifact and must still be satisfied by the embedding client.

Choose offline when the code set is closed, startup cost is
acceptable, and you want the patching decision made once, auditable
as an artifact. Choose runtime patching or page gates when the code
set only exists inside a running process.

## End to end: one small ELF, prepared and inspected

The input below is the two-`PT_LOAD` synthetic ELF64 built by
`input()` in `tools/elf-rewrite/tests/integration.rs` (kind
`ET_EXEC`, base `0x400000`): one nine-byte function at `0x401100`
(`nop`×3-byte form, `mov eax, 42`, `ret`) and a one-byte hook at
`0x401800`. Its selection file — strict format in the tool's
`SELECTION.md`, every digest binding exact bytes — selects the
three-byte `nop` at `0x401100` for the B2 generalized pun and
declares every instruction head:

```text
LI2TOOL 1
original 85958c3519c0c683a81910d614279207033494fae1b7d5faa95802dbde9d32b7
target fxsave64
domain 1
carrier 4227072
limits 1048576 16 16 65536 64 1048576 262144 64 4294967296
hook 7 4200448 1 ae3f4619b0413d70d3004b9131c3752153074e45725be13b9a148978895e359e
site 1 4198656 3 4352 4198640 25 4198656 9 4198656 9 7 observe original-decode
entries 1 complete a6621a9a16da8c7127998787d942af018636c32d01a01f5dc55e7e3ecd4da497 4198656:0 4198659:0 4198664:0
resumes 1 none
search 1 B2 0 80 1 4198720 64 256
allocation 1 selected 720933125 256 8192 720932864:8192
allocation 1 victim 104861952 256 8192 104861696:8192
```

```console
$ cargo run --offline --locked -p liteinst-rewrite -- prepare tiny-complete.elf tiny-complete.selection.txt rewrite-out
candidate_complete=true qualification_complete=false sites=1
$ echo $?
0
$ ls rewrite-out
COMPLETE  bundle-index.tsv  candidate.elf  image-0000.bin  ledger.tsv
metadata.li2meta  plan-ledger.tsv  report.tsv  selection.txt
site-1.diagnostics.txt  source.li2sparse  target.tsv
$ cat rewrite-out/report.tsv
LI2REPORT	1
original_sha256	85958c3519c0c683a81910d614279207033494fae1b7d5faa95802dbde9d32b7
selection_sha256	57fa650de4f50b595af8d649c37c2667e116cd12a5098ec763ef8707fec7f3d4
candidate_complete	true
qualification_complete	false
site	pc	file_offset	length	core_tactic	candidate_emitted	refusal_code	stage	detail_hex
1	4198656	4352	3	B2	true	none	none
```

Read the directory in this order. `report.tsv` is the verdict layer:
exit 0 means a *complete structural candidate* — and its own
`qualification_complete=false` line refuses to say more.
`plan-ledger.tsv` is the audit layer: the same two SHA-256
identities, the `generalized-pun` step's consumed range, and the
rows that keep success honest even here —
`requirement 0 101 declared-entry-completeness-not-proven` (your
`entries … complete` line is a caller *assertion*, recorded, not
proved) and `unresolved loader-abi-cpu-unwind-cet`.
`bundle-index.tsv` hashes every emitted file and carries the
consumer instruction `RuntimeScan-while-gated-until-qualified`;
`COMPLETE`, written last, binds that index. `metadata.li2meta`
(header `LI2META`) and `source.li2sparse` (header `LI2SPRS`) are
binary by design: inspect them through `liteinst-artifact` decoders
(`Metadata::decode` under an explicit compatibility policy), not
with `cat`. The sparse overlay binds the original identity to exact
edit declarations; it grants no execution authority.

Now change one word — `entries 1 unknown …` in place of `complete`
— and prepare again into a fresh directory. Unknown entry coverage
refuses, and the refusal is a *report*, not a crash: exit 2, no
`candidate.elf` or generated images, and the site row names stage
and reason (`detail_hex` is hex-encoded UTF-8):

```text
$ cargo run --offline --locked -p liteinst-rewrite -- prepare tiny-unknown.elf tiny-unknown.selection.txt rewrite-out-refused
candidate_complete=false qualification_complete=false sites=1
$ echo $?
2
$ cat rewrite-out-refused/report.tsv
LI2REPORT	1
original_sha256	85958c3519c0c683a81910d614279207033494fae1b7d5faa95802dbde9d32b7
selection_sha256	59addfe6b8f1e934fdd9274d899c3c74ef788f901df424d695582f1aa1468dbd
candidate_complete	false
qualification_complete	false
site	pc	file_offset	length	core_tactic	candidate_emitted	refusal_code	stage	detail_hex
1	4198656	4352	3	none	false	7	core	556e7265736f6c766564456e747279
```

(`556e…` decodes to `UnresolvedEntry`.) No selected failure is ever
removed from the denominator.

What neither run gives you is a program to execute. The CLI
deliberately does not mark the candidate executable, run it, or
overwrite the input; activating a rewritten image under the
offline router is a separate, unsafe bootstrap-DSO-constructor
integration (`liteinst::offline_router`, one attempt per process,
catalog embedded in the DSO), not a flag on this tool. That honesty
is the boundary of this chapter's promise: offline, you get an
inspectable candidate and its evidence — running it is the
embedding client's admitted act.

> 🚧 **Under construction — running a rewritten candidate.** TODO:
> extend the walkthrough above through router activation (catalog
> compilation, bootstrap DSO, first routed execution) once a
> non-Hermit candidate can be qualified and run end-to-end in this
> repository. <!-- UC: offline-walkthrough -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`offline-walkthrough`).
