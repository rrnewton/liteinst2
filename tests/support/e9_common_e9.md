# Controlled E9 null replay

This additive adapter implements controlled original-versus-actual-E9-image
comparisons. Current common-corpus E9 products and native admission remain
pending. The adapter alone does not establish normal
kernel-loader behavior, an ordinary rewritten run, recording-hook behavior,
performance, or complete A3 qualification. Those producer and runtime
requirements remain separate and mandatory.

## Authority and fixed input grammar

The existing standalone driver gains one additive mode:

```
DRIVER replay-common-e9 ORIGINAL INSTRUCTIONS TARGET WITNESS_JSON NATIVE_TSV NEW_CAPTURES
```

The enclosing caller must authenticate the exact reviewed driver build and
the actual reviewed `e9-null-witness.py` execution, its complete result and
parent closure, canonical JSON, `native.tsv`, `sites.tsv`, and `files.json`.
It must authenticate every one of the 23 complete named input files in the
witness, including the actual producer transport/lane records, original,
candidate, selection, policy, target and full instruction table. Stock and
bootstrap-patched reference lanes remain separately identified in that JSON.
No reader run or input owner can be fabricated by this adapter. No actual
request or whole-artifact launch authority is supplied by this proposal.

The native code consumes only `LI2COMMONE9NATIVE` version 1, a fixed ordered TSV
projection of the complete canonical JSON. It rejects unresolved status, lost,
extra or reordered rows, duplicates, incomplete heads/cases, changed operation
bytes, mismatched owners, and unconsumed tails. It opens canonical absolute
paths through held no-follow regular descriptors; the exact six-field owners
from the reader are joined to the native descriptor/path observations. All
whole files are re-read after every completed pair. Empty producer streams are
retained rather than discarded. The JSON itself is retained and rechecked as
an input; it is not interpreted by a new general JSON parser.

The native code has no SHA implementation. Its digest-string checks are syntax
checks, not authentication. The caller must bind the actual JSON/TSV hash join
and all file digests, lengths and owners to the reviewed reader's actual
execution before launching this mode. Holding a syntactically valid TSV or a
copied JSON is not sufficient authority. Native independently reconstructs and
checks the page bytes, routes, instruction encodings and seeded outcomes below.

## Complete image and physical completion

The controlled reference reuses `e9_common_image` literally: the complete
87-head table and three original byte ranges, all 174 normal and two read-only
store-fault seeds, guarded array/stack, one original hardware instruction per
fresh reference child, exact six original CALL return words, original fault
tuple, full target and canonical XSAVE requirements. No original case or
reference implementation changes. Source inverse removes only the new module
declaration and first driver dispatch arm; every old mode stays literal.

Candidate reconstruction applies actual PT_LOAD rows in program-header order,
then the structurally authenticated loader trampoline/refactoring mappings in
their exact original order. Each resulting page is bound to its final owner,
file offset, copied prefix, BSS zero boundary, permissions and full candidate
bytes. Every original page remains present with its original permissions. New
pages are immutable readable or executable, never RWX, and cannot overlap the
array, stack or guards. All pages use nonclobbering anonymous reservations; a
collision fails without a fixed-address replacement fallback. This is an
explicit controlled page view, not execution of E9's loader or dynamic linker.
No mapping-order or completion fact is inferred from a successful state match.

Each head starts at its exact original PC. The only prefix instructions accepted
are the pinned stateless EB/E9 gateways with the exact permitted prefix bytes.
Their source bytes, signed destinations and every physical step are checked.
The restored boundary must equal the full original-before state and **all**
64 KiB of owned stack. E9 null gateways have no scratch-write allowance.

Operation encodings are reconstructed from the independent original bytes and
the finite pinned relocation rules: original bytes at an unchanged head,
literal relocated non-relative operations, short conditional/ordinary branch
promotion to its exact original target, and a relocated CALL as PUSH of the
original return word followed by JMP to the original callee. The actual
candidate bytes must match before a child runs. The complete seed table fixes
branch decisions and fault outcomes before execution; no expected value is
learned from candidate runtime behavior.

For a two-instruction CALL, the intermediate PUSH state is fully checked and
captured. RSP must decrease by eight, the full stack differs only by the exact
original return word, every other register/flag/canonical XSAVE/data value is
unchanged, and raw RIP is exactly the declared JMP instruction. No registers
or memory are repaired after the initial seed. The final callee boundary again
checks the exact original return word. This intermediate check is reported
separately from the three original-versus-candidate comparisons per pair.

Every completion first checks raw physical RIP against the predeclared witness.
Only then is the separate logical PC supplied to the unchanged full comparator.
No equal-state search or broad address-range substitution is used. A relocated
fallthrough stops immediately after that operation, before E9's `$continue`.
The continuation and any declared bypass edges are authenticated but not
executed as part of the current logical instruction. Faults check the exact
SIGSEGV/code/address, unchanged architectural state and all data/stack bytes.

## Captures and bounds

Every artifact requires 176 pairs / 352 sequential children and 528 full
cross-version comparisons (entry, restored, completion). The six CALL heads
have two seeds each; let `E` be the number of cases whose admitted operation is
the two-instruction expansion. The witness fixes `0 <= E <= 12` before native
execution. `E` additional intermediate full-state checks are reported
separately; they never replace any of the 528 comparisons.

The complete filename inventory is written before the first child. It contains
13 root files plus 49 per case, and nine additional files for each expanded CALL:
`8,637 + 9*E` files, or at most 8,745. There are `880 + E` full snapshots. Each
snapshot retains all 27 raw registers, canonical and raw XSAVE, the full array,
fixed application stack `[E_frame-128, stack_end)`, the entire 64 KiB owned
stack, all 37 original LOAD pages including globals/journal, and exact maps.
Every candidate snapshot additionally retains every generated/loader page.
Here `E_frame` is the fixed frame anchor; it is unrelated to the expansion count.

The root retains original/table/target copies, both witness files, original and
candidate page images, page/case plans, owner/input bindings and the complete
inventory. Whole producer/source input files stay in their separately admitted
immutable owners; their bindings are retained here, not silently substituted
with reconstructed or truncated copies. Each child records its complete
physical prefix/operation trace and exact completion/reaping outcome. Failures
retain partial captures and do not create the missing completion records.

The existing `Tracee` deadline of 15 seconds and 20,000 stops is unchanged.
Prefix count is at most 32 and operation count at most two; these are additional
finite byte-witness constraints, not larger native limits. No new supervisor,
threading policy, global request or relaxed deadline is introduced. All complete
cases must run under a separately admitted whole-artifact request; insufficient
time or storage holds/fails the artifact and never reduces the case set.

The witness/native view permits at most 2,048 total pages, including the 37
original pages: generated union bytes `G <= 2,011*4,096 = 8,237,056`. The page
span is not an allocation. With canonical XSAVE bytes `C`, actual raw regset
length `R`, and exact maps lengths `M_i`, snapshot content is
`(880+E)*(254288+C+R) + sum(M_i) + (529+E)*G + Q`, where `Q` contains all root
and non-snapshot records except the generated portion of the root page copy.
No raw regset or maps suffix may be dropped to meet storage. A fresh actual
artifact/target/storage admission is still required; this formula is not a
measured RSS bound, allocated-byte proof, or execution permission.

Planned negative controls remain unexecuted. No source review, parser check,
original-only reference, or old core result is an E9 paired result.
