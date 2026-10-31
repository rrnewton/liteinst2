# Complete-program LI2 follow-up after the empty-GNU-hash repair

At `cbb585d9e2f250f5365b34aa654e14bf5e87aa48`, the pinned E9Patch input reached per-site planning. **Both profiles still refused the complete program; neither emitted a candidate.**

| Span | All sites | Local plans withheld by atomic selection | Primary refusals | Exit | Wall seconds |
|---|---:|---:|---:|---:|---:|
| 16 MiB | 2,053 | 1,749 | 304 | 2 | 20.295794 |
| 2 GiB | 2,053 | 2,011 | 42 | 2 | 17.732360 |

The 16 MiB primary reasons are 160 `NoPatchWindow`, 14 `AllocationUnavailable`, 129 `ExpectedBytesChanged`, and one `OwnershipConflict`. The 2 GiB counts are 21, 5, 9, and 6 respectively, plus one expanded-address-operand `UnmodelledEncoding` requiring an explicit PIC bridge. These retained reasons are not exhaustive search coverage or established root causes. Atomic-withheld rows are not successful whole-program patches.

Materials retain 13,143 heads, all 2,053 jumps and the same 14,997-message / 1,544,550-byte request. E9 was **NOT_REQUESTED, zero attempts**. Outer exit 0 records completed collection of refusal outcomes. The [earlier tag-6/backend failures](../full-program-whole-result-v1/) remain failed; default1,024-site and small-fixture bounds remain unchanged.

Formatting, strict rewrite Clippy and 172 library tests passed, including four new empty-GNU-hash controls. [receipt.json](receipt.json) records commands, environment overrides, hashes, CPUs/load, limits and timings. All dispatched owners closed normally with complete cleanup and zero rescues. No full-gate, native, performance or A5 qualification is granted. Complete-code and RX-gap premises remain caller supplied.

Retain the receipt outside the checkout and use its exact revision. Follow the [prior input/policy recipe](../full-program-whole-result-v1/README.md), including the legacy inventory and target text. Build both release examples using the recorded argv/profile; retain the successful bounded build receipt and fresh binary/receipt pins. Invoke tracked [run_full_program_attempt.py](../offline-corpus/run_full_program_attempt.py) with **--li2-only**, one disjoint HARD CPU, and recorded outer900-second wall/CPU,4GiB address-space,512MiB file/8MiB log bounds. Its inner commands retain their own limits; it never retries or executes a candidate. Placeholder paths identify checkout, fresh output, pinned inputs/policies, retained build receipt and selected Rust/Cargo bins.
