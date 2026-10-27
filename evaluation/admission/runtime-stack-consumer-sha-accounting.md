# SHA-256 temporary source-value accounting

The finite stack consumer uses the locked sha2 0.10.9, digest 0.10.7,
block-buffer 0.10.4 and cpufeatures 0.2.17 sources, identified by Cargo.lock
checksums. Its optional sha2 feature uses the ordinary dependency dispatch; no
force-soft, assembly or alternate backend is selected by the experiment. The
accounting adds both the software and x86 SHA-NI paths without assuming which
backend the host will select.

The implementation is `sha256_dependency_temporary_bytes` in the private
consumer's `protocol.rs`. Its checked twelve-family sum is added to the other
protocol temporary terms and included in Q before production execution. The
formulas below describe fixed source-level values and conservative allowances;
no compiler frame, RSS, physical-memory, performance or fit measurement is
claimed.

## Boundary and payload derivation

The accounting boundary is the monomorphized SHA256 new/update/finalize/digest source path through the pinned four dependencies, including their fixed byte conversions, iterator/control values and CPUID dispatch. It counts source-level argument/local/result families. Hardware intrinsics, scalar arithmetic and standard slice/iterator primitives are primitive boundaries; this is not an expansion of LLVM, libc, compiler spill slots or allocator internals. The bound deliberately sums sequential macro invocations and both mutually exclusive backends. Loops reuse their fixed scratch: it is not multiplied by input length, compression block count, number of protocol updates or digest calls. All referenced source input remains owned separately.

Let V=sizeof([u32;4]), U=sizeof(u32), H=sizeof(Sha256), O=sizeof([u8;32]), B=sizeof([u8;64]), X=sizeof(__m128i), C=sizeof(CpuidResult). The fixed payload derivation is:

| Family | Term | Source justification |
| --- | --- | --- |
| binary vector / load | 3V | two argument vectors and one result |
| shift; swap | 2V+U; 2V | argument/result plus shift amount |
| sigma0x4 | 27V+5U | argument, three locals, result, five shifts, two ors and two xors |
| msg1; msg2 | 36V+5U; 3V+10U | argument/result plus load/sigma/add, or ten scalar bindings |
| schedule | 53V+15U | four arguments, three locals, result and its msg1/load/add/msg2 calls |
| round_x2 | 4V+42U | three arguments/result, 26 scalar bindings and two eight-scalar tuples |
| rounds4 | 15V+84U | two vectors, add/swap and two round_x2 calls |
| complete software | 883V+1556U | seven block vectors, eight final scalars, sixteen rounds4, twelve schedule, and outer16+8 words |
| complete SHA-NI | 178X | eighteen body vectors, sixteen*(constant vector+three round vectors), twelve*(four schedule arguments+three locals+result) |
| common wrappers/output/pad | 4H+2O+B | by-value digest/finalize/finalize_fixed/finalize_into allowance, independent out/full_res, extra padding block |
| CPUID payload | 4C+4U | two retained results plus leaf result/argument copies |

The software/vector subtotals are 20,352 and 2,848 bytes respectively from their fixed element widths. H and every opaque standard-library header below are evaluated by `size_of` in the eventual target build; no Rust layout size was measured here.

## Additional explicit control/argument allowance

The following is a conservative slot census, not a minimal live-variable count. Each named group includes entry borrows, local aliases, passed/returned headers and both branch alternatives. A slot can be charged even when it is moved or optimized away. Thin-reference slots use `*const u8`; fat slices use `&[u8]`; these are sized pointees/byte slices, not trait objects. Fixed-array references, raw pointers and shared/mutable sized borrows have the corresponding thin form. Anonymous closures capture only one such reference; six additional thin slots count creation, forwarding and invocation of both update and padding closures.

| Header family | Explicit allowance | Assigned source families |
| --- | --- | --- |
| thin references/pointers | 64 pointers | 14 Digest/FixedOutput/CoreWrapper/CtVariable wrappers;18 BlockBuffer/Eager helpers and split pointers;10 compress256/dispatch/state borrows;8 software/SHA-NI loop/state/data aliases;8 conversion/output aliases;6 feature/cache borrows |
| fat slices | 48 slices | 10 wrapper input/output slices;20 digest_blocks/digest_pad/split/from_ref/suffix and branch slices;6 compress bridge/dispatch slices;4 backend block slices;4 conversion/output chunk slices;4 CPUID feature-tag string slices |
| captured closures | 6 thin references | update closure and finalize-padding closure, each captured/forwarded/called |
| lengths/indices | 96 usize | 12 wrapper/output sizes;24 buffer position/rem/n/leftover/split lengths and passed values;20 backend pointer/conversion/iterator indices;32 software+SHA-NI round ordinal slots (16 each);8 feature/census index/result slots |
| ranges | 24 Range<usize> | 8 wrapper/output alternative ranges;12 buffer split/pad/copy ranges;4 conversion chunk ranges; two-ended ranges conservatively cover one-ended ranges |
| length scalars | 8 u64 | core block-size/bit-length, padding data_len and their passed/returned conversions |
| bool controls | 48 bool | 16 buffer invariant/guard outcomes;8 backend loop/dispatch controls;16 four-feature reg_cap/bit-test/conjunction outcomes;8 initialization/result/option decisions |
| byte controls | 12 u8 | four pad/position slots, four dispatch cache load/store/cast slots, four fixed byte-input/control slots |
| CPUID bit operands | 16 u32 (in addition to4U above) | four selected features, each mask/shift/masked-value/copy slot; the actual selected sha/sse2/ssse3/sse4.1 tags do not require XGETBV |
| SHA-NI scalar arguments | 100 i32 +2 i64 | sixteen set_epi32 expansions*4=64; twenty shuffle immediates; fourteen align immediates; two blend immediates; two set_epi64x arguments |

The remaining control families use their actual complete public types, including any padding rather than manually summing fields:

- Four `slice::Iter<[u8;64]>` and four `Option<&[u8;64]>`: two backend loops, each iterator construction/loop ownership and item handoff. Two `IterMut<u8>` and two `Option<&mut u8>` cover padding iteration and handoff.
- Two complete input `Zip<IterMut<u32>, ChunksExact<u8>>` and two output `Zip<ChunksExactMut<u8>, Iter<u32>>`; additionally two of each of their four constituent iterator types. This retains a conservative construction-plus-loop allowance instead of assuming a Zip move makes component values disappear. Two complete input and output `Option<(reference,slice)>` item types cover next/item handoff.
- Two `Result<Sha256VarCore, InvalidOutputSize>` for core initialization/result consumption. Two `Result<[u8;4], TryFromSliceError>` for chunk conversion/result consumption. Four additional `[u8;4]` values cover input/output endian conversion argument/result copies; two `[u8;8]` cover suffix conversion/forwarding; two `[u8;32]` cover protocol by-value update input and returned digest conversion. These are additional to the original protocol digest/scalar terms and the two live finalization outputs.
- One complete `AtomicU8`, four `atomic::Ordering`, two `((),bool)` values for the feature cache, load/store order arguments and InitToken/bool result/consumption. Charging the cache here is conservative even when it was initialized previously. It is host dispatch metadata, never tracee eligibility evidence.
- The new calculator itself: `[usize;12]`, its complete `array::IntoIter<usize,12>`, two `Result<usize,OracleError>`, one `Option<usize>` and six scalar words. These cover array/iterator construction, fold/result handoffs, total/term and the additional caller-array slot. This fixed calculator is called before hashing and could be accounted with a maximum; summing it deliberately avoids that lifetime optimization. The existing caller's seven terms remain intact.

The scalar/vector payload and control terms overlap conservatively in places. None is subtracted because another family already owns a similar value. Both overflow errors are retained; no fallback value or saturated success is introduced. The helper has no allocation, dependency invocation, CPUID execution or runtime feature selection.

## Scope

The formulas include the source-level hashing path, while standard primitives,
compiler spills, allocator internals and machine stack frames remain outside
this managed source-evidence accounting boundary. A changed dependency, feature
or backend requires fresh source binding and review. Actual Q reservation,
settlement and consumer qualification are recorded separately by the experiment
drivers; this derivation is not an execution result.
