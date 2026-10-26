# Compiled heap-sort common-corpus fixture

This fixture defines a finite normal-loader application. The C kernel contains three complete functions and all its array writes go through `li2_array_store(base,index,value)`. The selected sites come from the complete compiled disassembly; no successful tactic is preselected. Compile, freeze that disassembly and reject any unaccounted writer or instruction before preparing selections. The [preparation recipe](PREPARATION.md) builds and checks the originals.

The input uses eight fixed unsigned-64 datasets: empty, singleton, reversed pair, 17 equal values, 17 sorted values, 17 reversed values, 17 duplicates and 64 mixed values. `datasets.json` and `expected/*.stdout` retain every input and sorted output. Expected values are an independent integer-sorting projection of the literal input; the instrumented algorithm is heap sort. No checksum or aggregate replaces element equality.

The process is dynamically linked non-PIE ET_EXEC. It allocates three anonymous pages using `mmap`, leaves the outside pages PROT_NONE and makes only the middle page RW. The array starts 64 bytes into that page. Every byte outside the array remains 0xa5, and the complete sorted array is checked. The kernel neither allocates nor calls libc. Ordinary interpreter/libc loading, output and mapping calls occur outside the selected kernel; this is not a freestanding/manual-mapping fixture. All runs are single-threaded.

## Prospective build and run

Use a freshly authenticated GNU C compiler. The last closed host observation was GCC 11.5.0; it is provenance, not current admission. The source uses GNU `noipa`, `noinline`, `used` and section attributes. `noipa` prevents interprocedural cloning/specialization that could evade the function inventory. The intended profile is:

```text
GCC -std=c11 -O2 -fomit-frame-pointer -fno-optimize-sibling-calls \
  -fno-pie -no-pie -fno-lto -fno-toplevel-reorder \
  -fno-reorder-blocks-and-partition -fno-stack-protector -fcf-protection=none \
  -Wall -Wextra -Werror -MD -MF NEW_DEPFILE -Wl,-Map,NEW_LINK_MAP \
  SOURCE/heap_sort.c -o NEW_ORIGINAL
STRIP --strip-all -o NEW_STRIPPED NEW_ORIGINAL
ORIGINAL_OR_REWRITTEN DATASET_NAME NEW_JOURNAL_FILE
```

The original receives ordinary compiler unwind sections: no flag removes them and no rewritten-unwind pass is claimed. `-fomit-frame-pointer` makes the proposed stack-owner policy explicit; the adapter still must inspect actual instructions. Root owns the existing bounded helper, complete source/tool/command identities and fresh output owners. No shell script or alternate executor is supplied here. Run every dataset separately with an exclusive journal output. Successful stdout is exactly its `expected/*.stdout`, stderr is empty and status is zero. A leftover output file is an error; no overwrite or retry is implemented.

The three input-section functions (`.text.li2_sort`) must reside in output `.text`. Freeze actual symbols, sizes, bytes and the enclosing range from the compiled ELF/link map. No numerical PC is guessed by this source. The adapter must show that the enclosing range contains only these functions and decoded alignment padding, with every legal instruction head represented. The selected jump policy includes every conditional/unconditional jump in the three functions; CALL and RET remain instruction/entry owners but are a separate category. Heap-write scope is all sorting-kernel array stores, not array initialization or arbitrary libc writes elsewhere in the executable.

The sole accepted heap-writer machine form is `MOV qword [RDI+RSI*8],RDX; RET` in `li2_array_store`, with no displacement or segment override. The other two functions may contain only admitted RSP-relative stack writes (no indexed address), including CALL pushes. This expected compiler form is a required actual check, not an assertion that compilation already produced it. Any additional writer, clone, indirect call or hidden helper must remain an explicit unsupported result. Do not delete its site or change the expected writer after a failed run.

At every baseline call to `li2_array_store`, independently observe that RDI equals the actual array base, RSI is below the original length and the effective write lies wholly inside that array. `li2_run` publishes the mapping bounds, array bounds, dataset and phase. `li2_before_sort`/`li2_after_sort` are ordinary noipa call boundaries, with no trap, SETREGS, mapper or supervisor. A future native observer must bind its actual invocation/stop path separately. Dynamic array addresses are not normalized into a whole-state-equivalence claim.

## Null and recording instrumentation

`li2_null_hook` is the core's same-module no-op callback. `li2_record_hook` reads only the existing HookContext's first u64, `instruction_pointer`, and appends it to `li2_journal`; it never modifies the context. Both actual function bytes and RX owners must be authenticated. The selected sorting region excludes these callbacks and the runtime, preventing recursive instrumentation.

For the pinned E9 frontend, primary null mode uses `passthru`. Real mode uses `call[clean,before]li2_e9_record(instrAddr)@HOOK_ELF`. Build the separate `e9_hook.c` using the pinned compatible hook profile (`e9compile.sh`'s actual compiler/link argv, recorded explicitly by root). `LI2_JOURNAL_ADDRESS` is mandatory and must be derived from the authenticated original ET_EXEC symbol; it is never a guessed address. The optional `li2_e9_null` entrypoint is available for an explicitly separate null-call ABI check, not substituted for passthru. The two recording wrappers use the same authored journal contract but have different entry ABIs. No E9 implementation or GPL code was copied into these sources.

The journal is exactly 131144 bytes: eight u64 header fields, 16384 PC slots and one trailing guard. All callbacks use bounded volatile accesses, publish the count last and make overflow/fault sticky. They perform no library call, syscall or allocation. Active is one only between the two sorting boundaries; the app disables it before validation. Every unused slot must remain zero. The app retains the entire fixed journal even when an invariant later causes exit 68. A journal file's existence is never a pass.

For every original/null cell, independently require zero recorded PCs. For a real-hook cell, require the complete ordered PC sequence from the original finite baseline and exact header/guards; empty or singleton heap-write cases legitimately have zero visits. Capacity is fixed before execution and never silently increased. The actual baseline sequence must fit it; overflow is a failed run. Full journal/raw address observations stay private. Application output, hook effects and selected-site retention are separate checks, and none substitutes for architectural state, unwind, CET, PIE/DSO or complete A3 qualification.

The [contract](contract.json) states exact field offsets and bounds. All old fixtures, comparator calibrations, limits and failed histories remain unchanged. Source declarations grant no execution or qualification credit; those require separately recorded results.
