# Compiled DSO fixture and structural inspection

These annotated GNU C sources have passed a fixed build and structural
inspection for the separate indexed-artifact route. Native DSO execution and
unwinding remain unqualified. These sources expose no registration
API and make no registration call; the driver must also inspect linked CRT code.

`li2_uw_work(input, length, seed, output)` performs actual compiled scalar work:
start with `seed`, replace the accumulator with `(accumulator * 33) ^ input[i]`
for every byte, store `accumulator ^ length`, and return the accumulator.
Unsigned arithmetic is modulo 2^64. The driver fixes both complete inputs and
independent expected results before execution and supplies valid, separately
owned input/output storage. The only authored instructions are one NOP5 and its
six explicit CFI SameValue annotations. Work is not naked, assembly-only or a
wrapper around another implementation. It has no source-level calls.

The producer must authenticate the actual whole function/CFG and prove that no
prefix instruction changes RSP, RBX/RBP/R12–R15 or caller-recovery memory before
`li2_uw_selected`. Prove selected+5 equals `li2_uw_continuation`, both are actual
heads, and both original rows have CFA=entry RSP+8, RA at CFA-8 and six explicit
SameValue rules. A compiler prologue, missing rule, unsupported row or relocated
owner is a refusal, not permission to move the anchor or repair its CFI.

Minimum fixed build requirements for the later driver: GNU C11 (`-std=gnu11`),
`-fPIC`, shared linking (`-shared`),
`-O2 -fomit-frame-pointer -fno-lto -fno-optimize-sibling-calls
-fcf-protection=none -fno-stack-protector -fvisibility=hidden
-fasynchronous-unwind-tables`; preserve symbol/CFI records and link with GNU
`--eh-frame-hdr`, `-z now`, `-z noexecstack` and the pinned shared libgcc consumer.
Do not use `-nostdlib`, a naked function, stripped CFI, profiling/sanitizer hooks,
LTO, IFUNC, user constructors or TLS callbacks. Authenticate the complete actual
link/initialization graph, including CRT paths. The exact tools, flags, objects
are recorded by the build. Actual loaded dependencies still require runtime
admission; no flag proves the compiled result. Both reference and collector
are ordinary compiled C.

The caller uses `RTLD_NOW|RTLD_LOCAL`, retains immutable file/map/CFI owners and
handles to process exit, and forbids interposition/preload/audit and reentry.
Run the explicitly counted `li2_uw_reference` walk before the first selected
call, after consumer/loader/CPU/XCR0/CET/stack admission. Reference never invokes
work and returns its argument XOR `0x5245464552454e43`. Eager binding alone does
not establish unwinder first-use readiness. An original work call has no hook;
it supplies output/ABI evidence only. No runtime baseline is claimed here.

`li2_uw_configure` accepts one frozen HookContext layout, at most two records and
a protected caller-memory interval containing the actual return slot. The
driver independently proves mappings/permissions and all storage disjointness;
numeric ranges do not prove that a pointer is mapped. Records must be outside
the entire caller stack, code and input configuration, and separately owned
from input/output, CFI and all other source dependencies. The caller return slot
must equal the original entry RSP for the NOP5 profile. The collector checks the
actual saved PC/RSP and return word, records bounded raw frames, and snapshots
all 176 context bytes and the declared caller bytes before/after the walk. It
never writes either source region. No restoration can hide a changed byte.
Raw xstate descriptors are retained; the driver must compare them to the exact
emitted layout. This collector does not dereference the xstate address.

Capture failures are sticky across configurations. After every complete call,
retain `li2_uw_capture_end()`'s status and all raw records before configuring the
next fixed input. Require the exact expected capture count, no flags/overflow,
normal-return evidence, exact caller/generated frame order, IP conventions,
recovered values and CFA; raw `_Unwind_Backtrace` codes are not reclassified by
this fixture. The driver supplies and validates actual C caller observations,
not the old assembly witness's stack constants. No concurrency, asynchronous
handler, stack switch, cancellation or unload is admitted.

The five consumer function addresses must join one authenticated loaded libgcc
binary and its source/build provenance. In separate fresh processes require all
original FDE lookups and exact generated FDE lookup addresses for the intact
index, plus a declared original-index-only negative with missing generated
lookups. A previous positive artifact must not populate that negative process.
Keep all original command/cleanup/32-frame bounds and both full inputs; every
failure and unexecuted case remains visible. Exceptions, LSDA, asynchronous
unwinding, general compiler-CFI support and A3 completion remain unqualified.

`build_fixture.py` is the explicit build entrypoint. It accepts a fresh output
directory under `ignored/`, an exact toolchain inventory and a bound source
review record; its module documentation gives the JSON schemas. It uses the
existing bounded command owner for eight tool probes, three C compilations and
two shared links. Every command has the unchanged 60 CPU second / 90 wall second
limit and 128 MiB file bound. Both links retain CRT inputs and use
`--hash-style=both`, so the hidden caller's complete dynamic symbol table has
an authoritative SysV count even when its GNU hash has no exported definitions.
Both links also use `-Wl,-e,0`; the build checks the resulting zero ELF entry
address required by the unchanged ET_DYN inspector.
The final build record retains exact commands, dependencies, input/output
hashes, link maps and every first outcome. A successful build is explicitly
`BUILD_ONLY_REVIEW_REQUIRED`; it does not run either DSO.

The separate Rust example inspects those two original artifacts:

```text
cargo run --locked -p liteinst-rewrite --example indexed_dso_inspect -- SUBJECT SUBJECT_SHA256 CALLER CALLER_SHA256
```

Run it through the campaign's bounded owner after build closure. It checks
whole input hashes, ELF ownership, actual work CFG/exact source CFI rows and
both ordinary caller CFGs. Its output uses ELF coordinates and retains both
complete original FDE counts. Full caller CFI semantics and native admission
remain false. The private `observations.rs` comparator supplies the two fixed
inputs and compares exact raw lifecycle/result/state records; its expected
frames must come independently from the admitted compiled code and CFI. The
separate five-symbol consumer entrypoint preserves the old six-symbol
registration oracle's checks and makes no registration query of its own.
All these new build, inspection and native paths remain **UNRUN**.
