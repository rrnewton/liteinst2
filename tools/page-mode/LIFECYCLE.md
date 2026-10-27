# Executable mapping admission

Setting `LI2_LIFECYCLE_FD` to an inherited sealed DSO descriptor enables actual
`dlopen`/`dlclose` and private anonymous RW→RX JIT mappings. The runtime retains
its own descriptor, verifies all four write/grow/shrink/seal seals, and associates
the backing with an actual private PROT_NONE mapping. It reads the sealed ELF
program headers; loader MAP_FIXED replacements must match their exact virtual
address, file offset, length and protection within the original owned allocation.
The default mode retains its previous executable-mapping refusals.

Run the optimized native/reference and refusal controls from a committed tree:

```sh
python3 evaluation/inprocess/lifecycle.py
```

This builds with `-O2`, pins fresh children to one allowed CPU, seals the compiled
DSO, and checks exact output from the real loader and JIT. One compact JSON
receipt records revision, source identity, hardware, commands, binary/capture
hashes and numeric observations. Raw captures remain under `target/`. The old
`evaluation/inprocess/dynamic.py` measurements remain a separate default-mode
regression; lifecycle validation durations are not steady-state benchmarks.

Accepted mmap/mprotect/munmap requests retain their original kernel arguments
and results, including PROT_EXEC permission checks and negative errno. New
executable pages are pending and NX before control returns to the application.
The actual fetch fault checks the current mapping generation and permissions,
opens the page, performs registered private expedited sync-core, then records
admission. RW changes and unmaps retire old generations; address reuse gets a
new allocation identity. Original code bytes and CALL return words are untouched.

A failed mprotect can change part of its range. Under singleton and signal
exclusion, the handler temporarily materializes pending pages to their retained
logical protections, invokes the original request, and reads actual post-state
even on error. It checks aliases again after partial effects, retires/recreates
generations and revokes execution before returning the original errno. Fatal
post-effect failures attempt PROT_NONE on every affected page and terminate;
they never return invented success. These trusted-handler RX windows establish
no application execution before admission, not literal NX at every instant
from mapping creation or a source-patch publication proof.

The fixture exercises two real dlopen/call/dlclose cycles, steady calls without
new admissions, partial sealed-VMA protection changes, JIT results 17→29→41
across rewrites/address reuse, cross-page fetch and boundary CALL/RET, and two
genuine partial-ENOMEM cases. Twelve separate processes require exact refusals:
W+X, shared execution, unsealed backing, writable alias, protected mutation,
unknown executable range, thread creation, stale RW execution, lifetime-table
exhaustion, injected post-mprotect failure, an alias left by partial failure,
and heap shrink across a JIT mapping inserted into an unmapped heap hole.
`LI2_LIFECYCLE_FAIL_AFTER_MPROTECT=1` is an explicit preactivation failure-test
control, never a successful workload mode.

The brk guard queries the actual current break and rejects a page-rounded shrink
that intersects a live owned mapping before invoking the original shrink.
Queries, growth and nonintersecting shrink retain the original syscall result.

Metadata has fixed bounds: 8,192 lifetime page records, 2,048 maps rows and a
256 KiB complete maps capture. Exhaustion refuses; records are not recycled.
Runtime, gateway, alternate stack and constructor-era executable mappings stay
protected. New file execution requires the retained sealed object; writable
same-offset aliases and shared execution refuse. The first DSO profile excludes
PT_TLS, PT_INTERP, anonymous BSS replacement and overlapping load pages.

This remains the post-constructor, singleton, kernel-trap backend with
`source_patches=0`. Ordinary externally writable DSOs, original loader startup,
thread/process lifecycle, Python signal setup and general signal/restorer
semantics remain open. Cooperative code must not overwrite runtime storage,
bypass the private gateway or use unsupported memory/control mutations. This
does not establish an adversarial sandbox or complete B3 coverage.
