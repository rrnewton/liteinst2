# Runtime binding of offline page certificates

This is the runtime half of the shared admission design in li2core's
`A3-SHARED-ADMISSION.md`. It specifies a future integration; the current page
loader does not implement or claim these exemptions. The initial executable
scope is the existing single-threaded, cooperative Linux x86-64 runtime without
CET. Multithreaded mutation needs an execution-and-writer exclusion protocol
before that scope can expand.

The same core decoder, CFG reconstruction, patch planner and encoder must serve
both modes. The selected C group/loop planners and emitters are part of the
consolidation inventory too. Runtime-specific signal handling, actual mapping
queries and lifetime ownership stay in the runtime adapter; they do not supply a
second interpretation of an instruction or a second patch implementation. The
common analysis must remain callable from the freestanding runtime.

## What the loader can admit

A certificate is inert producer evidence. Build-id locates a candidate; it is
not authentication or execution authority. Only the runtime owner can bind a
certificate to an actual mapped dependency group and admit it.

Binding requires all of the following, while entry and mutation are excluded:

- Authenticated producer provenance and compatible policy, decoder, CFG,
  encoder, CPU-feature and ABI versions.
- Complete CFG and byte coverage with no gaps, including allowed alternate
  starts and indirect entries. This requirement applies to both clean pages
  and patched pages. A count of selected sites found or patched is insufficient.
- Original and final page hashes, authenticated boundary halos and every
  generated/source dependency. The final hash covers actual loaded bytes after
  load bias, relocations, fixups and hook/arena addresses have been bound.
- Real writer exclusion, including aliases and backing-file writers. A private
  RX mapping by itself does not establish immutable source bytes. Use sealed
  immutable backing or an equivalent enforced ownership protocol.
- Actual publication permissions, synchronization and a held lifetime for all
  generated targets and saved execution continuations.
- Fresh mapping incarnations and content generations. Address, inode, build-id
  or an earlier successful certificate lookup cannot authorize a replacement.

A CALL on an admitted page may push a return address on a next page which has
never executed. A return or restored continuation must authenticate that target
before entry. Record the potential saved return before admitting the caller,
and preserve, reroute, drain or explicitly refuse that exact continuation if its
target is later patched, even when the target has never executed or the caller
has since been replaced. The next page is not implicitly admitted by admitting the CALL;
conversely, rejecting every boundary CALL solely because that page has not run
would reject valid execution. Cross-page instruction bytes and dependency halos
still need their ordinary complete fetch proof.

Bind before constructors, TLS initializers or IFUNC resolvers enter the object.
Resolver code must itself be admitted or gated before it runs; dependent final
bindings may be established afterward. Dlopen performs the same protocol for a
new mapping, even if another instance of the object was certified previously.
Unscanned gaps, JIT output and unmatched objects use the ordinary runtime gate.

Publish a successfully bound group in the maintained address-space view and
exclude its pages from the admission fault gate from the start. Unchanged
certified execution incurs zero admission faults, scans, CFG rebuilds, replans,
per-entry certificate lookups and admission maps refreshes. Startup hashing and
binding, ordinary OS demand paging and instrumentation hooks are measured
separately; none is claimed free. A semantic trap backstop is not automatically
eligible for the zero-admission-overhead exemption: its traps must be named,
counted and approved separately by the core owner and project owner.

## Retirement precedes mutation

| Event | Required runtime transition |
| --- | --- |
| Write permission, writable alias, direct code write or text relocation | Exclude entry and drain the affected dependency group; retire its admission and content generation before exposing a writer. Keep execution gated until authenticated readmission. |
| Mprotect or pkey protection changes | Retire before applying a relevant change. Any unchanged fast path needs an explicit permission/identity proof. Restoring execute does not restore an old certificate. |
| Mmap over a range, munmap, mremap, exec or loader replacement | Retire all intersecting source/generated dependencies before replacement can execute. Assign a fresh mapping incarnation. Exec resets the namespace. |
| Brk or other layout changes | Update the maintained view and invalidate every affected mapping/dependency. Disjoint data-only changes do not invalidate unrelated immutable page content. |
| Failed or partially applied mapping operation | Keep affected authority retired. Reconcile actual mappings before any reopening; a failed syscall is not proof that every page stayed unchanged. |
| Hash, policy, CPU, dependency or incarnation mismatch | Keep the group gated and invoke ordinary admission or refuse. Never execute first and repair metadata afterward. |
| Trampoline, hook, router or source lifetime ends | Remove incoming authority and drain active and saved continuations before storage is reused. |

A maps refresh cannot detect and undo an already executed write. Unknown external
writers or an unmediated alias make a page ineligible. This includes proc-memory
and tracing authorities unless the runtime excludes them within its stated
threat model. The mapping view is updated at intercepted mutations; an unexplained
fault triggers a fresh reconciliation and never silently grants an exemption.

## Acceptance evidence

The first paired experiment must use identical programs and policies with the
cache disabled/enabled, compare application output and state, and retain the
same selected-site coverage and patch plans. Enabled certified pages must show
exactly zero admission faults/scans/replans from their first entry; newly loaded
or changed pages must still enter the gate. Measure startup binding separately
from first-touch and steady execution in release builds.

Required negative cases include a same-build-id hash change, post-relocation
mismatch, wrong policy/CPU/ABI, an unscanned gap, boundary/overlapping decode,
indirect entry, the boundary CALL/return case, stale address reuse, writable
aliases, partial protection failure and retirement of a generated dependency.
Each must either use the unchanged runtime fallback or refuse while gated. The
existing publication, state, lifetime and qualification checks remain required.
