# Retained source history

The dynamic owner keeps an independent immutable source census for auditing
past plans, guards and continuation routes. This is a prerequisite for mapping
replacement and exec admission. It does not implement either native transition
or satisfy the B3 lifecycle and real-application exit criterion.

The catalog reuses the snapshots and complete head facts previously retained
for resource bounds. An opaque, non-reused binding identifies that source set.
Every installed plan and retired admission generation retains the binding.
Historical plan bytes, policy, head geometry, guard decodes and route decodes
are checked against that independent census. A retained plan cannot authenticate
itself, and identical bytes at the same address in another owner do not identify
the same source set. Guard checks allow embedded candidate starts; continuation
checks still require declared instruction heads.

Current images, mapping descriptors, complete page inventory and epoch identities
are checked separately. Every native release still authenticates actual held
tasks, registers, frames, bytes and page permissions. Same-source revocation and
rebind retain their original native checks. There is no catalog append or live
source replacement operation, no writer or alias capability, and no authority to
retire a CALL or saved continuation.

The catalog retains the complete original executable mapping descriptors,
including mappings with no source census whose pages must remain NX. It stores
ranges rather than a second per-page inventory. The additional descriptor and
string payload is reserved from the existing lifetime budget at the owned
initial EXEC stop. Bootstrap compares the actual EXIT mapping census before its
first application-code write. Plan and generation metadata remain charged by
their full sizes; history is never refunded.

## Reproduction and evidence

Use the unchanged six-command recorder on a clean committed source revision:

```sh
python3 evaluation/admission/run.py --expect-revision SOURCE_REVISION
```

The resulting typed JSON records the exact revision, source manifest, commands,
hardware, toolchain, test outcomes and cleanup. Private raw captures are not
published. A result report links the exact receipt after the complete protocol
passes; this design document alone reports no successful run.

Additive pure controls target foreign source bindings, retained-plan corruption,
historical/live-source independence, epoch discontinuity, changed route bytes,
mapping/page census mismatches and resource accounting. They confer no native
publication authority. All existing native instruction, signal, lifecycle,
publication and cleanup fixtures remain required with their original assertions,
deadlines and limits.

This foundation supports the validation of claims 1, 2 and 4 within existing
finite admission profiles. It supplies no new performance or preemption-clock
claim. Full B3 still requires actual mapping changes, admitted fork/exec,
dynamic loading, JIT invalidation, general continuation handling and real
applications. B4 still requires verified persisted metadata and sparse-overlay
consumption, fallback and semantic agreement through the same native gate.
