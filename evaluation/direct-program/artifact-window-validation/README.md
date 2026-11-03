# Shared artifact-window emission

Revision `172a7a9bc3fd361c91a5c94cd25e44af3ccdf1dd` adds a shape-checked ordered observation window using the same preparation, fitting, encoder and linker as existing trampoline emission. It emits artifact bytes and maps; source patch planning, member completeness, loader admission, writable callback scratch and runtime publication remain separate obligations.

Validation passed on an AMD EPYC Zen 5 dev host with twelve reserved CPUs, twelve Cargo jobs and twelve harness threads (serial launch uses one). Workspace: **4,640 top-level + 11 nested passes, zero failures, 43 unchanged ignores**. Serial launch: **1,039 passed, zero failures or ignores**. All previous test rows remain, including the allocation/identity concurrency regressions. Nine new controls check window shape, exact ordered fields and maps, internal branch entry routing, error precedence and unsupported live-action refusal. Strict Clippy, formatting and workspace check also passed. The separate focused run passed all nine controls.

[receipt.json](receipt.json) records the exact source/tree, commands, limits, CPU reservation, load and counts. Reproduce from a clean checkout of the exact revision above, using [../validate_artifact_window.py](../validate_artifact_window.py) and an unused output directory. Set `CPUSET_ALLOC` to the allocator executable and `TOOLCHAIN` to the recorded stable toolchain directory. The Rust version was queried separately after campaign closure. Raw logs remain private. Recorded command durations describe validation cost; they are not performance measurements.

This receipt covers the shared emitter and prior controls. It does not establish grouped planning, native multi-observer transparency, complete-program coverage or runtime page exemption. Historical corpus failures remain failures.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
