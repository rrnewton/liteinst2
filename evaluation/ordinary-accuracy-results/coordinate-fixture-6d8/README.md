# Coordinate fixture controls at 6d8

All **16 unchanged test IDs passed once** at `6d8e99c21e97d5e5ca8bcf2ad10b7b6926dde2dd`: no failures, errors or skips. The test-only change retains all 94 old assertions and adds three checks. Only two synthetic joined-payload paths use capped in-memory bytes; other reads and production joined-file I/O remain unchanged. Full canonical JSON, all 2,048 calls and the policy/hash/location mutants remain.

A separate diagnostic at 97ab measured **6,952,750 canonical bytes**. That probe is not another suite execution. The fixed control checks the complete parsed payload and population, and refuses an undersized read cap; it does not test filesystem identity for those memory-backed payloads.

The sole actual suite dispatch passed under unchanged **20 CPU seconds, 30 wall seconds, 1 MiB per-file limit (including logs), and 55-second outer deadline**. An earlier wrong private-log path was refused before child creation: zero dispatches. Both records remain. Closure was normal exit 0, complete cleanup, no rescues and unchanged sources. Elapsed times are bookkeeping, not performance.

Reproduce from the exact revision with a clean checkout. Use `receipt.json`'s exact request/argv/env templates: substitute `${ROOT}`, fresh `${RAW}` below its `ignored/`, `${USER_HOME}`, `${CARGO_HOME}` and `${TOOLCHAIN}` in JSON string values; create RAW/tmp and outer_parameters.log's parent, then write RAW/request.json. In a dedicated interpreter, invoke `evaluation/admission/processes.py:run_command` with the helper argv, request environment and recorded outer parameters. Its log must be below ROOT/target/evaluation. Preserve source hashes before/after; retain the outer closure before reading the helper receipt and all 16 verbose outcomes. Use the existing bounded helpers.

The [97ab campaign failure](../coordinate-97ab/README.md), unrun native cells and full 43,200-cell denominator remain unchanged. This targeted pass is neither campaign success nor native, geometry, phase, PMU, accuracy or performance qualification.
