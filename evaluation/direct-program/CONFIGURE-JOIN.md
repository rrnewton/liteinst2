# Configure child join protocol

The original cat build remains FAILED: configure's leader exited 0, but its owner recorded `descendants_after_exit`, two reaped descendants and complete cleanup; make was UNOBSERVED. The two original child exit statuses were not retained. This does not prove that both were zombies. The exact original authority is `cat-build-v1/closed.json`, 22,533 bytes, SHA256 `100d807e4d74750acd61d71ef4138559ebc1f46d8dea0dc14f3b6cc2e716d4f2`.

`configure_join.py` is a dedicated synchronous child join. It requires one thread, default SIGCHLD handling and initial ECHILD, sets Linux child-subreaper mode, starts exactly one configure process, then uses blocking `waitpid(-1, __WALL)` until ECHILD. It records the leader's and every adopted child's raw wait status and decoded exit code. It succeeds only if every exit code is zero. It has no kill, deadline, polling loop, child-discovery scan or recovery policy. A live orphan keeps the adapter blocked so the existing external owner must time out and reject it.

The tracked `build_cat.py` uses the reviewed adapter. Only configure is wrapped. Its original flags, working directory, environment, 180 CPU/300 wall seconds, 2 GiB AS, 64 MiB file cap and 1 MiB owner log cap remain literal. Metadata/extract/make, source inventory, 250 MB admission/postcheck, full-slot ceilings and the outer zero-rescue gate are unchanged. The parent pins the adapter and authenticates its durable join receipt only after the outer owner is durably closed and cleanup is complete. Nonzero joined children remain a failed build with make unobserved. There is no retry of the unchanged first attempt.

`configure_join_controls.py` runs exactly three tiny executions under the same existing process owner. Each has 3 CPU/5 wall seconds, 256 MiB AS, 64 KiB file/log limits, one reserved CPU and no automatic retry:

- A leader leaves one adopted child that exits 0: adapter and outer owner succeed, both child statuses retained, zero rescues.
- The child exits 7: adapter exits 1 and records FAILED; outer cleanup remains complete with zero rescues.
- The orphan announces itself then blocks: the outer owner must time out, SIGKILL the adapter, reap exactly one descendant and finish cleanup; no terminal join receipt exists.

The fixture's pipe EOF makes child continuation depend on the leader's exit; it uses no scheduler polling. Both negative cases must be rejected by the original fixed rules. All three control owners must be saved before any logs or join receipts are read. Incomplete cleanup stops the driver immediately. Each dispatch follows review and uses a distinct namespace. The three controls and corrected build passed; exact observations and the subsequent failed rewrite comparison are recorded in [README.md](README.md).
