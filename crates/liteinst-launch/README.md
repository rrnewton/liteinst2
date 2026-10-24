# liteinst-launch

This Linux x86-64 crate captures an owned ELF process at the kernel's exec
event, before its first executable or interpreter instruction. It exposes
registers, bounded memory reads, and entry evidence derived from the kernel's
auxiliary vector, mapped ELF headers, and `/proc/<pid>/maps`.

`ExecCheckpoint::launch` takes an explicit executable path and argument list;
it never invokes a shell or searches `PATH`. The child inherits an environment
snapshot. A private pre-exec stop lets the parent install `PTRACE_O_EXITKILL`
before allowing `execve`. The returned checkpoint has no resume or memory-write
API. Dropping it sends `SIGKILL` and reaps its child. `terminate` also reports
cleanup errors. All waits address that child only. The caller must not reap or
trace this child independently; changing the process-wide `SIGCHLD` disposition
to ignore children or using an unrelated global child reaper is unsupported.

Launch waits have a caller-selected limit of at most 30 seconds. Each cleanup attempt waits
up to two seconds after `SIGKILL`; a failed explicit `terminate` followed by
Drop may spend four seconds total. If the kernel delays exit, a dedicated
reaper retains ownership until exit. No application instructions are released during
cleanup. `PTRACE_O_EXITKILL` also kills a stopped child if its tracer exits.

This is B1 launch groundwork. It does **not** remove execute permission, scan
pages, publish patches, provide a quiescence lease, synchronize instruction
streams, or admit application code. It does not satisfy the B1 page-gate exit
criterion. An initial exec stop alone is insufficient to publish into a running
multithreaded application.

The initial envelope is native x86-64 ELF executables, including PIE and ELF
executables with an ET_DYN interpreter. Script interpreters, other ELF machines,
and fixed-address ET_EXEC interpreters are refused. The interpreter must map
its ELF header at AT_BASE (the usual zero-based first PT_LOAD layout). The metadata is evidence of
the stopped process; it is not a persistent source-content certificate or proof
against external mutation. General registers are exposed; extended register
state is not yet captured. No core publisher is called.

The tests construct tiny ELF files directly. Their first instruction is CPUID,
including a custom PT_INTERP image, so successful checks do not depend on a C
compiler or an instruction having already run. Tests also check unchanged
registers/bytes, invalid inputs, memory bounds, and child reaping. They require
permission to trace a child; a ptrace denial is a failure, not a skipped pass.

Inspect a checkpoint without running the program:

```console
cargo run -p liteinst-launch --example checkpoint -- /bin/true
```

The example prints entry addresses and exec-checkpoint startup time, then kills
and reaps the child. Its timing includes inspection; it is not page first-touch
latency or the application's startup time.
