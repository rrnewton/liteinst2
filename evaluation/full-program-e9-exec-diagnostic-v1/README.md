# Failed E9 exec-boundary diagnostic

At execution revision `3c1972d634428f7f73cd3ca0ac8cc8ec247481b6`, one candidate diagnostic authenticated the actual execveat FD, canonical `e9patch --help` arguments, fixed environment and original 1 GiB address-space limit. GDB then reported `Cannot find user-level thread for LWP <inferior_pid>: generic error`. The observer killed the inferior and closed with failure. Both process owners exited 1 without timeout or rescued descendants; the inferior PID was 0 after cleanup.

No successful exec event, candidate AT_ENTRY breakpoint, exec return or signal-delivery stop was observed. The empty stdout/stderr and cleanup exit event do not establish a candidate terminal signal or successful image transition. Cause remains **UNRESOLVED**. GDB had loaded the system `libthread_db` despite `set auto-load off`; stale thread-library state across exec is a hypothesis, not a diagnosed AS or rewrite failure.

The [earlier help failure](../full-program-e9-help-result-v1/README.md) remains unchanged: the original passed and the candidate received SIGSEGV in that separate run. This diagnostic grants no help parity, whole-program/native LI2, accuracy, performance, full-corpus or A5 qualification. [receipt.json](receipt.json) retains exact commands, bounds, pins, timings and load; raw maps and debugger captures stay private.

[run_diagnostic.py](run_diagnostic.py) and [observe_exec.py](observe_exec.py) are byte-identical to the executed private v2 scripts. Publication changes their location, not the recorded execution revision. The diagnostic remains known to fail; these assets reproduce the retained method, not a corrected observer.

For reproduction, use the pinned tool/helper bytes in the receipt and a separately reserved single HARD CPU within the 12-CPU lane cap. Supply an executable 282,324-byte candidate with SHA256 `eabf1d463a75d5644ec114bed7b66ace8c7a00f6a64892a4600e8a5661547afc`. Retain both exact scripts together in `SCRIPT_DIR` outside a clean checkout of execution revision `3c1972d634428f7f73cd3ca0ac8cc8ec247481b6`; verify their receipt hashes. From that checkout root, set `REV=3c1972d634428f7f73cd3ca0ac8cc8ec247481b6`, `CPU` to the reserved CPU, `CANDIDATE` to the input path, and `OUT` to a fresh direct child of `target/evaluation`. The controller resolves `observe_exec.py` beside itself through `HERE`. Use the existing [process owner](../admission/processes.py) around this exact argv with the receipt's environment, outer wall 60 seconds and outer log cap 131,072 bytes:

```sh
/usr/bin/prlimit --cpu=40 --as=2147483648 --fsize=1048576 --core=0 -- /usr/bin/python3.9 -I -B "$SCRIPT_DIR/run_diagnostic.py" --revision "$REV" --cpu "$CPU" --out "$OUT" --candidate "$CANDIDATE"
```

The retained controller owns its single GDB invocation (10 seconds including startup/stops), checks the clean revision and pinned inputs before/after, and writes closed ownership before examining outputs. Subject limits stay CPU 5 seconds, AS 1 GiB, each regular file 64 KiB and core 0. Read closed owner records before interpreting traces; preserve any failure. No reproduction or successor diagnostic has run as part of this publication.
