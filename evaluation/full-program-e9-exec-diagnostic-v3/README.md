# E9 exec observation complete; candidate still failed

At execution revision `4451a77540526c382f5fd82bd3674c4fddc4878e`, diagnostic v3 completed one bounded observation of the unchanged E9 candidate. It authenticated FD 3 and `e9patch --help`, observed `execveat(322)` followed by a syscall-return stop labelled 59 with `RAX=-12` and the same RIP/argument frame, then observed **SIGSEGV (`si_code=128`) and terminal signal 11** after forwarding that actual signal. There was no successful-exec event or candidate-entry hit; stdout/stderr were empty. The candidate remains failed.

The observer and its outer owner exited 0 with complete cleanup and zero rescues: 0.2748061609454453 s and 0.4076859860215336 s, on CPU 3. Exit 0 here means the observation reached a terminal event. It grants no candidate, help-parity or full-program qualification. Five pure protocol controls passed separately on CPU 1 in a 0.044363470980897546 s owner operation. Hardware: AMD EPYC Zen 5 dev host. Exact commands, loads, limits and hashes are in [receipt.json](receipt.json); these wall durations are not performance results.

Diagnostic v2, on CPU 8, remains **FAILED_OBSERVER_INCOMPLETE**. Suppressing the debugger's system `libthread_db` lookup allowed it to observe the same 322-to-59 negative return, but its exact pending-number comparator refused. The observer killed the inferior before a signal-delivery stop, so v2 proves no candidate terminal signal. Both owners exited 1 normally. The [earlier v1 failure](../full-program-e9-exec-diagnostic-v1/) and [original help comparison](../full-program-e9-help-result-v1/) are unchanged.

The narrow v3 correction is bound to GNU kernel build ID `fa15f90afce5930f146e2138d2ba10eb95e3e5ad`. Matching installed kernel instructions and BTF/generated headers show native ELF loading writes `orig_ax=59` after `begin_new_exec` has committed the new memory image. A later failure can deliver a fatal signal without a successful exec notification. This explains the observer's finite protocol distinction. It does **not** identify the failing allocation or prove RLIMIT_AS causation. The subject limit remains 1 GiB. Ordinary pending-number equality, descriptor/argv checks, original bounds, signal forwarding and terminal-evidence requirements remain.

The four Python files here are byte-identical to the executed v3 assets. [observer-v2.patch](observer-v2.patch) reconstructs the exact executed v2 driver/observer from the two already-published v1 scripts; receipt pins both before and after bytes. Apply it only to fresh copies, leaving historical assets intact. No raw trace, maps, internal kernel release name or machine identity is published.

For reproduction, supply the same executable 282,324-byte candidate with SHA256 `eabf1d463a75d5644ec114bed7b66ace8c7a00f6a64892a4600e8a5661547afc`, from the [recorded backend generation](../full-program-backend-result-v1/). Keep all four v3 files together in `$SCRIPT_DIR` outside a clean checkout of execution revision `4451a77540526c382f5fd82bd3674c4fddc4878e`, and verify the receipt's asset/tool/helper hashes. The running kernel must have the exact recorded build ID; other kernels refuse. From that checkout root, with a retained externally reserved one-HARD-CPU lease within the 12-CPU lane:

```sh
/usr/bin/prlimit --cpu=20 --as=268435456 --fsize=1048576 --core=0 -- \
  /usr/bin/python3.9 -I -B "$SCRIPT_DIR/controls.py" -v
/usr/bin/prlimit --cpu=40 --as=2147483648 --fsize=1048576 --core=0 -- \
  /usr/bin/python3.9 -I -B "$SCRIPT_DIR/run_diagnostic.py" \
  --revision 4451a77540526c382f5fd82bd3674c4fddc4878e --cpu "$CPU" \
  --candidate "$CANDIDATE" --out "$OUT"
```

`$OUT` must be a fresh direct child of `target/evaluation`. Use [the existing process owner](../admission/processes.py) around the controls (30 s / 1 MiB log) and diagnostic driver (60 s / 128 KiB log), with the exact environments in the receipt. The driver owns its single GDB invocation (10 s / 256 KiB log and trace), checks source/tool/kernel identity before and after closure, and enforces the same subject CPU 5 s / AS 1 GiB / file 64 KiB / core 0 limits. Retain every failure and read closed owner records before interpreting traces. Publication did not rerun either command.
