# Direct E8 CALL components and native observations

`evaluation/inprocess/reproduce_direct_call.py` runs the complete existing ten-stage CALL/RET/return-head chain, followed by this stage and the additive direct-CALL owner stage. All stages require the same clean revision, CPU, toolchain and retained decoder archive. The archive is built by the original archive stage with the existing linked-epoch and mov-guard features; this collector does not build another archive.

The driver requires Linux x86-64, Python 3.11+, the repository toolchain and the agent-utils CPU allocator. Start it with a broad parent affinity; the allocator must verify the hard CPU reservation before the child starts. CPU 3 is the fixed archive/cohort CPU. The output directory must be fresh and beneath `target/evaluation/inprocess`.

```sh
python3 -B - /path/to/agent-utils "$(git rev-parse HEAD)" target/evaluation/inprocess/direct-call-fresh <<'PYTHON'
import os
import sys
from pathlib import Path

assert not sys.flags.optimize and len(sys.argv) == 4
suite = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(suite / 'py'))
from dagrun import reservation, cpuset_allocator

cpu = 3
original = os.sched_getaffinity(0)
assert cpu in original and len(original) > 1
command = [sys.executable, '-B', 'evaluation/inprocess/reproduce_direct_call.py',
           '--expect-revision', sys.argv[2], '--cpu', str(cpu), '--output', sys.argv[3]]
with reservation.reserve_cores(1, tag='direct-call', sample_s=0.3,
                               exclude=original - {cpu}) as cores:
    assert list(cores) == [cpu] and os.sched_getaffinity(0) == original
    result = cpuset_allocator._run_reserved_hard(
        cores, command, tag='direct-call', prog='direct-call')
raise SystemExit(result)
PYTHON
```

This stage executes all fifteen complete component cohorts: the standalone CALL and RET emitters and both planners with return-heads off and on; the return-head graph component; then those five cohorts plus the new direct-CALL component with DIRECT_CALL enabled. The original register-CALL and RET cases, far-address/literal/relocation controls, full output comparators, and all original limits remain mandatory. Direct-only recipes and model/oracle files are separate; the old recipes and readers retain their original meanings.

Two fixed native chunks contain 12 pairs each (48 lanes, 100 full frames and 140 TRACE rows). They measure exact signed direct targets, hits and misses, PUSH faults including split pages, pre/post-PUSH recovery, high placement, and a page-end CALL whose numerically valid return PC lies on an unmapped page. That pushed PC grants no permission or source-admission authority. Full raw GREG, FP, context, mask, TLS, stack and signal records remain private and are read by the complete independent reader.

Build/metadata commands keep 30 CPU seconds, 60 wall seconds, 512 MiB address-space and 16 MiB file/capture limits; each component, native chunk and reader keeps 5 CPU seconds and 15 wall seconds with the same memory/file bounds. Compiler-M headers, saved objects, linker inputs, ELF/loader closure, emitted bootstrap, actual PID/CPU, exact raw sizes and source/cleanup closure are mandatory. No retry or relaxed comparator is added.

For a separately prepared chain, `run.py` requires `--expect-revision`, `--output`, `--cpu 3`, and explicit receipt paths plus full SHA-256 values for `--archive-receipt`, `--ret-owner-receipt` and `--return-heads-receipt`. It authenticates every prerequisite before any new component or native observation. Raw artifacts stay in the private output; the compact `summary.json` has no host paths or raw binary logs.

This portable recipe is source-reviewed, not yet executed as a published invocation. Historical private observations keep their original source identities and failure labels. This standalone stage grants no live-owner, whole-program, 392/522-gate or performance credit.
