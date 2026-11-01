# Direct E8 CALL owner experiment

`evaluation/inprocess/reproduce_direct_call.py` retains the entire existing ten-stage CALL/RET/return-head chain, runs all fifteen direct-CALL component cohorts and 24 native pairs, and finally runs this owner experiment. No old fixture, profile, reader or failed observation is replaced.

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

The additive owner fixture has one causal path: an E8 at source offset 0x60a encodes displacement -0x30f to 0x300. Its R12 register deliberately holds an unrelated value. The independent version-9 graph must publish callee row 4 and return row 5 (0x60f); C3 must use that validated return head. Real CALL pushes the original next PC, the cached RET commits the stack exactly once, and the genuine terminal/next events must match all ten original native frames and all 520 stack bytes. Full compiled plans, sealed slots, source identities, permissions, registry, window, generation and directory entries remain authenticated.

This collector requires explicit same-revision receipt+SHA arguments for archive, original CALL owner, RET components/native, RET15 ordering, RET runtime compile, original nine-case RET owner, return-head owner and direct native/components. The unchanged original nine cases provide loaded-miss and poison coverage; the three return-head cases remain mandatory. Their raw artifacts and archive remain in place. This collector performs two fresh complete bridge builds and byte oracles, one native application and maintained/differential owner observations. It retains all 60 native app controls, 252 owner controls and 56 pair controls per applicable record, plus the unchanged terminal/TLS/probe/subentry/effect controls.

The owner success route requires all loaded-miss, pending-resume, poison, committed and following-frame fields to be absent. It does not reinterpret a loaded miss as a hit. Native and owner fixtures/readers are separate from their predecessors; shared capture code has complete DIRECT_CALL-off and return-heads-off bodies.

All process, build, capture and disk limits are unchanged, including 30 CPU/60 wall seconds for complete builds and owner programs, 5 CPU/15 wall seconds for native/model readers, 512 MiB address space and 16 MiB file/capture caps where those profiles originally apply. The source manifest records the exact per-profile bounds. Fresh DWARF, full compiler-M and ELF/provider/link closure, byte oracles, original process owner, and complete source/cleanup checks stay mandatory. Raw output is private; no archive or prerequisite capture is copied.

This portable recipe has not yet been executed as a published invocation. The experiment proves only the finite causal in-pair E8/callee/RET/return-head path after actual execution. Repeated warm epoch reuse, external/missing-target owner paths, owner PUSH faults, asynchronous recovery, high original-owner placement and signed-extreme owner placement remain unqualified. Native coverage does not replace those owner obligations. Whole-program completion, the original 392/522 qualification gates and performance remain pending.
