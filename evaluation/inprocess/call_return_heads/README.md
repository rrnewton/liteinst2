# Finite CALL return-head owner experiment

This opt-in version 8 mode adds the original CALL next PC to the existing bounded graph only when that address belongs to the already held source pair. The existing before-effect CALL frontier, source checks, queue/head/exit limits, compact image comparisons, stack guards and recovery rules remain mandatory. It does not borrow the next page to admit a continuation.

The existing version 7 nine-case experiment is a prerequisite and remains unchanged. The additional mode 1 case runs once each as native, maintained and maps-differential. Its return address A-prime+13 was absent from the version 7 graph; the new eight-head directory admits it at row 5. The comparison retains all ten native frames, complete GREG/FP/context state and the complete 520-byte stack. It checks one CALL push and one cached RET pop, with no loaded miss or private-C3 continuation in this additional case.

The collector first runs nine complete component cohorts: standalone CALL, standalone RET, CALL planner and RET planner with the return-head flag off, then the same four with it on, then the additive return-head component. Separate on-mode planner source files preserve every original off-mode recipe and oracle. The new component retains 105 plans, 45 CALL/RET pairs, three honest CALL-RSP misses, 49 boundary cases, three deduplications, four positive capacity cases, nine refusals and eight corruptions. The original flag-on planner input that exhausts the unchanged exit cap remains an explicit refusal; a separate eight-CALL loop supplies the positive capacity case.

The owner collector requires both fresh full builds and byte oracles, complete compiler-M/provider/ELF/DWARF closure, 60 native app controls and 248 owner plus 52 pair controls per gated lane. It also retains each lane's 73 terminal, 33 TLS, 22 probe, 19 subentry and 12 effect controls. Builds use 30 CPU seconds / 60 wall seconds; native and component execution use 5 CPU seconds / 15 wall seconds; gated subjects use 30 CPU seconds / 60 wall seconds. The 512 MiB address-space, 16 MiB output and separate 4 MiB protected-record limits are unchanged. There are no address retries or failed-subject substitutions.

From a clean checkout, reserve CPU 3 for the complete sequence. Replace `/path/to/agent-utils` with the actual agent-utils checkout. The parent must retain a CPU affinity containing CPU 3 and at least one other CPU, so the allocator can test that its hard pin prevents escape. CPU 3 must be available to the reservation ledger. The command refuses if reservation or the hard-pin check fails:

```sh
python3 -B - /path/to/agent-utils "$(git rev-parse HEAD)" target/evaluation/inprocess/call-return-heads-fresh <<'PYTHON'
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
command = [sys.executable, '-B', 'evaluation/inprocess/reproduce_call_return_heads.py',
           '--expect-revision', sys.argv[2], '--cpu', str(cpu), '--output', sys.argv[3]]
with reservation.reserve_cores(1, tag='call-return-heads', sample_s=0.3,
                               exclude=original - {cpu}) as cores:
    assert list(cores) == [cpu] and os.sched_getaffinity(0) == original
    result = cpuset_allocator._run_reserved_hard(
        cores, command, tag='call-return-heads', prog='call-return-heads')
raise SystemExit(result)
PYTHON
```

The driver retains the complete existing [nine-stage RET sequence](../ret_owner/README.md), then runs this additive collector. Every receipt must join the same current revision, CPU, hardware and complete archive in place. A failed stage stops the chain. For an already completed fresh chain, `run.py` accepts `--archive-receipt`, `--call-owner-receipt`, `--ret-receipt`, `--ret15-receipt`, `--runtime-compile-receipt` and `--ret-owner-receipt`, each with a corresponding `--NAME-receipt-sha256`, plus `--expect-revision`, `--cpu 3` and a fresh `--output`.

Production bodies are exact exports of the reviewed private candidate. The existing observer filename retains both complete version 7 and version 8 bodies byte-exact under one explicit compile-time selector. The portable runner uses the authenticated installed source in place. Only two explicit private source aliases, with exact local model-header siblings, avoid duplicate diagnostic object basenames. The version 8 semantic reader inherits 15 whole unchanged version 7 methods; its graph, phase, completion and control overrides remain separate. Existing version 7 readers and wire/layout declarations remain unchanged.

This portable adapter has not been executed as part of its source preparation. Earlier private observations retain their actual command and source provenance. The finite result is not whole-profile or performance qualification. The original 392/522 gates and the within-10x-DynamoRIO objective remain pending. Direct E8, additional retained slots and arbitrary DSO admission are outside this checkpoint. Original-source before-load and spill references retain their strict rel32 placement checks; the sealed absolute RET loaded-miss landing does not relax them.
