#!/usr/bin/env python3
"""One additive compact byte-equivalence component, not the full seven-case suite.

Use the original component CLI and a retained persistent-loop-native-v2 receipt.
Its archive identity is reused without current-revision native qualification.
The complete old PF/LPF/guard-relocation oracle runs inside this single case.
"""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from loop_fused_far_components import run as lpf

component = lpf.component
component.need(component.BOUNDS == {'build': [30, 512 << 20, 16 << 20, 60],
    'component': [5, 512 << 20, 16 << 20, 15]}, 'original component resource limits')
original = lpf.CASES['loop_fused_far']
CASES = {'group_compact_fast_bytes': dict(
    recipe_sha256='d5b161fe1d75a8e129efd29ab9d09108d12878bc1851706f248d4d0e05143fab',
    units=[original['units'][0], 'tests/group_compact_fast_bytes/compare.c',
           'tests/group_compact_fast_bytes/scalar_compact.c', *original['units'][1:]],
    headers=[*original['headers'], 'span_fast_bytes.h'])}


def result(name, stdout, stderr):
    component.need(name == 'group_compact_fast_bytes' and type(stdout) is bytes and
                   0 < len(stdout) <= 4096 and stderr == b'',
                   'one bounded complete four-row compact comparison output')
    rows = stdout.splitlines(keepends=True)
    component.need(len(rows) == 4, 'three original rows plus one exact comparison row')
    prior = lpf.result('loop_fused_far', b''.join(rows[:3]), stderr)
    def unique(pairs):
        value = dict(pairs)
        component.need(len(value) == len(pairs), 'no duplicate comparison fields')
        return value
    value = json.loads(rows[3], object_pairs_hook=unique)
    expected = dict(profile='group-compact-fast-bytes-v1', builds=76,
        build_ok=24, build_corrupt=52, validations=324, validate_ok=24,
        validate_corrupt=300, whole_input_scratch_output=1,
        emitted_execution=0, owner_credit=0)
    component.need(type(value) is dict and set(value) == set(expected) and
                   all(type(value[k]) is type(v) and value[k] == v for k,v in expected.items()),
                   'all exact typed build/validation and whole-byte comparisons')
    component.need(json.dumps(value, separators=(',', ':')).encode()+b'\n' == rows[3],
                   'one canonical complete comparison row')
    return dict(original_lpf=prior, compact_equivalence=value)


if __name__ == '__main__':
    raise SystemExit(component.main(cases=CASES,
        profile='experimental-group-compact-fast-bytes-v1',
        result=result, reused_archive=True))
