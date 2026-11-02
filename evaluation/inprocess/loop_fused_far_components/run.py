#!/usr/bin/env python3
"""Run all six existing components plus LPF; no native or owner qualification.

After installation, use one externally reserved CPU and the unchanged component
CLI: --expect-revision REV --cpu N --output FRESH --archive PATH
--archive-sha256 SHA --archive-native-receipt PATH
--archive-native-receipt-sha256 SHA. The retained archive joins convey only its
original receipt identity, never current-revision native qualification.
"""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from loop_far_components import run as far

component = far.component
component.need(tuple(far.CASES) == ('scalar_span_metadata', 'scalar_read', 'loop_envelope',
    'bounded_fusion_plan', 'loop_plan', 'loop_direct_far'), 'all six original ordered component cases')
# Reuse every old descriptor and result callback without changing their fields.
CASES = {**far.CASES, 'loop_fused_far': dict(
    recipe_sha256='6cdd25530e85700bd3149eef4a8ee24568949fe9f8ad77f9f725add793143c80',
    units=['tests/loop_fused_far/oracle.c',
           'tests/bounded_fusion_plan/direct_model.c',
           'tests/bounded_fusion_plan/mov_model.c',
           *component.CASES['loop_plan']['units'][3:]],
    headers=[*component.CASES['loop_plan']['headers'],
             'tests/bounded_fusion_plan/oracle.c',
             'tests/loop_direct_far/direct_model.c',
             'linked_loop_direct.h', 'linked_loop_direct.inc',
             'persistent_loop_fused_plan.h', 'persistent_loop_fused_plan.inc',
             'persistent_loop_fused_compact.inc',
             'persistent_loop_runtime.h', 'persistent_fused_runtime.h'])}


def result(name, stdout, stderr):
    if name != 'loop_fused_far':
        return far.result(name, stdout, stderr)
    component.need(type(stdout) is bytes and 0 < len(stdout) <= 4096 and stderr == b'',
                   'complete bounded two-row LPF output without diagnostics')
    rows = stdout.splitlines(keepends=True)
    component.need(len(rows) == 2, 'whole original PF row followed by one additive LPF row')
    original = component.component_result('bounded_fusion_plan', rows[0], stderr)
    def unique(pairs):
        value = dict(pairs)
        component.need(len(value) == len(pairs), 'no duplicate LPF component fields')
        return value
    value = json.loads(rows[1], object_pairs_hook=unique)
    fixed = dict(profile='loop-fused-far-component-v1', near=12, far=12,
        histories=24, graph_controls=8, refusals=12, partial=4,
        partial_controls=24, direct_models=4608, mov_models=1280,
        corruptions=300, literal_refusals=96, links=8, copied_boundaries=556,
        old_sentinels=12, emitted_execution=0, owner_credit=0)
    dynamic = {'interiors', 'direct_steps', 'mov_recoveries'}
    component.need(type(value) is dict and set(value) == set(fixed) | dynamic and
                   all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items()) and
                   all(type(value[k]) is int for k in dynamic),
                   'every exact LPF population and typed descriptive field')
    # The pinned C oracle checks both complete byte interpreters and exactly
    # two full typed recovery calls per step/recovery. These totals describe
    # that execution; they never replace its assertions or the old PF row.
    component.need(value['interiors'] > 0 and value['direct_steps'] > value['direct_models'] and
                   value['mov_recoveries'] > value['mov_models'],
                   'nonempty complete interior and independent recovery observations')
    component.need(json.dumps(value, separators=(',', ':')).encode()+b'\n' == rows[1],
                   'one canonical complete additive LPF row')
    return dict(original_fused=original, loop_fused_far=value)


if __name__ == '__main__':
    raise SystemExit(component.main(cases=CASES,
        profile='experimental-loop-fused-far-components-v1', result=result, reused_archive=True))
