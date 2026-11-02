#!/usr/bin/env python3
"""Additive far-DIRECT component diagnostic; no native or owner qualification."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from loop_components import run as component

# The original ordered five descriptors are reused without mutating their
# dictionary or fields. The sole added recipe still compiles all eleven TUs.
component.need(component.CASES['loop_plan']['headers'].count(
    'tests/persistent_direct_frontier/model.c') == 1, 'one exact original model source dependency')
CASES = {**component.CASES, 'loop_direct_far': dict(
    recipe_sha256='c7782525316dc59b403d0cb7c9180ae4fc9229e01a76e959709f5aa3626dd38d',
    units=['tests/loop_direct_far/oracle.c', 'tests/loop_direct_far/direct_model.c',
           'tests/loop_direct_far/mov_model.c', *component.CASES['loop_plan']['units'][3:]],
    headers=[*('tests/loop_direct_far/direct_model.c'
               if h == 'tests/persistent_direct_frontier/model.c' else h
               for h in component.CASES['loop_plan']['headers']),
             'tests/loop_plan/oracle.c', 'linked_loop_direct.h', 'linked_loop_direct.inc'])}


def result(name, stdout, stderr):
    if name != 'loop_direct_far':
        return component.component_result(name, stdout, stderr)
    component.need(type(stdout) is bytes and 0 < len(stdout) <= 4096 and stderr == b'',
                   'complete bounded two-row far component output without diagnostics')
    rows = stdout.splitlines(keepends=True)
    component.need(len(rows) == 2, 'one original loop row followed by one additive far row')
    original = component.component_result('loop_plan', rows[0], stderr)
    def unique(pairs):
        value = dict(pairs)
        component.need(len(value) == len(pairs), 'no duplicate far component fields')
        return value
    value = json.loads(rows[1], object_pairs_hook=unique)
    fixed = dict(profile='loop-far-direct-component-v1', adapters=70, near=12, far=58,
        models=13440, literal_refusals=464, direct_corruptions=870, plans=4,
        plan_corruptions=128, relocations=6, relocation_controls=102,
        emitted_execution=0, owner_credit=0)
    component.need(type(value) is dict and set(value) == set(fixed) | {'steps'} and
                   all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items()) and
                   type(value['steps']) is int and value['steps'] > value['models'],
                   'every exact far population and observed decoder-free recovery steps')
    # The C oracle retains steps==recoveries for every independently modelled
    # state and all full-state/branch/row checks. No observed total is a test bar.
    component.need(json.dumps(value, separators=(',', ':')).encode()+b'\n' == rows[1],
                   'one canonical complete additive far row')
    return dict(original_loop=original, far_direct=value)


if __name__ == '__main__':
    raise SystemExit(component.main(cases=CASES,
        profile='experimental-loop-far-components-v1', result=result, reused_archive=True))
