#!/usr/bin/env python3
"""Old DIRECT/AUX components plus separate far-AUX model and finite native probe."""
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from loop_components import current_direct as shared
from page_selected import need

PROFILE = 'far-aux-components-native-current-archive-v1'
NAME = 'cached_direct_aux_far'
READER = None
INPUTS = dict(shared.INPUTS, **{
    'evaluation/inprocess/loop_components/current_direct.py': (14759, '2e03abff431121e2ef6acf3b2dbbcc5c538933dd5660e761e7c3dc6459f26edf'),
    'tools/page-entry/selected/linked_loop_direct.h': (1903, 'dd1a0411cb258fc4109f0f9ee855d2c2539cffb499b30ffa138ca47ffb56e516'),
    'tools/page-entry/selected/linked_loop_direct.inc': (5655, '217453f636b27862db716ad3dd6985c805b0a514e54d19dba53ef91028f225b7'),
    'tools/page-entry/selected/tests/cached_direct_aux_far/native.c': (14921, '9da647fd0796dfb0a5cea0854ca017b0f9c41e03350762a53d134413843715f1'),
    'tools/page-entry/selected/tests/cached_direct_aux_far/model.c': (6581, '1dcb80084ccc868625ec2fe66d26fdfa7de334beb94e29fa5518fb8474c379a0'),
    'tools/page-entry/selected/tests/cached_direct_aux_far/model.h': (340, '1f7baf777b3a6ebb0a012a83fd7ce810ae3f155689721d434a718a5ea19ee5f1'),
    'tools/page-entry/selected/tests/cached_direct_aux_far/read.py': (11471, 'e279f99c06b560517a8d604ae52fc020733601463a2d89249ee5c446bbaba19f'),
    'tools/page-entry/selected/tests/direct_call_native/frame.h': (255, 'c6d5616a7ac2e9cb9c1dcd9186398a26e303714a597dafcede594772df24bccc'),
    'tools/page-entry/selected/tests/direct_call_native/capture.inc': (2738, 'af391add5d2d9309ae40acabefddb687507e0d6a8e4379ac1bd328f8664bdf9a'),
    'tools/page-entry/selected/tests/direct_call_native/probe.S': (1846, '734a8e4eba941f3b69c4031c5281cb0b2ccc35c9b92fbc53596ebe95a9ed86b9'),
    'tools/page-entry/selected/tests/direct_call_native/read.py': (28909, '0537336ecab9a23aad14d8b09bea628e03cde98d70b2a204e8c78f63afb5b060'),
    'tools/page-entry/selected/tests/loop_direct_far/direct_model.c': (8855, '48e1ed6e051a287c633d38bf7c3c300955dc4aa44034328d30c213c91ef62281'),
})
CASES = dict(shared.CASES, **{NAME: dict(
    recipe_sha256='428f7019f2618ca56608477202a095ce7189befcc5d80ef4665d17d9c27c3379',
    units=['tests/cached_direct_aux_far/native.c', 'tests/cached_direct_aux_far/model.c',
           'tests/loop_direct_far/direct_model.c', 'tests/direct_call_native/probe.S',
           'linked_direct_dispatch.c', 'tests/decoder/support.c'],
    headers=['linked_loop_direct.h', 'linked_loop_direct.inc',
             'tests/cached_direct_aux_far/model.h', 'tests/direct_call_native/frame.h',
             'tests/direct_call_native/capture.inc'])})
SCHEDULE = shared.SCHEDULE + tuple(NAME+'-'+part for part in ('headers', 'build', 'dependencies', 'component'))


def result(name, stdout, stderr):
    if name != NAME:
        return shared.result(name, stdout, stderr)
    need(READER is not None, 'actual source-owned complete native reader')
    return READER.read(stdout, stderr)


def execution(record):
    need(tuple(record['components']) == tuple(CASES), 'both unchanged old components and new explicit native case')
    value = record['components'][NAME]
    need(value['status'] == 'passed', 'complete actual native reader acceptance')
    result = value['result']; command = record['commands'][-1]
    need(command['name'] == NAME+'-component' and command['exit'] == 0 and
         result['pid'] == command['pid'] and result['cpu'] == record['cpu'] and
         result['native_pairs'] == 6 and result['native_lanes'] == 18 and result['generated_lanes'] == 12 and
         result['full_frames'] == 36 and result['unique_recovery_boundaries'] == 37 and
         all(result[k] is False for k in ('owner_credit', 'qualification_credit', 'performance_credit')),
         'actual process/CPU/full-state native observations only, without owner authority')
    return dict(generated_execution=12, native_execution=18)


def main():
    global READER
    def module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
    common = module('far_aux_original_native_frame', ROOT/'tools/page-entry/selected/tests/direct_call_native/read.py')
    reader = module('far_aux_native_reader', ROOT/'tools/page-entry/selected/tests/cached_direct_aux_far/read.py')
    READER = reader.configured(common)
    return shared.execute(cases=CASES, profile=PROFILE, inputs=INPUTS, schedule=SCHEDULE,
        command_count=52, result=result, execution=execution, entry_file=__file__,
        command_message='all fifty-two bounded setup/component/native children',
        case_message='both unchanged old model populations and additive complete far-AUX native observations',
        scope='Original DIRECT and near AUX component populations remain intact. Separate far AUX '
              'models and six native original/generated pairs plus six real TRACE recovery lanes. '
              'No composed LCX owner, native43/55/79, full19, program-completion or performance credit.')


if __name__ == '__main__':
    raise SystemExit(main())
