#!/usr/bin/env python3
"""Pure LCX value component from installed source and a fresh current RO archive."""
import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from loop_components import current_direct as shared
from page_selected import need

PROFILE = 'cached-direct-context-component-current-archive-v1'
NAME = 'cached_direct_context_component'
READER = None
INPUTS = dict(shared.INPUTS, **{
    'evaluation/inprocess/loop_components/current_direct.py':
        (14759, '2e03abff431121e2ef6acf3b2dbbcc5c538933dd5660e761e7c3dc6459f26edf'),
    'tools/page-entry/selected/loop_cached_direct_context.h':
        (3933, '06fce76e8d5c48a89fd72427f5bed851e4f9d887b8ec9c10e4f5e929a64ba363'),
    'tools/page-entry/selected/loop_cached_direct_context.c':
        (10253, '6a83ad1af290681c9ffb4cf41ddecfb88bd1b2e7f1a0fe5c80ce297c0b49800a'),
    'tools/page-entry/selected/tests/cached_direct_context_component/build.sh':
        (3264, 'bed685beacc6c8433ec3ae78f539ffc1aafc312133f29f45c7b0452789905fd3'),
    'tools/page-entry/selected/tests/cached_direct_context_component/oracle.c':
        (22030, 'd44bba38a5820e34ee09735e3b2228202cf6aa6e091cabaa7738dcefb4219adc'),
    'tools/page-entry/selected/tests/cached_direct_context_component/model.c':
        (460, 'bd86f62c7bf42c3e7d99deac3bcd457731bc062736d7ee629f04a91a8149d74e'),
    'tools/page-entry/selected/tests/cached_direct_context_component/prepare.py':
        (2426, '8a390aa247c888b22e85cfaedd8af7447546dad12a629cd7e295f4a8b694ae27'),
    'tools/page-entry/selected/tests/cached_direct_context_component/read.py':
        (2102, 'efdcbb5739a106e8ec87e74fb287d037390ab9fe54d0534856b55861e24a7ca6'),
})
CASES = {NAME: dict(recipe_sha256='bed685beacc6c8433ec3ae78f539ffc1aafc312133f29f45c7b0452789905fd3',
    output_directory=True, output_leaf='context-component',
    units=['tests/cached_direct_context_component/oracle.c',
           'tests/cached_direct_context_component/model.c',
           'loop_cached_direct_context.c', 'persistent_group_plan.c',
           'persistent_group_compact.c', 'loop_read_bridge.c', 'loop_envelope.c',
           'loop_effects_bridge.c', 'loop_effects_envelope.c', 'linked_direct_dispatch.c',
           'linked_jmp_dispatch.c', 'linked_mov_guard.c', 'tests/decoder/support.c'],
    headers=['loop_cached_direct_context.h', 'tests/persistent_direct_frontier/model.c',
             'tests/persistent_direct_frontier/model.h'])}
# The authenticated shared descriptor has exactly forty setup commands followed
# by its two four-command components. This adds the explicit preparation child.
SCHEDULE = shared.SCHEDULE[:40] + tuple(NAME+'-'+part for part in
    ('prepare', 'headers', 'build', 'dependencies', 'component'))


def result(name, stdout, stderr):
    need(name == NAME and READER is not None, 'only the exact pure LCX component')
    # The shared invoker has already required the actual child exit zero.
    return READER.read(stdout, stderr, 0)


def prepare(name, selected, fixture, output, tools, pin, artifact, run):
    need(name == NAME and fixture == selected/'tests'/NAME and
         not list(output.iterdir()), 'one exact preparation in an empty output directory')
    for p in (fixture/'prepare.py', selected/'persistent_group_controller.inc',
              selected/'persistent_subentry_source.inc',
              selected/'tests/loop_cached_direct_context_app/machine.S',
              selected/'tests/loop_cached_direct_context_app/app.ld'):
        pin(p)
    out, err = run(name+'-prepare', [tools['python'], '-B', fixture/'prepare.py', selected,
        selected/'tests/loop_cached_direct_context_app', output])
    need(out == err == b'', 'complete successful preparer without output')
    expected = {'actual.inc', 'persistent_group_config.h'}
    need({p.name for p in output.iterdir()} == expected, 'both exact generated preparation artifacts only')
    paths = []
    for leaf in sorted(expected):
        p = output/leaf
        need(p.is_file() and not p.is_symlink(), 'regular generated header')
        artifact(p); paths.append(str(pin(p)))
    return tuple(paths)


def main():
    global READER
    path = ROOT/'tools/page-entry/selected/tests/cached_direct_context_component/read.py'
    spec = importlib.util.spec_from_file_location('lcx_component_reader', path)
    READER = importlib.util.module_from_spec(spec); spec.loader.exec_module(READER)
    return shared.execute(cases=CASES, profile=PROFILE, inputs=INPUTS, schedule=SCHEDULE,
        command_count=45, result=result, prepare=prepare, entry_file=__file__,
        command_message='all forty-five bounded collector/preparer children',
        case_message='actual complete LCX value component result',
        scope='Only the pure LCX planner/value/model component from installed source. '
              'Earlier DIRECT/aux outcomes remain separate. No generated-code, native owner, '
              'native55/79, full19, program-completion or performance credit.')


if __name__ == '__main__':
    raise SystemExit(main())
