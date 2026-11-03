#!/usr/bin/env python3
"""Two component recipes with a separately authenticated current RO archive.

No emitted code, native owner, real-program completion or performance credit.
The ordinary component collector and current_archive remain unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from checks import source
from page_selected import fact, need, save
from persistent_dynamic import imported_sources
from loop_ro_current_archive import current_archive
from loop_components import run as component

PROFILE = 'cached-direct-components-current-archive-v1'
INPUTS = {
    'evaluation/inprocess/loop_components/run.py': (34654, '24c8ab8012368097727292e3c30cb7f004a0dbab0a4c8d3eb42bee9d3ba16e70'),
    'evaluation/inprocess/loop_ro_current_archive.py': (6501, '87b8c393d93cf0679366ff62be12438cc97755aa778783a3346d2e0773898fd7'),
    'tools/page-entry/selected/linked_direct_dispatch.h': (5663, '72571ff2d571392e2ead7df1c4ba59c8fba0709efd7fbaea9987e19e8c1ebba9'),
    'tools/page-entry/selected/linked_direct_dispatch.c': (22664, 'e40761aa34a2ad87a3d4139bf8227a77a0d5e2b395d662a4b2ad4b728d184ea4'),
    'tools/page-entry/selected/tests/persistent_direct_frontier/oracle.c': (19093, '9cb736c77a75b25de07528038f085fdbb587ae9bd013adca5dbee627ced163d3'),
    'tools/page-entry/selected/tests/persistent_direct_frontier/model.c': (8264, 'a4a828079fa7099dda6accf7086e30a585af371d02b157bcf6361837156da3ac'),
    'tools/page-entry/selected/tests/persistent_direct_frontier/model.h': (610, '459f8dc91183f9393289e78f71823804226261934d55827a641118e71dbd919c'),
    'tools/page-entry/selected/tests/cached_direct_aux/oracle.c': (9255, 'fb7ae262f9bc2e974213fac8d6958362141fcfec7dea876105479688536661ea'),
}
CASES = {
    'persistent_direct_frontier': dict(
        recipe_sha256='6665415d8d5b41486c17d92fd82fb663a5afef5651bff8f55f4356ba9ecfb11e',
        units=['tests/persistent_direct_frontier/oracle.c', 'tests/persistent_direct_frontier/model.c',
               'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_direct_dispatch.c',
               'linked_jmp_dispatch.c', 'linked_mov_guard.c', 'tests/decoder/support.c'],
        headers=['tests/persistent_direct_frontier/model.h', 'linked_direct_dispatch.h']),
    'cached_direct_aux': dict(
        recipe_sha256='56728d877c16289d7b12d447be6d60886f1c63da25e108af846f38719f61b066',
        units=['tests/cached_direct_aux/oracle.c', 'tests/persistent_direct_frontier/model.c',
               'linked_direct_dispatch.c', 'tests/decoder/support.c'],
        headers=['tests/persistent_direct_frontier/model.h', 'linked_direct_dispatch.h']),
}
SCHEDULE = tuple('tool-'+n+'-dependencies' for n in ('cc', 'nm', 'python', 'git')) + tuple(
    label for n in ('cc1', 'collect2', 'as', 'ld')
    for label in ('resolve-'+n, 'tool-'+n+'-dependencies')) + tuple(
    'version-'+n for n in ('cc', 'as', 'ld', 'nm', 'python', 'git')) + tuple(
    'link-'+n for n in component.LINK_NAMES) + ('compiler-specs', 'archive-exports') + tuple(
    n+'-'+part for n in CASES for part in ('headers', 'build', 'dependencies', 'component'))


def result(name, stdout, stderr):
    observed = json.loads(stdout)
    if name == 'persistent_direct_frontier':
        expected = dict(version=1, descriptors=66, models=21442, proofs=38, selectors=6272,
            budgets=4, refusals=492, handoffs=192, emitted_execution=0, owner_credit=0)
        need(not stderr and type(observed) is dict and
             set(observed) == set(expected) | {'typed_recoveries', 'steps'} and
             all(type(observed[k]) is int and observed[k] == v for k, v in expected.items()) and
             type(observed['typed_recoveries']) is int and 0 < observed['typed_recoveries'] < 1 << 64 and
             type(observed['steps']) is int and observed['models'] < observed['steps'] < 1 << 64 and
             stdout == (json.dumps(observed, separators=(',', ':'))+'\n').encode(),
             'all exact direct model populations and actual typed recoveries; no emitted execution')
        return observed
    need(name == 'cached_direct_aux', 'only the two literal component descriptors')
    expected = dict(profile='cached_direct_aux_component', models=2048,
        whole_byte_mutations=2368, refusals=512, runtime_authority=False, native_credit=False)
    need(not stderr and type(observed) is dict and set(observed) == set(expected) | {'steps', 'recoveries'} and
         all(type(observed[k]) is type(v) and observed[k] == v for k, v in expected.items()) and
         type(observed['steps']) is int and observed['models'] < observed['steps'] < 1 << 64 and
         type(observed['recoveries']) is int and observed['recoveries'] == 2*observed['steps'] < 1 << 64 and
         stdout == (json.dumps(observed, separators=(',', ':'))+'\n').encode(),
         'complete actual auxiliary model, byte mutations, refusal population and two recoveries per step')
    return observed


def execute(*, cases=CASES, profile=PROFILE, inputs=INPUTS, schedule=SCHEDULE,
            command_count=48, result=result, prepare=None, execution=None, entry_file=__file__,
            command_message='all forty-eight bounded original collector children',
            case_message='both actual component results',
            scope='Only original DIRECT and auxiliary emitter/model/recovery components. No generated-code, '
                  'native owner, current native55/79, full19, program-completion or performance credit.'):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision', 'current-build', 'current-build-sha256', 'output'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--cpu', required=True, type=int)
    a = parser.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         Path.cwd().resolve() == ROOT and os.sched_getaffinity(0) == {a.cpu} and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', a.current_build_sha256),
         'Python3.12, assertions, exact revision/provider and externally reserved singleton')
    private = Path(a.output).absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh confined output')
    private.mkdir(mode=0o700)
    pins = {}; aliases = {}; artifacts = {}
    r = dict(schema=1, profile=profile, status='failed', revision=a.expect_revision, cpu=a.cpu,
        source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        bounds=component.BOUNDS, inputs=pins, aliases=aliases, artifacts=artifacts,
        source_archive_joined=False,
        error=None, final_errors=[], generated_execution=0, native_execution=0,
        qualification_credit=False, owner_credit=False, performance_credit=False)

    def pin(path):
        alias = Path(os.path.abspath(path)); p = alias.resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'unchanged input')
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'unchanged alias')
        pins[str(p)] = value; aliases[str(alias)] = str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'unchanged completed artifact')
        artifacts[str(p)] = value
        return p

    def stable():
        need(os.sched_getaffinity(0) == {a.cpu}, 'same reserved singleton')
        need(all(fact(p) == value for p, value in pins.items()), 'all whole inputs unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == value
                 for p, value in artifacts.items()), 'all whole completed artifacts unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()), 'all aliases unchanged')

    original_argv = sys.argv
    inner = None
    try:
        r['source'] = source()
        need(r['source']['revision'] == a.expect_revision, 'exact clean source before any child')
        pin(__file__)
        if entry_file != __file__: pin(entry_file)
        for name, (size, sha) in inputs.items():
            need(fact(pin(ROOT/name)) == dict(bytes=size, sha256=sha), 'reviewed whole input '+name)
        for name, case in cases.items():
            need(fact(pin(component.SELECTED/'tests'/name/'build.sh'))['sha256'] == case['recipe_sha256'],
                 'both unchanged literal compiler recipes')
        imported_sources(pin)
        builder, archive, r['archive_provider'] = current_archive(
            a.current_build, a.current_build_sha256, ROOT, pin, binary, aliases)
        need(r['archive_provider']['source'] == r['source'] and
             len(r['archive_provider']['compiled_sources']) == 14,
             'fresh same-source provider with all fourteen actual Rust inputs')
        r['source_archive_joined'] = True
        stable()
        sys.argv = [original_argv[0], '--expect-revision', a.expect_revision, '--cpu', str(a.cpu),
            '--archive', str(archive), '--archive-sha256', fact(archive)['sha256'],
            '--output', str(private/'components')]
        try:
            if execution is None:
                r['component_exit'] = component.main(cases=cases, profile=profile, result=result, prepare=prepare)
            else:
                r['component_exit'] = component.main(cases=cases, profile=profile, result=result, prepare=prepare, execution=execution)
        finally:
            sys.argv = original_argv
        path = binary(private/'components/receipt.json'); inner = json.loads(path.read_bytes())
        r['component_receipt'] = fact(path)
        r['component_status'] = inner['status']
        need(r['component_exit'] == 0 and inner['status'] == 'components_passed' and
             inner['source'] == r['source'] and inner['bounds'] == component.BOUNDS and
             inner['error'] is None and inner['final_errors'] == [] and
             all(inner[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')) and
             inner['archive_source_provenance_verified'] is False and inner['archive_builds'] == 0 and
             {k: inner['archive'][k] for k in ('bytes', 'sha256')} == fact(archive) and
             all(inner['tools'][k] == str(builder.tools[k]) for k in ('cc', 'nm', 'python', 'git')),
             'complete original component custody, current archive and actual compiler identities')
        need(len(schedule) == command_count and tuple(c['name'] for c in inner['commands']) == schedule and
             all(c['expected_exit'] == c['exit'] == 0 and c['reaped'] is True and
                 c['timed_out'] is False and c['error'] is None and c['cleanup_errors'] == []
                 for c in inner['commands']), command_message)
        need(set(inner['components']) == set(cases) and
             all(inner['components'][n]['status'] == 'passed' for n in cases), case_message)
        if execution is not None:
            observed = execution(inner)
            need(all(inner[k] == observed[k] for k in ('generated_execution', 'native_execution')),
                 'exact completed inner native/generated observation counts')
            r.update(observed)
        r['results'] = {name: inner['components'][name]['result'] for name in cases}
        r['status'] = 'components_passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        sys.argv = original_argv
        try:
            imported_sources(pin); stable()
            need(source() == r['source'], 'exact source unchanged after every child')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append(repr(error))
        r['cleanup_complete'] = inner is not None and inner['cleanup_complete'] is True
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        save(private/'receipt.json', r)
    proof = r.get('archive_provider')
    summary = {k: r[k] for k in ('schema', 'profile', 'status', 'revision', 'cpu', 'source', 'bounds',
        'source_unchanged', 'inputs_unchanged', 'cleanup_complete', 'generated_execution', 'native_execution',
        'qualification_credit', 'owner_credit', 'performance_credit')}
    summary.update(receipt=fact(private/'receipt.json'), component_receipt=r.get('component_receipt'),
        results=r.get('results'), commands=len(inner['commands']) if inner else 0,
        source_archive_joined=r['source_archive_joined'], error_type=(r['error'] or '').split(':', 1)[0] or None,
        final_error_count=len(r['final_errors']),
        scope=scope)
    summary['reproduce'] = ['python3.12', '-B', str(Path(entry_file).resolve().relative_to(ROOT)),
        '--expect-revision', a.expect_revision, '--cpu', str(a.cpu),
        '--current-build', str(Path(a.current_build).resolve().relative_to(ROOT)),
        '--current-build-sha256', a.current_build_sha256,
        '--output', str(private.relative_to(ROOT))+'-NEW']
    summary['runner'] = fact(Path(entry_file))
    if proof:
        summary['archive_provider'] = {k: proof[k] for k in ('receipt', 'revision', 'archive',
            'producer_status', 'producer_subjects', 'current_compiler_inputs_equal',
            'archive_rebuilt_by_consumer', 'program_qualification_credit', 'performance_credit')}
    if inner:
        summary['hardware'] = {k: inner['hardware'][k] for k in
            ('architecture', 'kernel_version', 'model', 'microcode', 'vendor_id', 'model name',
             'cpu family', 'stepping', 'probe_cpu', 'affinity_cpu_count')}
        summary['hardware_sha256'] = hashlib.sha256(component.canonical(inner['hardware'])).hexdigest()
        summary['command_names'] = [c['name'] for c in inner['commands']]
        summary['commands_sha256'] = hashlib.sha256(component.canonical(inner['commands'])).hexdigest()
    payload = json.dumps(summary, sort_keys=True, separators=(',', ':'))+'\n'
    need(len(payload.encode()) < 15 << 10 and '/home/' not in payload and str(ROOT) not in payload,
         'complete compact public component projection without private paths')
    with (private/'summary.json').open('x') as stream: stream.write(payload)
    print(json.dumps(dict(status=r['status'], summary=str((private/'summary.json').relative_to(ROOT)))))
    return int(r['status'] != 'components_passed')


def main():
    return execute()


if __name__ == '__main__':
    raise SystemExit(main())
