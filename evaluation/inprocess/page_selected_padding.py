#!/usr/bin/env python3
"""Original padding pairs plus the exact observed eleven-byte NOP, with explicit refusal promotion."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/padding'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def publish(path, record, receipt):
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds', 'elf')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        cases_sha256=digest(record['cases']), inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts={name: {k: value[k] for k in ('bytes', 'sha256')}
                         for name, value in build.get('artifacts', {}).items()},
        fixtures=record.get('fixtures'),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        native_commands=[{'name': c['name'], 'exit': c.get('exit'), 'expected_exit': c['expected_exit'],
                          'duration_ns': c.get('duration_ns'), 'reaped': c.get('reaped'),
                          'timed_out': c.get('timed_out'),
                          'cleanup_error_count': len(c.get('cleanup_errors', [])),
                          'captures': {n: {k: v[k] for k in ('bytes', 'sha256')}
                                       for n, v in c.get('captures', {}).items()}}
                         for c in record['commands'] if c['profile'] == 'native'],
        cases=[{'name': c['name'], 'accepted': c['accepted'], 'process_outcome': c['process_outcome'],
                'header': c.get('header'), 'record': c.get('record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/padding/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['padding-tf-fixture'], ['padding-long-tf-fixture']],
            'actual_commands': 'Complete ordered argv, environments and captures are retained privately and bound by commands_sha256.'})
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node())
    need(not any(x and len(x) > 1 and x in text for x in markers), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0, 'Python assertions must remain enabled')
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-padding-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-padding-oracle-v2', 'status': 'failed',
        'scope': 'Two bounded padding cohorts: all 20 original pairs plus 11 new pairs for the exact observed eleven-byte form, with two genuine startup pairs. All 47 generic and 11 retained padding refusals remain; two new neighbors refuse. Historical padding refusal entry two is explicitly promoted to accepted classification and positive full-state coverage. The original generic oracle and its failed-operation controls remain required. No program completion, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'verified_failed_operations': 0,
                   'additional_negative_command_selftests': 0, 'new_padding_pairs': 0,
                   'promoted_padding_encodings': 0, 'executed_promoted_acceptance_checks': 0,
                   'retained_padding_refusals': 0, 'new_padding_refusals': 0, 'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_padding.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('padding-tf-fixture', 'padding-long-tf-fixture')}
    build = None

    def pin(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'pinned input changed')
        pins[str(path)] = value
        return path

    def binary(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()), 'input changed before command')
        need(all(fact(p) == v for p, v in binaries.items()), 'artifact changed before command')
        native = profile == 'native'
        row = {'name': label, 'argv': list(map(str, argv)), 'bounds': PROFILES[profile],
               'expected_exit': expected, 'profile': profile,
               'capture_limit': 8192 if native else 1024*1024,
               'environment': dict(ENV, **(env or {}))}
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=native, step=native)
        need(row['exit'] == expected, 'exact process exit: '+label)
        return row, out, err

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                                        cwd=REPO, timeout=5).split(b'\0')
        for value in paths:
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(value))
        build = Build(record, private, pin, binary, run)
        products = build.prepare()
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        record['fixtures'], record['elf'] = {}, {}
        for index, (name, fixture) in enumerate(fixtures.items()):
            binary(fixture)
            record['fixtures'][name] = fact(fixture)
            record['elf'][name] = plain_executable(fixture)
            _, out, err = run('fixture-undefined' if index == 0 else 'fixture-undefined-long',
                              [build.tools['nm'], '-u', fixture], profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 2 and
             [c['name'] for c in outcomes['commands']] == ['positive', 'long-positive'] and
             [c['group'] for c in outcomes['commands']] == [0, 1], 'complete finite padding protocol')
        for case in outcomes['commands']:
            name = case['name']
            need(case['argv'][0] in fixtures and len(case['argv']) == 1, 'exact fixture command')
            fixture = fixtures[case['argv'][0]]
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False}
            record['cases'].append(result)
            _, out, err = run(name, [fixture, *case['argv'][1:]], case['exit'])
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            expected_pairs = 21 if case['group'] == 0 else 12
            need(header['pairs'] == header['completed'] == expected_pairs and
                 case['unused_sample_slots'] == 21-expected_pairs,
                 'actual finite pair count and unused bounded slots')
            used_end = header['header_bytes']+expected_pairs*header['sample_bytes']
            sample_end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[used_end:sample_end]) and
                 not any(data[sample_end:sample_end+header['sample_bytes']]),
                 'all unused positive slots and negative sample remain zero')
            result['accepted'] = True
            record['totals']['positive_pairs'] += expected_pairs
            record['totals']['generic_pairs'] += expected_pairs-1
            record['totals']['positive_selftest_pairs'] += 1
            record['totals']['executed_refusal_checks'] += header['refusals']
            record['totals']['executed_promoted_acceptance_checks'] += 1
            record['totals'].update(supplied_refusal_encodings=60, promoted_padding_encodings=1,
                                    retained_padding_refusals=11, new_padding_refusals=2)
            if case['group'] == 1:
                record['totals']['new_padding_pairs'] = 11
        need(record['totals']['positive_pairs'] == 33 and record['totals']['generic_pairs'] == 31 and
             record['totals']['positive_selftest_pairs'] == 2 and
             record['totals']['executed_refusal_checks'] == 120 and
             record['totals']['executed_promoted_acceptance_checks'] == 2,
             'both exact cohorts and every control completed')
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if build is not None:
            try:
                record['final_errors'].extend(build.finish())
                if record['status'] == 'passed':
                    need(record['build']['status'] == 'passed', 'build closure did not pass')
            except BaseException as exc:
                record['final_errors'].append('build closure: '+repr(exc))
        record['fixtures_after'] = {}
        for name, fixture in fixtures.items():
            try:
                if fixture.is_file():
                    record['fixtures_after'][name] = fact(fixture)
                    record.setdefault('fixtures', {}).setdefault(name, record['fixtures_after'][name])
                    binary(fixture)
            except BaseException as exc:
                record['final_errors'].append('fixture retention '+name+': '+repr(exc))
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for key, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = record[key] = {}
            for path, expected in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == expected, 'final byte identity')
                except BaseException as exc:
                    record['final_errors'].append(path+': '+repr(exc))
        try:
            record['source_unchanged'] = source() == record['source']
            need(record['source_unchanged'], 'source changed')
        except BaseException as exc:
            record['final_errors'].append('source: '+repr(exc))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None:
                record['error'] = 'FinalObservationError: input/source/artifact closure failed'
        receipt = private/'receipt.json'
        save(receipt, record)
        publish(public, record, receipt)
    print(json.dumps({'status': record['status'], 'totals': record['totals'],
                      'failure_type': (record['error'] or '').split(':')[0] or None}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
