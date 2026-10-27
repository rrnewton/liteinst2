#!/usr/bin/env python3
"""Canonical RDSSPQ with actual disabled-SHSTK queries and explicit pre-open failed controls."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
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
FIXTURE = REPO/'tools/page-entry/selected/tests/rdssp'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'OUTCOMES.json'
    binding = fact(path)
    need(binding['sha256'] == '8221b971b6ee1f5a488608c4ff17d709d952a3794078d3fb1ac8e66cccff472e', 'exact reviewed RDSSPQ protocol and catalogue')
    protocol = json.loads(path.read_bytes())
    expected = [dict(group=g, reg=r, bytes=bytes([0xf3, 0x48 if r < 8 else 0x49,
                   0x0f, 0x1e, 0xc8+(r & 7)]).hex(), tail=tail, code=1053)
                for g in range(2) for r in range(g*8, g*8+8) for tail in (5, 4)]
    need(protocol['pairs'] == expected and len(expected) == 32 and
         expected[0]['bytes'] == 'f3480f1ec8' and
         {r['reg'] for r in expected} == set(range(16)),
         'all canonical r64 destinations, actual loader opcode and ending/crossing geometry')
    return dict(source=binding, counts=dict(new_pairs=32, page_ending_pairs=16,
                crossing_pairs=16, r64_destinations=16), rows_sha256=digest(expected))


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
        fixtures=record.get('fixtures'), catalogue=record.get('catalogue'),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        native_commands=[{'name': c['name'], 'exit': c.get('exit'), 'expected_exit': c['expected_exit'],
                          'duration_ns': c.get('duration_ns'), 'reaped': c.get('reaped'),
                          'timed_out': c.get('timed_out'),
                          'cleanup_error_count': len(c.get('cleanup_errors', [])),
                          'environment_delta': {k: v for k, v in c['environment'].items() if ENV.get(k) != v},
                          'captures': {n: {k: v[k] for k in ('bytes', 'sha256')}
                                       for n, v in c.get('captures', {}).items()}}
                         for c in record['commands'] if c['profile'] == 'native'],
        cases=[{'name': c['name'], 'accepted': c['accepted'], 'process_outcome': c['process_outcome'],
                'actual_exit': c.get('actual_exit'), 'operation_completed': c.get('operation_completed'),
                'verified_preopen_refusal': c.get('verified_preopen_refusal'),
                'query_evidence': c.get('query_evidence'),
                'header': c.get('header'), 'record': c.get('record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/rdssp/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['rdssp-0'], ['rdssp-1']]+[['rdssp-0']]*4,
            'native_environment_controls': ['absent', 'absent', 'query-einval', 'query-enosys', 'status-shstk', 'status-wrss'],
            'control_variable': 'LI2_RDSSP_CONTROL',
            'actual_commands': 'Complete ordered argv, environments and captures are retained privately and bound by commands_sha256.'})
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node(), '/home/')
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
    name = stamp+'-page-selected-rdssp-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-rdssp-oracle-v1', 'status': 'failed',
        'scope': 'Two bounded canonical RDSSPQ r64 cohorts: 32 new original-PC native/TF pairs plus two startup pairs. Each new native and owner execution requires an actual successful zero ARCH_SHSTK_STATUS query. Four negative commands retain genuine NX pre-open failures with explicitly nonissued query errors/nonzero status; they do not count as target completion or actual kernel-query failures. All 47 old and 16 new supplied refusals remain required. Complete source-bound state/no-op predicates and private raw records remain retained. Existing generic, integer, SIMD, padding, XGETBV, REP and connected suites remain required separately. No RDSSPD, enabled CET, unsupported-query fallback, loader completion, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'rdsspq_pairs': 0, 'actual_native_zero_queries': 0, 'actual_owner_zero_queries': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0, 'new_refusal_encodings': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_preopen_refusal_commands': 0, 'nonissued_query_injections': 0,
                   'actual_native_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_rdssp.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('rdssp-0', 'rdssp-1')}
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
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
        record['catalogue'] = catalogue()
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record_header_fields']
        need(len(names) == 17 and len(outcomes['commands']) == 6, 'complete finite RDSSPQ protocol')
        controls = ['query-einval', 'query-enosys', 'status-shstk', 'status-wrss']
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] == ['group0', 'group1']+controls and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['rdssp-0'], ['rdssp-1']]+[['rdssp-0']]*4 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}]+[{'LI2_RDSSP_CONTROL': n} for n in controls] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact RDSSPQ names, input environments, exits, header schema and bounds')
        need(outcomes['query_trailer'] == dict(bytes=720, header_format='<6Q',
             header_fields=['magic', 'version', 'bytes', 'actual_native_queries', 'injected_calls', 'injected_control'],
             magic=0x315053534452324c, query_count=21, query_format='<QQqQ',
             query_fields=['attempted', 'complete', 'result', 'features']), 'closed actual-query trailer schema')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_preopen_refusal': False}
            record['cases'].append(result)
            row, out, err = run(name, [fixtures[case['argv'][0]], *case['argv'][1:]], case['exit'],
                                env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 136, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<17Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+720,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            positive = name in ('group0', 'group1')
            used = 17 if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            trailer = data[-720:]
            qheader = struct.unpack_from('<6Q', trailer)
            queries = [struct.unpack_from('<QQqQ', trailer, 48+i*32) for i in range(21)]
            control = 0 if positive else controls.index(name)+1
            need(qheader == (0x315053534452324c, 1, 720, 16 if positive else 0,
                             0 if positive else 1, control), 'actual query counts and injection identity')
            expected_queries = [(1, 1, 0, 0) if positive and 1 <= i <= 16 else (0, 0, 0, 0)
                                for i in range(21)]
            need(queries == expected_queries, 'each actual native query succeeded with zero features; unused slots zero')
            result['query_evidence'] = dict(actual_native_zero_queries=qheader[3],
                actual_owner_zero_queries=16 if positive else 0,
                nonissued_query_injections=qheader[4], injection_control=qheader[5],
                trailer_sha256=hashlib.sha256(trailer).hexdigest())
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['rdsspq_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['actual_native_zero_queries'] += 16
                record['totals']['actual_owner_zero_queries'] += 16
                record['totals']['new_page_ending_pairs'] += 8
                record['totals']['new_crossing_pairs'] += 8
                record['totals'].update(supplied_refusal_encodings=63,
                    old_refusal_encodings=47, new_refusal_encodings=16)
            else:
                need(any(data[end:end+header['sample_bytes']]), 'retain actual failed-operation sample')
                # The source-bound C comparator requires the real authenticated
                # NX frame, no RX opening/TRACE/continuation, unchanged state,
                # retained borrow and the exact explicitly nonissued query.
                # The operation stays failed; no native target/query credit.
                result['verified_preopen_refusal'] = True
                record['totals']['verified_preopen_refusal_commands'] += 1
                record['totals']['nonissued_query_injections'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=34, generic_pairs=32, rdsspq_pairs=32,
                 positive_selftest_pairs=2, actual_native_zero_queries=32, actual_owner_zero_queries=32,
                 supplied_refusal_encodings=63, old_refusal_encodings=47, new_refusal_encodings=16,
                 new_page_ending_pairs=16, new_crossing_pairs=16,
                 verified_preopen_refusal_commands=4, nonissued_query_injections=4,
                 actual_native_failed_operations=0, additional_negative_command_selftests=4,
                 executed_refusal_checks=378) and
             len(record['cases']) == 6 and all(c['accepted'] for c in record['cases']),
             'complete two17-pair cohorts and four retained pre-open failed commands')
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
        for fixture_name, fixture in fixtures.items():
            try:
                if fixture.is_file():
                    value = fact(fixture)
                    record.setdefault('fixtures_after', {})[fixture_name] = value
                    record.setdefault('fixtures', {}).setdefault(fixture_name, value)
                    binary(fixture)
            except BaseException as exc:
                record['final_errors'].append('fixture retention '+fixture_name+': '+repr(exc))
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
