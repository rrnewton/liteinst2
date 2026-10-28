#!/usr/bin/env python3
"""Finite legacy PSLLDQ/PSRLDQ byte-shift oracle with complete native/TF state."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/sse2_byte_shift'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '2ada4f13ddd3c3b46d33ca48bf8461914d0e24c10adcac7e6f6022a015d18f5d', 'exact reviewed byte-shift catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"]+)",([0-9,]+),\{([^}]*)\},\{([^}]*)\},\{([^}]*)\}\},', line)
        need(match is not None, 'closed literal byte-shift row')
        numbers = [int(n) for n in match[2].split(',')]
        need(len(numbers) == 6, 'exact byte-shift fields')
        length, code, xmm, left, count, tail = numbers
        blobs = [bytes(int(n, 16) for n in match[k].split(',')) for k in (3, 4, 5)]
        need([len(b) for b in blobs] == [length, 16, 16] and
             1 <= tail <= length <= 6 and left in (0, 1) and
             count in (0, 1, 15, 16, 255) and xmm in (1, 9), 'closed literal shift values')
        raw = bytes([0x66]+([0x41] if xmm == 9 else [])+[0x0f, 0x73, 0xf9 if left else 0xd9, count])
        value = int.from_bytes(blobs[1], 'little')
        expected = ((value << (8*count)) & ((1 << 128)-1) if left else value >> (8*count)).to_bytes(16, 'little')
        need(code == (1708 if left else 1695) and blobs[0] == raw and blobs[2] == expected,
             'literal instruction/byte-count result; no modulo-count masking')
        need(match[1] == f'ps{"ll" if left else "rl"}dq_xmm{xmm}_imm{count}_tail{tail}', 'literal row identity')
        rows.append(dict(name=match[1], code=code, xmm=xmm, left=left, count=count,
                         tail=tail, length=length, bytes=raw.hex()))
    counts = dict(new_pairs=len(rows), left_pairs=sum(r['left'] for r in rows),
                  right_pairs=sum(not r['left'] for r in rows),
                  page_ending_pairs=sum(r['tail'] == r['length'] for r in rows),
                  crossing_pairs=sum(r['tail'] < r['length'] for r in rows))
    need(counts == dict(new_pairs=40, left_pairs=20, right_pairs=20,
                       page_ending_pairs=20, crossing_pairs=20) and
         [r['xmm'] for r in rows] == [1]*20+[9]*20 and len({r['name'] for r in rows}) == 40,
         'complete two-register byte-shift cohorts')
    for xmm, size in ((1, 5), (9, 6)):
        for left in (1, 0):
            for ci, count in enumerate((0, 1, 15, 16, 255)):
                need([r['tail'] for r in rows if r['xmm'] == xmm and r['left'] == left and r['count'] == count] ==
                     [size, min(ci+1, size-1)], 'each count has ending and actual crossing geometry')
    return dict(source=binding, counts=counts, rows_sha256=digest(rows))

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
                'verified_memory_fault': c.get('verified_memory_fault'),
                'header': c.get('header'), 'record': c.get('record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/sse2_byte_shift/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['sse2-byte-shift-0'], ['sse2-byte-shift-1']],
            'native_environment_controls': ['absent', 'absent'],
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
    name = stamp+'-page-selected-sse2-byte-shift-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-sse2-byte-shift-oracle-v1', 'status': 'failed',
        'scope': 'Two additive legacy register-only byte-shift cohorts (21 pairs each): 40 new native/TF pairs plus two startup pairs, 47 old and 30 new supplied encoding refusals. No new executed memory-fault command is claimed. Complete source-bound C state predicates and private raw records are retained. All original generic, integer, padding, XGETBV, REP, SIMD, failure and connected suites remain required separately. No every-prefix, loader, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'byte_shift_pairs': 0,
                   'left_pairs': 0, 'right_pairs': 0, 'count_zero_pairs': 0, 'count_one_pairs': 0,
                   'count_fifteen_pairs': 0, 'count_sixteen_pairs': 0, 'count_255_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_sse2_byte_shift.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('sse2-byte-shift-0', 'sse2-byte-shift-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 2, 'complete finite byte-shift protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0] and
             [c['argv'] for c in outcomes['commands']] == [['sse2-byte-shift-0'], ['sse2-byte-shift-1']] and
             [c['environment_delta'] for c in outcomes['commands']] == [{}, {}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact byte-shift names, environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '9b5db86d63f7ad17bac6aea3b680c9beb0b85b4d95ec170900cfa4f69620766c',
             'exact reviewed two-command outcomes')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'verified_memory_fault': False}
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
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            need(name in ('group0', 'group1') and header['completed'] == header['pairs'] == 21,
                 'every expected positive pair completed')
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
            result['operation_completed'] = True
            record['totals']['positive_pairs'] += 21
            record['totals']['generic_pairs'] += 20
            record['totals']['byte_shift_pairs'] += 20
            record['totals']['positive_selftest_pairs'] += 1
            record['totals']['left_pairs'] += 10
            record['totals']['right_pairs'] += 10
            for key in ('count_zero_pairs', 'count_one_pairs', 'count_fifteen_pairs', 'count_sixteen_pairs', 'count_255_pairs'):
                record['totals'][key] += 4
            record['totals']['new_page_ending_pairs'] += 10
            record['totals']['new_crossing_pairs'] += 10
            record['totals']['executed_refusal_checks'] += header['refusals']
            record['totals'].update(supplied_refusal_encodings=77,
                old_refusal_encodings=47, new_refusal_encodings=30)
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=42, generic_pairs=40, byte_shift_pairs=40,
                 positive_selftest_pairs=2, supplied_refusal_encodings=77, old_refusal_encodings=47,
                 new_refusal_encodings=30, left_pairs=20, right_pairs=20,
                 count_zero_pairs=8, count_one_pairs=8, count_fifteen_pairs=8,
                 count_sixteen_pairs=8, count_255_pairs=8,
                 new_page_ending_pairs=20, new_crossing_pairs=20, executed_refusal_checks=154) and
             len(record['cases']) == 2 and all(c['accepted'] for c in record['cases']),
             'complete two twenty-one-pair byte-shift cohorts; original fault suites remain separate')
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
