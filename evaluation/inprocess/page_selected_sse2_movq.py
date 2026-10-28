#!/usr/bin/env python3
"""Finite legacy MOVQ register/m64 oracle and two genuine failed-memory controls."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/sse2_movq'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '8ea08159a362301345078ac9c01907160321546b48f05a6fc2ac71f967588931', 'exact reviewed literal MOVQ catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"]+)",([0-9,]+),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\),\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},\{([^}]*)\}\},', line)
        need(match is not None, 'closed literal MOVQ row')
        numbers = [int(n) for n in match[2].split(',')]
        need(len(numbers) == 8, 'exact MOVQ fields')
        length, code, xmm, store, memory, gpr, tail, offset = numbers
        input_gpr, expected_gpr = int(match[3], 16), int(match[4], 16)
        blobs = [bytes(int(n, 16) for n in match[k].split(',')) for k in (5, 6, 7, 8, 9)]
        group = 1 if xmm == 9 else 2 if xmm == 0 else 0
        need([len(b) for b in blobs] == [length, 16, 8, 16, 8] and
             1 <= tail <= length == 5 and store in (0, 1) and memory in (0, 1) and
             xmm in (0, 1, 9) and gpr == (7 if memory else 6)+(8 if group == 1 else 0) and
             (group != 2 or (store == 1 and memory == 0)) and input_gpr >> 32,
             'closed literal MOVQ operands')
        expected_offset = ((4088 if (group == 0 and not store) or (group == 1 and store) else 67)
                           if memory else 128+8*store)
        need(offset == expected_offset, 'actual guarded/unaligned data geometry')
        raw = bytes([0x66, 0x4d if group == 1 else 0x48, 0x0f, 0x7e if store else 0x6e,
                     0xc6 if group == 2 else 0x0f if memory else 0xce])
        xmm_result = blobs[1] if store else (blobs[2] if memory else input_gpr.to_bytes(8, 'little'))+bytes(8)
        memory_result = blobs[1][:8] if store and memory else blobs[2]
        register_result = int.from_bytes(blobs[1][:8], 'little') if store and not memory else input_gpr
        need(code == (1821 if store else 1582) and blobs[0] == raw and
             blobs[3] == xmm_result and blobs[4] == memory_result and expected_gpr == register_result,
             'literal encoding, upper64 clear and exact eight-byte/full64 effects')
        rows.append(dict(name=match[1], code=code, xmm=xmm, store=store, memory=memory,
                         gpr=gpr, tail=tail, length=length, bytes=raw.hex()))
    counts = dict(new_pairs=len(rows), loads=sum(not r['store'] for r in rows),
                  stores=sum(r['store'] for r in rows), registers=sum(not r['memory'] for r in rows),
                  memory=sum(r['memory'] for r in rows),
                  page_ending_pairs=sum(r['tail'] == r['length'] for r in rows),
                  crossing_pairs=sum(r['tail'] < r['length'] for r in rows))
    need(counts == dict(new_pairs=45, loads=20, stores=25, registers=25, memory=20,
                       page_ending_pairs=9, crossing_pairs=36) and
         [r['xmm'] for r in rows] == [1]*20+[9]*20+[0]*5 and
         rows[0]['bytes'] == '66480f6ece' and rows[-1]['bytes'] == '66480f7ec6',
         'all nine exact encodings, including both promotions and actual loader opcode')
    for raw in sorted({r['bytes'] for r in rows}):
        need([r['tail'] for r in rows if r['bytes'] == raw] == [5, 1, 2, 3, 4],
             'each admitted source ending and every crossing split')
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
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/sse2_movq/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['sse2-movq-0'], ['sse2-movq-1'], ['sse2-movq-2']]+[['sse2-movq-0']]*2,
            'native_environment_controls': ['absent', 'absent', 'absent', 'movq-load-fault', 'movq-store-fault'],
            'control_variable': 'LI2_MOVQ_CONTROL',
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
    name = stamp+'-page-selected-sse2-movq-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-sse2-movq-oracle-v1', 'status': 'failed',
        'scope': 'Nine narrowly encoded legacy MOVQ r/m64 forms: 45 new native/TF pairs plus three startup pairs in21/21/6-record cohorts, with47 old and28 new supplied refusals. Actual66480f7ec6 and both explicitly promoted MOVD neighbor bytes have independent literal64-bit effects and every ending/crossing split. Two actual native/stepped memory-fault comparisons remain failed. Complete full-state/literal/guarded-eight-byte records remain private. All old suites including MOVD38pairs/twofaults plus its explicit promotions remain separately required. Other MOVQ encodings, MMX, VEX and EVEX excluded. No loader/performance/full-B2 credit.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'movq_pairs': 0,
                   'load_pairs': 0, 'store_pairs': 0, 'register_pairs': 0, 'memory_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_sse2_movq.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('sse2-movq-0', 'sse2-movq-1', 'sse2-movq-2')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 5, 'complete finite MOVQ protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'group2', 'movq-load-fault', 'movq-store-fault'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['sse2-movq-0'], ['sse2-movq-1'], ['sse2-movq-2']]+[['sse2-movq-0']]*2 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}, {}]+[{'LI2_MOVQ_CONTROL': n} for n in ('movq-load-fault', 'movq-store-fault')] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact MOVQ names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '6e415e976021b299441e0c9cb1669679864741a981622a27ef510e9c93db19e1',
             'exact reviewed five-command outcomes')
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
            positive = name in ('group0', 'group1', 'group2')
            used = (6 if name == 'group2' else 21) if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['movq_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['load_pairs'] += 0 if name == 'group2' else 10
                record['totals']['store_pairs'] += 5 if name == 'group2' else 10
                record['totals']['register_pairs'] += 5 if name == 'group2' else 10
                record['totals']['memory_pairs'] += 0 if name == 'group2' else 10
                record['totals']['new_page_ending_pairs'] += 1 if name == 'group2' else 4
                record['totals']['new_crossing_pairs'] += 4 if name == 'group2' else 16
                record['totals'].update(supplied_refusal_encodings=75,
                    old_refusal_encodings=47, new_refusal_encodings=28)
            else:
                need(any(data[end:end+header['sample_bytes']]), 'retain actual failed-operation sample')
                # The authenticated C path requires actual native #PF and the
                # stepped unexpected frame, revoke/sync, unchanged state and
                # retained failed borrow before emitting this exact outcome.
                # Its full retained sample is not a successful continuation.
                result['verified_memory_fault'] = True
                record['totals']['verified_memory_fault_commands'] += 1
                record['totals']['actual_native_failed_operations'] += 1
                record['totals']['actual_stepped_failed_operations'] += 1
                record['totals']['additional_negative_command_selftests'] += 1
            result['accepted'] = True
        need(record['totals'] == dict(positive_pairs=48, generic_pairs=45, movq_pairs=45,
                 positive_selftest_pairs=3, supplied_refusal_encodings=75, old_refusal_encodings=47,
                 new_refusal_encodings=28, load_pairs=20, store_pairs=25, register_pairs=25, memory_pairs=20,
                 new_page_ending_pairs=9, new_crossing_pairs=36,
                 verified_memory_fault_commands=2, actual_native_failed_operations=2,
                 actual_stepped_failed_operations=2, additional_negative_command_selftests=2,
                 executed_refusal_checks=375) and
             len(record['cases']) == 5 and all(c['accepted'] for c in record['cases']),
             'complete21/21/6pair cohorts and two failed-memory commands')
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
