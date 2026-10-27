#!/usr/bin/env python3
"""Canonical RIP-relative LOCK ADD m32/imm8 oracle and two genuine failed RMW controls."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/lock_add'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '144dbefad97cae8ef528eee01c5299d18519daf8615c3403949679e0fdd94bda', 'exact reviewed literal LOCK ADD catalogue')
    rows = []
    patterns = [('plain', 1, 1), ('carry_zero', 0xffffffff, 1),
                ('signed_overflow', 0x7fffffff, 1), ('negative_overflow', 0x80000000, -1)]
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"\n]+)",([0-9,]+),\{([^}]*)\}\},', line)
        need(match is not None, 'closed literal LOCK ADD row')
        fields = [int(n) for n in match[2].split(',')]
        need(len(fields) == 6, 'exact literal fields')
        tail, immediate, value, output, flags, displacement = fields
        index = len(rows)
        need(index < 32, 'bounded literal row count')
        pattern, seed, signed_imm = patterns[index//8]
        expected_tail = [8, 1, 2, 3, 4, 5, 6, 7][index%8]
        rhs = signed_imm & 0xffffffff
        total = seed+rhs
        expected = total & 0xffffffff
        signed_seed = seed if seed < 1 << 31 else seed-(1 << 32)
        signed_total = signed_seed+signed_imm
        expected_flags = (int(total > 0xffffffff) | (int((expected & 255).bit_count()%2 == 0) << 2) |
                          (int((seed & 15)+(rhs & 15) > 15) << 4) | (int(expected == 0) << 6) |
                          ((expected >> 31) << 7) | (int(not -(1 << 31) <= signed_total < 1 << 31) << 11))
        raw = bytes(int(n, 16) for n in match[3].split(','))
        expected_disp = 3*4096+56+expected_tail
        need(match[1] == pattern+'-tail'+str(expected_tail) and
             fields == [expected_tail, signed_imm & 255, seed, expected, expected_flags, expected_disp] and
             raw == bytes.fromhex('f08305')+expected_disp.to_bytes(4, 'little', signed=True)+bytes([signed_imm & 255]),
             'literal sign extension, arithmetic flags, exact original-PC displacement and bytes')
        rows.append(dict(name=match[1], class_id=index//8, code=248, tail=tail,
                         immediate=signed_imm, input=value, output=output, flags=flags,
                         displacement=displacement, bytes=raw.hex()))
    counts = dict(new_pairs=len(rows), immediate_positive_pairs=sum(r['immediate'] == 1 for r in rows),
                  immediate_negative_pairs=sum(r['immediate'] == -1 for r in rows),
                  page_ending_pairs=sum(r['tail'] == 8 for r in rows),
                  crossing_pairs=sum(r['tail'] < 8 for r in rows))
    need(counts == dict(new_pairs=32, immediate_positive_pairs=24, immediate_negative_pairs=8,
                       page_ending_pairs=4, crossing_pairs=28), 'complete arithmetic and fetch geometry cohorts')
    declared = json.loads((FIXTURE/'CASES.json').read_bytes())
    need(declared == dict(schema_version=1, code=248, mask=0x8d5, source_length=8, new_pairs=32,
                         groups=2, pairs_per_group=17, ending=4, crossing=28, rows=rows),
         'exact JSON and C literal catalogue agreement')
    return dict(source=binding, counts=counts, rows_sha256=digest(rows))


def fault_trailer(data, negative, readonly):
    need(len(data) == 16512, 'complete fixed failed-operand trailer')
    fields = list(struct.unpack_from('<16Q', data))
    need(fields[:3] == [0x314b434f4c32494c, 1, 16512], 'exact trailer identity')
    if not negative:
        need(not any(data[24:]), 'positive has no fabricated failed-operand observation')
        return dict(bytes=len(data), observed=False)
    prot, error = (1, 7) if readonly else (0, 6)
    need(fields[3] == 1 and fields[4] == fields[5]+64 and fields[5] > 0 and
         fields[5]%4096 == 0 and fields[6:16] == [prot, 1, prot, prot, prot, prot, 1, 1, error, error],
         'actual operand/protection/error prefix and both independent observations')
    expected = bytearray((i*13+0x5b)&255 for i in range(4096))
    expected[64:68] = (1).to_bytes(4, 'little')
    need(all(data[128+4096*i:128+4096*(i+1)] == expected for i in range(4)),
         'all actual pre/post native/step failed-operand bytes unchanged')
    return dict(bytes=len(data), observed=True, memory_bytes_per_snapshot=4096,
                snapshots=4, protection=prot, native_error=error, stepped_error=error)


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
                'header': c.get('header'), 'record': c.get('record'), 'fault_trailer': c.get('fault_trailer')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/lock_add/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['lock-add-0'], ['lock-add-1']]+[['lock-add-0']]*2,
            'native_environment_controls': ['absent', 'absent', 'no-access', 'read-only'],
            'control_variable': 'LI2_LOCK_ADD_CONTROL',
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
    name = stamp+'-page-selected-lock-add-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-lock-add-oracle-v1', 'status': 'failed',
        'scope': 'Canonical f0 83 05 disp32 imm8 atomic ADD m32 at the original PC. Two additive 17-pair cohorts give 32 arithmetic pairs and two startup pairs, with 47 unchanged and 16 new supplied refusals per command. Genuine no-access and read-only RMW faults remain failed operations. Full source-bound native/TF state comparisons and actual private records are retained. Prior suites remain separately required. Singleton profile; no split-lock, concurrent atomicity, real-loader, performance or full-B2 qualification.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'lock_add_pairs': 0,
                   'immediate_positive_pairs': 0, 'immediate_negative_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_lock_add.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('lock-add-0', 'lock-add-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 4, 'complete finite LOCK ADD protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'no-access', 'read-only'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['lock-add-0'], ['lock-add-1']]+[['lock-add-0']]*2 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}]+[{'LI2_LOCK_ADD_CONTROL': n} for n in ('no-access', 'read-only')] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact LOCK ADD names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '172f09dba6c11e38f5401907847a17f328e262467f751ae3720ada6ea0ba0d79',
             'exact reviewed four-command outcomes')
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
            need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40+16512 and len(data) < 16 << 20,
                 'complete actual record extent')
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            # The C fixture's authenticated binary enforces full-state effects;
            # retain all complete samples for independent actual-layout replay.
            positive = name in ('group0', 'group1')
            used = 17 if positive else 1
            result['fault_trailer'] = fault_trailer(data[-16512:], not positive, name == 'read-only')
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['lock_add_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['immediate_positive_pairs'] += 16 if name == 'group0' else 8
                record['totals']['immediate_negative_pairs'] += 0 if name == 'group0' else 8
                record['totals']['new_page_ending_pairs'] += 2
                record['totals']['new_crossing_pairs'] += 14
                record['totals'].update(supplied_refusal_encodings=63,
                    old_refusal_encodings=47, new_refusal_encodings=16)
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
        need(record['totals'] == dict(positive_pairs=34, generic_pairs=32, lock_add_pairs=32,
                 positive_selftest_pairs=2, supplied_refusal_encodings=63, old_refusal_encodings=47,
                 new_refusal_encodings=16, immediate_positive_pairs=24, immediate_negative_pairs=8,
                 new_page_ending_pairs=4, new_crossing_pairs=28,
                 verified_memory_fault_commands=2, actual_native_failed_operations=2,
                 actual_stepped_failed_operations=2, additional_negative_command_selftests=2,
                 executed_refusal_checks=252) and
             len(record['cases']) == 4 and all(c['accepted'] for c in record['cases']),
             'complete two seventeen-pair cohorts and two failed atomic-memory operations')
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
