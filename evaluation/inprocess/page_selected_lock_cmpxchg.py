#!/usr/bin/env python3
"""Exact LOCK CMPXCHG dword [R13+0],EDX oracle and four genuine failed RMW controls."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/lock_cmpxchg'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == 'c1a4011007510520a3773997869a4bddd712b4bb487829d77e2a4a2d04ce3309', 'exact reviewed literal CMPXCHG catalogue')
    patterns = [
        ('success_store', 0xa5a5a5a500000001, 1, 0xfaceb00cdeadbeef, 64),
        ('success_same', 0x01234567ffffffff, 0xffffffff, 0xcafe9876ffffffff, 4092),
        ('failure_borrow', 0xfedcba9800000000, 1, 0x12345678abcdef01, 65),
        ('failure_overflow', 0x1111222280000000, 1, 0x8765432112345678, 64),
        ('failure_borrow_overflow', 0x333344447fffffff, 0xffffffff, 0x10203040aabbccdd, 4092),
        ('failure_plain', 0x5555666612345678, 0x12345670, 0xdecafbad01020304, 65),
    ]
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"\n]+)",(\d+),(\d+),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\),(\d+)U,(\d+)U,(\d+)U,\{([^}]*)\}\},', line)
        need(match is not None, 'closed literal CMPXCHG row')
        index = len(rows)
        need(index < 36, 'bounded literal row count')
        pattern, rax, memory, rdx, offset = patterns[index//6]
        tail = [6, 1, 2, 3, 4, 5][index%6]
        accumulator = rax & 0xffffffff
        difference = (accumulator-memory) & 0xffffffff
        signed_a = accumulator if accumulator < 1 << 31 else accumulator-(1 << 32)
        signed_m = memory if memory < 1 << 31 else memory-(1 << 32)
        flags = (int(accumulator < memory) | (int((difference & 255).bit_count()%2 == 0) << 2) |
                 (int((accumulator & 15) < (memory & 15)) << 4) | (int(difference == 0) << 6) |
                 ((difference >> 31) << 7) | (int(not -(1 << 31) <= signed_a-signed_m < 1 << 31) << 11))
        matched = accumulator == memory
        rax_after = rax if matched else memory
        output = rdx & 0xffffffff if matched else memory
        raw = bytes(int(n, 16) for n in match[10].split(','))
        need(match[1] == pattern+'-tail'+str(tail) and
             [int(match[i]) for i in (2, 3, 7, 8, 9)] == [tail, offset, memory, output, flags] and
             [int(match[i], 16) for i in (4, 5, 6)] == [rax, rdx, rax_after] and
             raw == bytes.fromhex('f0410fb15500'),
             'literal compare, full RAX width, memory result, subtraction flags and exact original bytes')
        rows.append(dict(name=match[1], class_id=index//6, code=2075, tail=tail, offset=offset,
                         rax=rax, rdx=rdx, input=memory, output=output, rax_after=rax_after,
                         flags=flags, matched=matched, bytes=raw.hex()))
    counts = dict(new_pairs=len(rows), success_pairs=sum(x['matched'] for x in rows),
                  failure_pairs=sum(not x['matched'] for x in rows),
                  page_ending_pairs=sum(x['tail'] == 6 for x in rows),
                  crossing_pairs=sum(x['tail'] < 6 for x in rows))
    need(counts == dict(new_pairs=36, success_pairs=12, failure_pairs=24,
                       page_ending_pairs=6, crossing_pairs=30), 'complete comparison and fetch geometry cohorts')
    declared = json.loads((FIXTURE/'CASES.json').read_bytes())
    need(declared == dict(schema_version=1, code=2075, mask=0x8d5, source_length=6, new_pairs=36,
                         groups=2, pairs_per_group=19, ending=6, crossing=30,
                         success_pairs=12, failure_pairs=24, rows=rows),
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
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/lock_cmpxchg/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['lock-cmpxchg-0'], ['lock-cmpxchg-1']]+[['lock-cmpxchg-0']]*4,
            'native_environment_controls': ['absent', 'absent', 'no-access-match', 'read-only-match', 'no-access-mismatch', 'read-only-mismatch'],
            'control_variable': 'LI2_LOCK_CMPXCHG_CONTROL',
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
    name = stamp+'-page-selected-lock-cmpxchg-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-lock-cmpxchg-oracle-v1', 'status': 'failed',
        'scope': 'Only f0410fb15500 atomic CMPXCHG dword [R13+0],EDX at the original PC. Two additive 19-pair cohorts give 36 compare-success/failure pairs and two startup pairs, with 47 unchanged and 24 neighboring supplied refusals per command. Four genuine no-access/read-only RMW faults cover both would-match and would-mismatch inputs and remain failed operations. Full source-bound native/TF state comparisons and complete private records are retained. Prior suites remain separately required. Singleton profile; no split-lock, concurrent atomicity, real-program completion, performance or full-B2 qualification.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'promoted_acceptance_checks': 0, 'lock_cmpxchg_pairs': 0,
                   'comparison_success_pairs': 0, 'comparison_failure_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_lock_cmpxchg.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('lock-cmpxchg-0', 'lock-cmpxchg-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 6, 'complete finite six-command CMPXCHG protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'no-access-match', 'read-only-match', 'no-access-mismatch', 'read-only-mismatch'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['lock-cmpxchg-0'], ['lock-cmpxchg-1']]+[['lock-cmpxchg-0']]*4 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}]+[{'LI2_LOCK_CMPXCHG_CONTROL': n} for n in ('no-access-match', 'read-only-match', 'no-access-mismatch', 'read-only-mismatch')] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact LOCK CMPXCHG names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '45e6ed6865a0358fde5e18fda231ef8a56ee829729628589db208d20d13c72c0',
             'exact reviewed six-command outcomes')
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
            used = 19 if positive else 1
            result['fault_trailer'] = fault_trailer(data[-16512:], not positive, name.startswith('read-only'))
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['lock_cmpxchg_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['comparison_success_pairs'] += 12 if name == 'group0' else 0
                record['totals']['comparison_failure_pairs'] += 6 if name == 'group0' else 18
                record['totals']['new_page_ending_pairs'] += 3
                record['totals']['new_crossing_pairs'] += 15
                record['totals'].update(supplied_refusal_encodings=71,
                    old_refusal_encodings=47, new_refusal_encodings=24)
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
        need(record['totals'] == dict(positive_pairs=38, generic_pairs=36, lock_cmpxchg_pairs=36,
                 positive_selftest_pairs=2, supplied_refusal_encodings=71, old_refusal_encodings=47,
                 new_refusal_encodings=24, comparison_success_pairs=12, comparison_failure_pairs=24,
                 new_page_ending_pairs=6, new_crossing_pairs=30,
                 verified_memory_fault_commands=4, actual_native_failed_operations=4,
                 actual_stepped_failed_operations=4, additional_negative_command_selftests=4,
                 executed_refusal_checks=426, promoted_acceptance_checks=0) and
             len(record['cases']) == 6 and all(c['accepted'] for c in record['cases']),
             'complete two nineteen-pair cohorts and four failed atomic-memory operations')
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
