#!/usr/bin/env python3
"""Finite BSF/BSR state oracle with exact native comparison and two failed-memory controls."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/bitscan'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == '3ef557cc667bed00b8e899bc3e266950292f0e49f4ea3b06f48b43a6a3fa0f86',
         'exact reviewed literal BSF/BSR catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"]+)",([0-9,]+),\{([^}]*)\},UINT64_C\(0x([0-9a-f]+)\),(\d+)\},', line)
        need(match is not None, 'closed literal bitscan row')
        numbers = [int(n) for n in match[2].split(',')]
        need(len(numbers) == 8, 'exact bitscan row fields')
        length, code, width, reverse, destination, source_register, memory, tail = numbers
        encoding = bytes(int(n, 16) for n in match[3].split(','))
        operand, index = int(match[4], 16), int(match[5])
        need(len(encoding) == length and 1 <= tail <= length <= 5 and
             width in (16, 32, 64) and reverse in (0, 1) and memory in (0, 1) and
             destination < 16 and source_register < 16 and operand < 1 << width and
             code == (2124 if reverse else 2118)+(16, 32, 64).index(width),
             'closed literal bitscan row values')
        set_bits = [bit for bit in range(width) if operand & (1 << bit)]
        need(index == ((max(set_bits) if reverse else min(set_bits)) if set_bits else 0),
             'independent literal nonzero bit index; zero is only a table placeholder')
        rows.append({'name': match[1], 'length': length, 'code': code, 'width': width,
                     'memory': memory, 'zero': operand == 0, 'tail': tail,
                     'bytes': encoding.hex(), 'input': operand,
                     'nonzero_literal_index': index if operand else None})
    counts = {'new_pairs': len(rows), 'register_pairs': sum(not r['memory'] for r in rows),
              'memory_pairs': sum(r['memory'] for r in rows),
              'zero_pairs': sum(r['zero'] for r in rows),
              'nonzero_pairs': sum(not r['zero'] for r in rows),
              'page_ending_pairs': sum(r['tail'] == r['length'] for r in rows),
              'crossing_pairs': sum(r['tail'] < r['length'] for r in rows)}
    need(counts == dict(new_pairs=48, register_pairs=24, memory_pairs=24,
                        zero_pairs=12, nonzero_pairs=36, page_ending_pairs=12, crossing_pairs=36) and
         all(len(rows[g*16:(g+1)*16]) == 16 and
             all(r['width'] == (16, 32, 64)[g] for r in rows[g*16:(g+1)*16]) for g in range(3)) and
         rows[16]['bytes'] == '0fbcc2', 'exact literal BSF/BSR catalogue counts')
    return {'source': binding, 'counts': counts, 'rows_sha256': digest(rows)}

def publish(path, record, receipt):
    # Small numeric/hash projection. Complete command rows, raw state records,
    # actual ELF/DWARF, tool pins and cleanup outcomes remain private and bound.
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        case_count=len(record['cases']), cases_sha256=digest(record['cases']),
        inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        elf_sha256=digest(record.get('elf', {})),
        catalogue=record.get('catalogue'),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts_sha256=digest(build.get('artifacts', {})),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']))
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
    name = stamp+'-page-selected-bitscan-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-bitscan-oracle-v1', 'status': 'failed',
        'scope': 'Three additive 17-pair BSF/BSR cohorts: 48 new native/TF pairs plus three startup pairs, 47 old and 24 new supplied encoding refusals. Two actual native/stepped memory-fault comparisons remain failed operations. Literal effects constrain ZF and nonzero destination only; exact whole native/TF comparisons retain every actual flag and zero-input destination. Complete source-bound C state predicates and private raw records are retained. All original suites remain separately required. No every-encoding, loader, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'bitscan_pairs': 0,
                   'register_pairs': 0, 'memory_pairs': 0, 'zero_pairs': 0, 'nonzero_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_bitscan.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('bitscan-0', 'bitscan-1', 'bitscan-2')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 5, 'complete finite bitscan protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'group2', 'bsf-load-fault', 'bsr-load-fault'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] ==
             [['bitscan-0'], ['bitscan-1'], ['bitscan-2'], ['bitscan-2'], ['bitscan-2']] and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}, {}, {'LI2_BITSCAN_CONTROL': 'bsf-load-fault'}, {'LI2_BITSCAN_CONTROL': 'bsr-load-fault'}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact bitscan names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '988be0929fc5b5c63090a5d7e4ab13e4b22b554cb14509ad16f9992afd1e1f3e',
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
            used = 17 if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += 17
                record['totals']['generic_pairs'] += 16
                record['totals']['bitscan_pairs'] += 16
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['register_pairs'] += 8
                record['totals']['memory_pairs'] += 8
                record['totals']['zero_pairs'] += 4
                record['totals']['nonzero_pairs'] += 12
                record['totals']['new_page_ending_pairs'] += 4
                record['totals']['new_crossing_pairs'] += 12
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
        need(record['totals'] == dict(positive_pairs=51, generic_pairs=48, bitscan_pairs=48,
                 positive_selftest_pairs=3, supplied_refusal_encodings=71, old_refusal_encodings=47,
                 new_refusal_encodings=24, register_pairs=24, memory_pairs=24, zero_pairs=12, nonzero_pairs=36,
                 new_page_ending_pairs=12, new_crossing_pairs=36,
                 verified_memory_fault_commands=2, actual_native_failed_operations=2,
                 actual_stepped_failed_operations=2, additional_negative_command_selftests=2,
                 executed_refusal_checks=355) and
             len(record['cases']) == 5 and all(c['accepted'] for c in record['cases']),
             'complete three seventeen-pair cohorts and two failed-memory commands')
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
