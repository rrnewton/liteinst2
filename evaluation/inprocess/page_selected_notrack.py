#!/usr/bin/env python3
"""Finite original-address NOTRACK register CALL/JMP state and return-word oracle."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/notrack'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == 'fca2cb7212f8e4c7e230cc906655429af496c45de7ce007749f1aa865302cdbc', 'exact reviewed NOTRACK input and refusal catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{([0-9,]+),\{([^}]+)\}\},', line)
        need(match is not None, 'closed NOTRACK positive row')
        fields = [int(x) for x in match[1].split(',')]
        need(len(fields) == 5, 'five exact NOTRACK row fields')
        length, tail, code, register, call = fields
        encoding = bytes(int(x, 16) for x in match[2].split(','))
        need(call in (0, 1) and 0 <= register < 16 and register != 4 and
             length == (3 if register < 8 else 4) and 1 <= tail <= length and
             code == (759 if call else 765) and
             encoding == bytes([0x3e]+([0x41] if register >= 8 else [])+
                               [0xff, (0xd0 if call else 0xe0)|(register & 7)]),
             'exact NOTRACK register bytes; no ignored prefix or RSP')
        rows.append(dict(length=length, tail=tail, code=code, register=register,
                         call=call, bytes=encoding.hex()))
    need(len(rows) == 40 and rows[0]['bytes'] == '3effe0', 'forty literal branches including observed form')
    registers = [r for r in range(16) if r != 4]
    for group in range(2):
        group_rows = rows[group*20:(group+1)*20]
        need(all(r['call'] == group for r in group_rows) and
             [r['register'] for r in group_rows[:15]] == registers and
             all(r['tail'] == r['length'] for r in group_rows[:15]) and
             [(r['register'], r['tail']) for r in group_rows[15:]] ==
             [(0, 1), (0, 2), (8, 1), (8, 2), (8, 3)],
             'every supported register and every three/four-byte crossing split')
    return dict(source=binding, counts=dict(new_pairs=40, jump_pairs=20, call_pairs=20,
        registers_per_operation=15, page_ending_pairs=30, crossing_pairs=10,
        old_refusals=47, new_refusals=44), rows_sha256=digest(rows))

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
    name = stamp+'-page-selected-notrack-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-notrack-oracle-v1', 'status': 'failed',
        'scope': 'Two additive 21-pair original-address near-register NOTRACK cohorts: 40 branch pairs plus two startup pairs. Fifteen non-RSP registers per operation; every three/four-byte crossing split. Exact actual target and original CALL return word supplement unchanged full-state comparisons. 47 old and 44 new supplied refusals; old suites and three actual failed generic operations remain separately required. Existing no-user-CET profile only; SHSTK status is not independent IBT status. No RSP-source, memory-NOTRACK, target-body/RET execution, transparent-fault, loader-completion, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'notrack_pairs': 0, 'positive_selftest_pairs': 0,
                   'jump_pairs': 0, 'call_pairs': 0, 'literal_original_return_words': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'executed_refusal_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_notrack.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('notrack-0', 'notrack-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 2, 'complete finite NOTRACK protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] == ['group0', 'group1'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0] and
             [c['argv'] for c in outcomes['commands']] == [['notrack-0'], ['notrack-1']] and
             [c['environment_delta'] for c in outcomes['commands']] == [{}, {}] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact NOTRACK names, environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '4072ca20074e642fa465d14201749ac476d4814b18705c4364aacd650ceca110', 'exact reviewed two-command outcomes')
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False,
                      'actual_exit': None, 'operation_completed': False,
                      'literal_original_return_words': 0}
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
            # All 21 complete samples and the unchanged zero negative slot
            # remain available for independent actual-DWARF endpoint replay.
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
            result['operation_completed'] = True
            result['literal_original_return_words'] = 20 if name == 'group1' else 0
            result['accepted'] = True
            total = record['totals']
            total['positive_pairs'] += header['completed']
            total['notrack_pairs'] += 20
            total['positive_selftest_pairs'] += 1
            total['jump_pairs'] += 20 if name == 'group0' else 0
            total['call_pairs'] += 20 if name == 'group1' else 0
            total['literal_original_return_words'] += result['literal_original_return_words']
            total['new_page_ending_pairs'] += 15
            total['new_crossing_pairs'] += 5
            total['executed_refusal_checks'] += header['refusals']
            total.update(supplied_refusal_encodings=91, old_refusal_encodings=47, new_refusal_encodings=44)
        need(record['totals'] == dict(positive_pairs=42, notrack_pairs=40, positive_selftest_pairs=2,
                 jump_pairs=20, call_pairs=20, literal_original_return_words=20,
                 new_page_ending_pairs=30, new_crossing_pairs=10,
                 supplied_refusal_encodings=91, old_refusal_encodings=47,
                 new_refusal_encodings=44, executed_refusal_checks=182) and
             len(record['cases']) == 2 and all(c['accepted'] and c['operation_completed'] for c in record['cases']),
             'complete two twenty-one-pair NOTRACK cohorts')
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
