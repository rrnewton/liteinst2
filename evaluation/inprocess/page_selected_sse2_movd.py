#!/usr/bin/env python3
"""Finite legacy MOVD register/m32 oracle and two genuine failed-memory controls."""
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
FIXTURE = REPO/'tools/page-entry/selected/tests/sse2_movd'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def catalogue():
    path = FIXTURE/'cases.inc'
    binding = fact(path)
    need(binding['sha256'] == 'fcd9a92587d640d85aa500fbb8e7054972528c491950057dd793539ccfd111b4', 'exact reviewed literal MOVD catalogue')
    rows = []
    for line in path.read_text().splitlines():
        if not line.startswith('  {'):
            continue
        match = re.fullmatch(r'  \{"([^"]+)",([0-9,]+),UINT64_C\(0x([0-9a-f]{16})\),UINT64_C\(0x([0-9a-f]{16})\),\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},\{([^}]*)\},\{([^}]*)\}\},', line)
        need(match is not None, 'closed literal MOVD row')
        numbers = [int(n) for n in match[2].split(',')]
        need(len(numbers) == 8, 'exact MOVD fields')
        length, code, xmm, store, memory, gpr, tail, offset = numbers
        input_gpr, expected_gpr = int(match[3], 16), int(match[4], 16)
        blobs = [bytes(int(n, 16) for n in match[k].split(',')) for k in (5, 6, 7, 8, 9)]
        group = int(xmm == 9)
        need([len(b) for b in blobs] == [length, 16, 4, 16, 4] and
             1 <= tail <= length <= 5 and store in (0, 1) and memory in (0, 1) and
             xmm in (1, 9) and gpr == (7 if memory else 6)+8*group and input_gpr >> 32,
             'closed literal MOVD operands')
        expected_offset = ((4092 if (group == 0 and not store) or (group == 1 and store) else 67)
                           if memory else 128+4*store)
        need(offset == expected_offset, 'actual guarded/unaligned data geometry')
        raw = bytes([0x66]+([0x45] if group else [])+[0x0f, 0x7e if store else 0x6e,
                                                          0x0f if memory else 0xce])
        xmm_result = blobs[1] if store else (blobs[2] if memory else (input_gpr & 0xffffffff).to_bytes(4, 'little'))+bytes(12)
        memory_result = blobs[1][:4] if store and memory else blobs[2]
        register_result = int.from_bytes(blobs[1][:4], 'little') if store and not memory else input_gpr
        need(code == (1820 if store else 1581) and blobs[0] == raw and
             blobs[3] == xmm_result and blobs[4] == memory_result and expected_gpr == register_result,
             'literal encoding, zero extension and exact four-byte effects')
        rows.append(dict(name=match[1], code=code, xmm=xmm, store=store, memory=memory,
                         gpr=gpr, tail=tail, length=length, bytes=raw.hex()))
    counts = dict(new_pairs=len(rows), loads=sum(not r['store'] for r in rows),
                  stores=sum(r['store'] for r in rows), registers=sum(not r['memory'] for r in rows),
                  memory=sum(r['memory'] for r in rows),
                  page_ending_pairs=sum(r['tail'] == r['length'] for r in rows),
                  crossing_pairs=sum(r['tail'] < r['length'] for r in rows))
    need(counts == dict(new_pairs=36, loads=18, stores=18, registers=18, memory=18,
                       page_ending_pairs=8, crossing_pairs=28) and
         [r['xmm'] for r in rows] == [1]*16+[9]*20 and rows[0]['bytes'] == '660f6ece',
         'complete two-length encoding cohorts including actual loader opcode')
    for xmm, size in ((1, 4), (9, 5)):
        for store in (0, 1):
            for memory in (0, 1):
                need([r['tail'] for r in rows if r['xmm'] == xmm and r['store'] == store and r['memory'] == memory] ==
                     [size]+list(range(1, size)), 'each source ending and every crossing split')
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
                'promoted_acceptance_checks': c.get('promoted_acceptance_checks'),
                'header': c.get('header'), 'record': c.get('record')} for c in record['cases']],
        command_recipe={
            'selected_build': ['sh', 'tools/page-entry/selected/build.sh'],
            'fixture_build': ['sh', 'tools/page-entry/selected/tests/sse2_movd/build.sh',
                              '<retained decoder.a>', '<private run directory>', 'tools/page-entry/selected'],
            'native': [['sse2-movd-0'], ['sse2-movd-1']]+[['sse2-movd-0']]*2,
            'native_environment_controls': ['absent', 'absent', 'movd-load-fault', 'movd-store-fault'],
            'control_variable': 'LI2_MOVD_CONTROL',
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
    name = stamp+'-page-selected-sse2-movd-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-sse2-movd-oracle-v2', 'status': 'failed',
        'scope': 'Unchanged MOVD38 original-PC pairs and two actual native/stepped failed-memory comparisons. All24 historical neighbor rows remain:22 refuse and two exact REX.W MOVQ rows require positive classification, counted separately. Their actual64-bit effects require the additive MOVQ suite. All47 generic refusals and full raw state comparisons remain. Other old suites remain separately required; no loader/performance/full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0,
                   'supplied_refusal_encodings': 0, 'old_refusal_encodings': 0,
                   'new_refusal_encodings': 0, 'movd_pairs': 0,
                   'load_pairs': 0, 'store_pairs': 0, 'register_pairs': 0, 'memory_pairs': 0,
                   'new_page_ending_pairs': 0, 'new_crossing_pairs': 0,
                   'verified_memory_fault_commands': 0, 'actual_native_failed_operations': 0,
                   'actual_stepped_failed_operations': 0, 'additional_negative_command_selftests': 0,
                   'executed_refusal_checks': 0, 'promoted_acceptance_checks_per_command': 0,
                   'executed_promoted_acceptance_checks': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_sse2_movd.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('sse2-movd-0', 'sse2-movd-1')}
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
        need(len(names) == 17 and len(outcomes['commands']) == 4, 'complete finite MOVD protocol')
        need(outcomes['schema_version'] == 1 and outcomes['record_header_format'] == '<17Q' and
             names == ['magic', 'version', 'header_bytes', 'sample_bytes', 'pairs', 'completed', 'control',
                       'xcr0', 'xsave_bytes', 'refusals', 'failed_refusal', 'decoder_result',
                       'expected_failure_verified', 'fixture_failure', 'owner_failure',
                       'owner_detail_abs', 'owner_detail_negative'] and
             [c['name'] for c in outcomes['commands']] ==
             ['group0', 'group1', 'movd-load-fault', 'movd-store-fault'] and
             [c['exit'] for c in outcomes['commands']] == [0, 0, 125, 125] and
             [c['argv'] for c in outcomes['commands']] == [['sse2-movd-0'], ['sse2-movd-1']]+[['sse2-movd-0']]*2 and
             [c['environment_delta'] for c in outcomes['commands']] ==
             [{}, {}]+[{'LI2_MOVD_CONTROL': n} for n in ('movd-load-fault', 'movd-store-fault')] and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_size_bytes=16 << 20, wall_seconds=15, cpu_affinity_count=1),
             'exact MOVD names, input environments, exits, header schema and bounds')
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '7adcafe5ecdf62f4f1709e88465a832ac5d26bd5778df50914357d22d6540f79',
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
            need(out.startswith(b'LI2_MOVD_PROMOTED_ACCEPTANCES 2\n'), 'both explicit MOVQ promotions executed')
            result['promoted_acceptance_checks'] = 2
            record['totals']['promoted_acceptance_checks_per_command'] = 2
            record['totals']['executed_promoted_acceptance_checks'] += 2
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
            positive = name in ('group0', 'group1')
            used = (17 if name == 'group0' else 21) if positive else 1
            start = header['header_bytes']+used*header['sample_bytes']
            end = header['header_bytes']+21*header['sample_bytes']
            need(not any(data[start:end]), 'all unused original sample slots remain zero')
            record['totals']['executed_refusal_checks'] += header['refusals']
            if positive:
                need(not any(data[end:end+header['sample_bytes']]), 'positive has no negative sample')
                result['operation_completed'] = True
                record['totals']['positive_pairs'] += used
                record['totals']['generic_pairs'] += used-1
                record['totals']['movd_pairs'] += used-1
                record['totals']['positive_selftest_pairs'] += 1
                record['totals']['load_pairs'] += (used-1)//2
                record['totals']['store_pairs'] += (used-1)//2
                record['totals']['register_pairs'] += (used-1)//2
                record['totals']['memory_pairs'] += (used-1)//2
                record['totals']['new_page_ending_pairs'] += 4
                record['totals']['new_crossing_pairs'] += used-5
                record['totals'].update(supplied_refusal_encodings=69,
                    old_refusal_encodings=47, new_refusal_encodings=22)
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
        need(record['totals'] == dict(positive_pairs=38, generic_pairs=36, movd_pairs=36,
                 positive_selftest_pairs=2, supplied_refusal_encodings=69, old_refusal_encodings=47,
                 new_refusal_encodings=22, load_pairs=18, store_pairs=18, register_pairs=18, memory_pairs=18,
                 new_page_ending_pairs=8, new_crossing_pairs=28,
                 verified_memory_fault_commands=2, actual_native_failed_operations=2,
                 actual_stepped_failed_operations=2, additional_negative_command_selftests=2,
                 executed_refusal_checks=276, promoted_acceptance_checks_per_command=2,
                 executed_promoted_acceptance_checks=8) and
             len(record['cases']) == 4 and all(c['accepted'] for c in record['cases']),
             'complete seventeen/twenty-one pair cohorts and two failed-memory commands')
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
