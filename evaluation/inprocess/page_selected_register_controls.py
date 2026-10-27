#!/usr/bin/env python3
"""Fourteen terminal register publisher/owner controls; no completion credit."""
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
from page_selected import ENV, fact, need, save, elf
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register import digest, publish, executable_layout

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/register_run_controls'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def control_layout(path, symbols):
    base = executable_layout(path, symbols)
    matches = [line.split() for line in symbols.decode('ascii').splitlines()
               if line.split()[-1:] == ['ctl']]
    need(len(matches) == 1 and len(matches[0]) == 4 and matches[0][2] in ('b', 'B'),
         'unique actual control BSS symbol')
    address, size = int(matches[0][0], 16), int(matches[0][1], 16)
    _, _, segments = elf(path)
    need(size >= 120 and sum(p[0] == 1 and p[1] == 6 and
         p[3] <= address < address+size <= p[3]+p[6] for p in segments) == 1 and
         all(address+size <= v['address'] or v['address']+v['bytes'] <= address
             for v in base['symbols'].values()), 'whole distinct actual control record extent')
    for name in ('li2_control_raw', 'li2_step_raw'):
        rows = [line.split() for line in symbols.decode('ascii').splitlines()
                if line.split()[-1:] == [name]]
        need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] == 'T',
             'one real adapter and one original raw gateway')
    base['control'] = {'address': address, 'bytes': size}
    base['complete_bytes'] = base['total_bytes']+size
    need(base['complete_bytes'] < 16 << 20, 'unchanged complete private record bound')
    return base


def control_record(data, names, layout, case):
    need(len(data) == layout['complete_bytes'], 'whole actual ELF-derived failure record')
    header = dict(zip(names, struct.unpack_from('<27Q', data)))
    need(all(header[k] == v for k, v in layout['sizes'].items()) and
         header['magic'] == 3552870968096606540 and header['version'] == 1 and header['group'] == 4,
         'exact original positive-prefix header and actual sizes')
    need(header['native_references'] == case['native_references'] and
         header['source_restorations'] == case['native_references'] and header['refusals'] == 47 and
         all(header[k] == 0 for k in ('completed_records', 'completed_capacity', 'published_runs',
            'hit_runs', 'fallback_runs', 'generated_trace_events', 'fallback_trace_events',
            'fixture_failure', 'owner_failure', 'owner_detail_abs', 'owner_detail_negative', 'complete')),
         'failed operation earns no publication execution or completion')
    need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
    at = header['header_bytes']
    need(any(data[at:at+header['startup_bytes']]), 'retain genuine old startup record')
    at += header['startup_bytes']
    records = data[at:at+6*header['record_bytes']]; at += 6*header['record_bytes']
    used = 1 if case['native_references'] else 0
    need((not used or any(records[:header['record_bytes']])) and
         not any(records[used*header['record_bytes']:]), 'actual source-bearing prefix and zero unused records')
    need(not any(data[at:at+64*header['capacity_row_bytes']]), 'no capacity completion rows')
    at += 64*header['capacity_row_bytes']
    need(any(data[at:at+header['tail_bytes']]), 'retain complete current owner/cache tail')
    at += header['tail_bytes']; need(at == layout['total_bytes'], 'exact trailer start')
    fields = ('magic version bytes mode expected_error expected_failure_verified raw_calls injections signals '
              'publication_started publication_returned operation_result primary_error secondary_error secondary_detail').split()
    ctl = dict(zip(fields, struct.unpack_from('<11Q4q', data, at)))
    mode = case['mode']
    need(ctl['magic'] == 3552304727946578252 and ctl['version'] == 1 and
         ctl['bytes'] == layout['control']['bytes'] and ctl['mode'] == mode and
         ctl['expected_error'] == ctl['primary_error'] == case['expected_error'] and
         ctl['expected_failure_verified'] == 1 and 1 <= ctl['raw_calls'] <= 128 and
         ctl['injections'] == case['raw_failure_injections'] and ctl['signals'] == case['real_injected_signals'],
         'exact actual failed-control identity, primary error and event counts')
    operation = (751, 750, 746, 745, 706, 745, 0, 706, 0, 753, 748, 749, 752, 0)
    need(ctl['operation_result'] == operation[mode] and
         ctl['publication_started'] == int(mode not in (9, 13)) and
         ctl['publication_returned'] == int(mode not in (9, 12, 13)) and
         (ctl['secondary_error'], ctl['secondary_detail']) == ((754, 3) if mode in (6, 7) else (0, 0)),
         'exact stopped operation and secondary-reset prefix')
    # The unchanged source-authenticated C predicates check detailed real
    # mapping/borrow/frame/raw-event state. Retain every byte for DWARF replay;
    # scalar acceptance is not an independent replay of all those fields.
    return {'header': header, 'control_prefix': ctl, 'attempted_operation_status': 'failed',
            'operation_completed': False, 'control_expected_failure_verified': True}


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
    name = stamp+'-page-selected-register-controls-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-register-controls-v1', 'status': 'failed',
        'scope': 'Fourteen finite terminal publisher/owner controls. Every attempted operation fails with exact exit125 and no generated execution/completion; acceptance verifies the expected failure. Three explicit negative raw injections and one actual tgkill interruption are labelled. Complete private frame/mapping/raw-call prefixes remain retained. No positive, connected, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'verified_failure_controls': 0, 'failed_operations': 0, 'completed_operations': 0,
                   'generated_executions': 0, 'native_reference_captures': 0, 'startup_pairs': 0,
                   'refusal_encodings': 0, 'executed_refusal_checks': 0,
                   'explicit_raw_failure_injections': 0, 'actual_injected_signals': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_register_controls.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {'register-run-controls': private/'register-run-controls'}
    objects = {'publisher-controls.o': private/'publisher-controls.o'}
    supports = {n: private/n for n in ('run_support.inc', 'control_support.inc')}
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
        _, out, err = run('fixture-support', [build.tools['python'], FIXTURE/'prepare.py',
            REPO/'tools/page-entry/selected/tests/generic/fixture.c',
            REPO/'tools/page-entry/selected/tests/register_run/fixture.c', private],
            profile='fixture_link', env=build.environment)
        generated = {'run_support.inc': {'bytes': 34613,
            'sha256': '49f738fab848dc56e64f4d3e52cc9f0e1320d4c968953dfdeaca474c3138f31d'},
            'control_support.inc': {'bytes': 30510,
            'sha256': 'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'}}
        need(not err and json.loads(out) == generated and
             all(fact(supports[n]) == value for n, value in generated.items()), 'exact three reviewed adapters')
        for support in supports.values(): pin(support)
        record['generated_support'] = generated
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private,
                              REPO/'tools/page-entry/selected'], profile='fixture_link', env=build.environment)
        obj = objects['publisher-controls.o']; binary(obj)
        _, out, err = run('publisher-adapter-import', [build.tools['nm'], '-u', obj],
                          profile='inspect', env=build.environment)
        imports = [line.split()[-1] for line in out.splitlines() if line.split()]
        need(not err and imports.count(b'li2_control_raw') == 1 and b'li2_step_raw' not in imports,
             'only publisher object binds the named raw-control adapter')
        fixture = fixtures['register-run-controls']; binary(fixture)
        record['fixtures'] = {'register-run-controls': fact(fixture)}
        record['elf'] = plain_executable(fixture)
        _, out, err = run('fixture-undefined', [build.tools['nm'], '-u', fixture],
                          profile='inspect', env=build.environment)
        need(not out and not err, 'no undefined fixture symbols')
        _, out, err = run('fixture-layout', [build.tools['nm'], '-S', '--defined-only', fixture],
                          profile='inspect', env=build.environment)
        need(not err, 'actual ELF symbol inspection stderr')
        record['layout'] = control_layout(fixture, out)
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             'ab9cad0ecbb51bb226acba1c926b6fbfc68378517a452cd2b8c2427b2404f026',
             'exact reviewed fourteen-control outcomes')
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = ('magic version header_bytes group record_bytes records_kept startup_bytes '
            'capacity_row_bytes capacity_rows tail_bytes completed_records completed_capacity native_references '
            'published_runs hit_runs fallback_runs source_restorations generated_trace_events fallback_trace_events '
            'refusals xcr0 xsave_bytes fixture_failure owner_failure owner_detail_abs owner_detail_negative complete').split()
        expected_names = ('corrupt-hit non-rx-hit wrong-plan released-borrow wrong-publication source-mutation '
            'premature-reset failed-reset protected-mprotect brk-hole raw-rx-error raw-sync-error '
            'nested-writing raw-allocation-error').split()
        need([c['name'] for c in outcomes['commands']] == expected_names and
             [c['mode'] for c in outcomes['commands']] == list(range(14)) and
             all(c['argv'] == ['register-run-controls'] and c['exit_code'] == 125 and
                 c['environment_delta'] == {'LI2_REGISTER_CONTROL': c['name']} and
                 c['attempted_operation_status'] == 'failed' and c['control_expected_failure_verified'] is True and
                 c['generated_executions'] == 0 and c['old_refusals'] == 47 and
                 c['fixture_failure'] == c['header_complete'] == 0 for c in outcomes['commands']) and
             outcomes['bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                 file_bytes=16 << 20, wall_seconds=15, external_cpus=1), 'exact terminal cohort and unchanged limits')
        record['catalogue'] = {'source': fact(FIXTURE/'OUTCOMES.json'), 'terminal_controls': 14,
                               'generated_executions': 0, 'raw_failure_injections': 3, 'real_injected_signals': 1}
        for case in outcomes['commands']:
            name = case['name']
            result = {'name': name, 'accepted': False, 'actual_exit': None,
                      'attempted_operation_status': 'failed', 'operation_completed': False,
                      'control_expected_failure_verified': False}
            record['cases'].append(result)
            row, out, err = run(name, [fixture], case['exit_code'], env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact terminal control output: '+name)
            data = (private/(name+'.record')).read_bytes()
            result['record'] = fact(private/(name+'.record'))
            result.update(control_record(data, names, record['layout'], case))
            result['accepted'] = True
            total = record['totals']; total['verified_failure_controls'] += 1; total['failed_operations'] += 1
            total['native_reference_captures'] += result['header']['native_references']
            total['startup_pairs'] += 1; total['refusal_encodings'] = result['header']['refusals']
            total['executed_refusal_checks'] += result['header']['refusals']
            total['explicit_raw_failure_injections'] += result['control_prefix']['injections']
            total['actual_injected_signals'] += result['control_prefix']['signals']
        need(record['totals'] == dict(verified_failure_controls=14, failed_operations=14, completed_operations=0,
            generated_executions=0, native_reference_captures=12, startup_pairs=14, refusal_encodings=47,
            executed_refusal_checks=658, explicit_raw_failure_injections=3, actual_injected_signals=1) and
            len(record['cases']) == 14 and all(c['accepted'] and not c['operation_completed'] for c in record['cases']),
            'complete failed-operation cohort; no completion relabel')
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
        for name, support in supports.items():
            try:
                if support.is_file():
                    record.setdefault('generated_support_after', {})[name] = fact(support)
                    pin(support)
            except BaseException as exc:
                record['final_errors'].append('generated support retention '+name+': '+repr(exc))
        for fixture_name, fixture in (fixtures | objects).items():
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
