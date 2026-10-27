"""Exact extracted old cohort blocks; original parsers are imported unchanged."""
import json
import struct
from page_selected import fact, need
from page_selected_register import record_sections
from page_selected_register_controls import control_record

def positive(FIXTURE, record, private, fixtures, run):
    need(fact(FIXTURE/'cases.h')['sha256'] ==
         '3a1e2e3564d106e509d83a5b814810716b5d4ed05bf9cf509af11b4b8b5e6e8f',
         'exact nine reviewed literal semantic inputs')
    record['catalogue'] = {'source': fact(FIXTURE/'cases.h'), 'semantic_inputs': 9,
                           'semantic_pairs': 18, 'capacity_pages': 64}
    need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
         '3175ba3724a47b94e60eecd1233fb80bc863b9636234823ac383432228408836',
         'exact reviewed four-command outcomes')
    outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
    names = outcomes['record']['header_u64_fields']
    need(names == ('magic version header_bytes group record_bytes records_kept startup_bytes '
        'capacity_row_bytes capacity_rows tail_bytes completed_records completed_capacity native_references '
        'published_runs hit_runs fallback_runs source_restorations generated_trace_events fallback_trace_events '
        'refusals xcr0 xsave_bytes fixture_failure owner_failure owner_detail_abs owner_detail_negative complete').split() and
        [c['name'] for c in outcomes['commands']] == list(fixtures) and
        [c['argv'] for c in outcomes['commands']] == [[x] for x in fixtures] and
        [c['exit_code'] for c in outcomes['commands']] == [0]*4 and
        [c['environment_delta'] for c in outcomes['commands']] == [{}]*4 and
        outcomes['native_bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
            file_bytes=16 << 20, wall_seconds=15, external_cpus=1),
        'exact finite process catalogue/header schema/native bounds')
    for group, case in enumerate(outcomes['commands']):
        name = case['name']; capacity = group == 3
        result = {'name': name, 'accepted': False, 'actual_exit': None,
                  'scope': 'capacity with genuine fallback' if capacity else 'full semantic native/cache pairs'}
        record['cases'].append(result)
        row, out, err = run(name, [fixtures[name]], case['exit_code'], env=case['environment_delta'])
        result['actual_exit'] = row['exit']
        need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
        data = (private/(name+'.record')).read_bytes()
        need(len(data) >= 216, 'retained complete header')
        header = dict(zip(names, struct.unpack_from('<27Q', data)))
        result.update(header=header, record=fact(private/(name+'.record')))
        need(header['magic'] == outcomes['record']['magic'] and header['version'] == 1 and
             header['group'] == group and all(header[key] == value for key, value in case['expected_header'].items()),
             'exact completed actual fixture outcome: '+name)
        need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
        result['sections'] = record_sections(data, header, record['layouts'][name], capacity)
        # The unchanged source-authenticated C comparator checks every
        # native/cache GPR/flags/FP/live-selector/stack/data endpoint. Full
        # raw records and the exact ELF/DWARF are retained for later replay.
        result['accepted'] = True
        total = record['totals']
        total['startup_pairs'] += 1
        total['native_references'] += header['native_references']
        total['refusal_encodings'] = header['refusals']
        total['executed_refusal_checks'] += header['refusals']
        total['generated_trace_events'] += header['generated_trace_events']
        total['fallback_trace_events'] += header['fallback_trace_events']
        if capacity:
            total['capacity_publications'] += header['completed_capacity']
            total['capacity_hit_after_full'] += header['hit_runs']
            total['capacity_fallbacks'] += header['fallback_runs']
            total['full_capacity_records'] += result['sections']['full_records']
            total['capacity_rows'] += result['sections']['capacity_rows']
            total['capacity_record_hashes_checked'] += result['sections']['capacity_full_hashes_checked']
        else:
            total['semantic_pairs'] += header['completed_records']
            total['semantic_hits'] += header['hit_runs']
            total['semantic_misses'] += header['published_runs']-header['hit_runs']
            total['full_semantic_records'] += result['sections']['full_records']
    need(record['totals'] == dict(semantic_pairs=18, semantic_misses=9, semantic_hits=9,
        capacity_publications=64, capacity_hit_after_full=1, capacity_fallbacks=1,
        fallback_trace_events=2, generated_trace_events=0, native_references=83,
        startup_pairs=4, refusal_encodings=47, executed_refusal_checks=188,
        full_semantic_records=18, full_capacity_records=5, capacity_rows=64,
        capacity_record_hashes_checked=3) and len(record['cases']) == 4 and
        all(c['accepted'] for c in record['cases']), 'complete semantic and capacity cohort')

def negative(FIXTURE, record, private, fixture, run):
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
