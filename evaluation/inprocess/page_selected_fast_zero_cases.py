"""Exact existing finite outcome blocks; generated once, no runtime source eval.
Full architectural comparison remains in the unchanged authenticated C fixtures.
"""
import json
import struct
from page_selected import fact, need
from page_selected_generic_build import PROFILES as BUILD_PROFILES
from page_selected_register import record_sections
from page_selected_register_controls import control_record
from page_selected_chain_record import check
from page_selected_register_time_compare import decode
from page_selected_repeat_oracle import ORACLE_COMMANDS

PROFILES = dict(BUILD_PROFILES, fixture_link=[5,512<<20,16<<20,15], native=[5,512<<20,16<<20,15])


def generic(record, private, run, fixture, FIXTURE):
    outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
    names = outcomes['record_header_fields']
    need(len(names) == 17 and len(outcomes['commands']) == 4, 'complete finite protocol')
    for case in outcomes['commands']:
        name = case['name']
        result = {'name': name, 'process_outcome': case['process_outcome'], 'accepted': False}
        record['cases'].append(result)
        _, out, err = run(name, [fixture, *case['argv'][1:]], case['exit'])
        need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
        data = (private/(name+'.record')).read_bytes()
        need(len(data) >= 136, 'retained complete header')
        header = dict(zip(names, struct.unpack_from('<17Q', data)))
        result.update(header=header, record=fact(private/(name+'.record')))
        need(all(header[key] == value for key, value in case['header_equals'].items()), 'exact header outcome: '+name)
        need(header['sample_bytes'] > 0 and len(data) == header['header_bytes']+22*header['sample_bytes']+40,
             'complete actual record extent')
        need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
        result['accepted'] = True
        if name == 'positive':
            record['totals'].update(positive_pairs=21, generic_pairs=20, positive_selftest_pairs=1,
                                    supplied_refusal_encodings=47)
        else:
            record['totals']['verified_failed_operations'] += 1
            record['totals']['additional_negative_command_selftests'] += 1


def chain(r, private, run, path, layout, builder, binary, pin, ROOT):
    outcomes=decode(pin(ROOT/'tools/page-entry/selected/tests/trace_chain/OUTCOMES.json').read_bytes())
    need(outcomes['cardinality']==dict(failed_operation_processes=11,old_encoding_refusals_per_process=47,
        old_startup_pairs_per_process=1,positive_processes=12,route_controls_per_process=15,
        three_lane_programs=12,total_native_processes=23) and outcomes['bounds']==dict(core_bytes=0,cores=1,
        file_bytes=16<<20,native_address_bytes=512<<20,native_cpu_seconds=5,wall_seconds=15) and
        len(outcomes['commands'])==23,'all23 exact outcomes and unchanged bounds')
    stage='qualification'
    for expected in outcomes['commands']:
        item=dict(name=expected['name'],status='failed',expected_operation=expected['operation'],environment_delta=dict(expected['env']));r['cases'].append(item)
        command,out,err=run(expected['name'],[path],expected=expected['exit'],profile='native',
            env=dict(builder.environment,**expected['env']),record=True,step=True)
        item['exit']=command['exit']
        need(out==expected['stdout'].encode() and err==b'','exact finite output')
        capture=command['captures']['record'];record_path=binary(private/capture['file'])
        need(fact(record_path)=={k:capture[k]for k in ('bytes','sha256')},'complete actual retained state record')
        item['record']=fact(record_path)
        value=check(record_path.read_bytes(),layout,expected['case'],expected['mode'])
        need(value['operation']==expected['operation'] and value['old_startup_pairs']==1 and
            value['refusal_bytes']==47 and value['route_controls']==15,'actual operation and old controls')
        if expected['operation']=='completed':
            need(value['programs']==1 and value['lanes']==3 and value['nx']==expected['nx'] and
                value['trace']==expected['trace'] and value['selected_callbacks']==expected['selected'],
                'exact native/reference/chained event counts')
            r['totals']['completed_programs']+=1;r['totals']['completed_lanes']+=3
        else:
            for key in ('completed','owner_error','native_failed_observations','nonissued_negative_returns'):
                need(value[key]==expected[key],'exact failed-operation field '+key)
            need(value['expected_failure_verified']is True and value['real_effects']==expected['actual_effects'] and
                 value['real_signals']==expected['actual_signals'],'genuine effects/signals versus named nonissued negatives')
            r['totals']['verified_failed_operations']+=1
            r['totals']['native_failed_observations']+=value['native_failed_observations']
        r['totals']['old_startup_pairs']+=1;r['totals']['old_refusal_checks']+=47;r['totals']['route_checks']+=15
        item.update(status='accepted_observation',outcome=value)
    need(len(r['cases'])==23 and all(x['status']=='accepted_observation'for x in r['cases']) and
        r['totals']==dict(completed_programs=12,completed_lanes=36,verified_failed_operations=11,
            old_startup_pairs=23,old_refusal_checks=1081,route_checks=345,native_failed_observations=2),
        'whole exact finite cohort, failures never counted as completions')


def register(record, private, run, fixtures, FIXTURE):
    layouts = list(record['layouts'].values())
    need(all(v['sizes'] == layouts[0]['sizes'] and v['total_bytes'] == layouts[0]['total_bytes']
             for v in layouts), 'same real C layout across four groups')
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


def controls(record, private, run, fixture, FIXTURE):
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


def repeat(record, private, run, fixture, FIXTURE, oracle_start):
    outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
    need(outcomes['schema_version'] == 1 and outcomes['header_bytes'] == 208 and
         outcomes['header_format'] == '<18QqQq5Q' and len(outcomes['header_fields']) == 26 and
         len(set(outcomes['header_fields'])) == 26 and
         [c['name'] for c in outcomes['commands']] == ['positive', 'write-fault'] and
         [c['exit'] for c in outcomes['commands']] == [0, 125] and
         [c['successful_operation'] for c in outcomes['commands']] == [True, False] and
         [c['argv'] for c in outcomes['commands']] == [['repeat-owner-fixture']]*2 and
         [c['environment_delta'] for c in outcomes['commands']] == [{}, {'LI2_REPEAT_WRITE_FAULT': '1'}] and
         outcomes['limits']['native'] == PROFILES['native'] and
         outcomes['limits']['external_cpu_count'] == 1 and outcomes['limits']['core_bytes'] == 0 and
         outcomes['record_limit_bytes_exclusive'] == 16 << 20, 'closed owner outcome protocol')
    record['outcomes'] = fact(FIXTURE/'OUTCOMES.json')
    for case in outcomes['commands']:
        name = case['name']
        result = dict(name=name, accepted=False, actual_exit=None, operation_completed=None,
                      actual_failed_operation=False)
        record['cases'].append(result)
        need(case['argv'][0] == fixture.name, 'exact retained executable name')
        row, out, err = run(name, [fixture, *case['argv'][1:]], case['exit'], env=case['environment_delta'])
        result['actual_exit'] = row['exit']
        need(err == case['stderr'].encode(), 'exact stderr: '+name)
        # Early setup failures can retain the inherited generic layout.
        # Preserve those bytes and never substitute a successful REP record.
        path = private/(name+'.record')
        data = path.read_bytes()
        need(208 <= len(data) < outcomes['record_limit_bytes_exclusive'], 'complete bounded owner header')
        header = dict(zip(outcomes['header_fields'], struct.unpack_from(outcomes['header_format'], data)))
        result.update(header=header, record=fact(path))
        need(all(header[k] == v for k, v in case['header_equals'].items()), 'exact owner header: '+name)
        need(header['xcr0'] & 3 == 3 and 576 <= header['xsave_bytes'] <= 65536, 'qualified XSAVE extent')
        need(all(header[k] > 0 for k in ('selftest_bytes', 'case_bytes', 'event_bytes')) and
             len(data) == 208+header['selftest_bytes']+6*header['case_bytes']+header['event_bytes'],
             'complete selftest/six-case/unexpected extents')
        if case['successful_operation']:
            need(case['trace_total_min'] <= header['traces'] <= case['trace_total_max'] and
                 out == (case['stdout_prefix']+str(header['traces'])+case['stdout_suffix']).encode(),
                 'exact successful stdout/trace total')
            need(not any(data[-header['event_bytes']:]), 'no unexpected event in successful record')
            result['operation_completed'] = True
            record['totals'].update(positive_pairs=6, positive_selftest_pairs=1, repeat_traces=header['traces'],
                                    old_refusal_encodings=47, stosq_refusal_encodings=6)
        else:
            need(case['actual_failed_operation'] and header['completed'] == 0 and
                 header['unexpected_observed'] == header['expected_failure_verified'] == 1 and
                 any(data[-header['event_bytes']:]) and out == case['stdout'].encode(),
                 'actual failed operation and exact diagnostic stdout')
            result.update(operation_completed=False, actual_failed_operation=True)
            record['totals']['verified_failed_operations'] += 1
        result['accepted'] = True
    need([c['name'] for c in record['commands'][oracle_start:]] == ORACLE_COMMANDS,
         'all six exact oracle commands completed after the fresh product build')

INITIAL_TOTALS = {'generic': {'positive_pairs': 0, 'generic_pairs': 0, 'positive_selftest_pairs': 0, 'supplied_refusal_encodings': 0, 'verified_failed_operations': 0, 'additional_negative_command_selftests': 0}, 'chain': {'completed_programs': 0, 'completed_lanes': 0, 'verified_failed_operations': 0, 'old_startup_pairs': 0, 'old_refusal_checks': 0, 'route_checks': 0, 'native_failed_observations': 0}, 'register': {'semantic_pairs': 0, 'semantic_misses': 0, 'semantic_hits': 0, 'capacity_publications': 0, 'capacity_hit_after_full': 0, 'capacity_fallbacks': 0, 'fallback_trace_events': 0, 'generated_trace_events': 0, 'native_references': 0, 'startup_pairs': 0, 'refusal_encodings': 0, 'executed_refusal_checks': 0, 'full_semantic_records': 0, 'full_capacity_records': 0, 'capacity_rows': 0, 'capacity_record_hashes_checked': 0}, 'controls': {'verified_failure_controls': 0, 'failed_operations': 0, 'completed_operations': 0, 'generated_executions': 0, 'native_reference_captures': 0, 'startup_pairs': 0, 'refusal_encodings': 0, 'executed_refusal_checks': 0, 'explicit_raw_failure_injections': 0, 'actual_injected_signals': 0}, 'repeat': {'positive_pairs': 0, 'positive_selftest_pairs': 0, 'repeat_traces': 0, 'old_refusal_encodings': 0, 'stosq_refusal_encodings': 0, 'verified_failed_operations': 0}}
