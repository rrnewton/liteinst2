"""Strict prospective predicates; imports do not execute any workload."""
import json
import struct
import page_selected as old

NEW_KEYS = set(('generic_tf_profile generic_tf_attempts generic_tf_steps step_route '
    'tf_phase tf_error tf_detail_abs tf_detail_negative tf_code tf_flow tf_family tf_trace tf_actual_flags '
    'tf_open_started tf_opened tf_revoke_started tf_revoked tf_sync_started tf_sync_abs tf_sync_negative '
    'tf_continuation_started tf_continuation_complete tf_continuation_result_abs tf_continuation_result_negative '
    'tf_query_attempted tf_query_complete tf_release_started tf_release_complete tf_release_result_abs '
    'tf_release_result_negative tf_unexpected_frame tf_pc tf_length tf_bytes_lo tf_bytes_hi').split())
KEYS = old.KEYS | NEW_KEYS
SCOPE = 'partial_selected_generic_tf_original_entry'
SENTINEL_B, SENTINEL_C = 0x1122334455667788, 0x8877665544332211


def need(value, message):
    if not value:
        raise ValueError(message)


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate field')
        result[key] = value
    return result


def parse(data):
    lines = data.splitlines()
    need(len(lines) == 1 and lines[0].startswith(b'LI2_LOADER '), 'one actual controller report')
    row = json.loads(lines[0][11:], object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite report')))
    need(set(row) == KEYS and row['scope'] == SCOPE, 'exact generic controller schema')
    need(all(type(v) is int and 0 <= v < 2**64 for k, v in row.items() if k != 'scope'), 'numeric report fields')
    need(row['version'] == row['selected_profile'] == row['generic_tf_profile'] == 1 and row['source_patches'] == 0,
         'actual mechanism')
    need(row['selected_selftests'] == row['first_target_is_interpreter_entry'] == row['interpreter_entry_faults'] == 1,
         'genuine pre-entry selftest and first interpreter entry')
    need(row['nx_faults'] == row['main_faults']+row['interpreter_faults']+row['dependency_faults'], 'fault attribution')
    need(row['generations'] == row['retired']+row['live_pages'], 'retained generation equation')
    need(row['admissions'] == row['sync_core'] == 0, 'no full-page admission')
    need(row['vdso_close_attempted'] == row['vdso_close_observed'] == row['vdso_closed'] == 1 and
         row['vdso_close_result_abs'] == row['vdso_close_result_negative'] == 0, 'actual vDSO closure')
    return row


def check_legacy(spec, row, command, stdout, native, hardware):
    # This is only a compatibility projection after authenticating the actual
    # new-profile report and proving the entire new route remained unused.
    need(all(row[k] == (1 if k == 'generic_tf_profile' else 0) for k in NEW_KEYS), 'legacy cases cannot use generic route')
    projected = {k: row[k] for k in old.KEYS}
    projected['scope'] = 'partial_selected_original_entry'
    checked = old.object_row(b'LI2_LOADER '+json.dumps(projected).encode()+b'\n')
    old.check_stream(spec, checked, command, stdout, native, hardware)


def clock(data, cpu):
    row = json.loads(data, object_pairs_hook=unique)
    need(set(row) == {'cpu', 'aux', 'cpuid0', 'tsc'} and type(row['cpu']) is int and row['cpu'] == cpu, 'native observer schema/CPU')
    need(type(row['aux']) is int and 0 <= row['aux'] < 2**32 and
         type(row['tsc']) is int and 0 < row['tsc'] < 2**64, 'actual AUX/TSC values')
    need(type(row['cpuid0']) is list and len(row['cpuid0']) == 4 and
         all(type(x) is int and 0 <= x < 2**32 for x in row['cpuid0']) and row['cpuid0'][0] >= 1,
         'native leaf0 values')
    return row


def check_completed_owner(row):
    # Shared completion contract: finite streams keep their stricter literal
    # fallthrough/integer/single-page checks below; actual ls may end on any
    # admitted flow/family, with the exact mask derived from its retained bytes.
    need(row['generic_tf_attempts'] == row['generic_tf_steps'] > 0 and
         row['step_route'] == 0 and row['tf_phase'] == 5 and
         row['tf_flow'] in (1, 2) and 1 <= row['tf_family'] <= 6, 'completed actual generic owner')
    n, pc = row['tf_length'], row['tf_pc']
    packed = struct.pack('<QQ', row['tf_bytes_lo'], row['tf_bytes_hi'])
    need(1 <= n <= 15 and 0 < pc <= 2**64-1-n and packed[n:] == bytes(16-n), 'complete retained request')
    pages = 1 if pc // 4096 == (pc+n-1) // 4096 else 3
    need(all(row[k] == pages for k in ('tf_open_started', 'tf_opened', 'tf_revoke_started', 'tf_revoked')),
         'all actual source pages opened and revoked')
    need(all(row[k] == 1 for k in ('tf_trace', 'tf_sync_started', 'tf_continuation_started',
         'tf_continuation_complete', 'tf_query_attempted', 'tf_query_complete', 'tf_release_started',
         'tf_release_complete')), 'complete actual close/query/release prefix')
    need(all(row[k] == 0 for k in ('tf_error', 'tf_detail_abs', 'tf_detail_negative', 'tf_sync_abs', 'tf_sync_negative',
         'tf_continuation_result_abs', 'tf_continuation_result_negative', 'tf_release_result_abs',
         'tf_release_result_negative', 'tf_unexpected_frame')), 'no hidden generic failure')
    need(row['tf_actual_flags'] & 0x10100 == 0x100, 'actual owner TF and absent RF')


def check_connected(spec, row, command, stdout, native, before, after, decoded):
    check_completed_owner(row)
    c = spec['counters']
    need(command['exit'] == native['exit'] == row['status'] == 0 and
         row['failure_code'] == row['detail_abs'] == row['detail_negative'] == 0, 'actual completion')
    need(row['selected_steps'] == c['old'] and row['generic_tf_attempts'] == row['generic_tf_steps'] == c['generic'],
         'exact separate old/generic instruction counts')
    need(row['main_faults'] == c['main'] and row['interpreter_faults'] == c['interpreter'] and
         row['dependency_faults'] == 0 and row['nx_faults'] == c['main']+c['interpreter'], 'exact connected fetch counts')
    need(row['source_syscalls'] == row['syscalls'] == row['forwarded'] == c['syscall'] == 2 and
         row['last_syscall'] == 60, 'exact write/exit dispatch and original exit')
    need(row['dependency_objects'] == 1 and row['mappings'] == 1 and row['generations'] == 7 and
         row['retired'] == 2 and row['live_pages'] == 5 and row['last_mapping_syscall'] == 11 and row['last_phase'] == 5,
         'actual main/interpreter pages and retired selftest owner')
    need(all(row[k] == 0 for k in ('rdrand', 'rdseed', 'rdpid', 'vdso_selected', 'tls_changes',
         'set_tid_address', 'set_robust_list', 'rseq', 'kernel_errors', 'partial_errors')), 'no unclaimed operations')
    need(all(row[k] == 0 for k in old.KEYS if k.startswith('selected_last_')), 'no fabricated random outcome')
    need(row['step_route'] == 0 and row['tf_phase'] == 5 and row['tf_flow'] == row['tf_family'] == 1,
         'completed last fallthrough integer owner')
    need(all(row[k] == 1 for k in ('tf_trace', 'tf_open_started', 'tf_opened', 'tf_revoke_started', 'tf_revoked',
         'tf_sync_started', 'tf_continuation_started', 'tf_continuation_complete', 'tf_query_attempted',
         'tf_query_complete', 'tf_release_started', 'tf_release_complete')), 'full actual last-page close/query/release prefix')
    need(all(row[k] == 0 for k in ('tf_error', 'tf_detail_abs', 'tf_detail_negative', 'tf_sync_abs', 'tf_sync_negative',
         'tf_continuation_result_abs', 'tf_continuation_result_negative', 'tf_release_result_abs',
         'tf_release_result_negative', 'tf_unexpected_frame')), 'no hidden generic failure')
    need(row['tf_actual_flags'] & 0x10100 == 0x100, 'actual owner TF and absent RF')
    rows = {x['name']: x for x in spec['rows']}
    last = [rows[n] for n in spec['executed'] if rows[n]['route'] == 'generic'][-1]
    source = bytes.fromhex(last['bytes'])
    packed = source.ljust(16, b'\0')
    need(row['tf_pc'] == last['pc'] and row['tf_length'] == len(source) and
         (row['tf_bytes_lo'], row['tf_bytes_hi']) == struct.unpack('<QQ', packed), 'actual retained final source bytes')
    need(decoded['pc'] == last['pc'] and decoded['length'] == len(source) and decoded['decode_status'] == 0 and
         decoded['kind'] == 0 and decoded['code'] == row['tf_code'], 'independent exact decode of retained source')
    need(before['cpu'] == after['cpu'] and before['aux'] == after['aux'] and before['cpuid0'] == after['cpuid0'] and
         before['tsc'] < after['tsc'], 'closed pinned hardware bracket')
    kind = spec['builtin']
    need([row[k] for k in ('cpuid', 'rdtsc', 'rdtscp')] == [int(kind == x) for x in (1, 5, 6)], 'exact builtin class count')
    if not kind:
        need(all(row[k] == 0 for k in old.KEYS if k.startswith('builtin_')), 'no fabricated builtin outcome')
        expected = struct.pack('<'+'Q'*len(spec['expected_words']), *spec['expected_words'])
        need(stdout == native['stdout'] == expected, 'exact independent branch/stack/memory/CALL results')
        return {'output_words': spec['expected_words']}
    need(row['builtin_kind'] == kind and row['builtin_phase'] == 7 and
         all(row[k] == 0 for k in ('builtin_enable_result_abs', 'builtin_enable_result_negative',
                                  'builtin_restore_result_abs', 'builtin_restore_result_negative')), 'real restored builtin completion')
    need(len(stdout) == len(native['stdout']) == 32, 'complete actual builtin registers')
    values, baseline = struct.unpack('<4Q', stdout), struct.unpack('<4Q', native['stdout'])
    need(all(row['builtin_'+x] < 2**32 for x in 'abcd'), 'hardware result zero extension')
    need(row['tf_actual_flags'] & 0x41 == 0x40, 'ZF1/CF0 survived completion and subsequent stores')
    if kind == 1:
        expected = tuple(before['cpuid0'])
        need(values == baseline == expected == tuple(row['builtin_'+x] for x in 'abcd'), 'actual CPUID0 four-register equality')
        return {'cpuid0': list(values)}
    aux = before['aux'] if kind == 6 else SENTINEL_C
    need(values == (row['builtin_a'], SENTINEL_B, aux, row['builtin_d']) and
         row['builtin_b'] == 0 and row['builtin_c'] == (before['aux'] if kind == 6 else 0), 'actual TSC/AUX and unaffected registers')
    need(baseline[0] < 2**32 and baseline[3] < 2**32 and baseline[1:3] == (SENTINEL_B, aux), 'native TSC architectural register semantics')
    # No equality, tolerance, rounding or retry between nondeterministic values.
    # The native and gated commands both occur inside this serialized bracket.
    native_tsc, gated_tsc = (baseline[3] << 32) | baseline[0], (values[3] << 32) | values[0]
    need(before['tsc'] < native_tsc < gated_tsc < after['tsc'], 'actual serialized native/gated TSC bracket')
    return {'native_tsc': native_tsc, 'gated_tsc': gated_tsc, 'before_tsc': before['tsc'], 'after_tsc': after['tsc'], 'aux': before['aux']}
