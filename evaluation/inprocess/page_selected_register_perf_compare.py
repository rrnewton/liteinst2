"""Strict finite correctness first; raw TSC intervals only after complete closure."""
import struct
import page_selected_register_connected_compare as finite
from page_selected_register_perf_images import LITERAL, SENTINELS, ITERATIONS, RECORD_BYTES, TRAILER

generic, need, parse = finite.generic, finite.need, finite.parse


def samples(data, spec, before, after):
    k, expected = spec['samples'], tuple(spec['expected_values'])
    need(len(data) == 4096 and spec['record_bytes'] == RECORD_BYTES == 40 and
         spec['trailer_offset'] == TRAILER == 4064 and k*40 <= TRAILER, 'exact bounded output extent')
    result = []
    previous = before['tsc']
    for offset in range(0, k*40, 40):
        lo, hi, aux, end_lo, end_hi, end_aux, r11, r12 = struct.unpack_from('<6I2Q', data, offset)
        start, end = (hi << 32) | lo, (end_hi << 32) | end_lo
        need(previous < start < end < after['tsc'], 'strict ordered actual hardware times; no retry or tolerance')
        need(aux == end_aux == before['aux'] == after['aux'], 'same actual pinned TSC_AUX at both endpoints')
        need((r11, r12) == expected, 'every actual dependent-MOV result or bracket sentinel')
        result.append(dict(start=start, end=end, ticks=end-start, aux=aux))
        previous = end
    need(data[k*40:TRAILER] == b'\xa5'*(TRAILER-k*40), 'every unused output byte unchanged')
    need(struct.unpack_from('<4Q', data, TRAILER) == (0, 0x600000+k*40, *expected),
         'actual final zero loop count, exact output pointer and both result registers')
    return result


def phase(rows):
    steady = [r['ticks'] for r in rows[1:]]
    need(len(steady) in ITERATIONS and len(rows) == len(steady)+1, 'first and steady phases are distinct')
    return dict(first_interval_ticks=rows[0]['ticks'], steady_interval_ticks=steady,
        steady_sum_ticks=sum(steady), steady_count=len(steady), steady_min_ticks=min(steady),
        steady_max_ticks=max(steady), steady_mean=dict(numerator=sum(steady), denominator=len(steady)),
        steady_span_ticks=rows[-1]['end']-rows[1]['start'])


def check(spec, loader, run, command, stdout, native, before, after, decoded, image):
    n, mode = spec['steady_iterations'], spec['mode']
    need(type(n) is int and n in ITERATIONS and mode in ('cache', 'bracket'), 'closed finite timing catalogue')
    k, cache = n+1, mode == 'cache'
    c = dict(old=6, generic=13*k+5, cpuid=2*k, rdtscp=2*k, syscall=2,
             main=14+(18 if cache else 17)*k, interpreter=2,
             runs=(k if cache else 0)+3, copied=2*((k if cache else 0)+3),
             slots=4 if cache else 3, hits=n if cache else 0, plan_misses=13*k+11)
    need(spec['name'] == f'{mode}_{n}' and spec['samples'] == k and spec['counts'] == c and
         spec['expected_values'] == ([LITERAL]*2 if cache else list(SENTINELS)), 'independent literal counts/results')
    need(command['exit'] == native['exit'] == loader['status'] == 0 and
         all(loader[x] == 0 for x in ('failure_code', 'detail_abs', 'detail_negative')), 'actual complete applications')
    # Unchanged full cache/publication/last-NX-guard/reset and generic-owner
    # predicates from the already qualified finite connected evaluator.
    finite.completed(spec, run)
    generic.check_completed_owner(loader)
    need(loader['selected_steps'] == c['old'] and
         loader['generic_tf_attempts'] == loader['generic_tf_steps'] == c['generic'] and
         loader['cpuid'] == loader['rdtscp'] == 2*k and loader['rdtsc'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded'] == 2,
         'exact old/generic/cache/CPUID/RDTSCP/write/exit counts')
    need(loader['main_faults'] == c['main'] and loader['interpreter_faults'] == 2 and
         loader['dependency_faults'] == 0 and loader['nx_faults'] == c['main']+2,
         'exact actual source fetches; generated guard redispatch counted once')
    need(loader['dependency_objects'] == loader['mappings'] == 1 and loader['generations'] == 7 and
         loader['retired'] == 2 and loader['live_pages'] == 5 and loader['last_mapping_syscall'] == 11 and
         loader['last_phase'] == 5 and loader['last_syscall'] == 60, 'unchanged exact lifecycle geometry')
    need(all(loader[x] == 0 for x in ('rdrand', 'rdseed', 'rdpid', 'vdso_selected', 'tls_changes',
         'set_tid_address', 'set_robust_list', 'rseq', 'kernel_errors', 'partial_errors')) and
         all(loader[x] == 0 for x in generic.old.KEYS if x.startswith('selected_last_')), 'no unclaimed selected effects')
    need(loader['builtin_kind'] == 6 and loader['builtin_phase'] == 7 and
         all(loader[x] == 0 for x in ('builtin_enable_result_abs', 'builtin_enable_result_negative',
         'builtin_restore_result_abs', 'builtin_restore_result_negative')), 'last genuine restored RDTSCP callback')
    need(before['cpu'] == after['cpu'] and before['aux'] == after['aux'] and
         before['cpuid0'] == after['cpuid0'] and before['tsc'] < after['tsc'], 'external pinned hardware bracket')
    actual, baseline = samples(stdout, spec, before, after), samples(native['stdout'], spec, before, after)
    need(baseline[-1]['end'] < actual[0]['start'], 'all native samples precede all gated samples in actual command order')
    need((loader['builtin_a'], loader['builtin_b'], loader['builtin_c'], loader['builtin_d']) ==
         (actual[-1]['end'] & 0xffffffff, 0, before['aux'], actual[-1]['end'] >> 32), 'last timestamp is actual reported outcome')
    # No timestamp equality or speed threshold: independently require every
    # other byte of both 4KiB outputs, including padding and exact loop trailer.
    a, b = bytearray(stdout), bytearray(native['stdout'])
    for i in range(k):
        a[i*40:i*40+8] = b[i*40:i*40+8] = bytes(8)
        a[i*40+12:i*40+20] = b[i*40+12:i*40+20] = bytes(8)
    need(a == b, 'exact matched native/gated deterministic output bytes')
    rows = {r['name']: r for r in spec['rows']}
    need(len(rows) == len(spec['rows']) and len(spec['executed']) == (19 if cache else 17)*k+17,
         'complete finite original instruction stream')
    for row in rows.values():
        code = bytes.fromhex(row['bytes']); offset = 4096+row['pc']-0x401000
        need(4096 <= offset < offset+len(code) <= 8192 and image[offset:offset+len(code)] == code,
             'all original instruction bytes and PCs authenticate')
    need(rows['start_clock']['bytes'] == rows['end_clock']['bytes'] == '0f01f9' and
         rows['serialize_after_start']['bytes'] == rows['cpuid_guard']['bytes'] == '0fa2' and
         rows['serialize_leaf0']['bytes'] == rows['guard_leaf0']['bytes'] == '31c0' and
         spec['executed'].count('cpuid_guard') == k and spec['executed'].count('start_clock') == k,
         'exact source hardware clock/serialization/control-flow sequence')
    if cache:
        need(rows['copy_r10_r11']['bytes'] == '4d89d3' and rows['copy_r11_r12']['bytes'] == '4d89dc' and
             rows['copy_r10_r11']['pc'] == spec['loop_run_pc'] and
             rows['copy_r11_r12']['pc'] == spec['loop_run_pc']+3 and
             rows['cpuid_guard']['pc'] == spec['loop_run_pc']+6 and
             spec['executed'].count('copy_r10_r11') == k and spec['executed'].count('copy_r11_r12') == k,
             'same real source PC for first publication and every subsequent hit')
    else:
        need('copy_r10_r11' not in rows and 'copy_r11_r12' not in rows and spec['loop_run_pc'] is None,
             'bracket-only control really omits the register run')
    last = rows['store_r12']; code = bytes.fromhex(last['bytes'])
    need(loader['tf_phase'] == 5 and loader['tf_flow'] == loader['tf_family'] == 1 and
         loader['tf_pc'] == last['pc'] and loader['tf_length'] == len(code) and
         (loader['tf_bytes_lo'], loader['tf_bytes_hi']) == struct.unpack('<QQ', code.ljust(16, b'\0')) and
         decoded['pc'] == last['pc'] and decoded['length'] == len(code) and decoded['decode_status'] == 0 and
         decoded['kind'] == 0 and decoded['code'] == loader['tf_code'] and loader['tf_actual_flags'] & 0x41 == 0x40,
         'independent actual final store, exact last-loop ZF1/CF0 and complete generic owner')
    return dict(mode=mode, samples=k, steady_iterations=n, expected_values=spec['expected_values'],
        publications=c['slots'], hits=c['hits'], completed_runs=c['runs'], copied_instructions=c['copied'],
        loop_publications=1 if cache else 0, tail_publications=3,
        native_samples=baseline, gated_samples=actual,
        native=phase(baseline), gated=phase(actual), unit='TSC ticks',
        timing_scope='Serialized source bracket including clock/CPUID and source-gate overhead; no subtraction or ns conversion.')
