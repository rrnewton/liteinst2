"""Exact finite evidence for real register runs followed by original CPUID guards."""
import json
import struct
import page_selected_generic_compare as generic

need = generic.need
SCALARS = set('version status failure_code detail_abs detail_negative cache_present publication_present '
              'plan_misses completed_runs copied_instructions pending route'.split())
ARRAYS = dict(cache=14, initialization=19, attempt=16, publication=33,
              last_complete=20, interrupted=9, active=10, private_brk=10)


def parse(data):
    lines = data.splitlines()
    need(len(lines) == 2 and all(len(line)+1 <= 4096 for line in lines) and
         lines[0].startswith(b'LI2_LOADER ') and lines[1].startswith(b'LI2_RUN '),
         'exact bounded loader and separate register-run reports; no REP line')
    decode = lambda b: json.loads(b, object_pairs_hook=generic.unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite runtime value')))
    loader = decode(lines[0][11:])
    need(type(loader) is dict and set(loader) == generic.KEYS and
         loader['scope'] == 'partial_selected_register_run', 'actual opt-in profile and unchanged loader fields')
    # Numeric loader predicates remain identical; this explicit profile has a
    # different scope string and an additional separately authenticated report.
    projected = dict(loader, scope=generic.SCOPE)
    need(generic.parse(b'LI2_LOADER '+json.dumps(projected).encode()+b'\n') == projected,
         'all unchanged loader admission/attribution predicates')
    run = decode(lines[1][8:])
    need(type(run) is dict and set(run) == SCALARS | set(ARRAYS), 'exact register-run schema')
    for key in SCALARS:
        need(type(run[key]) is int and 0 <= run[key] < 1 << 64, 'unsigned scalar '+key)
    for key, count in ARRAYS.items():
        need(type(run[key]) is list and len(run[key]) == count and
             all(type(x) is int and 0 <= x < 1 << 64 for x in run[key]), 'exact unsigned array '+key)
    need(run['version'] == 1 and all(run[k] == loader[k] for k in
         ('status', 'failure_code', 'detail_abs', 'detail_negative')) and run['route'] == loader['step_route'],
         'same actual terminal outcome and route')
    return loader, run


def completed(spec, run):
    c = spec['counts']
    need([run[k] for k in ('status', 'failure_code', 'detail_abs', 'detail_negative', 'pending', 'route')] == [0]*6,
         'no register owner failure or outstanding route')
    need(run['cache_present'] == run['publication_present'] == 1 and
         run['completed_runs'] == c['runs'] and run['copied_instructions'] == c['copied'] and
         run['plan_misses'] == c['plan_misses'], 'exact run completion and fallback counts')
    need(run['cache'] == [2, 0, 0, 0, c['slots'], c['slots'], c['runs'], c['hits'], 0, 0, 0, 0, 0, 0],
         'real READY cache, exact publications/hits and no interrupted or failed prefix')
    init = run['initialization']
    need(init[:7] == [1]*7 and init[7] > 0 and init[7] % 4096 == 0 and init[8] == 64*4096 and
         init[9] > 0 and init[10] == init[7] and init[11:16] == [0]*5 and init[16:] == [1, 1, 64],
         'actual fixed allocation/protection and full64-page RW inspection')
    a = run['attempt']; seq = a[1]
    need(seq > 0 and a == [c['runs'], seq, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, c['slots']-1, 1, 1, 0],
         'last fresh held borrow/plan rebuild and actual new-slot completion')
    p = run['publication']
    need(p == [2, 0, 0, 0, 1, c['slots'], seq, init[7]+(c['slots']-1)*4096,
               4096, 24, 4096, 1, 1, 1, 1, 1]+[0]*11+[1, 1, 1, 1, 0, 0],
         'complete immutable final publication: actual W^X/sync/before-after queries/full-page verification')
    by_name = {r['name']: r for r in spec['rows']}
    need(run['last_complete'] == [1, 1, 0, 0, 0, 7, by_name['exit_status']['pc'], by_name['exit']['pc'],
          2, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, seq],
         'last real NX entry/guard, closed queries, release and completed reset retained')
    for key in ('interrupted', 'active', 'private_brk'):
        need(run[key] == [0]*ARRAYS[key], 'no hidden interrupted/pending/reset/brk state')


def check(spec, loader, run, command, stdout, native, before, after, decoded, image):
    need(command['exit'] == native['exit'] == loader['status'] == 0 and
         all(loader[k] == 0 for k in ('failure_code', 'detail_abs', 'detail_negative')), 'actual completed process')
    completed(spec, run)
    generic.check_completed_owner(loader)
    c = spec['counts']
    need(loader['selected_steps'] == c['old'] and
         loader['generic_tf_attempts'] == loader['generic_tf_steps'] == c['generic'] and
         loader['cpuid'] == c['cpuid'] == 3 and loader['source_syscalls'] == loader['syscalls'] == loader['forwarded'] == 2,
         'exact distinct old/generic/cache/CPUID/syscall routes')
    need(loader['main_faults'] == c['main'] and loader['interpreter_faults'] == 2 and
         loader['dependency_faults'] == 0 and loader['nx_faults'] == c['main']+2,
         'exact genuine source fetch and same-event guard redispatch counts')
    need(loader['dependency_objects'] == 1 and loader['mappings'] == 1 and loader['generations'] == 7 and
         loader['retired'] == 2 and loader['live_pages'] == 5 and loader['last_mapping_syscall'] == 11 and
         loader['last_phase'] == 5 and loader['last_syscall'] == 60, 'actual closed application lifecycle')
    need(all(loader[k] == 0 for k in ('rdrand', 'rdseed', 'rdpid', 'rdtsc', 'rdtscp', 'vdso_selected',
         'tls_changes', 'set_tid_address', 'set_robust_list', 'rseq', 'kernel_errors', 'partial_errors')) and
         all(loader[k] == 0 for k in generic.old.KEYS if k.startswith('selected_last_')), 'no unclaimed selected effects')
    need(loader['builtin_kind'] == 1 and loader['builtin_phase'] == 7 and all(loader[k] == 0 for k in
         ('builtin_enable_result_abs', 'builtin_enable_result_negative', 'builtin_restore_result_abs',
          'builtin_restore_result_negative')), 'three real CPUID callbacks, final outcome and restored hardware gate')
    need(before['cpu'] == after['cpu'] and before['aux'] == after['aux'] and
         before['cpuid0'] == after['cpuid0'] and before['tsc'] < after['tsc'], 'actual pinned independent hardware bracket')
    expected = tuple(before['cpuid0'])+(spec['literal'], spec['literal'])
    need(len(stdout) == len(native['stdout']) == 48 and struct.unpack('<6Q', stdout) ==
         struct.unpack('<6Q', native['stdout']) == expected and
         tuple(loader['builtin_'+x] for x in 'abcd') == expected[:4],
         'native/patched CPUID0 ABCD and both dependent copied-register values')
    rows = {r['name']: r for r in spec['rows']}
    need(len(rows) == len(spec['rows']) and len(spec['executed']) in (34, 35), 'closed finite source stream')
    for row in rows.values():
        code = bytes.fromhex(row['bytes']); off = 4096+row['pc']-0x401000
        need(4096 <= off < off+len(code) <= 16384 and image[off:off+len(code)] == code,
             'every actual original instruction byte')
    need(rows['copy_r10_r11']['bytes'] == '4d89d3' and rows['copy_r11_r12']['bytes'] == '4d89dc' and
         rows['cpuid_guard']['bytes'] == '0fa2' and spec['executed'].count('cpuid_guard') == 3,
         'exact dependent two-MOV run and actual guard loop')
    last = rows['store_r12']; b = bytes.fromhex(last['bytes']); packed = b.ljust(16, b'\0')
    need(loader['tf_phase'] == 5 and loader['tf_flow'] == loader['tf_family'] == 1 and
         loader['tf_pc'] == last['pc'] and loader['tf_length'] == len(b) and
         (loader['tf_bytes_lo'], loader['tf_bytes_hi']) == struct.unpack('<QQ', packed) and
         decoded['pc'] == last['pc'] and decoded['length'] == len(b) and decoded['decode_status'] == 0 and
         decoded['kind'] == 0 and decoded['code'] == loader['tf_code'], 'independent actual final generic store descriptor')
    need(loader['tf_actual_flags'] & 0x41 == 0x40, 'final loop ZF1/CF0 survives stores and copied runs')
    return dict(cpuid0=list(expected[:4]), r11=expected[4], r12=expected[5],
                guard_completions=3, generated_runs=c['runs'], publications=c['slots'], hits=c['hits'],
                copied_instructions=c['copied'], loop_fallback=spec['loop_falls_back_before_publication'])
