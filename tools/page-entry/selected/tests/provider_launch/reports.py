"""Strict native-page reports; unchanged old completion predicates see real counts.

Only LOADER's explicit scope and positive admission contract are new. No report
is projected, no counter is rewritten, and parsing a failed prefix is not
completion. The caller must also prove actual exit/output/source/cleanup.
"""
from pathlib import Path
import native_pages_compare as predecessor

from page_selected import need
import page_selected_generic_compare as generic
import page_selected_register_connected_compare as register
import page_selected_register_real as real
import page_selected_repeat_compare as repetition
import page_selected_chain_compare as chain
import page_selected_rseq_compare as rseq

RSEQ_SCHEMA = predecessor.RSEQ_SCHEMA
ONESHOT_KEYS = set(('version status failure_code detail_abs detail_negative owners published restored completed syscall_patches rdtsc_patches effect_started effect_returned active_phase').split())
NATIVE_KEYS = set(('version status failure_code attempts admissions closed blocked low_address_refusals '
                   'epoch_exits refaults main_admissions main_refaults epoch_error close_error close_complete close_busy '
                   'first_admission_ns first_source_offset revisit_count revisit_ns').split())
ORDER = [b'LI2_LOADER', b'LI2_NATIVE', b'LI2_ONESHOT', b'LI2_RSEQ', b'LI2_CHAIN', b'LI2_RUN']
ZERO = real.ZERO


def _unsigned(row, scalars, arrays=None, scope=None):
    arrays = arrays or {}
    need(type(row) is dict and set(row) == set(scalars) | set(arrays) |
         ({'scope'} if scope is not None else set()), 'exact report keys')
    need(all(type(row[k]) is int and 0 <= row[k] < 1 << 64 for k in scalars),
         'exact unsigned scalar types')
    for key, count in arrays.items():
        need(type(row[key]) is list and len(row[key]) == count and
             all(type(x) is int and 0 <= x < 1 << 64 for x in row[key]), 'exact array '+key)
    if scope is not None:
        need(row['scope'] == scope, 'exact report scope')
    need(row['version'] == 1, 'report version')


def reports(stderr):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete stderr report terminator')
    lines = stderr[:-1].split(b'\n')
    need(len(lines) in (7,8) and lines[2].startswith(b'LI2_PROVIDER ') and len(lines[2])+1<=4096,
         'one actual configured provider report in fixed position')
    provider=rseq.decode(lines[2][13:]);lines=lines[:2]+lines[3:]
    keys=set(('version status failure_code initialized attempts busy cpuid_completed rdrand_completed rdseed_completed rdpid_completed random_entered random_returned random_committed random_error cpuid_entered cpuid_returned cpuid_committed').split())
    need(type(provider)is dict and set(provider)==keys|{'scope','policy'} and
         provider['scope']=='configured_cpuid_random_id' and provider['policy']=='mask-random-v1' and
         all(type(provider[k])is int and 0<=provider[k]<1<<64 for k in keys) and provider['version']==1,
         'exact configured provider schema/types/policy')
    need(len(lines) in (6, 7) and all(0 < len(x)+1 <= 4096 and b'\r' not in x for x in lines),
         'exact bounded report rows; no other stderr')
    parts = [line.partition(b' ') for line in lines]
    expected = ORDER if len(lines) == 6 else ORDER[:2]+[b'LI2_REPEAT']+ORDER[2:]
    need([x[0] for x in parts] == expected and all(x[1] == b' ' for x in parts),
         'LOADER,NATIVE,optional REP,ONESHOT,RSEQ,CHAIN,RUN order')
    values = {name: rseq.decode(payload) for name, _, payload in parts}
    loader, native = values[b'LI2_LOADER'], values[b'LI2_NATIVE']
    run, c, registration = values[b'LI2_RUN'], values[b'LI2_CHAIN'], values[b'LI2_RSEQ']
    repeat = values.get(b'LI2_REPEAT')

    # Preserve generic.parse's actual startup/attribution/lifecycle/vDSO facts.
    # Its zero-admission assertion belongs to the old profile and is replaced
    # here by the explicit native profile's actual positive-count contract.
    _unsigned(loader, generic.KEYS-{'scope'}, scope='partial_selected_oneshot')
    need(loader['selected_profile'] == loader['generic_tf_profile'] == 1 and
         loader['source_patches'] <= 8, 'bounded actual source-patching prefix; completion requires all six below')
    need(loader['selected_selftests'] == loader['first_target_is_interpreter_entry'] ==
         loader['interpreter_entry_faults'] == 1, 'actual startup and first interpreter entry')
    need(loader['nx_faults'] == loader['main_faults']+loader['interpreter_faults']+
         loader['dependency_faults'], 'actual fault attribution')
    need(loader['generations'] == loader['retired']+loader['live_pages'], 'generation equation')
    need(loader['sync_core'] >= loader['admissions'], 'actual admission sync prefix')
    need(loader['vdso_close_attempted'] == loader['vdso_close_observed'] == loader['vdso_closed'] == 1 and
         loader['vdso_close_result_abs'] == loader['vdso_close_result_negative'] == 0, 'actual vDSO closure')

    need(type(native) is dict and type(native.get('revisit_count')) is int and
         0 <= native['revisit_count'] <= 16, 'bounded actual revisit count')
    _unsigned(native, NATIVE_KEYS-{'revisit_ns'}, {'revisit_ns': native['revisit_count']})
    need(native['close_complete'] in (0, 1) and native['close_busy'] in (0, 1) and
         native['closed'] <= native['admissions'] <= native['attempts'] and
         native['main_admissions'] <= native['admissions'] and native['main_refaults'] <= native['refaults'],
         'actual native publication/close counts and main subsets')
    need(all(x > 0 for x in native['revisit_ns']), 'nonzero actual revisit intervals')
    need(native['first_source_offset'] % 4096 == 0 and
         native['revisit_count'] <= max(native['admissions']-1, 0),
         'page-aligned first source and revisits after an actual first admission')
    need(all(native[k] == loader[k] for k in ('status', 'failure_code')), 'same native terminal outcome')

    need(type(run) is dict and type(run.get('cache_present')) is int and
         type(run.get('publication_present')) is int and
         run['cache_present'] in (0, 1) and run['publication_present'] in (0, 1), 'actual RUN presence')
    arrays = {k: n for k, n in register.ARRAYS.items()
              if k not in ('cache', 'initialization', 'attempt', 'publication')}
    if run['cache_present']:
        arrays.update({k: register.ARRAYS[k] for k in ('cache', 'initialization', 'attempt')})
    if run['publication_present']:
        arrays['publication'] = register.ARRAYS['publication']
    _unsigned(run, register.SCALARS, arrays)
    need(run['route'] == loader['step_route'], 'same actual RUN route')

    _unsigned(c, chain.KEYS-{'scope'}, scope='opt_in_trace_to_plain')
    need(c['active'] in (0, 1) and c['pending'] in (0, 1) and c['proof_valid'] in (0, 1) and
         c['attempts'] == loader['generic_tf_attempts'] and c['steps'] == loader['generic_tf_steps'],
         'actual chain route/counters')
    for index in (0, 1):
        slot = chain.slot(c, index)
        need(slot['phase'] <= 7 and slot['origin'] <= 2 and slot['fallback'] <= 6 and slot['owner_phase'] <= 6 and
             all(slot[k] in (0, 1) for k in ('prepare', 'prepared', 'retry', 'trace', 'held', 'query',
                                           'queried', 'release', 'released', 'unexpected')) and
             all(slot[k] <= 3 for k in ('open', 'opened', 'revoke', 'revoked')) and slot['length'] <= 15,
             'exact old chain slot domains')
    if any(c[k] for k in ZERO) or c['pending'] or c['error'] or c['proof_valid'] or loader['step_route']:
        chain.same_slot(loader, chain.slot(c, c['active']))

    _unsigned(registration, RSEQ_SCHEMA['scalar_keys'],
              {k: len(v) for k, v in RSEQ_SCHEMA['arrays'].items()}, RSEQ_SCHEMA['scope'])
    need(registration['maps_profile'] == 1, 'actual RSEQ maps profile')
    if repeat is not None:
        _unsigned(repeat, repetition.SCALARS, repetition.ARRAYS)
        need(repeat['attempts'] > 0 and repeat['completed'] <= repeat['attempts'] and
             repeat['route'] == loader['step_route'], 'actual optional REP prefix')
    for row in (run, c, registration)+(() if repeat is None else (repeat,)):
        need(all(row[k] == loader[k] for k in ZERO), 'same actual outcome in every old report')
    o = values[b'LI2_ONESHOT']
    _unsigned(o, ONESHOT_KEYS, scope='singleton_initial_main_temporary_e9')
    need(all(o[k] == loader[k] for k in ZERO), 'same actual one-shot outcome')
    need(o['owners'] <= 8 and o['published'] == loader['source_patches'] and
         o['restored'] <= o['published'] <= o['owners'] and
         o['completed'] <= o['effect_returned'] <= o['effect_started'] <= o['restored'] and
         o['syscall_patches'] + o['rdtsc_patches'] == o['published'] and o['active_phase'] <= 9,
         'retained actual one-shot prefixes, no attempted work relabelled completed')
    need(all(provider[k]==loader[k]for k in ('status','failure_code')),'same actual configured terminal outcome')
    return dict(loader=loader, native=native, repeat=repeat, run=run, chain=c, rseq=registration, oneshot=o, provider=provider)


def completed(parsed, pid, variant):
    """Keep every old owner assertion; require the caller's actual launch PID."""
    need(type(pid) is int and pid > 0, 'actual positive launch PID')
    loader, native = parsed['loader'], parsed['native']
    need(native['status'] == native['failure_code'] == native['epoch_error'] ==
         native['close_error'] == native['close_busy'] == 0 and native['close_complete'] == 1 and
         0 < native['admissions'] == native['closed'] == loader['admissions'] and
         loader['sync_core'] == native['admissions']+native['closed'] and
         native['first_admission_ns'] > 0, 'complete genuine native admission and revocation')
    # This calls unchanged chain, register, generic-TF, REP and rseq closure.
    # All positive admission/sync values and the new scope remain untouched.
    rseq.completed(loader, parsed['repeat'], parsed['run'], parsed['chain'], parsed['rseq'], pid)

    # Fixture-specific assertions supplement every unchanged old completion
    # predicate above. Exit's effect never returns: its owner stays RESTORED7.
    o = parsed['oneshot']
    need(o['owners'] == o['published'] == o['restored'] == o['effect_started'] == 6 and
         o['completed'] == o['effect_returned'] == 5 and o['syscall_patches'] == 4 and
         o['rdtsc_patches'] == 2 and o['active_phase'] == 7,
         'six actual publications restored; five returned effects; honest nonreturning exit')
    need(loader['rdtsc'] >= 2 and loader['source_syscalls'] >= 4 and
         native['main_admissions'] == 32 and native['main_refaults'] == 0,
         'all 16 actual native seed and 16 actual live capture entries and selected effects')
    need(parsed['rseq']['owner'][1:4] == [0,0,0] and loader['rseq'] == 0,
         'explicit rseq-disabled fresh-exec fixture; no fabricated unregister')

    need(type(variant)is int and variant in (1,2,3,4),'literal first-main variant')
    p=parsed['provider'];counts=[3+int(variant==1),6+int(variant==2),6+int(variant==3),2+int(variant==4)]
    need(p['status']==p['failure_code']==p['busy']==p['random_error']==0 and
         p['initialized']==1 and p['attempts']==18 and
         [p[k]for k in ('cpuid_completed','rdrand_completed','rdseed_completed','rdpid_completed')]==counts and
         all(p[k]==1 for k in ('random_entered','random_returned','random_committed','cpuid_entered','cpuid_returned','cpuid_committed')),
         'all eighteen genuine configured callbacks returned and committed once')
    need([loader[k]for k in ('cpuid','rdrand','rdseed','rdpid')]==counts and loader['rdtsc']==2 and
         loader['rdtscp']==0 and loader['source_syscalls']==4 and loader['dependency_faults']==0,
         'exact configured/clock/syscall counts; no hidden dependency execution')
    need(loader['selected_last_kind']==4 and loader['selected_last_width']==64 and loader['selected_last_destination']==15 and
         loader['selected_last_value']==loader['selected_last_output_destination']==0xc00dcafe and
         loader['selected_last_carry']==loader['selected_last_status']==loader['selected_last_native_attempts']==0 and
         loader['selected_last_phase']==4,'last configured RDPID completion, no invented native sampling')
