"""Strict native-page reports; unchanged old completion predicates see real counts.

Only LOADER's explicit scope and positive admission contract are new. No report
is projected, no counter is rewritten, and parsing a failed prefix is not
completion. The caller must also prove actual exit/output/source/cleanup.
"""
from pathlib import Path

from page_selected import need
import page_selected_generic_compare as generic
import page_selected_register_connected_compare as register
import page_selected_register_real as real
import page_selected_repeat_compare as repetition
import page_selected_chain_compare as chain
import page_selected_rseq_compare as rseq

RSEQ_SCHEMA = rseq.decode(Path(__import__('page_selected_rseq_compare').__file__).with_name('page_selected_rseq_schema.json').read_bytes())
NATIVE_KEYS = set(('version status failure_code attempts admissions closed blocked low_address_refusals '
                   'epoch_exits refaults main_admissions main_refaults epoch_error close_error close_complete close_busy '
                   'first_admission_ns first_source_offset revisit_count revisit_ns').split())
ORDER = [b'LI2_LOADER', b'LI2_NATIVE', b'LI2_RSEQ', b'LI2_CHAIN', b'LI2_RUN']
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


def reports(stderr,nx=False,configured=False):
    stderr,extension=_extensions(stderr,nx,configured)
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete stderr report terminator')
    lines = stderr[:-1].split(b'\n')
    need(len(lines) in (5, 6) and all(0 < len(x)+1 <= 4096 and b'\r' not in x for x in lines),
         'exact bounded report rows; no other stderr')
    parts = [line.partition(b' ') for line in lines]
    expected = ORDER if len(lines) == 5 else ORDER[:2]+[b'LI2_REPEAT']+ORDER[2:]
    need([x[0] for x in parts] == expected and all(x[1] == b' ' for x in parts),
         'LOADER,NATIVE,optional REP,RSEQ,CHAIN,RUN order')
    values = {name: rseq.decode(payload) for name, _, payload in parts}
    loader, native = values[b'LI2_LOADER'], values[b'LI2_NATIVE']
    run, c, registration = values[b'LI2_RUN'], values[b'LI2_CHAIN'], values[b'LI2_RSEQ']
    repeat = values.get(b'LI2_REPEAT')

    # Preserve generic.parse's actual startup/attribution/lifecycle/vDSO facts.
    # Its zero-admission assertion belongs to the old profile and is replaced
    # here by the explicit native profile's actual positive-count contract.
    _unsigned(loader, generic.KEYS-{'scope'}, scope='partial_selected_native_pages_cpuid_nx' if nx else 'partial_selected_native_pages')
    need(loader['selected_profile'] == loader['generic_tf_profile'] == 1 and
         loader['source_patches'] == 0, 'actual unchanged-byte selected mechanism')
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
    return dict(loader=loader, native=native, repeat=repeat, run=run, chain=c, rseq=registration, **extension)


def completed(parsed, pid):
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

NX_SCALARS=set('version status failure_code hardware_entered hardware_returned phase attempts samples commits pc next_pc leaf subleaf'.split())
PROVIDER_SCALARS=set('version status failure_code initialized attempts busy cpuid_completed rdrand_completed rdseed_completed rdpid_completed random_entered random_returned random_committed random_error cpuid_entered cpuid_returned cpuid_committed'.split())

def _extensions(stderr,nx,configured):
    need(type(nx)is bool and type(configured)is bool and type(stderr)is bytes and stderr.endswith(b'\n'),'literal lane and complete report')
    lines=stderr[:-1].split(b'\n');extras={};at=2
    for enabled,name,key in ((configured,b'LI2_PROVIDER ','provider'),(nx,b'LI2_CPUID_NX ','cpuid_nx')):
        if not enabled:continue
        need(at<len(lines)and lines[at].startswith(name)and len(lines[at])+1<=4096,'exact extension position '+key)
        row=rseq.decode(lines[at][len(name):]);extras[key]=row;at+=1
        if key=='cpuid_nx':
            _unsigned(row,NX_SCALARS,{'raw':4,'result':4})
            need(row['hardware_entered']in(0,1)and row['hardware_returned']<=row['hardware_entered']and
                 row['phase']<=3 and row['commits']<=row['samples']<=row['attempts']and
                 all(x<1<<32 for x in row['raw']+row['result'])and row['leaf']<1<<32 and row['subleaf']<1<<32,'truthful NX partial prefix')
        else:
            need(type(row)is dict and row.get('policy')=='mask-random-v1','exact configured policy')
            # Removing the schema's string key does not alter any actual numeric value.
            check={k:v for k,v in row.items()if k!='policy'}
            _unsigned(check,PROVIDER_SCALARS,scope='configured_cpuid_random_id')
    return b'\n'.join(lines[:2]+lines[at:])+b'\n',extras

def qualify(parsed,pid,count,nx,configured,program):
    completed(parsed,pid) # unchanged old chain/register/rseq/native closure
    l,n=parsed['loader'],parsed['native']
    need(l['cpuid']==count and l['rdtsc']==l['rdtscp']==l['rdrand']==l['rdseed']==l['rdpid']==0 and
         l['source_patches']==l['rseq']==l['dependency_faults']==0 and l['source_syscalls']==2,'exact source effects, no invented publication or registration')
    need(parsed['rseq']['owner'][1:4]==[0,0,0],'actual unregistered fixture')
    if nx:
        r=parsed['cpuid_nx'];need(r['status']==r['failure_code']==0 and r['hardware_entered']==r['hardware_returned']==1 and
            r['phase']==3 and r['attempts']==r['samples']==r['commits']==count and r['next_pc']==r['pc']+2 and
            l['builtin_kind']==1 and l['builtin_phase']==0 and all(l[k]==0 for k in ('builtin_enable_result_abs','builtin_enable_result_negative','builtin_restore_result_abs','builtin_restore_result_negative'))and
            [l[k]for k in ('builtin_a','builtin_b','builtin_c','builtin_d')]==r['raw'],
            'actual NX completion with no control/rearm claim')
    else:
        need(l['builtin_kind']==1 and l['builtin_phase']==7 and all(l[k]==0 for k in ('builtin_enable_result_abs','builtin_enable_result_negative','builtin_restore_result_abs','builtin_restore_result_negative')),'unchanged actual faulted rearm')
    if configured:
        r=parsed['provider'];need(r['status']==r['failure_code']==r['busy']==r['random_error']==0 and r['initialized']==1 and
             r['attempts']==r['cpuid_completed']==count and all(r[k]==1 for k in ('cpuid_entered','cpuid_returned','cpuid_committed'))and
             all(r[k]==0 for k in ('rdrand_completed','rdseed_completed','rdpid_completed','random_entered','random_returned','random_committed')),'only actual CPUID callbacks completed')
    if program==4:need(n['main_refaults']==1,'one real MOVABS retry in added boundary corpus')
    else:need(n['main_refaults']==0,'no unplanned source-refault routes')

def arm_refusal(stderr,code,configured):
    """Strict early-failure schema; never returns completion or rewrites a row."""
    need(code in(236,238),'literal old gate refusal')
    stderr,extra=_extensions(stderr,False,configured)
    lines=stderr[:-1].split(b'\n');parts=[x.partition(b' ')for x in lines]
    need([x[0]for x in parts]==ORDER and all(x[1]==b' 'and 0<len(x[2])<4096 for x in parts),'all exact early report rows')
    rows={k:rseq.decode(v)for k,_,v in parts};l=rows[b'LI2_LOADER'];n=rows[b'LI2_NATIVE'];r=rows[b'LI2_RUN'];c=rows[b'LI2_CHAIN'];q=rows[b'LI2_RSEQ']
    _unsigned(l,generic.KEYS-{'scope'},scope='partial_selected_native_pages')
    _unsigned(n,NATIVE_KEYS-{'revisit_ns'},{'revisit_ns':n.get('revisit_count',-1)})
    need(r.get('cache_present')in(0,1)and r.get('publication_present')in(0,1),'actual early RUN presence')
    arrays={k:v for k,v in register.ARRAYS.items()if k not in('cache','initialization','attempt','publication')}
    if r['cache_present']:arrays.update({k:register.ARRAYS[k]for k in('cache','initialization','attempt')})
    if r['publication_present']:arrays['publication']=register.ARRAYS['publication']
    _unsigned(r,register.SCALARS,arrays);_unsigned(c,chain.KEYS-{'scope'},scope='opt_in_trace_to_plain')
    _unsigned(q,RSEQ_SCHEMA['scalar_keys'],{k:len(v)for k,v in RSEQ_SCHEMA['arrays'].items()},RSEQ_SCHEMA['scope'])
    need(all(x['status']==125 and x['failure_code']==code for x in(l,n,r,c,q,*extra.values())),'same actual early failure throughout')
    need(all(l[k]==0 for k in('source_patches','selected_selftests','first_target_is_interpreter_entry','interpreter_entry_faults','nx_faults','main_faults','interpreter_faults','dependency_faults','cpuid','generic_tf_attempts','generic_tf_steps','source_syscalls')),
         'gate refused before selftest or target entry; no qualification')
    need(n['attempts']==n['admissions']==n['closed']==0 and not n['revisit_ns'],'no native execution on old gate refusal')
    return dict(status='failed',failure_code=code,target_entered=False)
