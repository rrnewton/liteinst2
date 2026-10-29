"""Actual reusable-effect ls reports; terminal exit is an unreturned prefix."""
import importlib.util
from pathlib import Path
from page_selected import need
import page_selected_generic_compare as generic
import page_selected_register_connected_compare as register
import page_selected_repeat_compare as repetition
import page_selected_chain_compare as chain
import page_selected_rseq_compare as rseq
import page_default_ls_release_lease_reports as lease
import page_default_ls_release_reports as tty
ROOT=Path(__file__).resolve().parents[2]
_spec=importlib.util.spec_from_file_location('effect_ls_original_boundary',ROOT/'tools/page-entry/selected/tests/rseq_native_boundary/reports.py')
boundary=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(boundary)
registered=boundary.old;nx=registered.old
_unsigned=nx._unsigned;NATIVE_KEYS=nx.NATIVE_KEYS;RSEQ_SCHEMA=nx.RSEQ_SCHEMA;ZERO=nx.ZERO
ORDER=['LOADER','NATIVE','SELECTED_EFFECT','CPUID_NX','ONESHOT','RSEQ','RSEQ_NATIVE','RSEQ_BOUNDARY','RSEQ_BTRFS_TTY_QUERY','CHAIN','RUN']
EFFECT=set('version status failure_code detail_abs first_error stage busy finished sequence attempts commits completed native_completed scripted_completed kind action phase error pc next_pc callback_entered callback_returned native_entered native_returned random_backend_returned random_backend_status exit_entered post_guards_complete post_callback_entered post_callback_returned committed fp_bytes fp_before_initialized fp_after_initialized raw_entered raw_returned'.split())
ONESHOT=set('version status failure_code detail_abs detail_negative attempted published restored completed retired refused cpuid_patches syscall_patches rdtsc_patches effect_started effect_returned active_phase resetting last_completed_sequence last_refused_sequence backend_prepared backend_completed rseq_phase rseq_error rseq_attempts rseq_retired retained_records generations'.split())

def reports(stderr):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'complete actual stderr')
    lines=stderr[:-1].split(b'\n');parts=[line.partition(b' ')for line in lines]
    names=[p[0]for p in parts];order=['LI2_'+x for x in ORDER]
    if b'LI2_REPEAT'in names:order.insert(4,'LI2_REPEAT')
    need(names==[s.encode()for s in order]and all(p[1]==b' 'and 0<len(line)+1<=4096 and b'\r'not in line for p,line in zip(parts,lines)),
         'exact bounded report order with no duplicate or unrecognized rows')
    values={name:rseq.decode(raw)for name,_,raw in parts}
    loader,native=values[b'LI2_LOADER'],values[b'LI2_NATIVE']
    run,c,registration=(values[k]for k in(b'LI2_RUN',b'LI2_CHAIN',b'LI2_RSEQ'))
    repeat=values.get(b'LI2_REPEAT')
    extension=dict(effect=values[b'LI2_SELECTED_EFFECT'],oneshot=values[b'LI2_ONESHOT'],
        cpuid_nx=values[b'LI2_CPUID_NX'],rseq_native=values[b'LI2_RSEQ_NATIVE'],
        rseq_boundary=values[b'LI2_RSEQ_BOUNDARY'],tcgets=values[b'LI2_RSEQ_BTRFS_TTY_QUERY'])
    # Preserve generic.parse's actual startup/attribution/lifecycle/vDSO facts.
    # Its zero-admission assertion belongs to the old profile and is replaced
    # here by the explicit native profile's actual positive-count contract.
    _unsigned(loader, generic.KEYS-{'scope'}, scope='partial_selected_reusable_effects')
    need(loader['selected_profile'] == loader['generic_tf_profile'] == 1 and
         loader['source_patches'] > 0, 'actual reusable selected publication mechanism')
    need(loader['selected_selftests'] == loader['first_target_is_interpreter_entry'] ==
         loader['interpreter_entry_faults'] == 1, 'actual startup and first interpreter entry')
    need(loader['nx_faults'] == loader['main_faults']+loader['interpreter_faults']+
         loader['dependency_faults'], 'actual fault attribution')
    records=extension['oneshot']
    need(type(records)is dict and type(records.get('retained_records'))is int and
         records['retained_records']==loader['retired']+loader['live_pages'], 'retained record equation')
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

    _unsigned(c, (chain.KEYS-{'scope'})|lease.EXTRA, scope='opt_in_same_page_tf_lease')
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
    parsed=dict(loader=loader,native=native,repeat=repeat,run=run,chain=c,rseq=registration,
        lease={k:c[k]for k in lease.EXTRA},**extension)
    return parsed


def extensions(p):
    l=p['loader'];cp=p['cpuid_nx'];rn=p['rseq_native'];b=p['rseq_boundary'];t=p['tcgets']
    _unsigned(cp,nx.NX_SCALARS,{'raw':4,'result':4})
    need(cp['hardware_entered']in(0,1)and cp['hardware_returned']<=cp['hardware_entered']and
         cp['phase']<=3 and cp['commits']<=cp['samples']<=cp['attempts']and
         all(x<1<<32 for x in cp['raw']+cp['result'])and cp['leaf']<1<<32 and cp['subleaf']<1<<32,
         'truthful exact CPUID prefix')
    _unsigned(rn,registered.SCALARS,{'before':28,'after':28},'registered_native_epochs')
    need(rn['phase']<=4 and all(rn[k]in(0,1)for k in('unsafe_terminal','entry_checked','checking','detail_negative','first_detail_negative'))and
         all(rn[k]<1<<16 for k in('fs_selector_entry','gs_selector_entry','fs_selector_after','gs_selector_after')),
         'exact registered-native domains')
    need(rn['closed']<=rn['entries']<=rn['admissions']<=rn['attempts']and rn['tls_refreshes']<=rn['closed']and
         rn['entries']<=rn['preentries']and rn['admissions']<=p['native']['admissions'],'actual native epoch prefix')
    _unsigned(b,boundary.SCALARS,boundary.ARRAYS,'registered_current_pc_refault')
    need(b['phase']<=5 and all(b[k]in(0,1)for k in('entry_checked','detail_negative','first_detail_negative'))and
         all(x<1<<16 for x in b['tls'][4:]),'exact boundary scalar domains')
    a,perm,entry,observed,tls,closed=b['counts']
    need(closed<=tls<=observed<=entry<=perm<=a<=rn['admissions']and closed<=p['native']['refaults'],'actual boundary prefix')
    _unsigned(t,tty.SCALARS,tty.ARRAYS,'trusted_parent_capture_btrfs_tcgets_tiocgwinsz_v1')
    e=p['effect'];_unsigned(e,EFFECT,{'classes':7},'linked_full_input_effect')
    o=p['oneshot']
    need(type(o)is dict and set(o)==ONESHOT|{'scope'}and o['scope']=='singleton_reusable_sealed_temporary_e9'and
         all(type(o[k])is int and 0<=o[k]<1<<64 for k in ONESHOT)and o['version']==2,'exact reusable publication schema')
    for row in(cp,rn,b,t,e,o):
        need(all(row[k]==l[k]for k in('status','failure_code','detail_abs','detail_negative')if k in row),'same actual terminal outcome')

def effect_exit(p):
    l,e,o,cp=(p[k]for k in('loader','effect','oneshot','cpuid_nx'))
    need(l['last_syscall']in(60,231)and l['source_syscalls']==l['syscalls']==l['forwarded']>0,'actual successful exit syscall path')
    need(all(e[k]==v for k,v in dict(first_error=0,stage=4,busy=1,finished=0,kind=7,action=1,phase=5,error=0,
        callback_entered=0,callback_returned=0,native_entered=1,native_returned=0,exit_entered=1,
        post_guards_complete=0,post_callback_entered=0,post_callback_returned=0,committed=0,
        random_backend_returned=0,random_backend_status=0,fp_after_initialized=0,raw_entered=0,raw_returned=0).items()),
        'literal report-before-raw nonreturning exit prefix; never completed')
    need(0<e['pc']<=(1<<64)-3 and e['next_pc']==e['pc']+2 and
         512<=e['fp_bytes']==e['fp_before_initialized']<=65536 and
         e['sequence']==e['attempts']==e['completed']+1 and e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and e['classes']==[l['cpuid'],l['rdrand'],l['rdseed'],l['rdpid'],l['rdtsc'],l['rdtscp'],l['syscalls']-1]and
         sum(e['classes'])==e['completed'],'every returning Native class accounted separately from final exit')
    need(o['published']>8 and o['attempted']==o['published']==o['restored']==o['effect_started']==o['backend_prepared']==l['source_patches']and
         o['completed']==o['retired']==o['effect_returned']==o['backend_completed']==o['last_completed_sequence']==o['published']-1 and
         o['refused']==o['resetting']==o['last_refused_sequence']==o['rseq_error']==0 and o['active_phase']==7 and
         o['rseq_phase']==6 and o['rseq_attempts']==o['published']and o['rseq_retired']==o['retired'],
         'all temporary patches restored; only final exit remains unreturned and unretired')
    need([o[k]for k in('cpuid_patches','syscall_patches','rdtsc_patches')]==[l['cpuid'],l['syscalls'],l['rdtsc']]and
         o['published']==o['cpuid_patches']+o['syscall_patches']+o['rdtsc_patches']and
         o['generations']==l['generations']and o['retained_records']>0,'actual class publication and lifecycle accounting')
    # Each restored plan renews its fixed one or two source pages twice.
    # Page counts are not separately reported; do not invent an exact split.
    generation_delta=l['generations']-o['retained_records']
    need(generation_delta%2==0 and 2*o['published']<=generation_delta<=4*o['published'],
         'two in-place generation advances per restored one-or-two-page publication')
    need(cp['hardware_entered']==cp['hardware_returned']==1 and cp['phase']==3 and
         cp['attempts']==cp['samples']==cp['commits']==l['cpuid']>0 and cp['next_pc']==cp['pc']+2 and
         cp['raw']==cp['result'],'real complete unmodified hardware CPUID path')
    need(p['rseq']['owner'][1:4]==[1,1,3]and l['rseq']==p['rseq']['counts'][0]>0,
         'real default inactive registration remains held through process exit')

def gate(p,pid,exit_code,parent):
    o=p['tcgets']
    need(type(pid) is int and pid > 0 and type(exit_code) is int and exit_code in (0,125),
         'actual report-bearing terminal process')
    need(o['version'] == 1 and o['status'] == exit_code and
         all(o[k] == p['loader'][k] for k in ('status','failure_code','detail_abs','detail_negative')),
         'same terminal outcome, never a failed operation relabel')
    x,q,m = o['prefix'],o['query'],o['mount']
    need(x[0] == 1 and o['launch'] == parent['identity'] and
         all(v in (0,1) for v in (x[1],x[5],*q[:2],q[4],q[6],*m[:5],m[6],m[8],o['detail_negative'])) and
         x[2] <= 8 and x[11] <= x[10] <= x[9] <= x[8] <= x[7] and q[1] <= q[0] and
         m[9] <= 256<<10 and m[10] <= 2048 and m[11] <= 1,
         'actual normal-open launch identity and bounded truthful gate prefixes')
    need((x[1] == 0 and x[6] == 0) or (x[1] == 1 and x[6] == 3),
         'permanent invalidation records attempted close(1)')
    if x[8] and x[7] == x[8]:
        need(o['current'][:5] == o['launch'][:5] and
             o['current'][5] & 0o170000 == o['launch'][5] & 0o170000 == 0o100000 and
             not o['current'][6] & 0o10000000 and x[13] > 0 and x[14] > 0,
             'actual admitted descriptor identity and registration/check prefix')
    if x[11] and x[7] == x[11]:
        need(x[7] == x[8] == x[9] == x[10] == x[11] and q[5:] == [25,1] and
             q[:2] == [1,1] and m[:5] == [1]*5 and m[7:9] == [0,0] and
             m[9] > 0 and m[10] > 0 and m[11] == 1,
             'actual last completed result is -ENOTTY with full unique mount closure')
    commands=o['commands']
    need(commands[0]+commands[1]==x[11] and commands[2]in(0,0x5401,0x5413) and
         (commands[2]==0)==(x[7]==0),'exact per-command actual validated-return accounting')
    if x[11] and x[7]==x[11]:
        need(commands[0 if commands[2]==0x5401 else 1]>0,
             'actual last completed command belongs to its nonempty counter')
    completed = False
    if exit_code == 0:
        boundary.completed(p,pid)  # Every original report, epoch, rseq, native and owner guard.
        need(o['failure_code'] == o['detail_abs'] == o['detail_negative'] == x[3] == x[4] == x[5] == 0 and
             x[2] in (2,7) and x[7] == x[8] == x[9] == x[10] == x[11],
             'no pending or failed gate at application completion')
        if x[11]:
            need(x[2] == 7 and q[5:] == [25,1] and q[:2] == [1,1] and
                 m[:5] == [1]*5 and m[7:9] == [0,0] and m[9] > 0 and m[10] > 0 and m[11] == 1,
                 'actual last -ENOTTY and complete unique mount proof before commit')
        need(commands[0]>0 and commands[1]>0,
             'successful two-query diagnostic must actually validate both exact commands')
        completed = True
    else:
        refused = False
        try: boundary.completed(p,pid)
        except ValueError: refused = True
        need(refused, 'unchanged completed rejects failed operation')
    return o,p,dict(application_completed=completed,gate_result_validations=x[11],
        attempts=x[7],permitted=x[8],issued=x[9],returned=x[10],invalidated=x[1],
        tcgets_result_validations=commands[0],tiocgwinsz_result_validations=commands[1],last_command=commands[2],
        gate_phase=x[2],gate_first_error=x[3],gate_first_detail_abs=x[4],
        last_result_abs=q[5],last_result_negative=q[6],failure_code=o['failure_code'],
        detail_abs=o['detail_abs'],detail_negative=o['detail_negative'],
        original_completed_rejected=not completed)


def check(stderr,pid,exit_code,parent):
    need(type(exit_code)is int and exit_code==0,'actual successful process required')
    p=reports(stderr);extensions(p)
    _,same,gate_summary=gate(p,pid,exit_code,parent)
    need(same is p,'original actual report values retained')
    lease_summary=lease.counters(p);effect_exit(p)
    n=p['native'];e=p['effect'];o=p['oneshot']
    return p,dict(application_completed=True,default_rseq_registered=True,gate=gate_summary,lease=lease_summary,
        selected=dict(attempts=e['attempts'],completed=e['completed'],classes=e['classes'],unreturned_exit=1),
        publication={k:o[k]for k in('attempted','published','restored','completed','retired','refused','cpuid_patches','syscall_patches','rdtsc_patches','rseq_attempts','rseq_retired','retained_records','generations')},
        native={k:n[k]for k in('attempts','admissions','closed','blocked','epoch_exits','refaults','main_admissions','main_refaults')},
        admission_timing=dict(first_admission_ns=n['first_admission_ns'],first_source_offset=n['first_source_offset'],revisit_count=n['revisit_count'],revisit_ns=n['revisit_ns']))
