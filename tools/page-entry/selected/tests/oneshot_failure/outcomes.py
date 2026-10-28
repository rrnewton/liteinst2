"""Typed expectations supplement the unchanged strict product report parser.

The source-generated completion prefix below is byte-exact except its function
name. The original six-site completion function remains unchanged in product.
"""
from page_selected import need
import page_selected_rseq_compare as rseq

def refused_site_completed(parsed, pid):
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

    o=parsed['oneshot']
    need(o['owners']==6 and o['published']==o['restored']==o['effect_started']==5 and
         o['completed']==o['effect_returned']==4 and o['syscall_patches']==4 and
         o['rdtsc_patches']==1 and o['active_phase']==7,
         'one explicitly refused first site; five actual remaining publications and honest exit')
    need(loader['rdtsc']>=2 and loader['source_syscalls']>=4 and
         native['main_admissions']==2 and native['main_refaults']==0,
         'same actual original application and native observation entries')
    need(parsed['rseq']['owner'][1:4]==[0,0,0]and loader['rseq']==0,
         'same explicit unregistered comparison lane')


def terminal(parsed,pid,e):
    loader,o,r=parsed['loader'],parsed['oneshot'],parsed['rseq']
    need(loader['status']==o['status']==125 and loader['failure_code']==o['failure_code']==e['report_error'],
         'actual controller failure remains a failed operation')
    need(o['owners']==1 and o['published']==e['published'] and o['restored']==int(e['mode']==46)and
         o['completed']==o['effect_started']==o['effect_returned']==0 and
         o['syscall_patches']==0 and o['rdtsc_patches']==e['published']and o['active_phase']==9,
         'exact target-owner prefix; no selected effect or false COMPLETE')
    need(r['owner'][:7]==[1,0,0,0,0,0,0]and r['owner'][7:9]==[pid,pid]and
         r['owner'][9:]==[0]*5 and r['counts']==[0]*9 and loader['rseq']==0,
         'actual launch PID and no registration or fabricated unregister')
