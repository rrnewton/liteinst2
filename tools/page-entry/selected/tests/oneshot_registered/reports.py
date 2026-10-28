"""Separate zero-publication registered fixture; no old six-owner change."""
from page_selected import need
import page_selected_rseq_compare as rseq


def completed(parsed,pid):
    loader,native=parsed['loader'],parsed['native']
    need(native['status']==native['failure_code']==native['epoch_error']==native['close_error']==native['close_busy']==0 and
         native['close_complete']==1 and 0<native['admissions']==native['closed']==loader['admissions'] and
         loader['sync_core']==native['admissions']+native['closed'] and native['first_admission_ns']>0,
         'unchanged actual native admission/revocation completion')
    # Every old generic/chain/register/repeat/rseq completion predicate remains.
    rseq.completed(loader,parsed['repeat'],parsed['run'],parsed['chain'],parsed['rseq'],pid)
    o=parsed['oneshot']
    need(all(o[k]==0 for k in ('owners','published','restored','completed','syscall_patches','rdtsc_patches',
                              'effect_started','effect_returned','active_phase')) and loader['source_patches']==0,
         'registered ordinary fallback never consumes or publishes a one-shot owner')
    need(parsed['rseq']['owner'][1:4]==[1,1,3] and parsed['rseq']['counts'][:4]==[1,1,0,0] and
         loader['rseq']==1 and loader['rdtsc']>=1 and loader['source_syscalls']>=5 and
         native['main_admissions']==native['main_refaults']==0,
         'real registration remains ACTIVE at exit; main uses ordinary selected dispatch')
