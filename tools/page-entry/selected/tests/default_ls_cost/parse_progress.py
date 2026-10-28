"""Parse diagnostic prefixes only; terminal operation acceptance stays elsewhere."""
import json

KEYS=set(('version prefix sample boundary handlers signal entry_pc pc cpu_ns wall_ns '
          'route step_pending nx chain_steps trace_entries admissions closed retained_records '
          'live_pages rseq_registered rseq_phase rseq_registrations rseq_instruction_checks '
          'rseq_range_checks rseq_run_checks rseq_syscall_checks rseq_last_pc rseq_last_code '
          'maps_fresh_calls maps_acquisitions maps_reuses maps_invalidations maps_handler_id maps_mutation_epoch maps_active maps_valid maps_poisoned').split())
MONOTONIC=('handlers','cpu_ns','wall_ns','nx','chain_steps','trace_entries','admissions','closed',
           'rseq_registrations','rseq_instruction_checks','rseq_range_checks','rseq_run_checks','rseq_syscall_checks',
           'maps_fresh_calls','maps_acquisitions','maps_reuses','maps_invalidations','maps_handler_id','maps_mutation_epoch')
def need(ok,why):
    if not ok:raise ValueError(why)
def decode(text):
    def pairs(items):
        value={}
        for k,v in items:
            need(k not in value,'duplicate diagnostic field');value[k]=v
        return value
    return json.loads(text,object_pairs_hook=pairs)
def progress(stderr):
    rows=[];terminal=[];pending=None;paired=[];finished=False
    for line in stderr.splitlines(keepends=True):
        if not line.startswith(b'LI2_DIAG '):
            finished=True;terminal.append(line);continue
        need(not finished and line.endswith(b'\n')and b'\r'not in line and len(line)<=2048,'whole ordered bounded diagnostic line')
        r=decode(line[len(b'LI2_DIAG '):]);need(type(r)is dict and set(r)==KEYS,'exact diagnostic keys')
        need(all(type(v)is int and 0<=v<1<<64 for v in r.values()),'unsigned diagnostic scalars')
        need(r['version']==3 and r['prefix']==1 and 1<=r['sample']<=128 and r['boundary']in(1,2),
             'explicit nonterminal sample boundary')
        need(r['rseq_registered']in(0,1)and r['step_pending']in(0,1)and r['closed']<=r['admissions'],
             'actual observed state domains')
        need(all(r['maps_'+k]in(0,1)for k in('active','valid','poisoned'))and
             r['maps_acquisitions']<=r['maps_fresh_calls'],'actual maps counter domains')
        if rows:need(all(r[k]>=rows[-1][k]for k in MONOTONIC),'monotone actual observations')
        if r['boundary']==1:
            need(pending is None and r['sample']==len(paired)+1,'next actual sampled entry')
            if not rows:need(r['handlers']==1,'first genuine handler prefix')
            else:need(r['handlers']>rows[-1]['handlers'],'distinct later handler entry')
            pending=r
        else:
            need(pending is not None and all(r[k]==pending[k]for k in('sample','handlers','signal','entry_pc')),
                 'matching sampled handler return')
            paired.append(dict(sample=r['sample'],cpu_ns=r['cpu_ns']-pending['cpu_ns'],
                               wall_ns=r['wall_ns']-pending['wall_ns'],
                               counters={k:r[k]-pending[k]for k in('chain_steps','rseq_instruction_checks',
                                   'maps_fresh_calls','maps_acquisitions','maps_reuses','maps_invalidations')}))
            pending=None
        rows.append(r);need(len(rows)<=256,'fixed256-line cap')
    return dict(prefix_valid=True,lines=len(rows),paired_samples=len(paired),unreturned_sample=pending is not None,
                first=rows[0]if rows else None,last=rows[-1]if rows else None,sampled_handler_intervals=paired,
                operation_completed=False,kill_cause_proven=False),b''.join(terminal)
