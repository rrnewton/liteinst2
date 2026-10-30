"""Application-owner terminal qualification; no ls/true reader is changed.

The actual full owner record must pass before this report join. Required failed
operations keep exit125 and must be rejected by the original completion gate.
"""
import copy
import hashlib
import json
from page_selected import need
import maps_view
import page_cost_reports as cost
import page_native_pair_reports as old
import unrolled_hash_reports as unrolled
H=lambda b:hashlib.sha256(b).hexdigest()


def unused_repeat(p):
    """Whole initialized unused owner; actual global terminal outcome retained."""
    r=p['repeat_lease'];expected=dict.fromkeys(old.LEASE_SCALARS,0);expected['version']=1
    for key in ('status','failure_code','detail_abs','detail_negative'):
        if key in expected:expected[key]=p['loader'][key]
    # These are global controller observations, not unused REP-owner fields.
    expected['route']=p['loader']['step_route'];expected['pending']=p['run']['pending']
    for key,size in old.LEASE_ARRAYS.items():expected[key]=[0]*size
    expected['owner'][-1]=1;expected['custody'][0]=1
    need(r==expected and p['repeat']is None,'complete canonical unused REP state with exact actual terminal status')
    return dict(attempts=0,completed=0,source_observed=False)


def check(stderr,pid,exit_status,parent,images,image_bytes,carrier,carrier_bytes,owner,owner_reader):
    row,suffix=unrolled.split(stderr)
    view,original=maps_view.split_report(suffix,'maintained')
    parsed=old.reports(original);old.extensions(parsed)
    _,same,gate=old.gate(parsed,pid,exit_status,parent,0)
    need(same is parsed and all(row[k]==parsed['loader'][k]for k in
         ('status','failure_code','detail_abs','detail_negative')),'all actual terminal rows have one unchanged outcome')
    need(row['observe_only']==0,'actual generated-owner qualification, never observe-only')
    owner_reader.terminal(parsed,row,owner)
    inputs=cost._retained_inputs(images,image_bytes,carrier,carrier_bytes)
    retained=unused_repeat(parsed)
    summary=dict(application_completed=exit_status==0,gate=gate,repeat_lease=retained,
        input_authentication=inputs,maps_view=view,unrolled={k:row[k]for k in unrolled.COUNTERS},
        required_refusal=int(exit_status==125))
    if exit_status==0:
        unrolled.completed(row,False)
        summary.update(lease=old.lease.counters(parsed),trace_run=old.trace_completed(parsed),
            native_pair=old.pair_completed(parsed,pid),cache_reuse=old.reuse_completed(parsed['run'],parsed['reuse']))
        old.effect_exit(parsed)
    else:
        need(exit_status==125 and gate['original_completed_rejected']is True and
             row['first_error']==row['failure_code']>0,'required failed operation retains first error and cannot earn completion')
    return parsed,summary


def controls(stderr,*args):
    """Fixed supplied report changes after actual full-record/report acceptance."""
    parsed,_=check(stderr,*args);row,suffix=unrolled.split(stderr);view,original=maps_view.split_report(suffix,'maintained')
    lines=stderr[:-1].split(b'\n');trials=[]
    def changed(name,prefix,record):
        places=[i for i,line in enumerate(lines)if line.startswith(prefix)]
        need(len(places)==1,'one actual supplied report target');data=list(lines)
        data[places[0]]=prefix+json.dumps(record,separators=(',',':'),allow_nan=False).encode()
        trials.append((name,b'\n'.join(data)+b'\n'))
    for key in ('version','status','failure_code','first_error','initialized','observe_only','entries','completed','used','events'):
        value=copy.deepcopy(row);value[key]^=1;changed('owner_'+key,unrolled.PREFIX,value)
    for key in ('signals','current'):
        value=copy.deepcopy(row);value[key][0]^=1;changed('owner_'+key,unrolled.PREFIX,value)
    for key in ('version','enabled','differential','poisoned','reserved','mismatches','queries','comparisons'):
        value=dict(view);value[key]^=1;changed('maps_'+key,maps_view.PREFIX,value)
    for name,key,field,index in (('pair_slot','native_pair','slots',(0,5)),
         ('pair_live','native_pair','control',6),('pair_closes','native_pair','counts',3),
         ('rseq_pin','rseq','identity',1),('rseq_epoch','rseq','owner',13),
         ('unused_owner','repeat_lease','owner',0),('unused_source','repeat_lease','source',0),
         ('unused_frame','repeat_lease','frames',0),('unused_custody','repeat_lease','custody',4)):
        value=copy.deepcopy(parsed[key]);target=value[field][index[0]]if type(index)is tuple else value[field]
        at=index[1]if type(index)is tuple else index;target[at]^=1
        prefix={'native_pair':b'LI2_NATIVE_PAIR ','rseq':b'LI2_RSEQ ','repeat_lease':b'LI2_REPEAT_LEASE '}[key]
        changed(name,prefix,value)
    trials.extend([('truncated',stderr[:-1]),('duplicate_owner',stderr+lines[-1]+b'\n'),
        ('missing_owner',suffix),('missing_maps',b'\n'.join(lines[1:])+b'\n')])
    need(len(trials)==33 and len({n for n,_ in trials})==33,'complete fixed named terminal refusal population')
    names=[]
    for name,data in trials:
        rejected=False
        try:check(data,*args)
        except ValueError:rejected=True
        need(rejected,'complete actual terminal reader rejects '+name);names.append(name)
    return dict(refusals=names,native_operations=0,original_stderr_sha256=H(stderr))
