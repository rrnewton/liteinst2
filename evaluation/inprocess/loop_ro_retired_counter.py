"""Strict ABI6 retired-root observations, never a larger-cache simulation."""
from pathlib import Path
import json,struct
from page_selected import fact,need
from loop_ro_reason_counter import (MAGIC,KINDS,GATES,OUTCOMES,_prefix_cells,
    _completed_reason_cells,_completed_controls)

VERSION,BYTES,PAGE=6,2016,4096
NAMES=('error','saves','overwrites','gate4','search_done','root_seen','source_seen','exact_seen',
       'no_root','source_changed','context_changed','bank_changed','registry_changed','lifetime_changed')
AGE=('1','2','3-4','5-8','9-16','17-64','65-256','over256')
SCHEMA=dict(version=6,bytes=2016,base_bytes=1696,page=4096,initial_seals=6,final_seals=23)

def final_counter_prefix(data,initial,pid,seals):
    need(type(initial) is tuple and len(initial)==8 and all(type(n) is int and 0<=n<1<<64 for n in initial)
         and initial[:4]==(MAGIC,6,2016,4096) and all(n>0 for n in initial[4:]),'exact ABI6 initial identity')
    need(type(pid) is int and pid>0 and type(data) is bytes and len(data)==4096 and type(seals) is int and seals==23,
         'whole final sealed counter backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and 4096<=h[12]<1<<47 and h[12]%4096==0 and
         h[13:]==(1,1,1) and not any(data[2016:]) and not any(data[596:600]),
         'exact initialized/protected/closed/ready final counter header and zero tail')
    w=struct.unpack_from('<40Q',data,1696)
    need(w[0]<=7 and w[14:16]==(0,0),'typed ABI6 retired prefix and reserved cells')
    retired=dict(zip(NAMES,w[:14],strict=True))
    retired['retirement_rank']=list(w[16:32]);retired['offer_age']=dict(zip(AGE,w[32:],strict=True))
    return dict(version=6,logical_bytes=2016,**_prefix_cells(data),retired=retired,retired_prefix_usable=w[0]==0)

def final_prefix(row,private,binary):
    observed=row['counter_observation'];counter=row['counter_input']
    need(row['reaped'] is True and observed['usable'] is True and row['cleanup_errors']==[] and
         all(d['closed'] is True for d in row['descriptors']),'closed ABI6 read-only counter prefix')
    need(counter['version']==6 and counter['bytes']==4096 and counter['logical_bytes']==2016 and
         counter['initial_seals']==6,'actual ABI6 input schema')
    capture=row['captures']['counters'];need(capture['file']==row['name']+'.counters','actual child counter capture name')
    path=binary(private/capture['file'])
    need(fact(path)==observed['raw']=={k:capture[k] for k in ('bytes','sha256')},'whole retained ABI6 counter bytes')
    initial=(MAGIC,6,2016,4096,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    exact=final_counter_prefix(path.read_bytes(),initial,row['pid'],observed['final_seals'])
    need(all(observed[k]==v for k,v in exact.items()),'every retained ABI6 cell rejoins its original observation')
    return exact

def completed_prefix(prefix,terminal):
    need(type(prefix) is dict and prefix.get('version')==6 and prefix.get('logical_bytes')==2016,
         'distinct ABI6 completion input, never schema normalization')
    _completed_reason_cells(prefix,terminal)
    v=prefix['retired'];r=prefix['reasons']
    need(v['error']==0 and prefix['retired_prefix_usable'] is True and
         v['saves']==prefix['group']['retirements'] and v['overwrites']==max(0,v['saves']-16) and
         v['gate4']==v['search_done']==sum(r['first_failure'][k]['source_key'] for k in KINDS),
         'completed actual retirement and evaluated gate4 events')
    need(v['search_done']==v['no_root']+v['source_changed']+v['context_changed']+v['exact_seen'] and
         v['root_seen']==v['source_changed']+v['context_changed']+v['exact_seen'] and
         v['source_seen']==v['context_changed']+v['exact_seen'] and
         sum(v['retirement_rank'])==sum(v['offer_age'].values())==v['exact_seen'] and
         all(v[k]<=v['context_changed'] for k in ('bank_changed','registry_changed','lifetime_changed')) and
         v['context_changed']<=sum(v[k] for k in ('bank_changed','registry_changed','lifetime_changed'))<=3*v['context_changed'],
         'completed exact-root search partition and censored rank/age histograms')

def completed_controls(prefix,terminal):
    old=_completed_controls(prefix,terminal,completed_prefix);paths=[(n,) for n in NAMES]
    paths += [('retirement_rank',i) for i in range(16)]+[('offer_age',n) for n in AGE]
    refused=[]
    for path in paths:
        changed=json.loads(json.dumps(prefix));target=changed['retired']
        for part in path[:-1]:target=target[part]
        target[path[-1]]=prefix['retired']['context_changed']+1 if path[0] in (
            'bank_changed','registry_changed','lifetime_changed') else target[path[-1]]^1
        need(changed!=prefix,'nonidentity actual retired completion stimulus')
        try:completed_prefix(changed,terminal)
        except ValueError:refused.append('.'.join(map(str,path)))
        else:raise ValueError('accepted retired completion mutation '+str(path))
    need(len(refused)==len(set(refused))==38,'all38 additive actual retired completion refusals')
    return dict(refusals=old['refusals']+['retired.'+n for n in refused],guest_executions=0)

def prepare_counter_carrier(state,pin):
    root=Path(__file__).resolve().parents[2];old=pin(root/'tools/page-entry/carrier.py')
    need(state['carrier_tool']==old,'unchanged actual carrier creation tool')
    new=pin(root/'tools/page-entry/loop_ro_retired_carrier.py')
    state['carrier_make_tool']=old;state['carrier_tool']=new
    names=('evaluation/inprocess/loop_ro_retired_counter.py','evaluation/inprocess/loop_ro_retired_process.py',
           'evaluation/inprocess/loop_ro_reason_counter.py','evaluation/inprocess/loop_ro_reason_process.py',
           'evaluation/inprocess/persistent_loop_counter.py','evaluation/inprocess/persistent_loop_effects_counter.py',
           'tools/page-entry/loop_ro_reason_carrier.py','tools/page-entry/namespace.py')
    return dict(make=dict(path=str(old),**fact(old)),execute=dict(path=str(new),**fact(new)),
                sources={name:fact(pin(root/name)) for name in names})

def protocol(builder,run,record,pin):
    from loop_ro_reason_counter import protocol as old_protocol
    old_protocol(builder,run,record,pin)
    script=pin(Path(__file__).resolve().with_name('loop_ro_retired_protocol.py'))
    _,out,err=run('loop-ro-retired-protocol',[builder.tools['python'],'-B',script],profile='finite')
    expected=dict(scope='loop_ro_retired_protocol_only',version=6,cell_offset_checks=38,
                  refusal_count=30,guest_executions=0)
    need(err==b'' and out==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole ABI6 literal offsets and strict cross-version/descriptor refusals')
    record['loop_ro_retired_protocol']=dict(expected,script=dict(path=str(script),**fact(script)))
