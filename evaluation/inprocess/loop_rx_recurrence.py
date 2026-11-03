"""Strict ABI7 pe_build prefix and explicitly counterfactual recurrence models.

No row is execution authority. These are the actual first 1024 pe_build calls,
not all offered PCs: coarse refusals and the existing negative hint precede them.
"""
from collections import Counter, OrderedDict
from pathlib import Path
import struct
from page_selected import fact, need

MAGIC=0x31434f554e544750
VERSION,BYTES,STORAGE,ROWS,ROW=7,12382208,12582912,1024,12088
STOP=8960
COUNTERS=('events','segv','trap','ill','sys','other','offers','publications','hits',
          'cold_attempts','cancelled','retirements','permit_claims','entries','completed',
          'unexpected','code_opens','code_revokes','code_writes','code_syncs',
          'metadata_permissions','metadata_syncs','rx_entries','retained_entries')
SCHEMA=dict(version=VERSION,bytes=BYTES,storage_bytes=STORAGE,capacity=ROWS,
            row_bytes=ROW,source_bytes=8760,initial_seals=6,final_seals=23)


def source_key(raw):
    """Exact existing LOOP page/backing comparison fields plus both full pages.

    Runtime BEGIN follows actual source preparation. The recorded valid sealed
    object membership is an input fact; this offline model grants no ownership.
    Canonical anonymous backing includes all padding, as the actual helper does.
    """
    need(type(raw)is bytes and len(raw)==8760,'whole actual source key')
    entry=struct.unpack_from('<Q',raw)[0];pages=[]
    for i in range(2):
        at=8+4376*i
        identity=struct.unpack_from('<5Q4I6Q',raw,at)
        b=raw[at+104:at+280]
        fd=struct.unpack_from('<i',b)[0]
        seals,result=struct.unpack_from('<qq',b,8)
        observed=struct.unpack_from('<II',b,168)
        if identity[5]==1:
            need(identity[6]<34 and fd>=0 and seals>=0 and seals&15==15 and
                 result==0 and observed==(1,1),'actual valid sealed source backing')
            backing=(fd,seals,result,struct.unpack_from('<QQ',b,24),
                     struct.unpack_from('<q',b,72)[0],struct.unpack_from('<I',b,48)[0],observed)
        else:
            need(identity[5]==2 and identity[6]==34 and identity[4]==0 and
                 identity[11:14]==(0,0,0) and fd==-1 and not any(b[4:]),
                 'actual canonical anonymous source backing')
            backing=(-1,)
        pages.append((identity,backing,raw[at+280:at+4376]))
    return entry,tuple(pages)


def _rows(data):
    h=struct.unpack_from('<512Q',data)
    reserved,finished=h[17:19]
    need(h[16]==0 and 0<=finished<=reserved<=ROWS and reserved-finished<=1 and
         h[19] in (0,STOP) and not any(h[20:]),'valid observer state and reserved header')
    result=[];derived=0
    for i in range(reserved):
        at=4096+i*ROW;raw=data[at:at+ROW];v=struct.unpack_from('<128Q',raw)
        phase=v[127]
        need(phase in (0,1,3,7,11,15) and (i==reserved-1 or phase in (11,15)),
             'only the last reserved row can be partial')
        if phase==0:
            result.append(dict(index=i+1,phase=0));continue
        need(v[0]==i+1 and v[1]>0 and v[2]<2 and v[3]<2 and v[4]<3 and
             v[5]>0 and v[6]<=128 and v[47]==v[5] and v[48]==1 and v[49]==0 and
             not any(v[115:127]),'complete BEGIN identity and reserved words')
        key=source_key(raw[1024:9784]);need(key[0]==v[1],'actual requested source entry')
        registry=tuple(struct.unpack_from('<QQ',raw,9784+16*j) for j in range(v[6]))
        need(all(0<a<b<1<<47 for a,b in registry) and
             not any(raw[9784+16*v[6]:11832]) and
             any(a<=h[12] and h[12]+STORAGE<=b for a,b in registry),
             'whole bounded registry includes the complete protected observation bank')
        need(v[36] in (1,2) and v[114]==1 and v[43]<1<<16 and v[44]<1<<16 and
             (v[36]==1 and v[37]>0 and v[38]%32==0 and v[39]==32 and v[113]==1 or
              v[36]==2 and not any(v[38:41]) and v[46]==0 and v[113]==0),
             'actual registered or unregistered source context')
        slots=[tuple(v[22+5*j:27+5*j]) for j in range(2)]
        for generation,root,last,installed,bank in slots:
            need(installed in (0,1) and bank<2 and
                 (installed==1 and generation>0 and root>0 and last>0 or
                  installed==0 and (generation,root,last,bank)==(0,0,0,0)),
                 'literal actual retained-slot occupancy')
        heads=()
        if phase>=3:
            need(v[9] in (1,2,3,4) and v[7] in tuple((1<<n)-1 for n in range(1,11)) and
                 (v[7]==v[8]==1023 if v[9]<=2 else v[8]==v[7]>>1),
                 'exact original short-circuit warm decision')
            need(v[15] in (11,12,13) and (v[10]!=0 if v[9]==3 else v[10]==0),
                 'literal selected policy and actual plan return')
        if phase in (7,15):
            need(v[9]!=3 and v[16]>0 and v[17]>0 and v[18]>0 and 0<v[19]<=128 and
                 v[108]>0 and v[109]>0,'actual bound generation and head count')
            offsets=struct.unpack_from('<128H',raw,11832)
            need(all(x<8192 for x in offsets[:v[19]]) and len(set(offsets[:v[19]]))==v[19] and
                 not any(offsets[v[19]:]),'complete admitted head catalog and zero unused heads')
            heads=tuple(key[1][x//4096][0][0]+x%4096 for x in offsets[:v[19]])
            need(v[18] in heads and v[1] in heads,'actual compiled root and selected head')
        if phase in (11,15):
            derived+=1
            need(v[20]==(1 if phase==11 else 2) and v[59]==(14 if phase==11 else 13) and
                 all(a<=b for a,b in zip(v[60:84],v[84:108])),
                 'actual finish kind/phase and monotone pre-cleanup counters')
            if phase==11:
                need(v[9]==3 and not any(v[16:20]) and not any(v[21:22]) and
                     not any(v[50:59]) and not any(raw[11832:]),'cancel has no publication/member evidence')
            else:
                need(v[21] in (1,2) and v[58]<(1<<v[21]),'actual completed domain members')
                members=[tuple(v[50+4*j:54+4*j]) for j in range(v[21])]
                need(members[0]==(v[2],v[16],v[17],v[18]) and
                     len({m[0] for m in members})==len(members) and
                     all(m[0]<2 and all(x>0 for x in m[1:]) for m in members) and
                     (v[21]==2 or not any(v[54:58])), 'literal current primary and distinct peer identity')
        result.append(dict(index=i+1,phase=phase,words=v,key=key,registry=registry,slots=slots,heads=heads))
    need(derived in (finished,finished+1) and (not h[19] or finished==derived==reserved==ROWS),
         'row-first commit and final diagnostic cutoff ordering')
    need(not any(data[4096+reserved*ROW:BYTES]) and not any(data[BYTES:]),
         'whole unused rows and storage trailer remain zero')
    return h,result


def final_counter_prefix(data,initial,pid,seals):
    need(type(initial)is tuple and len(initial)==8 and all(type(n)is int and 0<n<1<<64 for n in initial)
         and initial[:4]==(MAGIC,VERSION,BYTES,STORAGE),'exact ABI7 initial identity')
    need(type(data)is bytes and len(data)==STORAGE and type(pid)is int and pid>0 and seals==23,
         'whole reaped sealed ABI7 backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and h[12]>=4096 and h[12]%4096==0 and
         h[12]+STORAGE<1<<47 and h[13:]==(1,1,1),'actual protected single writer and closed guest fd')
    header,rows=_rows(data)
    return dict(version=VERSION,logical_bytes=BYTES,storage_bytes=STORAGE,
                attempts=header[17],finished=sum(r['phase'] in (11,15) for r in rows),
                phases=dict(sorted(Counter(str(r['phase']) for r in rows).items())),
                diagnostic_cutoff=header[19]==STOP,observation_only=True,qualification_credit=False)


def model(data):
    """Whole-value offline equality; Python hashing is not runtime authority.

    PC-only LRU ignores every source/placement obligation. Qualified catalogs
    require matching actual page bytes/identity, rseq/TLS and ordered registry;
    a match is only a counterfactual opportunity. Placement, claim and lifetime
    success for a different capacity are unobserved and never assumed.
    """
    _,rows=_rows(data);complete=[r for r in rows if r['phase'] in (11,15)]
    previous=[None,None];published=[None,None];evictions=0;repeats=0;seen=set();negative=Counter()
    for r in complete:
        v=r['words']
        for i,slot in enumerate(r['slots']):
            need((previous[i] is None and slot[:3]==(0,0,0)) or
                 (previous[i] is not None and slot[:3]==previous[i]),
                 'actual two-slot generation/root/completion replay before each observed build')
        if v[9] in (1,2):
            known=published[v[2]]
            need(known is not None and known[0]==r['key'][1] and v[1] in known[1] and
                 known[2]==tuple(v[36:41]) and known[3]==r['registry'],
                 'actual warm source/head/registration/registry matches the published generation')
        if r['key'] in seen:repeats+=1
        seen.add(r['key'])
        if v[9]==3:negative[(r['key'],tuple(v[36:47]),r['registry'],tuple(v[10:16]))]+=1
        if v[9]==4 and r['phase']==15:
            evictions+=previous[v[2]] is not None
            previous[v[2]]=(v[16],v[18],v[5])
            published[v[2]]=(r['key'][1],r['heads'],tuple(v[36:41]),r['registry'])
        if r['phase']==15:
            for j in range(v[21]):
                slot,generation,serial,root=v[50+4*j:54+4*j]
                need(previous[slot] is not None and previous[slot][:2]==(generation,root),
                     'actual bound member was published in the observed prefix')
                previous[slot]=(generation,root,v[5])
    capacities={}
    for capacity in (2,8,64,256):
        pcs=OrderedDict();catalog=[];pc_hits=opportunities=0
        for r in complete:
            v=r['words'];pc=v[1];pc_hits+=pc in pcs
            pcs.pop(pc,None);pcs[pc]=None
            if len(pcs)>capacity:pcs.popitem(last=False)
            context=(r['key'][1],tuple(v[36:47]),r['registry'])
            hit=next((i for i,x in enumerate(catalog) if x[0]==context and pc in x[1]),None)
            if hit is not None:
                opportunities+=1;catalog.append(catalog.pop(hit))
            elif r['phase']==15:
                catalog.append((context,r['heads']))
                if len(catalog)>capacity:catalog.pop(0)
        capacities[str(capacity)]=dict(pc_only_hits=pc_hits,pc_only_misses=len(complete)-pc_hits,
            source_context_catalog_opportunities=opportunities,
            counterfactual_placement_claim_lifetime='unobserved')
    return dict(attempts_completed=len(complete),partial_rows=len(rows)-len(complete),
        actual_plan_kinds=dict(sorted(Counter(str(r['words'][9]) for r in complete).items())),
        actual_replacement_publications=evictions,exact_requested_source_repeats=repeats,
        repeated_negative_plans=sum(n-1 for n in negative.values()),capacities=capacities,
        event_deltas={} if not complete else dict(zip(COUNTERS,
            (b-a for a,b in zip(complete[0]['words'][60:84],complete[-1]['words'][84:108])),strict=True)),
        denominator='completed pe_build attempts after unchanged coarse and negative-hint gates',
        scope='bounded prefix; optimistic opportunities, no execution/admission/time prediction')


def final_prefix(row,private,binary):
    observation=row['counter_observation'];counter=row['counter_input']
    need(row['reaped'] is True and observation['usable'] is True and row['cleanup_errors']==[] and
         all(d['closed'] is True for d in row['descriptors']),'actual reaped readonly ABI7 custody')
    need(counter['version']==7 and counter['bytes']==STORAGE and counter['logical_bytes']==BYTES and
         counter['initial_seals']==6,'distinct ABI7 input')
    capture=row['captures']['counters'];need(capture['file']==row['name']+'.counters','literal capture path')
    path=binary(private/capture['file'])
    need(fact(path)==observation['raw']=={k:capture[k] for k in ('bytes','sha256')},'whole raw census bank')
    initial=(MAGIC,7,BYTES,STORAGE,counter['nonce'],counter['parent'],counter['device'],counter['inode'])
    data=path.read_bytes();parsed=final_counter_prefix(data,initial,row['pid'],observation['final_seals'])
    need(all(observation[k]==v for k,v in parsed.items()),'all retained parsed prefix fields')
    return dict(prefix=parsed,model=model(data))


def prepare_counter_carrier(state,pin):
    root=Path(__file__).resolve().parents[2]
    old=pin(root/'tools/page-entry/carrier.py');need(state['carrier_tool']==old,'actual carrier creator')
    new=pin(root/'tools/page-entry/loop_rx_recurrence_carrier.py')
    state['carrier_make_tool']=old;state['carrier_tool']=new
    support=('evaluation/inprocess/loop_rx_recurrence.py','evaluation/inprocess/loop_rx_recurrence_process.py',
             'evaluation/inprocess/loop_ro_reason_process.py','tools/page-entry/loop_ro_reason_carrier.py',
             'tools/page-entry/namespace.py')
    return dict(make=dict(path=str(old),**fact(old)),execute=dict(path=str(new),**fact(new)),
                sources={name:fact(pin(root/name)) for name in support})


def controls(data,initial,pid,seals):
    """Additive controls of the actual captured bank, never guest qualification."""
    baseline=final_counter_prefix(data,initial,pid,seals)
    _,rows=_rows(data)
    first=next((r for r in rows if r['phase'] in (11,15)),None)
    need(first is not None,'actual finished row for causal reader controls')
    at=4096+(first['index']-1)*ROW
    mutations=[('version',8,8),('logical_bytes',16,0),('storage_bytes',24,4096),
        ('writer_pid',64,pid+1),('seals',88,6),('observer_error',128,1),
        ('reserved_header',160,1),('row_sequence',at,0),('slot',at+16,2),
        ('registry_count',at+48,129),('row_reserved',at+115*8,1),
        ('trailer',BYTES,1)]
    refused=[]
    for name,offset,value in mutations:
        changed=bytearray(data);struct.pack_into('<Q',changed,offset,value)
        need(bytes(changed)!=data,'nonidentity actual capture mutation '+name)
        try:final_counter_prefix(bytes(changed),initial,pid,seals)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted actual ABI7 mutation '+name)
    need(len(refused)==12,'all twelve actual header/row/trailer controls')
    raw=data[at+1024:at+9784];key=source_key(raw)
    # These four changes are meaningful source comparisons, not parser errors:
    # different requested PC, either complete source page, and an actual rseq key.
    changed=bytearray(raw);struct.pack_into('<Q',changed,0,key[0]^1)
    need(source_key(bytes(changed))!=key,'requested PC participates in exact source equality')
    for offset in (8+280,8+4376+280):
        changed=bytearray(raw);changed[offset]^=1
        need(source_key(bytes(changed))!=key,'each full source page participates in equality')
    context=(key[1],tuple(first['words'][36:47]),first['registry'])
    values=list(context[1]);values[1]^=1
    need((key[1],tuple(values),first['registry'])!=context,'registration epoch distinguishes model context')
    model_refusals=[]
    later=next((r for r in rows if r['phase'] in (11,15) and any(x[3] for x in r['slots'])),None)
    bound=next((r for r in rows if r['phase']==15),None)
    need(later is not None and bound is not None,'actual publication and later occupied slot for model controls')
    slot=next(i for i,x in enumerate(later['slots']) if x[3])
    for label,offset,fmt,value in (
        ('actual_last_completed',4096+(later['index']-1)*ROW+8*(24+5*slot),'<Q',later['slots'][slot][2]+1),
        ('actual_bound_head',4096+(bound['index']-1)*ROW+11832,'<H',8192)):
        changed=bytearray(data);struct.pack_into(fmt,changed,offset,value)
        try:model(bytes(changed))
        except ValueError:model_refusals.append(label)
        else:raise ValueError('accepted actual model mutation '+label)
    need(len(model_refusals)==2,'two actual source-bound replay/catalog mutation controls')
    return dict(refusals=refused,model_refusals=model_refusals,source_context_controls=4,baseline=baseline,
                guest_executions=0,qualification_credit=False)


def records(data):
    """Compact scalars from strict rows; no full source pages in the projection."""
    _,rows=_rows(data);result=[]
    names=('index','pc','slot','bank','selection','serial','registry_count','seen','passed',
           'plan','result','miss_reason','miss_site','miss_pc','miss_detail','policy',
           'generation','build_serial','root','heads','finish','members')
    for r in rows:
        if r['phase']==0:
            result.append(dict(index=r['index'],phase=0));continue
        v=r['words'];n=7 if r['phase']==1 else 16 if r['phase']==3 else 20 if r['phase']==7 else 22
        value=dict(zip(names[:n],v[:n],strict=True));value['phase']=r['phase']
        value['slot0_generation'],value['slot1_generation']=v[22],v[27]
        value['slot0_root'],value['slot1_root']=v[23],v[28]
        value['before']=dict(zip(COUNTERS,v[60:84],strict=True))
        if r['phase'] in (11,15):value['after']=dict(zip(COUNTERS,v[84:108],strict=True))
        result.append(value)
    return result


def terminal(stderr,prefix,exit_code):
    """Literal diagnostic refusal and existing actual cleanup report; no success arithmetic."""
    from loop_resident_rx_reports import transit_row,PREFIX,FIELDS,LAST
    from loop_ro_oracle_reports import row
    from loop_ro_certificate_reports import PREFIXES,FIELDS as RO_FIELDS
    from persistent_loop_effects_counter_terminal import counters
    need(exit_code==125 and prefix['diagnostic_cutoff'] is True and
         prefix['finished']==prefix['attempts']==ROWS,'actual bounded cutoff, never a killed prefix')
    transit,remaining=transit_row(stderr)
    lines=remaining[:-1].split(b'\n')
    need(sum(x.startswith(PREFIX) for x in lines)==1 and lines[-1].startswith(PREFIX),
         'one actual final retained-RX row')
    rx=row(lines[-1],PREFIX,FIELDS);lines=lines[:-1]
    positions=[];certificate=[]
    for label,fields in zip(PREFIXES,RO_FIELDS,strict=True):
        found=[i for i,x in enumerate(lines) if x.startswith(label)]
        need(len(found)==1,'one actual certificate row')
        positions.append(found[0]);certificate.append(row(lines[found[0]],label,fields))
    first=positions[0]
    need(positions==list(range(first,first+3)) and first>0 and first+3<len(lines) and
         lines[first-1].startswith(b'LI2_PF_REFUSALS ') and
         lines[first+3].startswith(b'LI2_PERSISTENT_SUBENTRY '),'exact existing certificate insertion')
    raw=counters(b'\n'.join(lines[:first]+lines[first+3:])+b'\n')
    need(all(v['status']==125 and v['failure_code']==3303 for v in
             (*raw.values(),*certificate,transit,rx) if 'status'in v and 'failure_code'in v),
         'every actual typed row retains the deliberate failed outcome')
    d=raw['LI2_PERSISTENT_UNREGISTERED']
    need(d['detail_abs']==STOP and d['detail_negative']==0 and d['first_error']==3303 and
         d['phase']==15 and d['busy']==1 and raw['LI2_LOOP_RUNTIME']['scope']==
         raw['LI2_LOOP_EFFECTS']['scope']==0,'literal abort latch and no live planner scope')
    need(rx['terminal_attempts']==rx['terminal_closed']==1 and not any(rx[k] for k in LAST),
         'actual terminal pg_permissions/pg_closed cleanup completed; no false completed RX cell')
    return dict(status=125,failure_code=3303,detail=STOP,phase=15,busy=1,
                rx_terminal_cleanup_verified=True,application_completed=False,
                qualification_credit=False,performance_credit=False)
