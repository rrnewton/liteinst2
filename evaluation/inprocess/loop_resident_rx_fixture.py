"""Finite actual DIRECT44 observer/causal rows; no old owner schema cast."""
import json
from page_selected import need
from loop_ro_oracle_reports import row
import loop_ro_certificate_reports as ro
import loop_resident_rx_reports as rx
import persistent_loop_effects_counter_terminal as effects

EP=b'LI2_LOOP_RX_EPOCH ';MP=b'LI2_LOOP_RX_MEMBER '
CP=b'LI2_LOOP_RX_CONTROL ';OP=b'LI2_LOOP_RX_ORACLE '
TP=b'LI2_LOOP_RX_TARGET '
TF=('version','control','complete','checks','restorations','cell','id','serial',
    'target','code','proof','owner','kind_index','kind_before','kind_after','mutation_executed',
    'mutated_allowed','restored_allowed','armed','receipt')+tuple(
        name+'_'+field for name in ('original','code','proof','owner')
        for field in ('known','strict','allowed'))
COUNTS=('cold','publications','hits','opens','closes','writes','syncs')
EF=('version','index','started','complete','count','mask','warm','receipt','entry',
    'released_pc','root','head','id','serial')+tuple(side+'_'+n for side in ('before','after') for n in COUNTS)
MF=('version','epoch','member','seen','prot','slot','bank','retained','generation','serial',
    'root','entry','code','proof','opens_before','opens_after','syncs_before','syncs_after')
CF=('version','index','expected','actual','restored')
OF=('version','control','status','failure_code','initialized','active','epochs','failure','busy',
    'cell_done','branch_done','controls','restorations','unsafe_reason','unsafe_queries','complete',
    'unsafe_opens','unsafe_closes','unsafe_syncs')


VP=b'LI2_LOOP_RX_TRANSIT_TICKET ';VC=b'LI2_LOOP_RX_TRANSIT_CONTROL '
VF=('version','control','complete','checks','restorations','cell','branches','arm','slot','previous_slot',
    'id','serial','pc','target','flags','code','length','available','pages','borrow','source_page',
    'source_generation','generation','event','previous_generation','previous_event','bytes')


def transit_ticket_rows(stderr,control):
    lines=stderr[:-1].split(b'\n');n=16 if control else 0
    selected=[i for i,x in enumerate(lines) if x.startswith((VP,VC))]
    need(len(selected)==n+1 and selected==list(range(selected[0],selected[0]+n+1)) and
         selected[0]>0 and selected[-1]<len(lines)-1 and
         lines[selected[0]-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[selected[-1]+1].startswith(TP),'one exact second-ticket and restored-control insertion')
    start=selected[0];actual=row(lines[start],VP,VF)
    need(actual['control']==control and actual['complete']==1 and actual['checks']==1+n and
         actual['restorations']==n and actual['cell']<3 and actual['branches']==2 and
         actual['arm']==0 and actual['slot']in(0,1) and actual['previous_slot']==actual['slot']^1 and
         actual['id']>0 and actual['serial']>0 and
         (actual['pc'],actual['target'],actual['code'],actual['length'],actual['available'],actual['pages'])==
             (0x413ffa,0x410200,1871,6,6,1) and actual['bytes']==0xffffc200850f and
         actual['flags']<1<<32 and actual['flags']&0x10140==0 and
         actual['source_page']==0x413000 and actual['source_generation']>0 and
         actual['borrow']>0 and actual['generation']>0 and actual['previous_generation']>0 and
         actual['previous_event']>0 and actual['event']>actual['previous_event'],
         'actual second original JNZ descriptor/source/ticket and bounded predecessor ancestry')
    controls=[]
    for i in range(n):
        value=row(lines[start+1+i],VC,CF)
        need(value==dict(version=1,index=i,expected=0,actual=0,restored=1),
             'actual second-ticket refusal and whole restored armed/receipt baseline')
        controls.append(value)
    return b'\n'.join(lines[:start]+lines[start+n+1:])+b'\n',actual,controls


def target_row(stderr,control):
    _,stderr=rx.transit_row(stderr,oracle=True)
    stderr,_,_=transit_ticket_rows(stderr,control)
    return _target_row(stderr,control)


def observed(stderr,control):
    need(type(control)is int and control in (0,1) and type(stderr)is bytes and stderr.endswith(b'\n'),
         'explicit finite control and whole actual terminal')
    production_line=next((x for x in stderr[:-1].split(b'\n') if x.startswith(rx.TRANSIT_PREFIX)),b'')
    transit,stderr=rx.transit_row(stderr,oracle=True)
    stderr,transit_ticket,transit_controls=transit_ticket_rows(stderr,control)
    stderr,target=_target_row(stderr,control)
    lines=stderr[:-1].split(b'\n');n=32 if control else 0
    selected=[i for i,x in enumerate(lines) if x.startswith((EP,MP,CP,OP))]
    need(len(selected)==10+n and selected==list(range(selected[0],selected[0]+10+n)) and
         selected[-1]==len(lines)-2 and lines[-1].startswith(rx.PREFIX) and
         lines[selected[0]-1].startswith(b'LI2_PERSISTENT_UNREGISTERED '),
         'whole distinct observer/control roster immediately before RX terminal')
    start=selected[0];epochs=[];members=[]
    for i in range(3):
        e=row(lines[start+3*i],EP,EF)
        pair=[row(lines[start+3*i+j+1],MP,MF) for j in range(2)]
        need(e['index']==i and e['started']==e['complete']==1 and
             (e['entry'],e['released_pc'],e['root'])==((0x410200,)*3 if i!=1 else (0x412400,)*3) and
             e['head']==0 and e['count']==(2 if i==2 else 1) and
             e['mask']==(2 if i==2 else 0) and e['warm']==int(i==2) and
             e['receipt']<3 and e['id']>0 and e['serial']>0,
             'literal actual cold A/B and retained-peer A direct activations')
        need(tuple(e['after_'+k]-e['before_'+k] for k in COUNTS[:3])==
             ((0,0,1) if i==2 else (1,1,0)),
             'actual cold/publication/hit deltas; no publication inferred from wall time')
        for j,m in enumerate(pair):
            need((m['epoch'],m['member'])==(i,j),'literal member row location')
            if j>=e['count']:
                need(all(m[k]==0 for k in MF[3:]),'whole unused member observation remains zero')
                continue
            retained=(e['mask']>>j)&1
            need(m['seen']==2 and m['slot']in(0,1) and m['bank']in(0,1) and
                 m['generation']>0 and m['root']==(0x412400 if i==1 or j==1 else 0x410200) and
                 m['entry']==e['entry'] and m['code']>0 and m['code']%4096==0 and
                 m['proof']>0 and m['proof']%4096==0 and m['retained']==retained and
                 m['prot']==(5 if retained else 1) and
                 m['opens_after']-m['opens_before']==3*(1-retained) and
                 m['syncs_after']-m['syncs_before']==3*(1-retained),
                 'actual member identity and zero code permission/sync calls for retained peer')
        epochs.append(e);members.append(pair)
    for i in (1,2):
        need(epochs[i]['serial']==epochs[i-1]['serial']+1 and epochs[i]['id']==epochs[i-1]['id']+1,
             'three distinct consecutive actual completed activations')
    for j,old in ((0,members[0][0]),(1,members[1][0])):
        now=members[2][j]
        need(all(now[k]==old[k] for k in ('slot','bank','generation','root','code','proof')) and
             now['serial']==epochs[j]['serial'],
             'warm member reuses exact previously observed storage/generation and lifetime serial')
    need(members[0][0]['slot']!=members[1][0]['slot'] and
         members[2][1]['opens_before']==members[2][1]['opens_after'] and
         members[2][1]['syncs_before']==members[2][1]['syncs_after'],
         'two actual slots and exact retained peer zero-call boundary')
    controls=[]
    for i in range(n):
        value=row(lines[start+9+i],CP,CF)
        need(value==dict(version=1,index=i,expected=0,actual=0,restored=1),
             'each actual full-predicate rejection and exact successful restoration')
        controls.append(value)
    oracle=row(lines[start+9+n],OP,OF)
    need(oracle['control']==control and oracle['initialized']==oracle['complete']==1 and
         oracle['active']==oracle['failure']==oracle['busy']==0 and oracle['epochs']==3 and
         oracle['controls']==oracle['restorations']==n and
         oracle['cell_done']==oracle['branch_done']==control and
         oracle['unsafe_reason']in(2,3,4,5,6) and oracle['unsafe_queries']==12 and
         oracle['unsafe_opens']>=epochs[2]['after_opens'] and
         oracle['unsafe_closes']>epochs[2]['after_closes'] and
         oracle['unsafe_syncs']>epochs[2]['after_syncs'] and
         (oracle['status'],oracle['failure_code'])==((125,3303) if control else (0,0)),
         'real non-LOOP route physically closed before handoff; literal causal outcome')
    ordinary=b'\n'.join(lines[:start]+[production_line,lines[-1]])+b'\n'
    if control:
        actual=row(lines[-1],rx.PREFIX,rx.FIELDS)
        need(actual['status']==125 and actual['failure_code']==3303 and
             all(actual[k]==0 for k in rx.LAST),
             'exceptional terminal contains no invented completed RX cell')
        certificate=[]
        for prefix,fields in zip(ro.PREFIXES,ro.FIELDS,strict=True):
            found=[x for x in lines[:start] if x.startswith(prefix)]
            need(len(found)==1,'one whole actual causal certificate row')
            value=row(found[0],prefix,fields)
            need(value['status']==125 and value['failure_code']==3303,
                 'literal causal failure retained in every certificate row')
            certificate.append(value)
        need(certificate[0]['differential']==certificate[2]['differential']==1 and
             certificate[0]['disagreements']==certificate[2]['disagreements']==0,
             'actual every-hit differential theorem still agrees after all restores')
        positions=[next(i for i,line in enumerate(lines[:start]) if line.startswith(prefix)) for prefix in ro.PREFIXES]
        need(positions==list(range(positions[0],positions[0]+3)) and
             lines[positions[0]-1].startswith(b'LI2_PF_REFUSALS ') and
             lines[positions[-1]+1].startswith(b'LI2_PERSISTENT_SUBENTRY '),
             'actual unchanged certificate row order in deliberate failure')
        ordinary_rows=[line for i,line in enumerate(lines[:start]) if i not in positions]
        raw=effects.counters(b'\n'.join(ordinary_rows)+b'\n');d=raw['LI2_PERSISTENT_UNREGISTERED']
        need(d['status']==125 and d['failure_code']==d['first_error']==3303 and
             d['detail_abs']==8850 and d['detail_negative']==0 and d['phase']==15 and
             d['active']==0 and d['busy']==1 and d['entries']==d['completed'] and
             d['completed']>=3 and d['guest_data_fault']==0,
             'actual deliberately stopped restored suite, not a successful application')
    need((target['cell'],target['id'],target['serial'])==
         tuple(epochs[2][k] for k in ('receipt','id','serial')) and
         (target['code'],target['proof'])==tuple(members[2][1][k] for k in ('code','proof')),
         'actual target checks belong to third retained-peer completion and its real private storage')
    actual_rx=row(lines[-1],rx.PREFIX,rx.FIELDS)
    rx.transit_joined(transit,actual_rx)
    need((transit_ticket['cell'],transit_ticket['id'],transit_ticket['serial'])==
         tuple(epochs[1][k] for k in ('receipt','id','serial')) and transit['offers']>0,
         'second original branch belongs to the actual B completion before retained-peer A')
    return dict(epochs=epochs,members=members,controls=controls,oracle=oracle,target=target,
        transit=transit,transit_ticket=transit_ticket,transit_controls=transit_controls,
        permission_scope='actual pe_permission calls only; metadata calls remain separately reported',
        qualification_credit=False),ordinary


def controls(stderr,control):
    observed(stderr,control);lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'actual supplied observer mutation')
        try:observed(changed,control)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted observer mutation '+label)
    # Schema controls plus causal identity/call-count mutations on all actual
    # rows, including zero unused members and every restored control result.
    for index,line in enumerate(lines):
        spec=next(((p,f) for p,f in ((EP,EF),(MP,MF),(CP,CF),(OP,OF)) if line.startswith(p)),None)
        if spec is None:continue
        prefix,fields=spec;actual=row(line,prefix,fields)
        for field in fields:
            for kind in ('missing','boolean'):
                changed=dict(actual)
                if kind=='missing':del changed[field]
                else:changed[field]=bool(changed[field])
                copy=list(lines);copy[index]=prefix+json.dumps(changed,separators=(',',':')).encode()
                reject(str(index)+'.'+kind+'.'+field,b'\n'.join(copy)+b'\n')
        for field in fields:
            if field in ('version','index','epoch','member','complete','restored','actual','expected',
                         'generation','root','entry','released_pc','retained','opens_after','syncs_after'):
                changed=dict(actual);changed[field]^=1
                copy=list(lines);copy[index]=prefix+json.dumps(changed,separators=(',',':')).encode()
                reject(str(index)+'.semantic.'+field,b'\n'.join(copy)+b'\n')
    need(len(refusals)==len(set(refusals))==(976 if control else 496),
         'fixed complete distinct observer schema/identity controls')
    return dict(refusals=refusals,target_refusals=target_controls(stderr,control),
        transit_refusals=rx.transit_controls(stderr,lambda value:observed(value,control),oracle=True),
        ticket_refusals=ticket_controls(stderr,control),
        abort_refusals=abort_controls(stderr,control),
        scope='supplied-row-only; no native execution')


def _target_row(stderr,control):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole target observation terminal')
    lines=stderr[:-1].split(b'\n');found=[i for i,x in enumerate(lines) if x.startswith(TP)]
    need(len(found)==1 and 0<found[0]<len(lines)-1 and
         lines[found[0]-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[found[0]+1].startswith(EP),'one exact target insertion before original observer roster')
    i=found[0];t=row(lines[i],TP,TF)
    need(t['control']==control and t['complete']==1 and t['checks']==4+control and
         t['restorations']==t['mutation_executed']==control and t['cell']<3 and
         t['id']>0 and t['serial']>0 and 0<=t['kind_index']<128 and
         t['kind_before']==t['kind_after']==1 and t['mutated_allowed']==0 and
         t['restored_allowed']==t['armed']==t['receipt']==1,
         'four actual target decisions plus explicit causal strict-kind mutation and whole restoration')
    need(all(0<t[k]<(1<<47) for k in ('target','code','proof','owner')) and
         t['code']%4096==t['proof']%4096==0 and
         len({t[k] for k in ('target','code','proof','owner')})==4,
         'four distinct actual original/generated/proof/owner addresses')
    for name in ('original','code','proof','owner'):
        need(tuple(t[name+'_'+k] for k in ('known','strict','allowed'))==
             ((1,0,1) if name=='original' else (0,1,0)),
             'unchanged current-code ownership plus actual shared strict-private range predicate')
    return b'\n'.join(lines[:i]+lines[i+1:])+b'\n',t


def target_controls(stderr,control):
    _,actual=target_row(stderr,control);lines=stderr[:-1].split(b'\n')
    index=next(i for i,line in enumerate(lines) if line.startswith(TP));refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'actual supplied target-row mutation')
        try:observed(changed,control)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted target mutation '+label)
    for field in TF:
        for kind in ('missing','boolean','semantic'):
            changed=dict(actual)
            if kind=='missing':del changed[field]
            elif kind=='boolean':changed[field]=bool(changed[field])
            elif field in ('target','code','proof','owner','id','serial'):changed[field]=0
            elif field=='kind_index':changed[field]=128
            else:changed[field]^=1
            copy=list(lines);copy[index]=TP+json.dumps(changed,separators=(',',':')).encode()
            reject('target.'+kind+'.'+field,b'\n'.join(copy)+b'\n')
    for label,changed in (
        ('missing',lines[:index]+lines[index+1:]),
        ('duplicate',lines[:index]+[lines[index]]+lines[index:]),
        ('late',lines[:index]+lines[index+1:]+[lines[index]]),
        ('unknown',lines[:index]+[lines[index][:-1]+b',"unknown":0}']+lines[index+1:]),
        ('truncated',lines[:index]+[lines[index][:-1]]+lines[index+1:])):
        reject('target.row.'+label,b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==101,'all separate target-row schema and semantic controls')
    return refusals


def ticket_controls(stderr,control):
    observed(stderr,control);lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'actual supplied second-ticket mutation')
        try:observed(changed,control)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted second-ticket mutation '+label)
    for index,line in enumerate(lines):
        spec=next(((p,f) for p,f in ((VP,VF),(VC,CF)) if line.startswith(p)),None)
        if spec is None:continue
        prefix,fields=spec;actual=row(line,prefix,fields)
        for key in fields:
            for kind in ('missing','boolean','semantic'):
                changed=dict(actual)
                if kind=='missing':del changed[key]
                elif kind=='boolean':changed[key]=bool(changed[key])
                elif key=='cell':changed[key]=3
                elif key=='flags':changed[key]|=0x100
                elif key in ('borrow','source_generation','generation','previous_generation','previous_event','id','serial'):
                    changed[key]=0
                elif key=='event':changed[key]=actual['previous_event']
                else:changed[key]^=1
                copy=list(lines);copy[index]=prefix+json.dumps(changed,separators=(',',':')).encode()
                reject(str(index)+'.'+kind+'.'+key,b'\n'.join(copy)+b'\n')
    start=next(i for i,x in enumerate(lines) if x.startswith(VP))
    for label,copy in (('missing',lines[:start]+lines[start+1:]),
                       ('duplicate',lines[:start]+[lines[start]]+lines[start:]),
                       ('late',lines[:start]+lines[start+1:]+[lines[start]])):
        reject(label,b'\n'.join(copy)+b'\n')
    need(len(refusals)==len(set(refusals))==84+240*control,
         'separate fixed second-ticket and per-control schema/semantic mutations')
    return refusals


def abort_controls(stderr,control):
    """Separate actual terminal latch corruptions; never alter the oracle state."""
    observed(stderr,control)
    if not control:return []
    prefix=b'LI2_PERSISTENT_UNREGISTERED '
    lines=stderr[:-1].split(b'\n')
    index=next(i for i,line in enumerate(lines) if line.startswith(prefix))
    actual=json.loads(lines[index][len(prefix):]);refusals=[]
    for key,value in (('busy',0),('busy',2),('active',1)):
        changed=dict(actual);changed[key]=value;copy=list(lines)
        copy[index]=prefix+json.dumps(changed,separators=(',',':')).encode()
        mutant=b'\n'.join(copy)+b'\n'
        need(mutant!=stderr,'actual distinct failed terminal latch mutation')
        try:observed(mutant,control)
        except ValueError:refusals.append(key+'.'+str(value))
        else:raise ValueError('accepted failed terminal latch mutation '+key+'.'+str(value))
    need(refusals==['busy.0','busy.2','active.1'],'all three separate exact abort-latch refusals')
    return refusals
