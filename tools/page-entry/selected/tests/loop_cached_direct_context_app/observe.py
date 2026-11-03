"""Finite AB146 cached-DIRECT experiment, with actual typed native frames.

This positive experiment checks source, membership, lease/directory identity,
permission records and event counts. Completion internals and auxiliary image
semantics still require the separate production/component/causal qualification.
No byte record, supplied corruption or positive run grants runtime authority.
"""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

MAGIC,FOOTER=0x314f58434132494c,0x314658434132494c
ROOTS=(0x410200,0x412200)
HEADS=((0x410200,0x410204,0x410207),(0x412200,0x412204,0x412208,0x41220c,0x412212))
MEMBERS=((ROOTS[0],),(ROOTS[1],ROOTS[0]))
ENTRIES,EXITS=(1,5),(3,144)
CHECKPOINTS={s:i for i,s in enumerate((0,1,3,4,5,9,10,14,77,136,144,146))}
LAYOUT_NAMES=('version','wire','epoch','epochs','wire_epoch','member','phase',
    'epoch_member','epoch_phase','epoch_entry','epoch_event','epoch_bundle','epoch_completion','epoch_side',
    'bundle','side','completion','ref','key','frame','frame_si','frame_uc','frame_step','frame_fs','frame_tls',
    'step','step_fp','permission','query','stat','image','lease','directory','capability','tail','aux_plan',
    'bundle_ref','bundle_key','bundle_route','bundle_image','bundle_lease','bundle_directory',
    'side_bundle','side_code_closed','side_spill_closed','completion_member_size','completion_member',
    'completion_source','completion_domain_source','completion_rseq','completion_fetch',
    'completion_directory_closed','completion_rx','completion_direct_exit','pe','payload','proof_bytes',
    'payload_source','payload_plan','live_bytes','cell_bytes','runtime_bytes')

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)
def u(data,at=0,count=1):return struct.unpack_from('<'+'I'*count,data,at)
def zero(data,why):need(not any(data),why)

def _layout(v,h):
    need(type(v)is dict and set(v)==set(LAYOUT_NAMES)|{'symbol','owners','inferior_started'} and
         v['inferior_started']is False and all(type(v[n])is int and v[n]>0 for n in LAYOUT_NAMES),
         'complete actual compiler layout authority')
    expected=dict(version=1,epochs=4,ref=96,key=8760,frame=67008,frame_si=24,frame_uc=152,
        frame_step=1152,frame_fs=66944,frame_tls=66976,step=65792,step_fp=256,
        permission=336,query=296,stat=144,image=2784,lease=2832,directory=8224,capability=344,
        tail=416,aux_plan=2368,bundle_ref=144,bundle_key=912,bundle_route=70992,
        bundle_image=71120,bundle_lease=93392,bundle_directory=96224,bundle=104448,
        side_code_closed=40,side_spill_closed=336,side_bundle=632,side=105080,
        member=9944,phase=3248,epoch_member=256,proof_bytes=89*4096,payload_source=296,payload_plan=9056)
    need(all(v[k]==n for k,n in expected.items()),'independent original ABI and distinct LCX typed layout')
    need(v['wire']+64<4<<20 and v['wire_epoch']>=544 and
         v['wire_epoch']+4*v['epoch']==v['wire'] and v['completion']%4096==0 and
         v['payload_plan']<v['payload']<=v['proof_bytes'] and
         v['live_bytes']==106496 and v['cell_bytes']==106496,
         'whole bounded wire and page-rounded original immutable publication')
    intervals=[(v['epoch_'+n],size)for n,size in (('member',8*v['member']),('phase',4*v['phase']),
        ('entry',v['frame']),('event',v['frame']),('bundle',v['bundle']),
        ('completion',v['completion']),('side',v['side']))]
    need(all(at+size<=v['epoch'] and (i==0 or intervals[i-1][0]+intervals[i-1][1]<=at)
             for i,(at,size)in enumerate(intervals)),'ordered complete nonoverlapping epoch fields')
    owners=v['owners'];need(type(owners)is dict and set(owners)=={'pe','lcx_live','lcx_cells','lcx_runtime','lcxo'},
        'actual independently inspected ELF owners')
    need(all(type(x)is dict and set(x)=={'address','bytes'} and
         all(type(n)is int and n>0 for n in x.values())for x in owners.values()),'whole actual owner symbols')
    bias=h[9]-owners['pe']['address'];need(bias>=0 and bias%4096==0,'one actual ELF load bias')
    addresses={n:bias+x['address']for n,x in owners.items()};extents=[]
    for n,x in owners.items():
        at=addresses[n];size=x['bytes']
        need(0<at<at+size<1<<47 and all(at+size<=a or a+s<=at for a,s in extents),
             'whole disjoint actual owner objects')
        if n!='lcxo':need(at%4096==size%4096==0,'page-isolated runtime authority')
        extents.append((at,size))
    need(addresses['lcxo']==h[10] and owners['pe']['bytes']==v['pe'] and
         owners['lcx_live']['bytes']==v['live_bytes'] and owners['lcx_cells']['bytes']==9*v['cell_bytes'] and
         owners['lcx_runtime']['bytes']==v['runtime_bytes'],'observed process and complete compiled owner identity')
    return addresses,intervals

def _frame(raw,v,e,app,native,model,step,event,previous,common):
    need(len(raw)==v['frame'] and u(raw,0,4)==(1,1,1,1),'actual complete original le_frame')
    zero(raw[20:24]+raw[1120:1152]+raw[66980:],'whole original frame padding')
    si=raw[v['frame_si']:v['frame_si']+128];uc=raw[v['frame_uc']:v['frame_uc']+968]
    s=raw[v['frame_step']:v['frame_step']+v['step']];g=q(s,0,23)
    mask,address,size,initialized=q(s,184,4)
    need(initialized==size and 580<=size<=65536,'whole initialized kernel floating-point frame')
    zero(s[216:256]+s[256+size:],'all uninitialized FP capacity and step padding zero')
    fs,gs,fr,gr=q(raw,v['frame_fs'],4);tls=u(raw,v['frame_tls'])[0]
    h=(1,u(raw,16)[0],e[20]if event else 0,e[21]if event else 0,address,size,
       q(uc,16)[0],q(uc,32)[0],mask,tls,fs,gs,fr,gr,0,0)
    return common.frame_fields(h,g,si,uc,s[256:],app,native,model,step,event,previous,
                               native_kinds=CHECKPOINTS)

def _ref(raw,root,directory):
    need(len(raw)==96,'whole actual arena member identity')
    generation,binding=q(raw,0,2);node,reserved,slot,bank=u(raw,16,4)
    proof,actual_root=q(raw,32,2);layout=q(raw,48,6)
    need(generation>0 and binding>0 and node<12 and reserved==0 and slot<8 and bank<2 and
         proof>0 and proof%4096==0 and actual_root==root and all(x>0 and x%4096==0 for x in layout) and
         layout[1]==layout[0]+32768 and layout[2]==layout[1]+32768 and
         layout[3]==layout[2]+4096 and layout[4]==layout[3]+4096 and layout[5]==directory,
         'actual node/generation/binding and complete original code/data/directory layout')
    return dict(raw=raw,generation=generation,binding=binding,node=node,slot=slot,bank=bank,
                proof=proof,root=root,layout=layout)

def _member(raw,root,h,v,image,backing,common):
    ref=_ref(raw[:96],root,h[11]);key=raw[96:8856];words=q(raw,8856,8)
    index=ROOTS.index(root);heads=HEADS[index]
    need(words[:5]==(1,11,len(heads),1 if index==0 else 2,0) and
         words[5:]==(ref['proof']+v['payload_source'],ref['proof']+v['payload_plan'],0) and
         q(raw,8920,128)==heads+(0,)*(128-len(heads)) and q(key)[0]==root,
         'all actual original heads and exact immutable publication pointers')
    identity=common._key_pages(key,image['source_pairs'][index],root-0x200,
                              image['source_offsets'][index],backing)
    return dict(ref,key=key,heads=heads,source_identity=identity)

def _bundle(raw,v,h,members,pid,app,binding):
    need(len(raw)==v['bundle'] and q(raw,0,2)==(1,h[5]) and u(raw,16,4)==(2,2,0,0),
         'exact two-member two-tail sealed LCX proof')
    session=struct.unpack_from('<4qQ2I',raw,32)
    need(session[:3]==(pid,pid,0) and session[3]>0 and session[4:]==(app.MASK,1,1),
         'actual initialized self-tested singleton and application mask')
    need(raw[80:112]==bytes.fromhex(binding['archive']['sha256']) and
         raw[112:144]==bytes.fromhex(binding['policy_sha256']),'exact compiled archive and policy in sealed LCX proof')
    for i,m in enumerate(members):
        need(raw[v['bundle_ref']+i*96:v['bundle_ref']+(i+1)*96]==m['raw'] and
             raw[v['bundle_key']+i*8760:v['bundle_key']+(i+1)*8760]==m['key'],
             'whole current source and generation identity copied into LCX proof')
    zero(raw[v['bundle_ref']+192:v['bundle_key']]+raw[v['bundle_key']+2*8760:v['bundle_route']],
         'whole unused LCX member and source capacity')
    routes=((0,3,0,1),(1,2,0,0))
    need(tuple(u(raw,v['bundle_route']+16*i,4)for i in range(2))==routes,
         'actual original external DIRECT arms and distinct source owners')
    zero(raw[v['bundle_route']+32:v['bundle_image']]+raw[v['bundle_image']+2*v['image']:v['bundle_lease']],
         'whole unused route and generated image capacity')
    lease=raw[v['bundle_lease']:v['bundle_directory']];token,serial,code,spill,directory=q(lease,0,5)
    need(token>0 and serial==h[5] and code>0 and code%4096==spill%4096==0 and spill==code+4096 and
         directory==h[11] and q(lease,40,3)==(v['proof_bytes'],v['payload_source'],v['payload_plan']) and
         u(lease,64,4)==(1,2,2,0),'whole current auxiliary lease and actual publication allocation geometry')
    rows=[]
    for m in members:
        rows.extend((pc,m['layout'][j//64]+512*(j%64),m['generation'],m['slot'],j)
                    for j,pc in enumerate(m['heads']))
    for i,(from_member,head,arm,owner_member)in enumerate(routes):
        m=members[owner_member];cap=lease[80+i*344:80+(i+1)*344]
        tail=m['root']-0x200+0xffa
        need(u(cap,0,4)==routes[i] and cap[16:112]==members[from_member]['raw'] and
             cap[112:208]==cap[208:304]==m['raw'] and
             q(cap,304,3)==(tail,code+512*i,m['layout'][0]) and u(cap,328,4)==(i,0,arm,0),
             'complete actual source/owner/target capability, never an invented ordinary head')
        image=raw[v['bundle_image']+i*v['image']:v['bundle_image']+(i+1)*v['image']]
        need(u(image,0,4)==(1,0,0xffa,0) and q(image,16)[0]==tail and
             u(image,352,6)==(1,len(m['heads']),0,0,0,0) and
             q(image,376,5)==(m['root'],m['root'],m['layout'][0],m['root']-0x200,m['root']-0x200+4096),
             'actual in-page auxiliary original and real legal target head')
        need(u(image,416,4)==(1,1,0,0) and q(image,472,2)==(code,spill) and
             u(image,488,2)==(i,0),'auxiliary placement remains separate from its actual ordinary owner')
        rows.append((tail,code+512*i,m['generation'],m['slot'],0x80000000|i))
    zero(lease[80+2*344:],'unused complete auxiliary capability capacity')
    directory_raw=raw[v['bundle_directory']:]
    need(q(directory_raw,0,4)==(2,10,h[5],0) and
         [struct.unpack_from('<3Q2I',directory_raw,32+32*i)for i in range(10)]==rows,
         'every exact ordinary and separately tagged auxiliary dispatch row')
    zero(directory_raw[352:],'whole unused sealed directory capacity')
    return dict(code=code,spill=spill,token=token,rows=10,auxiliary=2)

def _phase(raw,v,h,stage,present,bundle,owners,descriptor):
    words=q(raw,0,16);counts=q(raw,128,64)
    phase=(7,9,9,13)[stage];active=int(stage>0);busy=(1,1,0,1)[stage]
    need(words[:7]==(1,h[5],phase,busy,active,h[5],1) and words[7:10]==
         ((1,int(stage>0),int(stage==3))if present else(0,0,0)) and
         all(x>0 for x in words[10:13]) and words[13:]==(0,0,0),
         'actual bound/entered/preentry/completed auxiliary owner phases')
    need(counts[0]==sum(counts[1:6]) and counts[41]==0 and counts[40]>=8 and not any(counts[49:]),
         'actual conserved events, unpoisoned arena and zero unused counter capacity')
    permission=640;query=permission+6*v['permission']
    if not present:zero(raw[permission:],'ordinary activation has no auxiliary permission or query records')
    else:
        for i,(at,size,prot)in enumerate(((bundle['code'],4096,3),(bundle['code'],4096,1),
            (bundle['code'],4096,5),(bundle['code'],4096,1),
            (owners['lcx_live'],v['live_bytes'],3),(owners['lcx_live'],v['live_bytes'],1))):
            value=raw[permission+i*336:permission+(i+1)*336]
            if i==2 and stage==0 or i==3 and stage!=3:zero(value,'unattempted actual auxiliary transition is wholly zero')
            else:descriptor._permission(value,at,size,prot)
        descriptor._query(raw[query:query+296],bundle['spill'],4096,3)
        if stage==3:descriptor._query(raw[query+296:query+592],bundle['spill'],4096,3)
        else:zero(raw[query+296:],'no pre-completion spill closure')
    return counts

def _framing(data,control,layout):
    need(type(data)is bytes and type(control)is int and control==0 and
         type(layout)is dict and type(layout.get('wire'))is int and len(data)==layout['wire']+64,
         'whole distinct finite LCX record and literal positive experiment')
    h=q(data,0,32);footer=q(data,layout['wire'],8)
    need(h[:9]==(MAGIC,1,layout['wire'],layout['epoch'],4,8,8,9,12) and
         h[16:28]==(2,0,0,0,0,0,0,0,0,0,0,0),
         'exact two completed activations without causal or program qualification credit')
    need(footer[:4]==(FOOTER,1,layout['wire'],layout['wire']) and
         1<=footer[4]<=64 and 0<footer[5]<=layout['wire'] and footer[6:]==(0,0),
         'whole actual bounded FD3 write and successful positive outcome')
    return h

def terminal_observation(data,control,*,layout):
    _framing(data,control,layout)
    at=layout['wire_epoch']+layout['epoch']+layout['epoch_phase']+3*layout['phase']+128
    return 0,0,q(data,at,32)

def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,
         differential,binding,dependencies):
    common,descriptor=dependencies;h=_framing(data,control,layout);v=layout
    owners,intervals=_layout(v,h)
    need(type(differential)is bool and binding['mode']==('differential'if differential else'release') and
         type(pid)is int and pid>0 and type(uid)is int and uid>=0 and exit_status==0 and
         h[11]==h[13]==h[29]==0 and h[12]&0o6003==1 and h[28]==h[12] and
         h[14]>0 and h[14]%4096==0 and h[15]==524288 and h[30:]==(pid,pid),
         'actual positive process, compiler mode and original alternate stack')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and
         u(initial,24,2)==(0o100600,uid) and q(initial,48)[0]==q(terminal,48)[0]==0,
         'whole same fresh regular private sink before first write')
    zero(data[544:v['wire_epoch']],'whole wire alignment padding')
    need(native['header'][5]==1 and len(native['observations'][0]['frames'])==12,
         'complete independently checked146-step native reference')
    model=app.trace_model(native);epochs=[]
    for index,roots in enumerate(MEMBERS):
        at=v['wire_epoch']+index*v['epoch'];raw=data[at:at+v['epoch']];e=q(raw,0,32);present=int(index==1)
        need(e[:5]==(1,1,1,1,roots[0]) and e[5]>0 and e[6:8]==(len(roots),0) and
             e[8]<8 and e[9]<2 and e[10]<9 and e[11]>0 and e[11]%4096==0 and
             e[12]>0 and e[13]>0 and e[14]==roots[0] and e[16:19]==(0,present,present) and
             e[19]>0 and e[22:28]==(0,index,1,1,0,13) and not any(e[28:]),
             'actual two-epoch member/exit geometry and explicitly present auxiliary proof')
        cursor=256
        for offset,size in intervals:
            zero(raw[cursor:offset],'whole epoch alignment padding');cursor=offset+size
        zero(raw[cursor:],'whole trailing epoch padding')
        members=[]
        for i in range(8):
            value=raw[v['epoch_member']+i*v['member']:v['epoch_member']+(i+1)*v['member']]
            if i<len(roots):members.append(_member(value,roots[i],e,v,image,backing_size,common))
            else:zero(value,'whole unused actual member capacity')
        need(all(len({m[k]for m in members})==len(members)for k in('generation','binding','node','slot')),
             'simultaneously live members have distinct complete identities')
        primary=members[0]
        need(e[8:10]==(primary['slot'],primary['bank']) and e[12]==primary['generation'] and
             e[15]==primary['layout'][0],'actual original head0 of the primary member')
        proof=raw[v['epoch_bundle']:v['epoch_bundle']+v['bundle']]
        side=raw[v['epoch_side']:v['epoch_side']+v['side']]
        bundle=_bundle(proof,v,e,members,pid,app,binding)if present else None
        if not present:zero(proof+side,'ordinary activation has genuinely absent LCX proof')
        else:
            need(bundle['token']==h[9] and q(side,0,3)==(1,e[19],e[5]) and q(side,24)[0]>0 and
                 q(side,32)[0]>0 and side[v['side_bundle']:]==proof,
                 'same actual immutable auxiliary proof and issued side completion identity')
            descriptor._query(side[40:336],bundle['code'],4096,1)
            descriptor._query(side[336:632],bundle['spill'],4096,3)
        completion=raw[v['epoch_completion']:v['epoch_completion']+v['completion']]
        need(q(completion,0,2)==(e[19],e[5]) and u(completion,16,2)==(len(roots),1),
             'original completion identity and actual completed member count')
        for i,m in enumerate(members):
            offset=v['completion_member']+i*v['completion_member_size']
            need(completion[offset:offset+96]==m['raw'] and
                 completion[offset+96+296:offset+96+296+8760]==m['key'],
                 'whole member and source identities in the actual original completion')
        counts=[_phase(raw[v['epoch_phase']+i*v['phase']:v['epoch_phase']+(i+1)*v['phase']],
            v,e,i,present,bundle,owners,descriptor)for i in range(4)]
        need(all(all(x<=y for x,y in zip(counts[i],counts[i+1]))for i in range(3)),
             'all observed counters are monotonic')
        before,entered,event,complete=counts
        need(entered[10]==before[10]+1 and entered[11]==before[11],
             'one actual generated entry follows each bound snapshot')
        need(entered==event,'zero interior signals or owner operations in the actual generated interval')
        need(tuple(b-a for a,b in zip(event[:6],complete[:6]))==(1,1,0,0,0,0) and
             complete[11]==event[11]+1,'one final NX and one actual completed epoch')
        need(entered[42:49]==event[42:49] and complete[44]==event[44]+present and
             complete[46:48]==event[46:48]==(0,0) and complete[48]==event[48]+3*present,
             'actual auxiliary close and two side seals, without recovery or retirement')
        entry=_frame(raw[v['epoch_entry']:v['epoch_entry']+v['frame']],v,e,app,native,model,
                     ENTRIES[index],False,0x4101fe if index==0 else 0x410207,common)
        event_frame=_frame(raw[v['epoch_event']:v['epoch_event']+v['frame']],v,e,app,native,model,
                     EXITS[index],True,0,common)
        epochs.append(dict(header=e,members=members,counts=counts,entry=entry,event=event_frame))
    zero(data[v['wire_epoch']+2*v['epoch']:v['wire']],'whole unused observer epoch capacity')
    need(epochs[0]['header'][5]<epochs[1]['header'][5] and
         epochs[0]['header'][19]<epochs[1]['header'][19] and
         all(x<=y for x,y in zip(epochs[0]['counts'][3],epochs[1]['counts'][0])),
         'actual inter-activation chronology and all intervening work counted')
    a,b=epochs[0]['members'][0],epochs[1]['members'][1]
    need(a['raw']==b['raw'] and a['key']==b['key'],'whole prior A generation reused in the genuine B/A union')
    need(gated is not None,'actual complete gated application required')
    pair=app.application_pair(native,gated)
    need(pair==dict(full_application_state_equal=True,interior_owner_state_observed=False),
         'unchanged whole native/gated application state comparator')
    return dict(epochs=2,native_pair=pair,actual_refusals=0,actual_restorations=0,
        intervals=[dict(entry=e['entry']['pc'],exit=e['event']['pc'],
            original_instructions=EXITS[i]-ENTRIES[i],interior_signals=0,final_nx=1)
            for i,e in enumerate(epochs)],whole_record_sha256=hashlib.sha256(data).hexdigest(),
        qualification_credit=False,performance_credit=False,completion_internals_independently_validated=False,
        auxiliary_image_semantics_independently_validated=False)

def control_sites(v):
    sites=[('wire_version',8),('process',30*8),('epochs',16*8),('sink_inode',264),('footer',v['wire']+48)]
    for i in range(2):
        at=v['wire_epoch']+i*v['epoch']
        sites.extend((f'epoch{i}_{name}',at+offset)for name,offset in (
            ('complete',24),('entry',32),('serial',40),('members',48),('proof_presence',17*8),
            ('member_generation',v['epoch_member']),('member_key',v['epoch_member']+96),
            ('head',v['epoch_member']+8920),('entry_gpr',v['epoch_entry']+v['frame_step']+13*8),
            ('event_gpr',v['epoch_event']+v['frame_step']+13*8),
            ('event_fp',v['epoch_event']+v['frame_step']+v['step_fp']+160),
            ('fp_initialized',v['epoch_event']+v['frame_step']+208),
            ('completion',v['epoch_completion'])))
    at=v['wire_epoch']+v['epoch']+v['epoch_bundle']
    sites.extend((name,at+offset)for name,offset in (
        ('archive',80),('policy',112),('route',v['bundle_route']),
        ('capability',v['bundle_lease']+80+16),('directory_tag',v['bundle_directory']+32+8*32+28),
        ('unused_capability',v['bundle_lease']+80+2*344)))
    return sites

CONTROL_COUNT=37
PHASE_CONTROL_COUNT=20
BACKING_CONTROL_COUNT=8

def controls(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,
             differential,binding,dependencies):
    args=(app,native,image,pid,uid,control,exit_status,gated)
    kw=dict(backing_size=backing_size,layout=layout,differential=differential,binding=binding,dependencies=dependencies)
    original=read(data,*args,**kw);sites=control_sites(layout)
    need(len(sites)==CONTROL_COUNT and len(set(sites))==CONTROL_COUNT,'literal distinct native-observer corruption roster')
    def reject(name,changed,refused,**overrides):
        try:read(bytes(changed),*args,**dict(kw,**overrides))
        except ValueError:refused.append(name)
        else:raise ValueError('accepted cached DIRECT observation corruption '+name)
    refused=[]
    for name,offset in sites:
        changed=bytearray(data);changed[offset]^=1;reject(name,changed,refused)
    phase=[]
    for i in range(2):
        at=layout['wire_epoch']+i*layout['epoch']+layout['epoch_phase']+2*layout['phase']+128
        for kind in range(1,6):
            changed=bytearray(data)
            for stage in (0,1):
                for word in (0,kind):
                    where=at+stage*layout['phase']+8*word
                    struct.pack_into('<Q',changed,where,q(data,where)[0]+1)
            reject(f'epoch{i}_interior{kind}',changed,phase)
            changed=bytearray(data);complete=at+layout['phase']
            struct.pack_into('<Q',changed,complete+8,q(data,complete+8)[0]-1)
            word=0 if kind==1 else kind
            struct.pack_into('<Q',changed,complete+8*word,q(data,complete+8*word)[0]+(-1 if kind==1 else 1))
            reject(f'epoch{i}_final{kind}',changed,phase)
    backing=[]
    for i,members in enumerate(MEMBERS):
        for member in range(len(members)):
            for page in range(2):
                at=layout['wire_epoch']+i*layout['epoch']+layout['epoch_member']+member*layout['member']+96+8+page*4376+104+72
                changed=bytearray(data);struct.pack_into('<Q',changed,at,q(data,at)[0]+1)
                reject(f'epoch{i}_member{member}_page{page}',changed,backing)
    need(image['bytes']!=backing_size,'original ELF differs from actual sealed carrier')
    for name,size in (('original_ELF',image['bytes']),('wrong_carrier',backing_size+1)):
        reject(name,data,backing,backing_size=size)
    need(len(phase)==len(set(phase))==PHASE_CONTROL_COUNT and
         len(backing)==len(set(backing))==BACKING_CONTROL_COUNT,'every supplied phase and backing corruption refused')
    return dict(original_sha256=original['whole_record_sha256'],refusals=refused,
                phase_refusals=phase,backing_refusals=backing,native_operations=0)

def configured(common,descriptor):
    need(callable(common.frame_fields) and callable(common._key_pages) and
         callable(descriptor._query) and callable(descriptor._permission),'original shared semantic validators')
    deps=(common,descriptor)
    return SimpleNamespace(q=q,read=partial(read,dependencies=deps),controls=partial(controls,dependencies=deps),
        terminal_observation=terminal_observation,CONTROL_COUNT=CONTROL_COUNT,
        PHASE_CONTROL_COUNT=PHASE_CONTROL_COUNT,BACKING_CONTROL_COUNT=BACKING_CONTROL_COUNT)
