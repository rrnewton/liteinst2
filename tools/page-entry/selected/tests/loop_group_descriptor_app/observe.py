"""Actual ABC255 descriptor observations and independently eligible RAW controls.

The configured old observer supplies the unchanged member/key/frame predicates.
This distinct schema proves fresh activation claims and canonical-directory
reuse; neither supplied corruptions nor trusted RAW controls are guest results.
"""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

WIRE,EPOCH,SNAPSHOT,EXTRA=1186576,227264,2280,48944
APPEND,RESULTS=1137632,1136864
RAW=APPEND+128+5*4*SNAPSHOT
ENTRIES=(1,4,7,84,169)
EXITS=(3,6,82,167,253)
CHECKPOINTS={1:1,3:2,4:3,6:4,7:5,82:6,84:7,167:8,169:9,253:10}
MEMBERS=((0x410200,),(0x412400,),(0x414600,0x410200,0x412400),
         (0x416000,0x410200,0x412400,0x414600),
         (0x416000,0x410200,0x412400,0x414600))
PHASES=((7,0,1,1,0),(9,1,1,1,0),(9,1,0,1,0),(13,1,1,1,1))
CONTROL_COUNTS={0:193,1:279,2:279,3:279,4:279,5:279,6:227}
PHASE_CONTROL_COUNT=50
BACKING_CONTROL_COUNT=28


def need(ok,why):
    if not ok:raise ValueError(why)


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def u(data,offset=0,count=1):return struct.unpack_from('<'+'I'*count,data,offset)


def _zero(data,why):need(not any(data),why)


def _layout(layout,pe):
    need(type(layout)is dict and set(layout)=={'version','symbol','values','owners','inferior_started'} and
         layout['version']==1 and layout['inferior_started']is False,
         'actual compiler-only descriptor layout authority')
    v=layout['values'];owners=layout['owners']
    need(type(v)is list and len(v)==18 and all(type(n)is int and n>=0 for n in v) and
         v[:9]==[1,WIRE,EPOCH,APPEND,EXTRA,SNAPSHOT,3216,296,336] and v[11]==4096 and
         v[16:]==[4096,5] and type(owners)is dict and set(owners)=={'pe','lhc','lgd_group','lgd_writer'},
         'exact independently decoded layout dimensions and owners')
    need(all(type(x)is dict and set(x)=={'address','bytes'} and
             all(type(x[k])is int and x[k]>0 for k in x) for x in owners.values()) and
         type(layout['symbol'])is dict and set(layout['symbol'])=={'address','bytes'} and
         type(layout['symbol']['bytes'])is int and layout['symbol']['bytes']==144 and
         type(layout['symbol']['address'])is int and layout['symbol']['address']>0,
         'whole actual defined ELF owner and readonly layout symbols')
    need(v[9]>0 and v[9]%4096==0 and v[10]%4096==0 and v[10]+9*v[9]<=v[14] and
         v[12]>0 and v[12]%4096==0 and v[11]+9*v[12]<=v[15] and
         0<v[13]<=16*4096 and v[13]%4096==0 and
         owners['pe']['bytes']==v[14] and owners['lhc']['bytes']==v[15] and
         owners['lgd_group']['bytes']==v[13] and owners['lgd_writer']['bytes']==4096,
         'complete page-isolated completion, capsule, group and epoch-owner extents')
    bias=pe-owners['pe']['address']
    need(bias>=0 and bias%4096==0,'actual PE address establishes one ELF load bias')
    extents=[]
    for name,x in owners.items():
        at=bias+x['address'];size=x['bytes']
        need(at>0 and at+size<1<<47 and at%4096==0 and size%4096==0 and
             all(at+size<=a or a+n<=at for a,n in extents),'whole distinct actual private owner extents')
        extents.append((at,size))
    return v,{name:bias+x['address'] for name,x in owners.items()}


def _query(raw,first,size,prot):
    need(len(raw)==296 and first>0 and first%4096==size%4096==0 and size>0,
         'complete typed private query extent')
    a=q(raw,0,5)
    need(a[0:2]==(first,first+size) and a[2]%4096==a[3]%4096==0 and
         a[2]<=first and a[3]>=first+size and a[4]==size//4096 and
         u(raw,40,5)==(1,1,prot,prot,0) and raw[60:64]==bytes(4) and q(raw,64)[0]==0,
         'actual whole successful private permission query')
    fd,last,closed,amount,rows=struct.unpack_from('<qqqQQ',raw,72)
    acquisition,handler,epoch=q(raw,128,3);kind,io=u(raw,152,2)
    need(fd>=0 and last==closed==0 and amount>0 and rows>0 and u(raw,112,3)==(1,1,1) and
         raw[124:128]==bytes(4) and acquisition>0 and handler>0 and epoch>0 and
         kind in(1,2,3,4) and io==int(kind in(1,3)),
         'complete closed maps acquisition or explicitly recorded maintained-view reuse')
    _zero(raw[160:],'anonymous query cannot claim a sealed-file identity')


def _permission(raw,first,size,prot):
    need(len(raw)==336 and u(raw,0,6)==(1,1,1,1,1,prot) and q(raw,24,2)==(0,0),
         'actual completed permission syscall and SYNC_CORE')
    _query(raw[40:],first,size,prot)


def _snapshot(raw,epoch,stage,differential):
    need(len(raw)==SNAPSHOT,'whole descriptor snapshot')
    h=q(raw,0,32);d=q(raw,256,16);history=q(raw,384,16)
    e=epoch['header'];count=e[6];phase,active,busy,bound,complete=PHASES[stage]
    need(h[:6]==(1,e[5],phase,active,busy,count) and h[6:9]==(bound,complete,e[10]) and
         h[9]>0 and h[9]==h[11]==h[16]==h[24] and
         h[10]>0 and h[10]==h[12]==h[13] and h[14]>0 and h[15]>0 and h[17]==0 and
         h[19]==e[18]-(stage!=3) and h[20]==e[5] and
         h[21:27]==((1 if count==1 else 0x103),0x8d5,e[11],h[9],
                     sum(len(m['heads'])for m in epoch['members']),count) and h[27:]==(0,)*5,
         'exact fresh activation, immutable descriptor identity and original recovery masks')
    need(d[11:]==(0,)*5 and history[5]==0 and history[11:]==(0,)*5 and
         d[4]==(d[2]if differential else 0) and d[7]==(d[5]if differential else 0) and
         history[4]==(history[1]if differential else 0),
         'every-hit original topology/common/history differential checks remain exact')
    claims=[q(raw,512+64*i,8)for i in range(8)]
    cells=[q(raw,1024+32*i,4)for i in range(9)]
    for c in cells:
        need(c==(0,0,0,0) or (0<c[0]<=h[19] and 0<c[1]<=h[20] and 1<=c[2]<=8 and
             c[3]<(1<<c[2])),'complete actual completion-cell identity and consumed-member mask')
    slots={m['words'][1]:i for i,m in enumerate(epoch['members'])}
    for slot,r in enumerate(claims):
        need(r[3]in(0,1) and r[4]==0 and r[7]==int(slot in slots and stage!=3),
             'actual claim validity, reserved field and live domain-reference count')
        if r[3]:
            need(r[0]>0 and r[1]<9 and r[2]<cells[r[1]][2] and
                 cells[r[1]][:2]==(r[0],r[6]) and not(cells[r[1]][3]>>r[2]&1),
                 'unconsumed per-slot claim joins its complete issued cell')
        else:need(r[:5]==(0,)*5,'consumed claim is whole zero')
        if slot in slots:
            member=slots[slot];m=epoch['members'][member]['words']
            need(r[5]==m[3] and (r[:5]==(e[18],e[10],member,1,0) and r[6]==e[5] if stage==3
                 else r[:5]==(0,)*5),'each current member has its exact generation and fresh completion claim')
    if stage==3:need(cells[e[10]]==(e[18],e[5],count,0),'new completion has no preconsumed member')
    write,seal,query=raw[1312:1648],raw[1648:1984],raw[1984:]
    if e[7]:
        _zero(write+seal,'warm descriptor reuse has no fabricated directory permission transaction')
    else:
        _permission(write,e[11],12288,3);_permission(seal,e[11],12288,1)
    _query(query,e[11],12288,1)
    return dict(h=h,descriptor=d,history=history,claims=claims,cells=cells,
                write=write,seal=seal,query=query)


def _raw(raw,header,final,epoch,control,values,owners):
    need(len(raw)==3216,'whole fixed RAW observation')
    h=q(raw,0,32);a=header
    if not control:
        need(a==(1,1,EXTRA,0)+(0,)*12,'positive descriptor has no invented RAW action')
        _zero(raw,'positive descriptor has no fabricated exposure');return
    if control==6:
        need(a==(1,1,EXTRA,6,0,1,owners['lgd_writer'],4096,0,0,10,1,0,0,0,0),
             'actual epoch-owner overlap refuses before RAW returns')
        _zero(raw,'epoch-owner refusal cannot fabricate later RAW probes');return
    kind=control-1;cell=epoch['header'][10]
    first=(owners['pe']+values[10]+cell*values[9],owners['lhc']+values[11]+cell*values[12],
           owners['lhc'],owners['lgd_group'],epoch['header'][11])[kind]
    size=(values[9],values[12],4096,values[13],12288)[kind]
    need(a==(1,1,EXTRA,control,1)+(0,)*11 and
         h==(1,kind,cell,first,size,int(kind==1),1,1,int(kind>=3),0,0,0,7,11)+(0,)*18,
         'one genuine exact RAW exposure, full restoration and unchanged reconstruction outcome')
    calls=[q(raw,256+64*i,8)for i in range(4)]
    need(calls==[(10,first,size,prot,0,0,0,0)for prot in(3,1,3,1)],
         'four exact real mprotect calls with actual successful return values')
    epochs=[q(raw,512+32*i,4)for i in range(5)]
    need(all(n>0 for n in epochs[0]) and epochs[0][0]==final['h'][15],
         'RAW begins at the actual current issued root exposure epoch')
    step=[0,0,0,1]
    if kind<3:step[(1,2,0)[kind]]=1
    for i,multiplier in enumerate((0,1,1,2,2)):
        need(epochs[i]==tuple(n+multiplier*d for n,d in zip(epochs[0],step)),
             'only the two real writable exposures advance the exact independent epochs')
    counts=[q(raw,672+256*i,32)for i in range(3)]
    need(all(c[18:]==(0,)*14 and c[8]==c[17]==0 for c in counts),
         'RAW count capacity, disagreement and poison remain exact')
    baseline=counts[0]
    need(baseline[13:16]==(final['h'][13],final['h'][14],final['h'][15]),
         'RAW count epochs join actual completion snapshot')
    for at,c in enumerate(counts[1:],1):
        delta=[0]*32
        if kind<3:
            delta[1]=2 if at==1 else 3
            fallback=(int(kind==1) if at==1 else 1+int(kind==1))
            delta[3]=delta[5]=delta[6]=fallback
        elif at==2:
            delta[0]=delta[2]=delta[4]=delta[6]=delta[7]=1
        if kind==2:delta[15]=at
        elif kind>=3:delta[13+kind-3]=at
        delta[16]=at
        need(c==tuple(n+d for n,d in zip(baseline,delta)),
             'exact exposed fallback and every-hit differential reconstruction counts')
    need(counts[0][16]==epochs[0][3] and counts[1][16]==epochs[2][3] and counts[2][16]==epochs[4][3],
         'separate RAW count and exposure records agree')
    need(size<=128*4096,'the actual object fits two unchanged bounded queries')
    for i in range(3):
        at=first;remaining=size
        for part in range(2):
            offset=1440+296*(2*i+part);query=raw[offset:offset+296]
            if remaining:
                count=min(remaining,64*4096)
                _query(query,at,count,1)
                at+=count;remaining-=count
            else:_zero(query,'whole unused second physical query is zero')
        need(remaining==0 and at==first+size,'actual contiguous chunks cover the full original object')


def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,differential,common):
    need(type(data)is bytes and len(data)==WIRE+64 and type(control)is int and 0<=control<=6 and
         type(pid)is int and pid>0 and type(uid)is int and uid>=0 and type(differential)is bool and
         (not control or differential),'whole distinct descriptor wire, actual process and build profile')
    need(type(backing_size)is int and backing_size>0 and native['header'][1]==3 and
         native['header'][5]==1 and native['header'][36]==255 and
         len(native['observations'][0]['frames'])==12,'full actual ABC255 native and carrier authorities')
    h=q(data,0,32);footer=q(data,WIRE,8);status,code=(125,3303)if control else(0,0)
    detail=8990 if control==6 else 8971
    need(exit_status==status and footer[:4]==(common.FOOTER,2,WIRE,WIRE) and
         1<=footer[4]<=64 and 0<footer[5]<=WIRE and footer[6:]==(status,code),
         'complete actual descriptor write and literal subject result')
    need(h[:9]==(common.MAGIC,2,WIRE,EPOCH,control,8,8,9,5) and h[9]>0 and h[10]>0 and
         h[11]==0 and h[12]&0o6003==1 and h[13]==0 and h[14]%4096==0 and h[15]==524288 and
         h[16:24]==(5,0,0,0,24 if control else 0,24 if control else 0,status,code) and
         h[24:28]==((3303,detail,1,1)if control else(0,0,0,0)) and h[28:]==(h[12],0,pid,pid),
         'five actual completions, all24 original restorations and exact stopped abort state')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and u(initial,24,2)==(0o100600,uid) and
         q(initial,48)[0]==q(terminal,48)[0]==0,'same untouched private regular record inode')
    values,owners=_layout(layout,h[9]);model=app.trace_model(native,reference='cache8-abc255')
    epochs=[];snapshots=[]
    for i in range(5):
        at=APPEND+128+i*4*SNAPSHOT;descriptor_id=q(data,at+9*8)[0]
        geometry=dict(members=MEMBERS[i],entry=MEMBERS[i][0],warm=int(i==4),entry_step=ENTRIES[i],
            exit_step=EXITS[i],previous_nx=(0x4101fe,0x410207,0x412408,0x414616,0x414616)[i],
            directory_serial=descriptor_id,native_kinds=CHECKPOINTS)
        e=common._epoch(data[544+i*EPOCH:544+(i+1)*EPOCH],i,app,native,image,model,backing_size,
                        geometry=geometry)
        need(e['header'][17]==(15 if i==4 else 0),'exact cold openings then four-member retained warm activation')
        phases=[_snapshot(data[at+j*SNAPSHOT:at+(j+1)*SNAPSHOT],e,j,differential)for j in range(4)]
        for j in range(3):
            a,b=phases[j],phases[j+1]
            need(all(x<=y for x,y in zip(a['descriptor'],b['descriptor'])) and
                 all(x<=y for x,y in zip(a['history'],b['history'])) and
                 a['h'][9:15]==b['h'][9:15] and a['h'][18]==b['h'][18] and
                 a['write']==b['write'] and a['seal']==b['seal'] and a['query']==b['query'],
                 'immutable group and original directory records persist through each real activation')
            if j<2:need(a['claims']==b['claims'] and a['cells']==b['cells'],
                         'live claims and cells are unchanged before real completion')
        for cell in range(9):
            if cell!=e['header'][10]:need(phases[2]['cells'][cell]==phases[3]['cells'][cell],
                                         'completion writes only the selected real receipt cell')
        delta=[b-a for a,b in zip(e['counters'][2],e['counters'][3])];expected=[0]*32
        expected[0]=expected[1]=expected[11]=1;expected[16]=expected[17]=2*e['header'][6]
        need(delta==expected,'one final NX and exact original per-member metadata closure')
        epochs.append(e);snapshots.append(phases)
    for i in range(4):
        a,b=epochs[i],epochs[i+1];x,y=snapshots[i][3],snapshots[i+1][0]
        need(a['header'][5]<b['header'][5] and a['header'][18]<b['header'][18] and
             all(v<=w for v,w in zip(a['counters'][3],b['counters'][0])),
             'whole genuine inter-activation serial, completion and counter chronology')
        need(y['descriptor'][0]==x['descriptor'][0]+int(i<3) and
             y['descriptor'][1]==x['descriptor'][1]+int(i==3) and
             y['descriptor'][9]==x['descriptor'][9]+int(i<3),
             'four actual descriptor issues followed by one unchanged-group reuse')
    for i in(3,4):
        previous={m['root']:m for m in epochs[i-1]['members']};current={m['root']:m for m in epochs[i]['members']}
        for root,a in previous.items():
            b=current[root]
            need(a['words']==b['words'] and a['key']==b['key'] and a['heads']==b['heads'],
                 'later activation preserves every cached source, generation, build and layout')
    fourth,fifth=epochs[3],epochs[4];old,new=snapshots[3][3],snapshots[4][0]
    need(old['h'][9:15]==new['h'][9:15] and old['h'][16]==new['h'][16] and
         old['h'][21:27]==new['h'][21:27] and
         new['h'][18]==old['h'][18]+4 and new['cells'][fourth['header'][10]]==
         (fourth['header'][18],fourth['header'][5],4,15),
         'same canonical descriptor consumes all four genuine preceding claims')
    need(data[544+3*EPOCH+81088:544+3*EPOCH+93376]==data[544+4*EPOCH+81088:544+4*EPOCH+93376],
         'whole canonical directory reused byte-for-byte with descriptor serial')
    bridge=tuple(b-a for a,b in zip(fourth['counters'][3],fifth['counters'][0]))
    need(bridge[:6]==(2,0,2,0,0,0) and bridge[8:12]==(1,1,0,0) and
         all(bridge[i]==0 for i in(6,7,12,13,14,15,18,19,20,21)),
         'two genuine original DIRECT traps reach one warm offer without code construction or revocation')
    need(all(fifth['counters'][0][i]==fifth['counters'][1][i] for i in(6,7,12,13,14,15,19,20,21)) and
         fifth['counters'][1][18]==fifth['counters'][0][18]+4,
         'warm four-member entry performs no code permission, construction or publication operations')
    rows=[q(data,RESULTS+32*i,4)for i in range(24)]
    need(rows==([(i,0,0,1)for i in range(24)]if control else[(0,0,0,0)]*24),
         'all24 actual original predicates and complete restorations remain separate')
    _raw(data[RAW:RAW+3216],q(data,APPEND,16),snapshots[4][3],epochs[4],control,values,owners)
    if control:need(gated is None,'failed RAW subject cannot claim full application completion');pair=None
    else:
        need(gated is not None,'actual complete gated application is required')
        pair=app.application_pair(native,gated)
        need(pair==dict(full_application_state_equal=True,interior_owner_state_observed=False),
             'unchanged whole native/gated application-state comparison')
    return dict(schema=2,control=control,epochs=5,active_members=[1,1,3,4,4],native_pair=pair,
        actual_refusals=24 if control else 0,actual_restorations=24 if control else 0,
        raw_controls=int(1<=control<=5),epoch_owner_refusal=control==6,
        intervals=[dict(entry=e['entry']['pc'],exit=e['event']['pc'],original_instructions=e['original_instructions'],
            events=1,final_nx=1,interior_signals=0,code_permission_operations=0,publications=0,planning_operations=0)
            for e in epochs[2:]],descriptor_reused=True,whole_record_sha256=hashlib.sha256(data).hexdigest(),
        qualification_credit=False,performance_credit=False)


def controls(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,differential,common):
    args=(app,native,image,pid,uid,control,exit_status,gated)
    keywords=dict(backing_size=backing_size,layout=layout,differential=differential,common=common)
    original=read(data,*args,**keywords)
    tests=[('wire_version',8),('member_capacity',6*8),('record_pid',30*8),('completion_count',16*8),
           ('actual_refusal_count',20*8),('actual_sink_inode',256+8),('footer_outcome',WIRE+48)]
    for i in range(5):
        at=544+i*EPOCH
        tests.extend((f'epoch{i}_{name}',at+offset)for name,offset in(
            ('complete',24),('entry',32),('serial',40),('members',48),('typed_RX',19*8),
            ('event_count',256+2*256),('trap_count',256+2*256+2*8),
            ('publication',256+2*256+6*8),('code_open',256+2*256+12*8),
            ('compact_validate',256+2*256+21*8),('directory',81088+32),
            ('entry_GPR',93376+128+13*8),('event_GPR',160320+128+13*8),
            ('event_PC',160320+128+16*8),('event_FP',160320+1408+160)))
    for i in(2,3,4):
        at=544+i*EPOCH+1280+2*common.MEMBER
        tests.extend((f'third{i}_{name}',at+offset)for name,offset in(
            ('generation',3*8),('build_serial',4*8),('root',5*8),('source_identity',192+8+16),
            ('source_first',192+8+280),('source_second',192+8+4376+280),('head',8952)))
    if control:tests.extend((f'actual_restoration{i}',RESULTS+i*32+24)for i in range(24))
    for i in range(5):
        slot=q(data,544+i*EPOCH+1280+8)[0]
        for j in range(4):
            at=APPEND+128+(4*i+j)*SNAPSHOT
            tests.extend((f'snapshot{i}_{j}_{name}',at+offset)for name,offset in(
                ('descriptor_id',9*8),('manifest_exposure',13*8),
                ('member_generation',512+64*slot+5*8),('actual_query',1984+52)))
    fifth=544+4*EPOCH;bound=APPEND+128+16*SNAPSHOT
    tests.extend((name,offset)for name,offset in(
        ('warm_primary',fifth+7*8),('all_four_retained',fifth+17*8),
        ('prior_canonical_serial',544+3*EPOCH+81088+16),('warm_canonical_serial',fifth+81088+16),
        ('no_warm_directory_write',bound+1312),('no_warm_directory_seal',bound+1648),
        ('real_descriptor_hit',bound+256+8),('four_fresh_claims',bound+18*8)))
    if 1<=control<=5:
        tests.append(('actual_RAW_completed',APPEND+4*8))
        tests.extend((f'raw_header{n}',RAW+8*n)for n in(0,1,2,3,4,5,6,7,8,10,11,12,13))
        for i in range(4):
            tests.extend((f'raw_call{i}_{name}',RAW+256+64*i+8*n)
                         for name,n in(('address',1),('protection',3),('result',7)))
        selected=(1,2,0,0,0)[control-1]
        for i in range(5):
            tests.extend((f'raw_epoch{i}_{n}',RAW+512+32*i+8*n)for n in(selected,3))
        for i in range(3):
            tests.extend((f'raw_counts{i}_{n}',RAW+672+256*i+8*n)for n in(0,1,6,16,17))
            tests.extend((f'raw_query{i}_{n}',RAW+1440+296*(2*i)+n)for n in(0,44,52))
    elif control==6:
        tests.extend((f'epoch_owner{n}',APPEND+8*n)for n in(5,6,7,8,9,10,11))
        tests.append(('no_fabricated_RAW_after_refusal',RAW))
    else:
        tests.extend((('no_positive_RAW_count',APPEND+4*8),('no_positive_RAW_record',RAW)))
    need(len({name for name,_ in tests})==len(tests) and len({at for _,at in tests})==len(tests),
         'all descriptor supplied fields have distinct names and physical offsets')
    refused=[]
    for name,at in tests:
        changed=bytearray(data);changed[at]^=1
        try:read(bytes(changed),*args,**keywords)
        except ValueError:refused.append(name)
        else:raise ValueError('actual descriptor corruption accepted '+name)
    if control:
        for field,at in(('active',26*8),('busy',27*8)):
            for invalid in(0,2):
                changed=bytearray(data);struct.pack_into('<Q',changed,at,invalid)
                try:read(bytes(changed),*args,**keywords)
                except ValueError:refused.append('abort_'+field+'_'+str(invalid))
                else:raise ValueError('actual stopped abort state corruption accepted')
    need(len(refused)==len(set(refused))==CONTROL_COUNTS[control],
         'fixed complete descriptor corruption roster')
    phases=[]
    for i in range(5):
        event=544+i*EPOCH+256+2*256;complete=event+256
        for kind in range(1,6):
            changed=bytearray(data)
            for at in(event,complete):
                for word in(0,kind):struct.pack_into('<Q',changed,at+8*word,q(data,at+8*word)[0]+1)
            try:read(bytes(changed),*args,**keywords)
            except ValueError as error:
                need(str(error)=='zero interior signals and zero plan/publication/code-permission operations before final-event accounting',
                     'coherent interior corruption reaches the unchanged original predicate')
                phases.append(f'epoch{i}_interior_{common.COUNTERS[kind]}')
            else:raise ValueError('descriptor interior event accepted')
            changed=bytearray(data);struct.pack_into('<Q',changed,complete+8,q(data,complete+8)[0]-1)
            if kind==1:struct.pack_into('<Q',changed,complete,q(data,complete)[0]-1)
            else:struct.pack_into('<Q',changed,complete+8*kind,q(data,complete+8*kind)[0]+1)
            try:read(bytes(changed),*args,**keywords)
            except ValueError as error:
                need(str(error)=='exactly one final NX counted after preentry and before completion',
                     'coherent final corruption reaches the unchanged original predicate')
                phases.append(f'epoch{i}_final_{common.COUNTERS[kind]}')
            else:raise ValueError('descriptor final event accepted')
    need(len(phases)==len(set(phases))==PHASE_CONTROL_COUNT,'all50 coherent phase controls')
    backing=[]
    for i,members in enumerate(MEMBERS):
        for member in range(len(members)):
            for page in range(2):
                at=544+i*EPOCH+1280+member*common.MEMBER+192+8+page*4376+104+72
                changed=bytearray(data);struct.pack_into('<Q',changed,at,backing_size+1)
                try:read(bytes(changed),*args,**keywords)
                except ValueError as error:
                    need(str(error)=='exact sealed main ELF size and complete source VMA/device/inode/offset',
                         'backing mutation reaches original exact carrier-size predicate')
                    backing.append(f'epoch{i}_member{member}_page{page}_backing_size')
                else:raise ValueError('descriptor backing corruption accepted')
    for changed_size in(backing_size-1,backing_size+1):
        changed_keywords=dict(keywords,backing_size=changed_size)
        try:read(data,*args,**changed_keywords)
        except ValueError as error:
            need(str(error)=='exact sealed main ELF size and complete source VMA/device/inode/offset',
                 'wrong authority reaches original exact carrier-size predicate')
            backing.append('carrier_authority_'+str(changed_size-backing_size))
        else:raise ValueError('wrong carrier backing authority accepted')
    need(len(backing)==len(set(backing))==BACKING_CONTROL_COUNT,'all28 exact backing controls')
    chunks=[]
    if 1<=control<=5:
        for i in range(3):
            second=RAW+1440+296*(2*i+1)
            fields=(('first',0),('end',8),('complete',44))if control==1 else(('unused',0),)
            for name,offset in fields:
                changed=bytearray(data);changed[second+offset]^=1
                try:read(bytes(changed),*args,**keywords)
                except ValueError:chunks.append(f'raw_query{i}_second_{name}')
                else:raise ValueError('actual contiguous query corruption accepted '+name)
    need(len(chunks)==len(set(chunks))==(9 if control==1 else 3 if 2<=control<=5 else 0),
         'separate whole-validator tail-query and unused-capacity corruptions')
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,
                phase_refusals=phases,backing_refusals=backing,query_chunk_refusals=chunks,
                original=original,native_operations=0)


def configured(common):
    return SimpleNamespace(WIRE=WIRE,q=q,read=partial(read,common=common),
                           controls=partial(controls,common=common),CONTROL_COUNTS=CONTROL_COUNTS,
                           PHASE_CONTROL_COUNT=PHASE_CONTROL_COUNT,BACKING_CONTROL_COUNT=BACKING_CONTROL_COUNT)
