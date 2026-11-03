"""Actual ten-node arena execution and separately restored predicate controls.

No old wire or completion claim becomes new authority. Whole source bytes and
native frames use the shared validators; the ABA subject stops at real reentry.
"""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

MAGIC,FOOTER=0x314f41544132494c,0x314641544132494c
WIRE,EPOCH,MEMBER,FRAME=3471320,227776,9976,66944
APPEND,EXTRA,NODE,RAW_BYTES=3190176,281144,592,13624
RESULTS=544+14*EPOCH
NODES=APPEND+256
ARENA_RESULTS=NODES+14*2*12*NODE
RAW=ARENA_RESULTS+20*32
REENTRY=RAW+RAW_BYTES
REENTRY_COUNTS=REENTRY+FRAME
PENDING=REENTRY_COUNTS+384
ROOTS=tuple(0x410200+0x2000*i for i in range(10))
HEADS=tuple(tuple(root+j for j in ((0,4,7)if i==0 else(0,4,8,12,18,25)if i==4 else
             (0,4,8,12,18,25,29,35)if i==9 else(0,4,8)))for i,root in enumerate(ROOTS))
MEMBERS=tuple((r,)for r in ROOTS[:4])+((ROOTS[4],)+ROOTS[:4],)+tuple((r,)for r in ROOTS[5:9])+\
        ((ROOTS[9],)+ROOTS[5:9],ROOTS[:5],ROOTS[5:],ROOTS[:5],ROOTS[5:])
ENTRIES=(1,4,7,10,13,132,135,138,141,144,264,395,527,658)
EXITS=(3,6,9,12,130,134,137,140,143,262,393,525,656,789)
PREVIOUS=(0x4101fe,0x410207,0x412208,0x414208,0x416208,0x418219,0x41a208,
          0x41c208,0x41e208,0x420208,0x42221d,0x418219,0x42221d,0x418219)
CHECKPOINTS={step:i for i,step in enumerate((0,1,130,132,262,264,393,395,525,527,789,791))}
CONTROL_COUNTS={0:427,1:471,2:363}
PHASE_CONTROL_COUNTS={0:140,1:140,2:100}
BACKING_CONTROL_COUNTS={0:78,1:78,2:38}
PENDING_CONTROL_COUNTS={0:1,1:1,2:46}


def need(ok,why):
    if not ok:raise ValueError(why)


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def u(data,offset=0,count=1):return struct.unpack_from('<'+'I'*count,data,offset)


def zero(data,why):need(not any(data),why)


def _framing(data,control):
    need(type(data)is bytes and len(data)==WIRE+64 and type(control)is int and control in(0,1,2),
         'whole distinct arena wire and literal control')
    status,code=((0,0),(125,3303),(125,3309))[control];count=10 if control==2 else 14
    h=q(data,0,32);footer=q(data,WIRE,8)
    need(h[:9]==(MAGIC,1,WIRE,EPOCH,control,8,8,9,14) and
         h[16:24]==(count,0,0,0,24 if control else 0,24 if control else 0,status,code) and
         h[24:28]==((3303,8971,1,1)if control==1 else(3309,9232,0,1)if control==2 else(0,0,0,0)),
         'exact actual completion population and distinct stopped causal chronology')
    need(footer[:4]==(FOOTER,1,WIRE,WIRE) and 1<=footer[4]<=64 and
         0<footer[5]<=WIRE and footer[6:]==(status,code),'whole actual FD3 write and exact terminal outcome')
    return h,count,status,code


def terminal_observation(data,control):
    h,count,status,code=_framing(data,control);at=544+(count-1)*EPOCH
    need(q(data,at,4)==(1,1,1,1),'terminal projection uses the last actual completed epoch')
    return status,code,q(data,at+256+3*384,32)


def terminal_transit(data,control):
    _,count,_,_=_framing(data,control)
    raw=data[PENDING:WIRE]
    if control!=2:
        zero(raw,'no pending ticket outside the actual stale-node reentry');return 0,None
    p=q(raw,0,48);at=544+(count-1)*EPOCH;e=q(data,at,32)
    c=q(data,at+256+3*384,48);r=q(data,REENTRY_COUNTS,48)
    f=q(data,REENTRY,16);g=q(data,REENTRY+128,23)
    need(e[:4]==(1,1,1,1) and e[4]==ROOTS[9] and e[6]==5 and
         p[:6]==(1,2,2,e[10],e[18],e[5]),
         'pending second DIRECT ticket names the actual last completed five-member receipt')
    need(p[6]<2 and p[7]>0 and p[8]>1 and p[9:14]==(ROOTS[0],0x202,1,0,1) and
         p[14:18]==(p[6],1,0,p[8]+1) and p[18:22]==(p[7],p[8],3,3),
         'actual incoming event advances beyond the still-pending armed chain slot')
    need(p[22]==(p[6]^1) and p[23]>0 and p[24]==p[8]-1 and
         p[29:31]==(2,1) and p[31:38]==(p[23],p[24],5,5,1,1,1) and
         p[38:45]==(0x410ffa,p[10]|0x100,0x410ffa,696,6,0x410ffa,p[10]) and p[47]==0,
         'whole actual prior-slot ancestry and page-tail original JMP without cross-slot generation ordering')
    need(f[:2]==(1,5) and g[16:18]==(p[9],p[10]|0x100) and
         g[19:21]==(0,1) and g[22]==0x42221d and
         u(data,REENTRY+312,3)==(5,0,2) and q(data,REENTRY+328)[0]==p[9] and
         q(data,REENTRY+480,23)==g and r[6:12]==c[6:12],
         'pending ticket joins the genuine raw TRACE frame and unchanged six owner counters')
    need(0<p[25]==p[26]<=c[11] and p[27]==p[28]+1 and
         p[27]+p[45]<=p[26] and p[46]<=p[28],
         'one observed pending transit explains the exact offers-minus-steps count')
    return 1,(p[25],p[26],p[27],p[28],p[45],p[46])


def _layout(layout,pe,observer):
    need(type(layout)is dict and set(layout)=={'version','symbol','values','owners','inferior_started'} and
         layout['version']==1 and layout['inferior_started']is False,'actual compiler-only arena layout authority')
    v=layout['values'];owners=layout['owners'];symbol=layout['symbol']
    need(type(v)is list and len(v)==19 and all(type(n)is int and n>=0 for n in v) and
         v[:9]==[1,WIRE,EPOCH,APPEND,EXTRA,NODE,RAW_BYTES,296,200] and
         v[13:18]==[8192,4096,14,FRAME,MEMBER] and
         type(owners)is dict and set(owners)=={'pe','lta_writer','lta_topology','sg_owner','lc8o'},
         'exact independently decoded arena wire, node and private-owner dimensions')
    need(type(symbol)is dict and set(symbol)=={'address','bytes'} and
         type(symbol['address'])is int and symbol['address']>0 and symbol['bytes']==152 and
         all(type(x)is dict and set(x)=={'address','bytes'} and
             all(type(x[k])is int and x[k]>0 for k in x)for x in owners.values()),
         'whole actual readonly layout and defined ELF owner symbols')
    need(all(v[i]>0 and v[i]%4096==0 for i in(9,10,11,12)) and
         v[10]+12*v[11]<=v[9] and v[12]+89*4096<=v[11] and
         88*4096<v[18]<=89*4096 and owners['pe']['bytes']==v[9] and
         owners['lta_writer']['bytes']==v[13] and owners['lta_topology']['bytes']==v[14] and
         owners['sg_owner']['bytes']==8192 and owners['lc8o']['bytes']>WIRE,
         'complete twelve-node storage and exact actual publication payload extent')
    bias=pe-owners['pe']['address'];need(bias>=0 and bias%4096==0,'one actual ELF load bias')
    extents=[]
    for name,x in owners.items():
        at=bias+x['address'];size=x['bytes']
        need(at>0 and at+size<1<<47 and (name=='lc8o' or at%4096==size%4096==0) and
             all(at+size<=a or a+n<=at for a,n in extents),'distinct complete private owner objects')
        extents.append((at,size))
    need(observer==bias+owners['lc8o']['address'],'actual observer address joins the same compiled ELF')
    return v,{name:bias+x['address']for name,x in owners.items()}


def _counts(raw):
    need(len(raw)==384,'whole actual forty-eight-counter snapshot')
    c=q(raw,0,48)
    need(c[0]==sum(c[1:6]) and c[25:32]==(0,)*7 and c[42:]==(0,)*6 and
         c[41]==0 and c[40]>=8,'actual signal conservation and unpoisoned arena count capacity')
    need(c[35]==c[6] and c[39]==c[33]+c[34],
         'every cold node is a real publication and every completed dormant preparation is counted')
    return c


def _epoch(raw,index,app,native,image,model,backing_size,common):
    need(len(raw)==EPOCH,'whole distinct arena epoch')
    h=q(raw,0,32);roots=MEMBERS[index];count=len(roots)
    need(h[:5]==(1,1,1,1,roots[0]) and h[5]>0 and h[6:8]==(count,int(index>=10)) and
         h[8]<8 and h[9]<2 and h[10]<9 and h[11]>0 and h[11]%4096==0 and
         h[12]>0 and h[13]>0 and h[14]==roots[0] and h[16]==0 and
         h[17]<(1<<count) and h[18]>0 and h[19:21]==(2,h[17]) and h[21]<count and h[22]<8 and
         h[23:28]==(1,1,0,13,0) and h[28]>0 and h[29]<12 and h[30]>0 and h[31]==0,
         'actual fourteen-epoch geometry, fresh binding and complete typed RX lifetime')
    counters=[_counts(raw[256+i*384:256+(i+1)*384])for i in range(4)]
    need(all(all(a<=b for a,b in zip(counters[i],counters[i+1]))for i in range(3)),
         'all actual epoch counters are monotonic')
    before,entered,event,complete=counters
    need(entered[10]==before[10]+1 and entered[11]==before[11],
         'one actual generated entry follows the bound snapshot')
    need(entered==event,'zero interior signals and zero plan/publication/code-permission operations before final-event accounting')
    delta=tuple(b-a for a,b in zip(event,complete));wanted=[0]*48
    wanted[0]=wanted[1]=wanted[11]=1;wanted[16]=wanted[17]=2*count
    need(delta==tuple(wanted),'exactly one final NX and original per-member metadata closure after preentry')
    members=[]
    for i in range(8):
        value=raw[1792+i*MEMBER:1792+(i+1)*MEMBER]
        if i>=count:zero(value,'whole unused arena member capacity');continue
        m=q(value,0,24);root=roots[i];which=ROOTS.index(root);heads=HEADS[which]
        need(m[0]==1 and m[1]<8 and m[2]<2 and m[3]>0 and m[4]>0 and m[5]==root and
             m[6]>0 and m[6]%4096==0 and m[7:12]==(11,len(heads),2 if which==4 else 3 if which==9 else 1,0,root) and
             m[18:22]==(m[3],1,1,1) and m[22]<12 and 0<m[23]<=before[40],
             'immutable shared PF member and exact node versus active-binding identity')
        need(all(x>0 and x%4096==0 for x in m[12:18]) and m[17]==h[11] and
             m[13]==m[12]+8*4096 and m[14]==m[12]+16*4096 and
             m[15]==m[12]+17*4096 and m[16]==m[12]+18*4096,
             'whole unchanged generated code, stubs, slots and spill layout')
        need(q(value,8952,128)==heads+(0,)*(128-len(heads)),
             'every original head and zero whole unused head capacity')
        key=value[192:8952];need(q(key)[0]==root,'actual arena key root')
        identity=common._key_pages(key,image['source_pairs'][which],root&~4095,
                                  image['source_offsets'][which],backing_size)
        members.append(dict(words=m,root=root,key=key,heads=heads,source_identity=identity))
    need(all(len({m['words'][j]for m in members})==count for j in(1,3,22,23)),
         'simultaneously live slots, generations, nodes and binding identities are distinct')
    primary=members[0]['words']
    need(h[8:10]==primary[1:3] and h[12:14]==primary[3:5] and h[15]==primary[12] and
         h[28:30]==(primary[23],primary[22]),'entry joins its actual primary compiled node and fresh binding')
    directory=raw[81600:93888];n=sum(len(m['heads'])for m in members)
    need(n<=256 and sum(m['words'][9]+m['words'][10]for m in members)<=8 and
         q(directory,0,4)==(1,n,h[30],0),'unchanged domain limits and actual canonical descriptor directory ID')
    rows=[struct.unpack_from('<QQQII',directory,32+32*i)for i in range(n)];expected=[]
    for m in sorted(members,key=lambda m:m['words'][1]):
        w=m['words'];expected.extend((pc,w[12+j//64]+512*(j%64),w[3],w[1],j)for j,pc in enumerate(m['heads']))
    need(rows==expected and directory[32+32*n:]==bytes(12288-32-32*n),
         'every actual canonical original/generated/generation/slot/head directory row')
    entry=common._frame(raw[93888:160832],app,native,model,ENTRIES[index],False,PREVIOUS[index],native_kinds=CHECKPOINTS)
    event=common._frame(raw[160832:],app,native,model,EXITS[index],True,0,native_kinds=CHECKPOINTS)
    exit_root=roots[0]if count==1 else(ROOTS[4]if index in(4,10,12)else ROOTS[9])
    need(members[h[21]]['root']==exit_root,'actual final original NX belongs to the source-derived exit member')
    return dict(header=h,counters=counters,members=members,entry=entry,event=event,
                original_instructions=EXITS[index]-ENTRIES[index])


def _certificate(raw,node,h,values,owners,pid,mask):
    need(len(raw)==200 and u(raw,0,4)==(1,node,u(raw,8)[0],0) and u(raw,8)[0]<2,
         'whole issued SBC and actual immutable storage-node index')
    c=q(raw,16,7)
    need(c[0]>0 and c[1]>0 and c[2:]==(h[4],h[5],owners['pe'],h[10],values[18]),
         'actual certificate generation/build/owner/mirror and compiler-sized payload')
    session=struct.unpack_from('<4qQ2I',raw,72)
    need(session[:3]==(pid,pid,0) and session[3]>=0 and session[3]&96==96 and
         session[4:]==(mask,1,1),'whole actual process, synchronization and application-mask session')
    b=struct.unpack_from('<q8Q2I',raw,120)
    need(0<=b[0]<=0x7fffffff and b[2]>0 and b[3:]==(106*4096,h[4],h[8],h[7],17*4096,89*4096,1,1),
         'complete sealed code/proof backing identity and both actual live extents')
    return dict(serial=c[0],bank=u(raw,8)[0],session=session,backing=b)


def _nodes(data,index,stage,epoch,values,owners,pid,mask):
    rows=[];members={m['words'][22]:m for m in epoch['members']};e=epoch['header'];counts=epoch['counters'][0 if stage==0 else 3]
    for node in range(12):
        at=NODES+((index*2+stage)*12+node)*NODE;raw=data[at:at+NODE];h=q(raw,0,24)
        need(h[0]in(0,1) and h[1]==node and h[2]<=8 and
             ((h[2]==8 and h[3]==0)or(h[2]<8 and 0<h[3]<=counts[40])) and
             all(h[k]>0 and h[k]%4096==0 for k in(7,8,9,10)) and h[9]==h[8]+18*4096 and
             h[10]==owners['pe']+values[10]+node*values[11]+values[12] and h[11]>0 and
             h[12]in(0,1) and h[13]in(0,1) and h[14]in(0,1) and h[21]in(0,1),
             'complete actual node topology, binding range and compiler-bound mirror address')
        if h[0]:
            need(h[4]>0 and h[5]>0 and h[6]>0 and h[12]==1 and h[15]==h[11] and
                 raw[192:392]==raw[392:592],'installed node retains its complete genuine issued SBC and RAW epoch')
            certificate=_certificate(raw[192:392],node,h,values,owners,pid,mask)
            if h[2]==8:
                need(h[13:15]==(1,1) and 0<h[16]<=counts[40] and
                     0<h[17]<=e[18] and h[18]==h[23] and 0<h[18]<=e[5] and
                     h[19:23]==(0,0,0,0),'inactive immutable node has consumed its old claim and retains no execution permit')
            if node in members:
                m=members[node]['words']
                need(h[2:7]==(m[1],m[23],m[3],m[4],m[5]) and h[7:10]==(m[6],m[12],m[16]) and
                     h[13:15]==(0,0) and h[19:21]==(0,0) and certificate['bank']==m[2],
                     'each current member joins its genuine active node, bank and consumed preparation')
                need(h[21:23]==((1,e[18])if stage else(0,0)) and
                     (h[23]==e[5]if stage else h[23]<e[5]),
                     'only real completion issues the new current member claim')
            elif not h[21]:need(h[22]==0,'invalid actual claim has zero ID')
        else:
            certificate=None
            need(node not in members and h[4]==0 and h[21:23]==(0,0),
                 'uninstalled node cannot be a live member or claim a completion')
        rows.append(dict(h=h,issued=raw[192:392],current=raw[392:592],certificate=certificate))
    active=[r['h']for r in rows if r['h'][2]<8]
    need(len(active)==8 and len({r[2]for r in active})==len({r[3]for r in active})==8,
         'exactly eight distinct active bindings over twelve storage nodes')
    need(all(rows[n]['h'][7]==rows[0]['h'][7]+n*89*4096 for n in range(12)),
         'all twelve immutable proof extents retain their actual allocation offsets')
    return rows


def _query(raw,first,prot):
    need(len(raw)==296 and q(raw,0,2)==(first,first+4096) and
         q(raw,16)[0]<=first and q(raw,24)[0]>=first+4096 and
         q(raw,16)[0]%4096==q(raw,24)[0]%4096==0 and q(raw,32)[0]==1 and
         u(raw,40,5)==(1,1,prot,prot,0) and raw[60:64]==bytes(4) and q(raw,64)[0]==0,
         'whole actual successful one-page physical permission query')
    fd,last,closed,amount,rows=struct.unpack_from('<qqqQQ',raw,72)
    acquisition,handler,epoch=q(raw,128,3)
    need(fd>=0 and last==closed==0 and amount>0 and rows>0 and u(raw,112,3)==(1,1,1) and
         raw[124:128]==bytes(4) and acquisition>0 and handler>0 and epoch>0 and
         u(raw,152,2)==(4,0),'complete retained maps acquisition and exact maintained projection')
    zero(raw[160:],'anonymous mirror query has no fabricated sealed-file identity')
    return acquisition,handler,epoch


def _raw(data,control,epochs,nodes,app,native,model,common):
    raw=data[RAW:RAW+RAW_BYTES];frame=data[REENTRY:REENTRY+FRAME]
    if control!=2:
        zero(raw+frame+data[REENTRY_COUNTS:WIRE],'no fabricated RAW action or original reentry');return None
    h=q(raw,0,32);last=epochs[-1];e=last['header'];before=last['counters'][3]
    actual=[n for n in nodes[-1][1]if n['h'][0]and n['h'][6]==ROOTS[0]]
    need(len(actual)==1,'one actual previously constructed first-group primary')
    target=actual[0];n=target['h'];node=n[1]
    need(n[2]==8 and h[:7]==(1,node,n[10],4096,n[11],n[11]+1,1) and
         h[7:15]==(0,0,0,0,0,1,1,0) and h[15:]==(8,e[5],e[18],1,
             (1<<12)-1-(1<<node),3,1,0,1,0,1,0,0,0,0,0,0),
         'one actual inactive-mirror RW/byte-change/R ABA retires reuse before genuine reentry')
    prior=q(raw,256,12);after=q(raw,352,12)
    need(prior==tuple(x['h'][11]for x in nodes[-1][1]) and
         after==tuple(x+int(i==node)for i,x in enumerate(prior)),
         'only the actual exposed immutable node advances its nonwrapping RAW epoch')
    queries=[_query(raw[448+i*296:448+(i+1)*296],n[10],prot)for i,prot in enumerate((1,3,1))]
    need(queries==[(queries[0][0],queries[0][1],queries[0][2]+i)for i in range(3)],
         'both real permission transactions preserve acquisition and advance its projection epoch once')
    pages=raw[1336:];first,changed,restored=(pages[i*4096:(i+1)*4096]for i in range(3))
    need(len(first)==4096 and restored==first and changed==bytes([first[0]^1])+first[1:],
         'whole actual original/changed/restored publication page with one literal byte changed')
    reentry=common._frame(frame,app,native,model,264,False,0x42221d,
                          native_kinds=CHECKPOINTS,raw_trace=True)
    counts=_counts(data[REENTRY_COUNTS:PENDING]);delta=tuple(y-x for x,y in zip(before,counts))
    need(delta[:6]==(2,0,2,0,0,0) and delta[6:12]==(0,)*6 and
         all(delta[i]==0 for i in(14,19,20,21,32,33,34,35,36,38,39,40,41)) and delta[37]==1,
         'two genuine original DIRECT TRACE events reach stale-node refusal without a new publication or claim')
    return dict(node=node,mirror=n[10],epoch_before=h[4],epoch_after=h[5],reentry=reentry,
                counts=counts,whole_page_restored=True,execution_reused=False)


def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,differential,common):
    h,count,status,code=_framing(data,control)
    need(type(pid)is int and pid>0 and type(uid)is int and uid>=0 and type(differential)is bool and
         (not control or differential) and exit_status==status,'actual process, build profile and exact result')
    need(type(backing_size)is int and backing_size>0 and native['header'][1]==4 and
         native['header'][5]==1 and native['header'][36]==791 and len(native['observations'][0]['frames'])==12,
         'complete independently validated native791 reference and distinct carrier backing authority')
    need(h[9]>0 and h[10]>0 and h[11]==0 and h[12]&0o6003==1 and h[13]==0 and
         h[14]>0 and h[14]%4096==0 and h[15]==524288 and h[28:]==(h[12],0,pid,pid),
         'exact original fresh writable sink, process and real signal stack')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and u(initial,24,2)==(0o100600,uid) and
         q(initial,48)[0]==q(terminal,48)[0]==0,'same untouched private regular record inode')
    values,owners=_layout(layout,h[9],h[10]);model=app.trace_model(native,reference='arena10-ab791')
    epochs=[];nodes=[]
    for i in range(count):
        e=_epoch(data[544+i*EPOCH:544+(i+1)*EPOCH],i,app,native,image,model,backing_size,common)
        snapshot=[_nodes(data,i,j,e,values,owners,pid,app.MASK)for j in range(2)]
        for node,(a,b)in enumerate(zip(*snapshot)):
            need(a['h'][:21]==b['h'][:21] and a['issued']==b['issued'] and a['current']==b['current'],
                 'completion preserves actual immutable node and binding identities')
            if node not in {m['words'][22]for m in e['members']}:
                need(a==b,'completion changes no nonmember claim')
        epochs.append(e);nodes.append(snapshot)
    zero(data[544+count*EPOCH:RESULTS],'whole unexecuted epoch capacity remains zero')
    zero(data[NODES+count*2*12*NODE:ARENA_RESULTS],'whole unexecuted node snapshot capacity remains zero')
    for i in range(1,count):
        a,b=epochs[i-1],epochs[i]
        need(a['header'][5]<b['header'][5] and a['header'][18]<b['header'][18] and
             all(x<=y for x,y in zip(a['counters'][3],b['counters'][0])),
             'whole genuine inter-activation serial, completion and count chronology')
    identities={}
    for e in epochs:
        for m in e['members']:
            w=m['words'];identity=(w[2:17],w[22],m['key'],m['heads'])
            if m['root']in identities:need(identities[m['root']]==identity,
                'all ten roots retain exact compiled generation/build/source/code/proof identities')
            else:identities[m['root']]=identity
    need(set(identities)==set(ROOTS),'ten distinct genuinely constructed source roots')
    stable={n['h'][6]:n for n in nodes[9][1]if n['h'][0]and n['h'][6]in ROOTS}
    need(set(stable)==set(ROOTS) and len({n['h'][1]for n in stable.values()})==10 and
         len({n['h'][4]for n in stable.values()})==10,
         'all ten distinct immutable translations coexist before alternating reuse or the real ABA')
    if count==14:
        baseline=epochs[9]['counters'][3]
        for i in range(10,14):
            e=epochs[i];previous=epochs[i-1]['counters'][3];current=e['counters'][0]
            need(tuple(y-x for x,y in zip(previous[:6],current[:6]))==(2,0,2,0,0,0),
                 'actual two-DIRECT external frontier forces each later group activation')
            for c in e['counters']:
                need(all(c[k]==baseline[k]for k in(6,7,14,19,20,21,35,36,37,38)),
                     'post-warmup traversal performs zero construction, compact validation, publication or generated-code writes')
            need(current[8]==previous[8]+1 and current[33]+current[34]>previous[33]+previous[34] and
                 current[32]>previous[32] and current[40]>previous[40],
                 'each alternating group genuinely rebinds dormant nodes and retires prior active bindings')
            for stage in range(2):
                actual={n['h'][6]:n for n in nodes[i][stage]if n['h'][0]and n['h'][6]in ROOTS}
                need(set(actual)==set(ROOTS),'all ten immutable roots survive every later activation')
                for root,a in stable.items():
                    b=actual[root]
                    need(a['h'][4:13]==b['h'][4:13] and a['h'][15]==b['h'][15] and
                         a['issued']==b['issued'] and a['current']==b['current'],
                         'rebinding changes no immutable node address, generation, source or issued certificate')
    old=[q(data,RESULTS+32*i,4)for i in range(24)]
    need(old==([(i,0,0,1)for i in range(24)]if control else[(0,0,0,0)]*24),
         'all24 original actual source/owner mutations and full restorations remain separate')
    wanted=20 if control==1 else 12 if control==2 else 0
    results=[q(data,ARENA_RESULTS+32*i,4)for i in range(20)]
    need(results==[(i,0,0,1)if i<wanted else(0,0,0,0)for i in range(20)],
         'every separate dormant-node and binding mutation restored through its genuine predicate')
    a=q(data,APPEND,32);last=epochs[-1]['counters'][3]
    need(a[:9]==(1,12,8,3,wanted,wanted,status,code,int(control!=0)) and not any(a[17:]),
         'actual terminal arena version, capacity, controls and abort poison chronology')
    for word,index in enumerate((32,33,34,35,36,37,39,40),9):
        expected=last[index]+int(control==2 and index==37)
        need(a[word]>=expected and (not control or a[word]==expected),
             'terminal arena counter retains all actual focal work and the real RAW exposure')
    raw=_raw(data,control,epochs,nodes,app,native,model,common)
    pending,_=terminal_transit(data,control)
    if not control:
        need(gated is not None,'positive arena run requires the whole completed application')
        pair=app.application_pair(native,gated)
        need(pair==dict(full_application_state_equal=True,interior_owner_state_observed=False),
             'unchanged whole native/gated application comparator')
    else:
        need(gated is None,'causal abort cannot claim application completion');pair=None
    return dict(schema=1,control=control,epochs=count,active_members=[len(x)for x in MEMBERS[:count]],
        constructed_roots=list(ROOTS),native_pair=pair,actual_refusals=24 if control else 0,
        actual_restorations=24 if control else 0,arena_refusals=wanted,arena_restorations=wanted,
        raw_controls=int(control==2),raw=raw,pending_transit=pending,
        whole_record_sha256=hashlib.sha256(data).hexdigest(),
        intervals=[dict(entry=e['entry']['pc'],exit=e['event']['pc'],original_instructions=e['original_instructions'],
            final_nx=1,interior_signals=0,code_permission_operations=0,publications=0,planning_operations=0)
            for e in epochs if e['header'][6]==5],
        qualification_credit=False,performance_credit=False)


def _control_sites(data,control):
    count=10 if control==2 else 14
    tests=[('wire_version',8),('member_capacity',6*8),('record_pid',30*8),('completion_count',16*8),
           ('actual_refusal_count',20*8),('actual_sink_inode',256+8),('footer_outcome',WIRE+48)]
    for i in range(count):
        at=544+i*EPOCH
        tests.extend((f'epoch{i}_{name}',at+offset)for name,offset in(
            ('complete',24),('entry',32),('serial',40),('members',48),('typed_RX',19*8),
            ('event_count',256+2*384),('trap_count',256+2*384+2*8),
            ('publication',256+2*384+6*8),('code_open',256+2*384+12*8),
            ('compact_validate',256+2*384+21*8),('directory',81600+32),
            ('entry_GPR',93888+128+13*8),('event_GPR',160832+128+13*8),
            ('event_PC',160832+128+16*8),('event_FP',160832+1408+160),
            ('binding',28*8),('node',29*8),('descriptor_id',30*8),('reserved',31*8),
            ('unused_member',1792+len(MEMBERS[i])*MEMBER)))
        if len(MEMBERS[i])==5:
            at_member=at+1792+2*MEMBER
            tests.extend((f'third{i}_{name}',at_member+offset)for name,offset in(
                ('generation',3*8),('build_serial',4*8),('root',5*8),('source_identity',192+8+16),
                ('source_first',192+8+280),('source_second',192+8+4376+280),('head',8952)))
        node=q(data,at+1792+22*8)[0]
        need(node<12,'actual primary node controls use the recorded bounded identity')
        first=NODES+(i*2*12+node)*NODE;last=first+12*NODE
        tests.extend((f'node{i}_{name}',offset)for name,offset in(
            ('bound_binding',first+3*8),('mirror',first+10*8),('epoch',first+11*8),
            ('issued_generation',first+192+32),('claim_valid',last+21*8),
            ('claim_id',last+22*8),('current_generation',last+392+32)))
    if control:
        tests.extend((f'original_restoration{i}',RESULTS+i*32+24)for i in range(24))
        tests.extend((f'arena_restoration{i}',ARENA_RESULTS+i*32+24)for i in range(20 if control==1 else 12))
    if control==2:
        tests.extend((f'raw_{name}',RAW+8*word)for name,word in(
            ('node',1),('mirror',2),('advanced_epoch',5),('baseline',6),('RW_result',7),
            ('writable_refusal',8),('changed_refusal',9),('R_result',10),('restored_refusal',11),
            ('page_restored',12),('SBC_equal',13),('other_epoch_mask',19),('invalidations',21),
            ('poison_before_abort',22),('reusable_after',24),('actual_resume',25)))
        node=q(data,RAW+8)[0]
        tests.extend((('raw_prior_epoch',RAW+256+8*node),('raw_after_epoch',RAW+352+8*node)))
        for i in range(3):
            tests.extend((f'raw_query{i}_{name}',RAW+448+i*296+offset)
                         for name,offset in(('address',0),('protection',48),('provenance',152)))
        tests.extend((f'raw_page{i}',RAW+1336+i*4096)for i in range(3))
        tests.extend((name,offset)for name,offset in(
            ('raw_entry_GPR',REENTRY+128+13*8),('raw_entry_PC',REENTRY+128+16*8),
            ('raw_entry_flags',REENTRY+128+17*8),('raw_entry_FP',REENTRY+1408+160),
            ('raw_entry_events',REENTRY_COUNTS),('raw_entry_publication',REENTRY_COUNTS+6*8)))
    need(len(tests)==CONTROL_COUNTS[control] and len({name for name,_ in tests})==len(tests) and
         len({at for _,at in tests})==len(tests),'literal distinct whole-reader arena corruption roster')
    return tests


def controls(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,layout,differential,common):
    arguments=(app,native,image,pid,uid,control,exit_status,gated)
    keywords=dict(backing_size=backing_size,layout=layout,differential=differential,common=common)
    original=read(data,*arguments,**keywords);count=10 if control==2 else 14
    def reject(label,changed,refused,expected=None,authority=None):
        need(changed!=data or authority is not None,'each supplied corruption differs from the actual valid record')
        try:read(changed,*arguments,**(keywords if authority is None else dict(keywords,backing_size=authority)))
        except ValueError as error:
            if expected is not None:need(str(error)==expected,'coherent corruption reaches its intended whole-reader predicate')
            refused.append(label)
        else:raise ValueError('actual full arena corruption accepted '+label)
    refused=[]
    for name,at in _control_sites(data,control):
        changed=bytearray(data);changed[at]^=1;reject(name,bytes(changed),refused)
    phase=[]
    for i in range(count):
        event=544+i*EPOCH+256+2*384;complete=event+384
        for kind in range(1,6):
            changed=bytearray(data)
            for at in(event,complete):
                for word in(0,kind):struct.pack_into('<Q',changed,at+8*word,q(data,at+8*word)[0]+1)
            reject(f'epoch{i}_interior_signal{kind}',bytes(changed),phase,
                'zero interior signals and zero plan/publication/code-permission operations before final-event accounting')
            changed=bytearray(data);struct.pack_into('<Q',changed,complete+8,q(data,complete+8)[0]-1)
            if kind==1:struct.pack_into('<Q',changed,complete,q(data,complete)[0]-1)
            else:struct.pack_into('<Q',changed,complete+8*kind,q(data,complete+8*kind)[0]+1)
            reject(f'epoch{i}_final_signal{kind}',bytes(changed),phase,
                'exactly one final NX and original per-member metadata closure after preentry')
    need(len(phase)==len(set(phase))==PHASE_CONTROL_COUNTS[control],
         'all separate coherent interior and final-event phase corruptions refused')
    backing=[]
    for i in range(count):
        for member in range(len(MEMBERS[i])):
            for page in range(2):
                at=544+i*EPOCH+1792+member*MEMBER+192+8+page*4376+104+72
                changed=bytearray(data);struct.pack_into('<Q',changed,at,q(data,at)[0]+1)
                reject(f'epoch{i}_member{member}_page{page}_carrier_size',bytes(changed),backing,
                       'exact sealed main ELF size and complete source VMA/device/inode/offset')
    for label,size in(('original_ELF_size',image['bytes']),('wrong_carrier_size',backing_size+1)):
        need(size!=backing_size,'distinct real carrier versus original ELF authority')
        reject(label,data,backing,'exact sealed main ELF size and complete source VMA/device/inode/offset',size)
    need(len(backing)==len(set(backing))==BACKING_CONTROL_COUNTS[control],
         'all actual backing records and both external backing-size authorities refused')
    pending=[]
    for word in tuple(range(45))+(47,)if control==2 else(0,):
        changed=bytearray(data);struct.pack_into('<Q',changed,PENDING+8*word,q(data,PENDING+8*word)[0]^1)
        reject(f'pending_ticket_word{word}',bytes(changed),pending)
    need(len(pending)==len(set(pending))==PENDING_CONTROL_COUNTS[control],
         'all separate pending-ticket identity, ancestry, frame and count corruptions refused')
    return dict(original_sha256=original['whole_record_sha256'],refusals=refused,
                phase_refusals=phase,backing_refusals=backing,pending_refusals=pending,native_operations=0)


def configured(common):
    need(common.MEMBER==MEMBER and common.FRAME==FRAME and callable(common._key_pages) and
         callable(common._frame),'same complete source-key and native-frame validators')
    return SimpleNamespace(WIRE=WIRE,EPOCH=EPOCH,APPEND=APPEND,q=q,CONTROL_COUNTS=CONTROL_COUNTS,
        PHASE_CONTROL_COUNTS=PHASE_CONTROL_COUNTS,BACKING_CONTROL_COUNTS=BACKING_CONTROL_COUNTS,
        PENDING_CONTROL_COUNTS=PENDING_CONTROL_COUNTS,
        read=partial(read,common=common),controls=partial(controls,common=common),
        terminal_observation=terminal_observation,terminal_transit=terminal_transit)
