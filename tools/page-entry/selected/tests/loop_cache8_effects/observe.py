"""Actual guest effects after three genuine CACHE8 completions.

This is a distinct wire. The first three epochs use the unchanged owner
predicates; later lifecycle calls and failed generic steps have their own
literal observations. Supplied corruptions are never guest executions.
"""
import hashlib
import struct
from functools import partial
from types import SimpleNamespace

BASE=910368
EXTRA=1092536
WIRE=BASE+64+EXTRA
SIZE=WIRE+64
MAGIC=0x314538434132494c
FOOTER=0x314645384332494c
MEMORY=35152
BIND=13568
SLOT=198056
STEP=65848
STATE=0x800000
ROOTS=(0x410200,0x412400,0x414600)
STOP={2:(0,0,0),3:(125,7,11),4:(125,101,305)}


def need(ok,why):
    if not ok:raise ValueError(why)


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def _zero(data,why):need(not any(data),why)


def _counts(raw):
    value=q(raw,0,32)
    need(value[0]==sum(value[1:6]) and value[25:]==(0,)*7,'whole event/signal counter conservation')
    return value


def _memory(raw,index,kind,app,native,image,earlier,backing_size):
    need(len(raw)==MEMORY,'whole actual lifecycle memory snapshot')
    h=q(raw,0,16);life=q(raw,128,18);maps=q(raw,272,16)
    before=q(raw,400,10);after=q(raw,480,10)
    rows=[q(raw,560+192*i,24)for i in range(6)]
    guest=[q(raw,1712+64*i,8)for i in range(3)];state=q(raw,1904,32)
    need(h[:8]==(1,1,0,0,6,24576,8192,224) and h[8]<(1<<31) and h[9:11]==(15,0) and
         h[13]==backing_size and h[14]&0o170000==0o100000 and h[15]==native['rsp'],
         'actual complete source/backing observation with exact carrier size')
    # mv_fresh tags actual I/O as DIRECT outside a maps phase, or FRESH
    # inside one. These fixed completion/cancel/syscall/failure seams have
    # ended the phase; the cumulative handler counter still survives.
    need(life[0]==1 and maps[0]<(1<<31) and maps[1:3]==(0,0) and maps[3]>0 and maps[4]>0 and
         maps[5:8]==(1,1,1) and maps[8]>0 and before[4]>0 and before[6]==0 and
         after[4]==before[4] and after[6]==before[6] and maps[11:]==(before[6],1,0,0,0) and
         after[0]==before[0]+1 and after[1]==before[1]+1 and after[8:]==(0,0) and
         maps[8:11]==(after[1],after[4]if after[6]else 0,after[5]),
         'one real fresh complete maps acquisition with exact phase provenance and closed descriptor')
    dev,ino=h[11:13];major=((dev>>8)&0xfff)|((dev>>32)&0xfffff000)
    minor=(dev&255)|((dev>>12)&0xffffff00)
    for i,row in enumerate(rows):
        root=ROOTS[i//2];m=earlier[root];key=m['key'];at=8+4376*(i%2)
        old=m['source_identity'][i%2];backing=key[at+104:at+280]
        logical=1 if kind==2 and i==2 and index in(3,4) else 5
        need(row[0]==0x410000+4096*i and row[1]>0 and row[2]>0 and
             row[3:7]==(image['source_offsets'][i//2]+4096*(i%2),0,1,old[6]) and
             row[7:10]==(logical,1,1) and row[10]in(0,1) and
             row[11]<=row[0] and row[12]>=row[0]+4096 and row[11]%4096==row[12]%4096==row[13]%4096==0 and
             row[13]+row[0]-row[11]==row[3] and row[14:19]==(major,minor,ino,1,1) and
             row[19:]==(0,)*5,'whole actual closed source page, original file offset and checked alias')
        need(struct.unpack_from('<i',backing)[0]==h[8] and q(backing,24,2)==(dev,ino) and
             q(backing,72)[0]==h[13] and struct.unpack_from('<I',backing,48)[0]==h[14],
             'actual retained descriptor/stat identity joins the original issued source certificate')
        if index==0:
            need(row[:9]==old[:9],'first effect snapshot joins every original source identity field')
    for row,first,size in zip(guest,(0x500000000000,native['rsp']-128,STATE),(8192,224,256),strict=True):
        need(row[0]%4096==row[1]%4096==0 and row[0]<=first and row[1]>=first+size and
             row[2:]==(0,0,0,0,3,1),'whole actual original RW/NX anonymous guest mapping')
    model,states=app.model(native)
    need(raw[2160:26736]==image['source']==native['source'] and
         raw[26736:34928]==model[82][3] and raw[34928:]==native['stack'],
         'all six original source pages, full guest data and stack remain byte exact')
    if kind!=2:
        want=[0]*32
        if kind==4 and index:want[12]=state[12]
        need(state==tuple(want),'no unexecuted guest effect-state stores')
    elif index==0:need(state==(0,)*32,'whole zero state before the actual effect window')
    elif index in(1,2,3,4,5):
        # The runtime hooks bracket RAW, before ordinary guest-result application.
        step=83+(11 if index in(1,2,3)else 17)
        need(state==states[step],'literal state stores before each actual guest syscall')
    return dict(header=h,life=life,maps=maps,before=before,after=after,rows=rows,state=state)


def _code(raw,earlier,kind,stage,memory):
    need(len(raw)==1152,'whole three-member physical code-query set')
    first=q(raw,0,16)
    snapshot=(1,2,4)[stage]if stage<3 else(6 if kind!=2 else None)
    stats=memory[snapshot]['before']if snapshot is not None else None
    provenance=(first[11],stats[4]if stats else first[12],first[13])
    need(all(x>0 for x in provenance),'real maintained-map acquisition, cumulative handler and epoch')
    if stats:
        need(stats[6:]==(0,1,0,0) and provenance==(stats[1],stats[4],stats[5]),
             'code-query set joins the following fresh-memory pre-acquisition state')
    else:
        after=memory[5]['after']
        need(all(x>=y for x,y in zip(provenance,(after[1],after[4],after[5]),strict=True)),
             'final maintained query provenance follows the second real mapping result')
    for member,root in enumerate((0x414600,0x410200,0x412400)):
        w=earlier[root]['words']
        for extent,(first,size)in enumerate(zip(w[12:15],(32768,32768,4096),strict=True)):
            v=q(raw,128*(3*member+extent),16)
            # JMP refusal has already revoked its original step before abort,
            # so phase_fail leaves its first terminal query to acquire DIRECT.
            # Writer abort instead refreshes through the real revoke callback.
            # The remaining fixed queries use the maintained table after revoke.
            direct=kind==4 and stage==3 and member==extent==0
            observed=(provenance[0],0 if direct else provenance[1],provenance[2],
                      0 if direct else 4,int(direct))
            need(v[0:2]==(first,first+size) and v[2]<=first and v[3]>=first+size and
                 v[2]%4096==v[3]%4096==0 and v[4:11]==(size//4096,1,1,1,1,0,0) and
                 v[11:]==observed,
                 'all51 actual generated pages physically R with exact maintained-map provenance')


def _step(raw,app,native,gpr,pc,flags,cr2,exception):
    need(len(raw)==STEP,'whole actual generic step frame')
    h=q(raw,0,16);g=q(raw,128,23);fp=raw[312:]
    native_frame=native['observations'][0]['frames'][0]
    need(h[0]==app.MASK and h[1]>0 and h[1]%16==0 and
         h[2]==native_frame['header'][9] and h[3]==h[2] and h[4:]==(0,)*12 and fp==native_frame['fp'],
         'complete real generic frame mask and all65536 native FP bytes')
    need(tuple(g[i]for i in app.GREG)==tuple(gpr) and g[16:]==
         (pc,flags,0x2b000000000033,*exception,app.MASK,cr2),
         'every actual generic GPR/flag/selector/mask and exact architectural signal origin')
    return g


def _negative(raw,h,app,native,kind,private_target):
    active=h[25];need(active<2,'actual failed generic owner index')
    current=raw[696424+active*SLOT:696424+(active+1)*SLOT]
    s=q(current,0,64);pc,code,length=(0x416000,401,8)if kind==3 else(0x416007,765,2)
    status,error,detail=STOP[kind]
    need(h[23:27]==(error,detail,active,int(kind==3)) and h[27:]==(0,)*5 and
         s[:4]==(7,active,2,0) and s[4]>0 and s[5]>0 and s[6:9]==(pc,code,length) and
         s[14:23]==(6,error,detail,int(kind==4),pc,code,length,1,0x202) and
         s[23:27]==(5,2,0,pc if kind==3 else private_target) and s[52]>0 and s[53:]==(0,)*11,
         'one genuine TRACE-origin failed step with literal source-bound descriptor and error')
    model,_=app.model(native);g=list(model[83][1])
    if kind==4:g[0]=private_target
    _step(current[512:512+STEP],app,native,g,pc,0x202,0x414616,(0,1))
    after=current[512+STEP:512+2*STEP];unexpected=current[512+2*STEP:]
    if kind==3:
        need(s[9:14]==(1,11,2,0,0x412400) and s[27:40]==(0,)*13,
             'real write fault captured only by chain unexpected path before continuation')
        _zero(after,'unexpected chain fault does not invent step.after')
        _step(unexpected,app,native,g,pc,0x202|app.TF|app.RF,0x412400,(7,14))
    else:
        need(s[9:14]==(0,)*5 and s[27:40]==
             (private_target,0x202|app.TF,1,0,305,private_target,1,0,0,305,0,0,0),
             'real JMP TRACE reaches the original closed-continuation refusal before release')
        _zero(unexpected,'private JMP refusal has no invented unexpected fault')
        _step(after,app,native,g,private_target,0x202|app.TF,0x414616,(0,1))
    # The other slot is the actual completed predecessor. Bind chronology and
    # full captured frames without guessing absolute event or generation ids.
    prior=raw[696424+(active^1)*SLOT:696424+((active^1)+1)*SLOT];p=q(prior,0,64)
    previous_pc,previous_code,previous_length=(0x414616,1871,6)if kind==3 else(0x416000,286,7)
    previous_origin=1 if kind==3 else 2
    need(p[:4]==(5,active^1,previous_origin,0) and p[4]>0 and p[5]>0 and p[5]<s[5] and
         p[6:9]==(previous_pc,previous_code,previous_length) and p[14]==5 and
         p[9:14]==(0,)*5 and p[15:17]==(0,0) and p[17]==1 and
         p[18:23]==(previous_pc,previous_code,previous_length,1,0x202) and
         p[23:27]==(5,2,0,pc) and
         p[27]==pc and p[28]==0x202|app.TF and p[29:32]==(1,1,0) and
         p[32:40]==(pc,1,1,1,0,1,1,0) and p[40:52]==(0,)*12 and p[52]>0 and p[53:]==(0,)*11,
         'exact successful predecessor continuation/release precedes the failed new generic step')
    # chain_produce binds per-slot generations; chain_begin_trace consumes
    # valid. Both failures retain that exact entry and one later event boundary.
    entry=s[40:50]
    need(entry==(0,active^1,active,s[5],s[50],p[4],s[4],pc,0x202,p[52]) and
         s[50]>0 and s[51]==s[5]+1,
         'exact consumed TRACE entry joins both slot generations, event, sequence, PC, flags and predecessor borrow')
    _zero(prior[512+2*STEP:],'successful predecessor has no unexpected frame')
    _step(prior[512:512+STEP],app,native,model[82 if kind==3 else 83][1],previous_pc,
          0x202|(app.RF if kind==3 else 0),0x414616,(21,14)if kind==3 else(0,1))
    _step(prior[512+STEP:512+2*STEP],app,native,g,pc,0x202|app.TF,0x414616,(0,1))
    return dict(slot=active,event=s[5],generation=s[4],pc=pc,code=code,error=error,detail=detail)


def _bindings(raw,h,app,native,image,earlier,common,backing_size):
    need(0<h[18]<=32 and h[19]==0 and h[20]==1,'actual bounded later bindings all completed at final C frontier')
    model,_=app.model(native);original_pcs={x[0]for x in model}
    result=[];seen_new_b=False
    for index in range(32):
        value=raw[253488+index*BIND:253488+(index+1)*BIND]
        if index>=h[18]:_zero(value,'whole unused later binding capacity');continue
        b=q(value,0,32);n=b[6]
        need(b[:4]==(1,1,1,1) and b[4]in original_pcs and b[5]>h[7] and 1<=n<=8 and
             b[7]in(0,1) and b[8]<8 and b[9]>0 and b[10]>0 and b[11]>0 and b[11]%4096==0 and
             b[12]in(0,1,2) and b[13]<1<<n and b[14:16]==(11,2) and
             b[16]==b[17]==b[19] and b[16]in original_pcs and b[18]==h[6]+index+1 and b[20:]==(0,)*12,
             'complete real later binding/entry/final NX/receipt with bounded current membership')
        members=[q(value,256+128*i,16)for i in range(8)]
        need(all(m==(0,)*16 for m in members[n:]) and len({m[0]for m in members[:n]})==n and
             len({m[2]for m in members[:n]})==n,'distinct actual current members and whole unused member slots')
        if index==0:
            need(b[4]==0x416000 and b[6:8]==(1,0) and b[12:14]==(0,0) and b[16]==0x416048 and
                 members[0][9:13]==(11,11,1,0),
                 'first actual cold reset prefix has eleven NONE heads and no DIRECT peer before either syscall')
        directory=value[1280:];dh=q(directory,0,4);head_count=sum(m[10]for m in members[:n])
        need(0<head_count<=256 and dh==(1,head_count,b[5],0) and
             directory[32+32*head_count:]==bytes(12288-32-32*head_count),
             'whole sealed later directory header, head bound and unused capacity')
        cursor=0;entry_rows=[]
        for m in members[:n]:
            need(m[0]<8 and m[1]<2 and m[2]>0 and m[3]>0 and m[4]in original_pcs and
                 m[5]>0 and m[5]%4096==0 and m[6]==m[4] and m[7]>0 and m[8]>0 and
                 m[9]==11 and 0<m[10]<=128 and m[11]+m[12]<=8 and
                 all(x>0 and x%4096==0 for x in m[13:]),
                 'actual immutable later member descriptor and exact planner/storage bounds')
            rows=[struct.unpack_from('<QQQII',directory,32+32*(cursor+j))for j in range(m[10])]
            need(all(r==(r[0],m[13+j//64]+512*(j%64),m[2],m[0],j) and r[0]in original_pcs
                     for j,r in enumerate(rows)) and rows[0][0]==m[4] and len({r[0]for r in rows})==m[10],
                 'every actual directory entry binds its source instruction, member generation and generated head')
            if m[4]in ROOTS:
                which=common.ROOTS.index(m[4]);need(tuple(r[0]for r in rows)==common.HEADS[which] and
                    m[9:13]==(11,len(common.HEADS[which]),3 if which==2 else 1,0),
                    'unchanged literal complete ABC planner head/exit geometry after the real effect')
            if index==0:
                need(tuple(r[0]-0x416000 for r in rows)==(0,7,14,21,28,35,42,52,57,62,67),
                     'every literal first reset instruction precedes the actual syscall frontier')
            if m[4]==0x412400 and b[12]:
                old=earlier[0x412400]
                need(m[2]!=old['words'][3] and m[7]!=old['source_identity'][0][2],
                     'old B publication and old source generation absent after real mprotect')
                if not seen_new_b:
                    key=raw[687664:696424];ids=common._key(key,image,0x412400,backing_size)
                    need((m[2],m[3])==h[12:14] and (m[7],m[8])==(ids[0][2],ids[1][2]),
                         'first new B publication joins its whole fresh unchanged-byte source key')
                    seen_new_b=True
            entry_rows.extend(r for r in rows if r[0]==b[4] and r[1]==b[10] and r[2:4]==(b[9],b[8]))
            cursor+=m[10]
        need(len(entry_rows)==1 and sum(m[11]+m[12]for m in members[:n])<=8,
             'one exact current generated entry and unchanged aggregate boundary bound')
        if result:need(result[-1]['serial']<b[5] and result[-1]['receipt']<b[18],
                       'strict actual post-effect publication/receipt chronology')
        result.append(dict(serial=b[5],receipt=b[18],root=b[4],members=n,returned=b[12],exit=b[19]))
    need(seen_new_b and result[-1]['exit']==0x41461c and result[-1]['returned']==2,
         'actual valid original reentry after both guest calls completes the final C frontier')
    return result


def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,common):
    need(type(data)is bytes and len(data)==SIZE and type(control)is int and control in(2,3,4) and
         type(backing_size)is int and backing_size>0 and type(pid)is int and pid>0 and type(uid)is int and uid>=0,
         'whole distinct genuine-effect wire and exact process/backing authorities')
    kind=control;status,code,detail=STOP[kind]
    need(exit_status==status and native['header'][5]==1 and native['effect_kind']==kind and
         len(native['observations'][0]['frames'])=={2:12,3:7,4:6}[kind],
         'literal actual effect outcome and previously validated complete or partial native reference')
    bh=q(data,0,32);bf=q(data,BASE,8);raw=data[BASE+64:-64];h=q(raw,0,32);f=q(data,WIRE,8)
    for actual,magic,version,size in ((bf,common.FOOTER,1,BASE),(f,FOOTER,2,EXTRA)):
        need(actual[:4]==(magic,version,size,size) and 1<=actual[4]<=64 and 0<actual[5]<=size and actual[6:]==(status,code),
             'whole original and appended actual descriptor writes with exact child outcome')
    need(bh[:9]==(common.MAGIC,2,BASE,common.EPOCH,kind,8,8,9,4) and bh[9]>0 and bh[10]>0 and
         bh[11]==0 and bh[12]&0o6003==1 and bh[13]==0 and bh[14]>0 and bh[14]%4096==0 and bh[15]==524288 and
         bh[16:24]==(3,0,0,0,0,0,status,code) and bh[24:28]==(0,0,0,0) and bh[28:]==(bh[12],0,pid,pid),
         'three genuine old completions and exact new role without fabricated fourth completion or controls')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and
         struct.unpack_from('<II',initial,24)==(0o100600,uid) and q(initial,48)[0]==q(terminal,48)[0]==0,
         'same fresh private actual output inode before either descriptor write')
    model,_=app.model(native)
    epochs=[common._epoch(data[544+i*common.EPOCH:544+(i+1)*common.EPOCH],i,app,native,image,model,backing_size)
            for i in range(3)]
    _zero(data[544+3*common.EPOCH:BASE],'whole absent fourth epoch and unexecuted old control capacity')
    for a,b in zip(epochs,epochs[1:]):
        need(a['header'][5]<b['header'][5] and a['header'][18]<b['header'][18] and
             all(x<=y for x,y in zip(a['counters'][3],b['counters'][0])),
             'genuine first-phase serial/receipt/counter chronology')
    earlier={m['root']:m for m in epochs[2]['members']}
    need(h[:4]==(MAGIC,2,EXTRA,kind) and h[4]>0 and h[5]==32 and
         h[6:8]==(epochs[2]['header'][18],epochs[2]['header'][5]) and h[10:12]==(3 if kind==2 else 6,1) and
         h[14:16]==(1,1) and h[21:23]==(status,code) and h[27:]==(0,)*5,
         'exact distinct effect observer identity and actual original issued completion')
    if kind==4:
        generated=earlier[0x412400]['words'][12]
        need(h[8:10]==(generated,generated+1),'descriptive actual private B entry and strict interior target')
    else:need(h[8:10]==(0,0),'no unused private target observation')
    used=(0,1,2,3,4,5)if kind==2 else(0,1,6)
    memory={}
    for index in range(7):
        value=raw[7424+index*MEMORY:7424+(index+1)*MEMORY]
        if index in used:memory[index]=_memory(value,index,kind,app,native,image,earlier,backing_size)
        else:_zero(value,'whole unobserved physical-memory snapshot')
    for index in used:
        if kind==4 and index:need(memory[index]['state'][12]==h[9],'actual guest mailbox preserves the observed private target')
        if index:
            need(memory[index]['header'][8:15]==memory[0]['header'][8:15],
                 'same retained sealed object throughout real effects')
            for page in range(6):
                a,b=memory[0]['rows'][page],memory[index]['rows'][page]
                if kind!=2 or page!=2:need(a[:11]==b[:11],'all unchanged source-page identities remain exact')
                elif index in(1,2):need(a[:11]==b[:11],'B identity is unchanged before the first actual mapping call')
    for stage in range(4):
        value=raw[2816+1152*stage:2816+1152*(stage+1)]
        if kind==2 or stage in(0,3):_code(value,earlier,kind,stage,memory)
        else:_zero(value,'unexecuted syscall code-query stages wholly zero')
    used_counts=(0,1,2,3,4,5,6,7)if kind==2 else(0,1,7)
    counts={}
    for index in range(8):
        value=raw[768+256*index:768+256*(index+1)]
        if index in used_counts:counts[index]=_counts(value)
        else:_zero(value,'no unexecuted counter snapshot')
    need(counts[0]==epochs[2]['counters'][3],'first effect counters equal the actual third completion')
    for a,b in zip(used_counts,used_counts[1:]):
        need(all(x<=y for x,y in zip(counts[a],counts[b])),'actual effect counters never reset')
    bindings=[];failed=None
    if kind==2:
        need(h[12]>0 and h[13]>0 and h[16:18]==(2,2) and h[23:25]==(0,0) and h[26]==0,
             'both actual guest syscall completions and no generic error')
        for i in range(2):
            call=q(raw,256+256*i,32);step=83+(11 if i==0 else 17);g=model[step][1]
            args=tuple(g[j]for j in(7,6,2,10,8,9))
            need(call[:4]==(1,1,0x41604a if i==0 else 0x416071,10) and call[4:10]==args and
                 call[10:]==(0,)*22,'literal actual mprotect syscall, all six real args and zero result')
            before,after=memory[2+2*i],memory[3+2*i]
            need(after['life'][1]==before['life'][1]+1 and after['life'][3]==before['life'][3]+1 and
                 after['life'][4]==before['life'][4]+1 and after['life'][5]==before['life'][5] and
                 after['rows'][2][2]>before['rows'][2][2] and after['state']==before['state'],
                 'actual completed lifecycle invalidation/generation/retirement before guest result application')
        need(memory[4]['rows'][2][:11]==memory[3]['rows'][2][:11] and
             memory[5]['rows'][2][2]>memory[3]['rows'][2][2]>memory[2]['rows'][2][2],
             'both real ABA mapping generations advance despite identical final bytes and protections')
        bindings=_bindings(raw,h,app,native,image,earlier,common,backing_size)
        ids=common._key(raw[687664:696424],image,0x412400,backing_size)
        need(tuple(x[2]for x in ids)==tuple(memory[5]['rows'][i][2]for i in(2,3)),
             'new B source generations are the actual post-ABA lifecycle generations')
        need(gated is not None and gated['application_complete'] and gated['effect_kind']==2,
             'complete actual ABA application output')
        pair=app.application_pair(native,gated)
        need(pair==dict(full_application_state_equal=True,interior_owner_state_observed=False) and
             native['effect_tail']['state']==gated['effect_tail']['state'],
             'whole native/gated application state and every actual guest effect-state byte')
    else:
        need(h[12:14]==(0,0) and h[16:21]==(0,0,0,0,0),
             'failed original guest instruction issues no real syscall, new binding or application completion')
        _zero(raw[256:768],'negative subjects do not fabricate guest syscall observations')
        _zero(raw[253488:696424],'negative subjects do not fabricate later bindings or new B source')
        need(gated is not None and not gated['application_complete'] and gated['effect_kind']==kind and
             all(gated[k]==native[k]for k in('seed','source','stack','data','rsp','predecessor','hardware')),
             'whole actual failed application prefix equals the genuine native reference')
        failed=_negative(raw,h,app,native,kind,h[9]);pair=None
    return dict(schema=2,control=kind,epochs=3,first_phase_members=[1,1,3],
        whole_record_sha256=hashlib.sha256(data).hexdigest(),native_pair=pair,
        application_complete=kind==2,actual_syscalls=2 if kind==2 else 0,
        actual_source_write_fault=kind==3,actual_private_entry_refusal=kind==4,
        actual_mapping_ABA=kind==2,later_bindings=bindings,failed_generic=failed,
        final_counts=counts[7],qualification_credit=False,performance_credit=False)


def controls(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size,common):
    original=read(data,app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size,common=common)
    at=BASE+64
    tests=[('base_version',8),('base_complete',16*8),('base_pid',30*8),('base_inode',256+8),
           ('effects_version',at+8),('first_receipt',at+6*8),('first_serial',at+7*8),
           ('unsafe_complete',at+11*8),('actual_status',at+21*8),('actual_error',at+23*8),
           ('footer_status',WIRE+6*8)]
    for i in range(3):
        e=544+i*common.EPOCH
        tests.extend((f'epoch{i}_{name}',e+offset)for name,offset in
                     (('entry',32),('complete',24),('directory',81088+32),('source',1280+192+288),
                      ('event_PC',160320+128+16*8),('entry_GPR',93376+128+13*8),
                      ('event_FP',160320+1408+160)))
    for i in ((0,1,2,3,4,5)if control==2 else(0,1,6)):
        m=at+7424+i*MEMORY
        tests.extend((f'memory{i}_{name}',m+offset)for name,offset in
                     (('complete',8),('backing_size',13*8),('maps_close',272+7*8),
                      ('B_generation',560+2*192+16),('B_protection',560+2*192+7*8),
                      ('source',2160+8192),('data',26736),('stack',34928),('state',1904+31*8)))
    for stage in ((0,1,2,3)if control==2 else(0,3)):
        for i in range(9):tests.append((f'physical_R{stage}_{i}',at+2816+1152*stage+128*i+8*8))
    if control==2:
        for i in range(2):
            for j in range(11):tests.append((f'call{i}_{j}',at+256+256*i+8*j))
        for j in (0,1,2,3,4,5,6,8,9,10,11,12,13,14,16,18,19):
            tests.append((f'later_binding{j}',at+253488+8*j))
        tests.extend((('new_B_source',at+687664+288),('new_B_generation',at+687664+8+16)))
    else:
        active=q(data,at+25*8)[0];s=at+696424+active*SLOT
        for j in (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39):
            tests.append((f'failed_slot{j}',s+8*j))
        tests.extend((('actual_before_GPR',s+512+128),('actual_before_FP',s+512+312+160),
                      ('actual_final_GPR',s+512+(2 if control==3 else 1)*STEP+128),
                      ('actual_final_FP',s+512+(2 if control==3 else 1)*STEP+312+160)))
    need(len(tests)==(163 if control==2 else 121) and len({name for name,_ in tests})==len(tests),
         'fixed complete genuine-effect wire corruption population')
    refused=[]
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        if name in('failed_slot4','failed_slot5'):struct.pack_into('<Q',changed,offset,0)
        try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,
                 backing_size=backing_size,common=common)
        except ValueError:refused.append(name)
        else:raise ValueError('actual genuine-effect corruption accepted '+name)
    entry_tests=[]
    if control!=2:
        active=q(data,at+25*8)[0];s=at+696424+active*SLOT;p=at+696424+(active^1)*SLOT
        entry_tests.extend((f'consumed_entry{j}',s+8*(40+j))for j in range(10))
        entry_tests.extend((('chain_sequence',s+8*50),('terminal_event',s+8*51),
            ('current_borrow',s+8*52),('previous_borrow',p+8*52),
            ('current_generation',s+8*4),('previous_generation',p+8*4),
            ('unused_previous_entry',p+8*40),('current_reserved',s+8*53)))
    need(len(entry_tests)==(0 if control==2 else 18) and
         len({name for name,_ in entry_tests})==len(entry_tests),'fixed separate consumed-entry corruption population')
    entry_refused=[]
    for name,offset in entry_tests:
        changed=bytearray(data);changed[offset]^=1
        # Current borrow is independently joined to the actual terminal row;
        # the wire itself requires a real nonzero retained borrow identity.
        if name=='current_borrow':struct.pack_into('<Q',changed,offset,0)
        try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,
                 backing_size=backing_size,common=common)
        except ValueError:entry_refused.append(name)
        else:raise ValueError('actual consumed-entry corruption accepted '+name)
    phase_refused=[]
    for i in ((0,1,2,3,4,5)if control==2 else(0,1,6)):
        m=at+7424+i*MEMORY
        for name,offsets in (
            ('kind',(272+11*8,)),('handler',(272+9*8,)),
            ('before_active',(400+6*8,)),('after_active',(480+6*8,)),
            ('cumulative_handler',(480+4*8,)),
            ('coherent_active_phase',(400+6*8,480+6*8,272+11*8))):
            changed=bytearray(data)
            for offset in offsets:changed[m+offset]^=1
            if name=='coherent_active_phase':
                struct.pack_into('<Q',changed,m+272+9*8,q(data,m+400+4*8)[0])
            try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,
                     backing_size=backing_size,common=common)
            except ValueError:phase_refused.append(f'memory{i}_phase_{name}')
            else:raise ValueError('actual maps phase corruption accepted '+name)
    need(len(phase_refused)==len(set(phase_refused))==(36 if control==2 else 18),
         'six separate actual phase-provenance corruptions per observed snapshot')
    code_refused=[]
    for stage in ((0,1,2,3)if control==2 else(0,3)):
        row=at+2816+1152*stage+128*8
        for name,field in (('acquisition',11),('handler',12),('epoch',13),('kind',14),('io',15),
                           ('coherent_old_reuse',None)):
            changed=bytearray(data)
            if field is None:
                for i in range(9):
                    struct.pack_into('<2Q',changed,at+2816+1152*stage+128*i+8*14,2,0)
            else:changed[row+8*field]^=1
            try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,
                     backing_size=backing_size,common=common)
            except ValueError:code_refused.append(f'code{stage}_maps_{name}')
            else:raise ValueError('actual code-query provenance corruption accepted '+name)
    need(len(code_refused)==len(set(code_refused))==(24 if control==2 else 12),
         'six separate full-reader code-query provenance corruptions per used stage')
    initialized_refused=[]
    if control!=2:
        active=q(data,at+25*8)[0]
        frames=(('current_before',active,0),('current_final',active,2 if control==3 else 1),
                ('previous_before',active^1,0),('previous_after',active^1,1))
        for label,slot,frame in frames:
            offset=at+696424+slot*SLOT+512+frame*STEP
            size=q(data,offset+2*8)[0]
            for name,value in (('zero',0),('boolean',1),('short',size-1),('long',size+1)):
                changed=bytearray(data);struct.pack_into('<Q',changed,offset+3*8,value)
                try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,
                         backing_size=backing_size,common=common)
                except ValueError as error:
                    need(str(error)=='complete real generic frame mask and all65536 native FP bytes',
                         'initialized-length corruption reaches its exact complete-frame predicate')
                    initialized_refused.append(label+'_'+name)
                else:raise ValueError('actual initialized-length corruption accepted '+label+'_'+name)
    need(len(initialized_refused)==len(set(initialized_refused))==(0 if control==2 else 16),
         'four exact initialized-length corruptions per actual populated generic frame')
    return dict(original_sha256=original['whole_record_sha256'],refusals=refused,
                entry_refusals=entry_refused,maps_phase_refusals=phase_refused,
                code_maps_refusals=code_refused,initialized_refusals=initialized_refused,native_operations=0)


def configured(common):
    return SimpleNamespace(WIRE=WIRE,SIZE=SIZE,q=q,read=partial(read,common=common),
                           controls=partial(controls,common=common))
