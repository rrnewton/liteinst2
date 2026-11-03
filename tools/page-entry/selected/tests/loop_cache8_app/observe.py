"""Exact ABC169 CACHE8 observation; no old owner wire is cast to this schema.

The application/native oracle remains separate. This reader checks genuine
four-epoch membership, full native checkpoint state, and literal event/API
counter conservation. Supplied corruptions are not guest executions.
"""
import hashlib
import struct

MAGIC,FOOTER=0x314f38434132494c,0x314638434132494c
WIRE,EPOCH,MEMBER,FRAME=910368,227264,9976,66944
ROOTS=(0x410200,0x412400,0x414600,0x416000)
HEADS=((0x410200,0x410204,0x410207),(0x412400,0x412404,0x412408),
       (0x414600,0x414604,0x414608,0x41460c,0x414612,0x414616,0x41461c),
       (0x416000,0x416007))
MEMBERS=((ROOTS[0],),(ROOTS[1],),(ROOTS[2],ROOTS[0],ROOTS[1]),
         (ROOTS[3],ROOTS[0],ROOTS[1],ROOTS[2]))
ENTRIES=(1,4,7,83)
EXITS=(3,6,82,167)
NATIVE_KINDS={1:1,4:2,7:3,82:4,83:5,167:10}
COUNTERS=('events','segv','trap','ill','sys','other','publications','cold_attempts','hits',
          'offers','entries','completed','code_opens','code_revokes','code_writes','code_syncs',
          'metadata_permissions','metadata_syncs','retained_entries','cold_calls',
          'compact_build_calls','compact_validate_calls','attach_attempts','accepted','source_declines')

def need(value,why):
    if not value:raise ValueError(why)

def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)

def u(data,offset=0,count=1):return struct.unpack_from('<'+'I'*count,data,offset)

def _frame(data,app,native,model,step,event,previous_nx):
    need(type(data)is bytes and len(data)==FRAME,'whole actual fixed frame')
    h=q(data,0,16);g=q(data,128,23);si=data[312:440];uc=data[440:1408];fp=data[1408:]
    sig=11 if event else 5
    need(h[0:2]==(1,sig) and h[6]%4096==0 and h[7]==524288 and h[8]==app.MASK and
         h[9:14]==((0,0,0,0,0)if event else(1,0,0,0,0)) and h[14:]==(0,0),
         'actual frame completion, TLS observation status and exact signal stack')
    need(q(uc,40,23)==g and uc[304:432]==si and q(uc,224)[0]==h[4] and
         q(uc,16)[0]==h[6] and u(uc,24)[0]==0 and q(uc,32)[0]==h[7] and q(uc,296)[0]==app.MASK,
         'whole GREG/UC and actual Linux siginfo-mask alias')
    need(h[4]%16==0 and h[6]<=h[4]<=h[6]+h[7]-h[5] and 580<=h[5]<=65536,
         'whole actual FP storage range')
    if event:
        need(h[2]==h[3]+304 and h[6]<=h[2]<=h[6]+h[7]-128 and
             h[6]<=h[3]<=h[6]+h[7]-968,'actual preentry SI/UC physical addresses')
        for a,value in ((h[2],si),(h[3],uc),(h[4],fp[:h[5]])):
            for b,other in ((h[2],si),(h[3],uc),(h[4],fp[:h[5]])):
                lo,hi=max(a,b),min(a+len(value),b+len(other))
                if lo<hi:need(value[lo-a:hi-a]==other[lo-b:hi-b],'whole actual aliased kernel storage')
    else:
        need(h[2:4]==(0,0),'entry copy does not fabricate unretained SI/UC addresses')
    reference=native['observations'][0]['frames'][0]
    need(h[5]==reference['header'][9] and fp==reference['fp'] and
         uc[:16]==reference['uc'][:16], 'all65536 actual FP bytes and kernel context flags equal native')
    pc,expected,flags,_,_=model[step]
    need(tuple(g[i]for i in app.GREG)==expected and g[16]==pc and
         g[17]==(flags|(app.RF if event else 0)) and g[18]==0x2b000000000033 and
         g[19:21]==((21,14)if event else(0,1)) and g[21]==app.MASK and
         g[22]==(pc if event else previous_nx), 'every original GPR/flag and exact final NX or post-close entry')
    need(u(si,0,3)==(sig,0,2) and q(si,16)[0]==pc,'literal TRACE or final original NX signal')
    if step in NATIVE_KINDS:
        actual=native['observations'][0]['frames'][NATIVE_KINDS[step]]['greg']
        changed=list(actual);changed[17]=flags|(app.RF if event else 0)
        changed[19:21]=((21,14)if event else(0,1));changed[22]=pc if event else previous_nx
        need(g==tuple(changed),'whole23-register native checkpoint with exact final NX or post-close transformation')
    return dict(pc=pc,step=step,signal=sig,greg=g,fp_sha256=hashlib.sha256(fp).hexdigest())

def _key(raw,image,root,backing_size):
    need(len(raw)==8760 and q(raw)[0]==root,'whole exact source key root')
    index=ROOTS.index(root);pair=image['source_pairs'][index] if index<3 else image['reset_pair']
    base=(0x410000,0x412000,0x414000,0x416000)[index]
    result=[]
    for i in range(2):
        at=8+i*4376;identity=struct.unpack_from('<5Q4I6Q',raw,at);backing=raw[at+104:at+280]
        fd=struct.unpack_from('<i',backing)[0];seals,returned=struct.unpack_from('<qq',backing,8)
        need(identity[0]==base+4096*i and identity[1]>0 and identity[2]>0 and
             identity[3]==image['source_offsets'][index]+4096*i and identity[4]==0 and
             identity[5]==1 and identity[6]<34 and identity[7]==5 and identity[8]==1,
             'actual closed sealed executable-source identity')
        need(identity[9]<=identity[0] and identity[10]>=identity[0]+4096 and
             fd>=0 and seals==15 and returned==0 and u(backing,168,2)==(1,1),
             'actual complete retained sealed backing observation')
        need(raw[at+280:at+4376]==pair[i*4096:(i+1)*4096], 'whole actual source page equals exact application ELF')
        dev,ino=q(backing,24,2)
        need(u(backing,48)[0]&0o170000==0o100000 and q(backing,72)[0]==backing_size and
             identity[9]%4096==identity[10]%4096==identity[14]%4096==0 and
             identity[14]+identity[0]-identity[9]==identity[3] and identity[11:14]==
             ((((dev>>8)&0xfff)|((dev>>32)&0xfffff000)),((dev&255)|((dev>>12)&0xffffff00)),ino),
             'exact sealed main ELF size and complete source VMA/device/inode/offset')
        result.append(identity)
    return tuple(result)

def _epoch(raw,index,app,native,image,model,backing_size):
    need(len(raw)==EPOCH,'whole actual epoch')
    h=q(raw,0,32);count=len(MEMBERS[index]);entry=ROOTS[index]
    need(h[:5]==(1,1,1,1,entry) and h[5]>0 and h[6]==count and h[7]==0 and
         h[8]<8 and h[9]<2 and h[10]<9 and h[11]%4096==0 and h[11]>0 and
         h[12]>0 and h[13]>0 and h[14]==entry and h[16]==0,
         'literal actual cold primary and completed source-derived four-epoch geometry')
    need(h[17]<(1<<count) and h[18]>0 and h[19]==2 and h[20]==h[17] and h[21]<count and
         h[22]<8 and h[23:27]==(1,1,0,13) and h[27:]==(0,)*5,
         'exact typed completed RX lifetime, selected exit and no guest data fault')
    counters=[q(raw,256+256*i,32)for i in range(4)]
    need(all(not any(c[25:]) and c[0]==sum(c[1:6])for c in counters),
         'whole event/signal conservation and unused counter words')
    need(all(all(a<=b for a,b in zip(counters[i],counters[i+1]))for i in range(3)),
         'actual counters never reset inside observed epoch')
    before,entered,event,complete=counters
    need(entered[10]==before[10]+1 and event[10]==entered[10] and
         complete[10]==entered[10] and complete[11]==entered[11]+1,
         'actual one entry and one completed issued receipt')
    delta=tuple(b-a for a,b in zip(entered,event))
    # The persistent preentry snapshot precedes linked preentry's accounting
    # of this final NX. Completion follows that exact event-counter update.
    need(delta[:6]==(0,0,0,0,0,0) and all(delta[i]==0 for i in tuple(range(6,16))+tuple(range(18,25))),
         'zero interior signals and zero plan/publication/code-permission operations before final-event accounting')
    need(tuple(b-a for a,b in zip(event[:6],complete[:6]))==(1,1,0,0,0,0),
         'exactly one final NX counted after preentry and before completion')
    members=[]
    for i in range(8):
        value=raw[1280+i*MEMBER:1280+(i+1)*MEMBER]
        if i>=count:
            need(value==bytes(MEMBER),'whole unused member capacity zero');continue
        m=q(value,0,24);root=MEMBERS[index][i];which=ROOTS.index(root);heads=HEADS[which]
        need(m[0]==1 and m[1]<8 and m[2]<2 and m[3]>0 and m[4]>0 and m[5]==root and
             m[6]>0 and m[6]%4096==0 and m[7]==11 and m[8]==len(heads) and
             m[9]==(3 if which==2 else 1) and m[10]==0 and m[11]==root and
             m[18:22]==(m[3],1,1,1) and m[22:]==(0,0),
             'actual immutable PF member, full generation and original head/boundary dimensions')
        need(all(x>0 and x%4096==0 for x in m[12:18]) and m[17]==h[11],
             'whole actual member layout and shared sealed directory')
        need(q(value,8952,128)==heads+(0,)*(128-len(heads)), 'every original head and whole unused head capacity')
        identity=_key(value[192:8952],image,root,backing_size)
        members.append(dict(words=m,root=root,key=value[192:8952],heads=heads,source_identity=identity))
    need(len({m['words'][1]for m in members})==count and len({m['words'][3]for m in members})==count,
         'all simultaneously live members have distinct slots and generations')
    primary=members[0]['words'];need(h[8:10]==primary[1:3] and h[12:14]==primary[3:5] and h[15]==primary[12],
         'actual entry belongs to the genuine primary publication')
    directory=raw[81088:93376];n=sum(len(m['heads'])for m in members)
    need(q(directory,0,4)==(1,n,h[5],0),'complete sealed dispatch directory header')
    rows=[struct.unpack_from('<QQQII',directory,32+32*i)for i in range(n)]
    expected=[]
    for m in members:
        w=m['words']
        expected.extend((pc,w[12+j//64]+512*(j%64),w[3],w[1],j)for j,pc in enumerate(m['heads']))
    need(rows==expected and directory[32+32*n:]==bytes(12288-32-32*n),
         'whole exact member/head-order original/generated/generation dispatch directory')
    previous=(0x4101fe,0x410207,0x412408,0x414616)[index]
    entry_frame=_frame(raw[93376:160320],app,native,model,ENTRIES[index],False,previous)
    exit_frame=_frame(raw[160320:],app,native,model,EXITS[index],True,0)
    need(members[h[21]]['root']==(ROOTS[index]if index<3 else ROOTS[2]),
         'actual final event selected the exact member that owns original exit')
    return dict(header=h,counters=counters,members=members,entry=entry_frame,event=exit_frame,
                interior_events=0,original_instructions=EXITS[index]-ENTRIES[index])

def read(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size):
    need(type(data)is bytes and len(data)==WIRE+64 and type(control)is int and control in(0,1) and
         type(pid)is int and pid>0 and type(uid)is int and uid>=0,'whole actual typed CACHE8 wire/process')
    need(type(backing_size)is int and backing_size>0,'actual sealed carrier backing size authority')
    need(native['header'][5]==1 and len(native['observations'][0]['frames'])==12,
         'complete previously validated actual native ABC169 reference')
    h=q(data,0,32);footer=q(data,WIRE,8);status,code=(0,0)if control==0 else(125,3303)
    need(exit_status==status and footer[:4]==(FOOTER,1,WIRE,WIRE) and
         1<=footer[4]<=64 and 0<footer[5]<=WIRE and footer[6:]==(status,code),
         'complete real record write and literal subject outcome')
    need(h[:9]==(MAGIC,1,WIRE,EPOCH,control,8,8,9,4) and h[9]>0 and h[10]>0 and
         h[11]==0 and h[12]&0o6003==1 and h[13]==0 and h[14]%4096==0 and h[15]==524288,
         'exact independent CACHE8 ABI and original fresh writable sink')
    controls=24 if control else 0
    need(h[16:24]==(4,0,0,0,controls,controls,status,code) and
         h[24:28]==((0,0,0,0)if control==0 else(3303,8971,1,1)) and
         h[28:]==(h[12],0,pid,pid), 'all four completions, restored actual controls and exact abort chronology')
    initial,terminal=data[256:400],data[400:544]
    need(initial[:40]==terminal[:40] and q(initial,16)[0]==1 and
         u(initial,24,2)==(0o100600,uid) and q(initial,48)[0]==q(terminal,48)[0]==0,
         'same untouched private regular record inode before first write')
    model=app.trace_model(native)
    epochs=[_epoch(data[544+i*EPOCH:544+(i+1)*EPOCH],i,app,native,image,model,backing_size)for i in range(4)]
    need(all(epochs[i]['header'][5]<epochs[i+1]['header'][5] and
             epochs[i]['header'][18]<epochs[i+1]['header'][18]for i in range(3)),
         'actual distinct serial and completion chronology')
    for i in range(3):
        need(all(a<=b for a,b in zip(epochs[i]['counters'][3],epochs[i+1]['counters'][0])),
             'all inter-activation work remains in monotonically increasing counters')
    earlier={m['root']:m for m in epochs[2]['members']}
    later={m['root']:m for m in epochs[3]['members']}
    for root in ROOTS[:3]:
        a,b=earlier[root],later[root]
        need(a['words']==b['words'] and a['key']==b['key'] and a['heads']==b['heads'],
             'second genuine ABC activation reuses every exact original generation/build/source/layout')
    results=[q(data,909600+32*i,4)for i in range(24)]
    need(results==([(i,0,0,1)for i in range(24)]if control else[(0,0,0,0)]*24),
         'literal24 actual refusals with complete restoration or whole unused control array')
    if control==0:
        need(gated is not None,'actual full gated application output is required')
        pair=app.application_pair(native,gated)
        need(pair==dict(full_application_state_equal=True,interior_owner_state_observed=False),
             'whole original native/gated state comparator')
    else:
        need(gated is None,'causal terminal prefix cannot claim whole application completion')
        pair=None
    return dict(schema=1,control=control,epochs=4,active_members=[1,1,3,4],
        intervals=[dict(entry=e['entry']['pc'],exit=e['event']['pc'],
            original_instructions=e['original_instructions'],events=1,final_nx=1,interior_signals=0,
            code_permission_operations=0,publications=0,planning_operations=0)for e in epochs[2:]],
        native_pair=pair,actual_refusals=controls,actual_restorations=controls,
        whole_record_sha256=hashlib.sha256(data).hexdigest(),qualification_credit=False,
        source_writer_exercised=False,guest_private_entry_exercised=False)


def controls(data,app,native,image,pid,uid,control,exit_status,gated=None,*,backing_size):
    original=read(data,app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
    tests=[('wire_version',8),('member_capacity',6*8),('record_pid',30*8),('completion_count',16*8),
           ('actual_refusal_count',20*8),('actual_sink_inode',256+8),('footer_outcome',WIRE+48)]
    for i in range(4):
        at=544+i*EPOCH
        tests.extend((f'epoch{i}_{name}',at+offset)for name,offset in(
            ('complete',24),('entry',32),('serial',40),('members',48),('typed_RX',19*8),
            ('event_count',256+2*256),('trap_count',256+2*256+2*8),
            ('publication',256+2*256+6*8),('code_open',256+2*256+12*8),
            ('compact_validate',256+2*256+21*8),('directory',81088+32),
            ('entry_GPR',93376+128+13*8),('event_GPR',160320+128+13*8),
            ('event_PC',160320+128+16*8),('event_FP',160320+1408+160)))
    for index in(2,3):
        at=544+index*EPOCH+1280+2*MEMBER
        tests.extend((f'third{index}_{name}',at+offset)for name,offset in(
            ('generation',3*8),('build_serial',4*8),('root',5*8),('source_identity',192+8+16),
            ('source_first',192+8+280),('source_second',192+8+4376+280),('head',8952)))
    if control:tests.extend((f'actual_restoration{i}',909600+i*32+24)for i in range(24))
    need(len(tests)==(105 if control else 81) and len({x[0]for x in tests})==len(tests),
         'literal full-reader supplied mutation roster')
    refused=[]
    for name,offset in tests:
        changed=bytearray(data);changed[offset]^=1
        try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
        except ValueError:refused.append(name)
        else:raise ValueError('actual CACHE8 corruption accepted '+name)
    if control:
        for field,offset in (('active',26*8),('busy',27*8)):
            for invalid in (0,2):
                changed=bytearray(data);struct.pack_into('<Q',changed,offset,invalid)
                try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
                except ValueError:refused.append('abort_'+field+'_'+str(invalid))
                else:raise ValueError('actual stopped abort state corruption accepted')
    need(len(refused)==(109 if control else 81),'all original controls plus four exact abort-state refusals')
    phase_refused=[]
    for i in range(4):
        event=544+i*EPOCH+256+2*256;complete=event+256
        for kind in range(1,6):
            # Keep each counter snapshot's total equal to its signal sum.
            # Preserve the final delta while inserting one interior signal.
            changed=bytearray(data)
            for at in (event,complete):
                for word in (0,kind):
                    struct.pack_into('<Q',changed,at+8*word,q(data,at+8*word)[0]+1)
            try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
            except ValueError as error:
                need(str(error)=='zero interior signals and zero plan/publication/code-permission operations before final-event accounting',
                     'interior phase corruption reaches its exact full-reader predicate')
                phase_refused.append(f'epoch{i}_interior_{COUNTERS[kind]}')
            else:raise ValueError('interior phase corruption accepted')
            # Remove the final NX, or replace it with one other signal class;
            # all snapshots still satisfy conservation and monotonicity.
            changed=bytearray(data)
            struct.pack_into('<Q',changed,complete+8,q(data,complete+8)[0]-1)
            if kind==1:
                struct.pack_into('<Q',changed,complete,q(data,complete)[0]-1)
            else:
                struct.pack_into('<Q',changed,complete+8*kind,q(data,complete+8*kind)[0]+1)
            try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
            except ValueError as error:
                need(str(error)=='exactly one final NX counted after preentry and before completion',
                     'final phase corruption reaches its exact full-reader predicate')
                phase_refused.append(f'epoch{i}_final_{COUNTERS[kind]}')
            else:raise ValueError('final phase corruption accepted')
    need(len(phase_refused)==len(set(phase_refused))==40,'all40 separate coherent phase-counter corruptions refused')
    backing_refused=[]
    # The sealed source is the carrier, whose complete bytes were authenticated
    # by the collector; the application oracle still uses the original ELF.
    for i,roots in enumerate(MEMBERS):
        for member in range(len(roots)):
            for page in range(2):
                at=544+i*EPOCH+1280+member*MEMBER+192+8+page*4376+104+72
                changed=bytearray(data)
                struct.pack_into('<Q',changed,at,q(data,at)[0]+1)
                try:read(bytes(changed),app,native,image,pid,uid,control,exit_status,gated,backing_size=backing_size)
                except ValueError as error:
                    need(str(error)=='exact sealed main ELF size and complete source VMA/device/inode/offset',
                         'each actual backing-size mutation reaches its source identity predicate')
                    backing_refused.append(f'epoch{i}_member{member}_page{page}_backing_size')
                else:raise ValueError('actual backing size corruption accepted')
    for label,size in (('original_ELF_size',image['bytes']),('wrong_carrier_size',backing_size+1)):
        need(size!=backing_size,'distinct external backing-size authority mutation')
        try:read(data,app,native,image,pid,uid,control,exit_status,gated,backing_size=size)
        except ValueError as error:
            need(str(error)=='exact sealed main ELF size and complete source VMA/device/inode/offset',
                 'external backing-size mutation reaches its source identity predicate')
            backing_refused.append(label)
        else:raise ValueError('wrong backing-size authority accepted')
    need(len(backing_refused)==len(set(backing_refused))==20,'all eighteen backing records and two external size authorities refused')
    return dict(original_sha256=original['whole_record_sha256'],refusals=refused,native_operations=0,
                phase_refusals=phase_refused,backing_refusals=backing_refused)
