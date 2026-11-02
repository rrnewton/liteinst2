"""Strict finite effects13 native-wire reader; never execution authority.

The C oracle validates each emitted plan and actual protected-spill recovery.
This reader independently checks whole source, typed plan/image associations,
all original histories, every generated boundary association, complete terminal
state and zero tails. Spill words are not serialized: recovery of dirty scratch
registers remains an explicit C-oracle assertion, not a fabricated observation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location(__name__+'_old_state',HERE.parent/'scalar_span/check.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
need,q,u,seed_fp,live=old.need,old.q,old.u,old.seed_fp,old.live
_spec=importlib.util.spec_from_file_location(__name__+'_tables',HERE.parent/'persistent_direct_frontier_owner/plan.py')
independent=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(independent)
_spec=importlib.util.spec_from_file_location(__name__+'_direct',HERE.parent/'persistent_loop_owner/direct_model.py')
direct=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(direct)
P,FP,DATA,STACK=4096,65536,8192,160
TF,RF,U64=0x100,0x10000,(1<<64)-1
MASK=U64^sum(1<<(s-1)for s in(11,5,31,9,19))
REGS=old.REGS
OBS,STATE,BOUNDARY,COMPACT,GUARD=271744,8496,176,353608,6488
SOURCE_AT,IMAGE_AT,GUARD_AT,COMPACT_AT,HISTORY_AT,TRACE_AT,OBS_AT=2016,10208,79840,86328,439936,2614912,3335808
WIRE=4151040
NATIVE_MODES=40
FAULTS=(24,25,26,27)
OLD_METADATA=b'{"schema":1,"store_codes":4,"descriptors":704,"byte_models":3272,"refusals":15,"corruptions":19,"interval_edges":465,"max_tree_height":8,"postseal_equal":1,"emitted_instruction_execution":0}\n'
META_FIXED=dict(schema=1,descriptor_version=3,byte_guard_version=2,byte_descriptors=390,byte_models=1162,
    byte_refusals=30,byte_corruptions=17,interval_edges=426,imul_descriptors=240,imul_refusals=32,
    scalar_legacy=9,postseal_equal=1,instruction_execution=0,owner_execution=0)

def digest(b):return hashlib.sha256(b).hexdigest()
def zero(b,why):need(not any(b),why)
def physical(x):return x&~(TF|RF)
def row(raw):
    def unique(pairs):
        out={}
        for key,value in pairs:need(key not in out,'duplicate JSON field');out[key]=value
        return out
    need(type(raw)is bytes and 0<len(raw)<=4096,'bounded whole stdout row')
    value=json.loads(raw,object_pairs_hook=unique)
    need(type(value)is dict and json.dumps(value,separators=(',',':'),allow_nan=False).encode()+b'\n'==raw,'one canonical JSON row')
    return value

def exact(actual,expected,why):
    need(type(actual)is type(expected),why+' type')
    if type(expected)is dict:
        need(actual.keys()==expected.keys(),why+' fields')
        for k in expected:exact(actual[k],expected[k],why+'.'+k)
    elif type(expected)in(list,tuple):
        need(len(actual)==len(expected),why+' count')
        for a,b in zip(actual,expected,strict=True):exact(a,b,why)
    else:need(actual==expected,why)

def metadata(stdout,stderr,status):
    need(type(status)is int and status==0 and stderr==b'' and stdout.startswith(OLD_METADATA),'whole mandatory original MOV oracle and exit')
    value=row(stdout[len(OLD_METADATA):]);fixed={k:v for k,v in value.items()if k not in('recovery_checks','interior_refusals')}
    exact(fixed,META_FIXED,'all additive metadata populations')
    need(set(value)==set(META_FIXED)|{'recovery_checks','interior_refusals'}and all(type(value[k])is int and 0<value[k]<1000000 for k in('recovery_checks','interior_refusals')),'actual bounded decoder-free boundary census')
    return dict(old_mov=row(OLD_METADATA),effects=value)

def fixture(mode,sp):
    bank=0x10000000;data=bank+0xc0000;pc=bank+256
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)];seed[4]=sp
    need(4096<=sp<1<<47 and sp%16==8,'actual guarded guest stack pointer')
    ea=data+128;fault=mode in FAULTS
    if fault:ea=data+P
    dst=src=None;iterations=0
    if mode<16:
        raw=(bytes((0x40|(4 if mode>=8 else 0),))if mode>=4 else b'')+bytes((0x88,0x47|((mode&7)<<3),0xff));seed[7]=ea+1;value=seed[mode]&255
    elif mode<20:
        value=(0,1,128,255)[mode-16];raw=bytes((0xc6,0,value));seed[0]=ea
    elif mode==20:
        raw=bytes.fromhex('47887c88f0');seed[8]=ea+4;seed[9]=3;value=seed[15]&255
    elif mode in(21,26):raw=b'\x88\x15'+struct.pack('<i',ea-pc-6);value=seed[2]&255
    elif mode==22:raw=b'\xc6\x04\x25'+struct.pack('<I',ea)+b'\xcc';value=0xcc
    elif mode==23:ea=data+P-1;seed[0]=ea;raw=b'\xc6\x00\xcc';value=0xcc
    elif mode==24:raw=b'\x88\x07';seed[7]=ea;value=seed[0]&255
    elif mode==25:raw=b'\xc6\x00\xcc';seed[0]=ea;value=0xcc
    elif mode==27:raw=b'\x88\x00';seed[0]=ea;value=ea&255
    elif mode<36:
        k=mode-28;dst=(0,0,0,0,8,8,9,0)[k];src=(6,6,6,6,15,15,9,4)[k]
        seed[dst]=(0,1,U64,1<<63,(1<<63)-1,U64,(1<<63)+1,3)[k]
        if src!=dst and src!=4:seed[src]=(U64,U64,U64,U64,2,2,0,0)[k]
        raw=bytes((0x48|(4 if dst>=8 else 0)|(1 if src>=8 else 0),15,0xaf,0xc0|((dst&7)<<3)|(src&7)));value=None
    elif mode<38:
        iterations=17 if mode==36 else 1;raw=bytes.fromhex('c600cc4883c0014839c275f4');seed[0]=data;seed[2]=data+iterations;value=0xcc
    else:
        iterations=17 if mode==38 else 1
        raw=bytes.fromhex('89d04883c101480fafc648c1e8278d44020183c2118841ff81fa')+struct.pack('<I',17*iterations)+bytes.fromhex('75e0')
        seed[1]=data;seed[2]=0;seed[6]=0x80808081;value=None
    source=bytearray(b'\xcc'*8192);source[256:256+len(raw)]=raw
    memory=bytes(1+(i*17)%255 for i in range(DATA));stack=bytes((i*29+7)&255 for i in range(STACK));after=bytearray(memory)
    if mode<28 and not fault:after[ea-data]=value
    elif mode>=36:
        for i in range(iterations):after[i]=0xcc if mode<38 else 1+(17*i)%255
    offsets=(0,3,7,10)if mode in(36,37)else(0,2,6,10,14,18,21,24,30)if mode>=38 else(0,len(raw))
    terminal=pc+len(raw)-(2 if iterations else 0)
    if fault:path=(pc,)
    elif not iterations:path=(pc,terminal)
    else:path=tuple(pc+off for _ in range(iterations)for off in offsets)
    return dict(seed=tuple(seed),source=bytes(source),raw=raw,memory=memory,stack=stack,after=bytes(after),ea=ea,
        iterations=iterations,path=path,offsets=offsets,terminal=terminal,dst=dst,src=src)

def frame(data,mask):
    need(len(data)==65792,'exact signal frame ABI');g=q(data,0,23);m,address,count,initialized=q(data,184,4)
    need(m==mask and initialized==count and 580<=count<=FP and 4096<=address<1<<47 and address%16==0,'complete actual frame extent/mask/address')
    zero(data[216:256],'frame padding');fp=data[256:];zero(fp[count:],'unused whole kernel FP tail')
    need(u(fp,464,2)==(0x46505853,count)and u(fp,480)[0]==count-4 and u(fp,count-4)[0]==0x46505845 and q(fp,520)[0]==0,'whole standard kernel FP header/footer')
    return dict(g=g,mask=m,address=address,count=count,fp=fp)

def observation(raw,h,f,layout,lane):
    need(len(raw)==OBS,'whole aligned observation')
    before,after=live(raw[:152]),live(raw[152:304]);xb,xa=raw[304:65840],raw[65840:131376]
    zero(raw[131376:131392],'observation frame alignment');zero(raw[271712:],'observation alignment tail')
    ent,end=frame(raw[131392:197184],MASK),frame(raw[197184:262976],MASK)
    si,se=raw[262976:263104],raw[263104:263232];memory,stack=raw[263232:271424],raw[271424:271584];m=q(raw,271584,16)
    fault=h[16];rawpc=h[14]if fault and lane else h[11]if fault else h[12]
    traces=h[18]-1 if lane==0 else h[19]-1 if lane==1 and fault else h[19]+1 if lane==1 else 0
    need(m[:4]==(lane,2 if lane==2 and not fault else 1,traces,fault)and m[4:7]==m[7:10]and m[6]==MASK and
         m[10:]==(rawpc,h[11]if fault else h[12],h[18],h[19]if lane==1 else 0,0,0),'all actual lane event and cleanup fields')
    need(before[0]==f['seed']and before[1]==h[31]and before[2]==after[2]and after[1]==physical(end['g'][17]),'whole before/after live state and physical flags')
    need(xb==xa and ent['fp']==end['fp']and ent['count']==end['count'],'whole live and signal FP equality')
    for fp in(xb,xa,ent['fp'],end['fp']):seed_fp(fp,layout,h[9])
    need(memory==f['after']and stack==f['stack'],'whole exact final8192data160stack')
    eg,gg=ent['g'],end['g'];selectors=struct.unpack('<6H',before[2]);cs,ss,ds,es,fs,gs=selectors
    need(tuple(eg[r]for r in REGS)==f['seed']and eg[16:]==(h[11],h[31]|RF,cs|(gs<<16)|(fs<<32)|(ss<<48),21,14,MASK,h[11]),'all entry registers/selectors/NX metadata')
    need(u(si,0,3)==(11,0,2)and q(si,16)[0]==h[11],'actual original NX siginfo')
    need(tuple(gg[r]for r in REGS)==after[0]and gg[16]==rawpc and gg[18]==eg[18]and gg[21]==MASK and
         gg[17]==after[1]|(TF if lane<2 else 0)|(RF if fault or lane==2 else 0),'all final GPR/physical flags/selector association')
    if fault:need(gg[19:21]==(6 if h[17]==0 else 7,14)and gg[22]==f['ea']and u(se,0,3)==(11,0,2)and q(se,16)[0]==f['ea'],'genuine unchanged one-byte write fault')
    elif lane==2:need(gg[19:21]==(21,14)and gg[22]==h[12]and u(se,0,3)==(11,0,2)and q(se,16)[0]==h[12],'actual generated terminal original-NX stop')
    else:need(gg[19:21]==(0,1)and gg[22]==h[11]and u(se,0,3)==(5,0,2),'actual terminal TRACE stop')
    return dict(before=before,after=after,xb=xb,xa=xa,entry=ent,end=end,entry_si=si,exit_si=se,data=memory,stack=stack,meta=m)

# Fixed common compact offsets, derived from the exact C ABI in this recipe.
HEAD,ORIGINAL,FRONTIER,INSTRUCTION,EXIT,EDGE,TABLE,RECORD=77960,82056,125064,127752,146184,146248,146632,150856

def boundaries(record,code,kind):
    v,ready,status,n,count,a,b,reserved=u(record,0,8);scratch=u(record,32,4)
    need(v==(2 if kind==4 else 1)and ready==1 and status==reserved==0 and 0<n<=512 and 0<count<=64 and
         scratch[0]==0 and len(set(scratch))==4 and all(r<16 and r!=4 for r in scratch),'typed immutable guard record')
    rows=[u(record,48+24*i,6)for i in range(count)];zero(record[48+24*count:],'all inactive guard recovery rows')
    need(rows[0][0]==0 and all(off+length<=n and 1<=length<=15 and valid<=15 and dirty&~valid==0 and flags<=2 and phase<=(3 if kind==4 else 1)
        for off,length,valid,dirty,flags,phase in rows),'complete bounded typed recovery rows')
    need(all(x[0]+x[1]==y[0]for x,y in zip(rows,rows[1:]))and rows[-1][0]+rows[-1][1]==n,'every generated instruction byte classified once')
    need(a<n and b<n and any(x[0]==a for x in rows)and any(x[0]==b for x in rows),'exact typed special instruction offsets')
    if kind==4:need(rows[-1][0]==b and rows[-1][5]==3 and code[b:b+2]==b'\x0f\x0b'and any(x[0]==a and x[5]==1 for x in rows),'store and rejected no-effect boundaries')
    zero(code[n:],'whole unused generated slot tail')
    return n,rows,scratch

def byte_plan(pc,window,raw,generated,spill,successor,table):
    """Independent finite byte encoding plus the old37-row MOV state schedule."""
    op=int(0x40<=raw[0]<=0x4f);rex=raw[0]if op else 0;modrm=raw[op+1];mod=modrm>>6;rm=modrm&7
    immediate=raw[op]==0xc6;source_reg=16 if immediate else((modrm>>3)&7)+(8 if rex&4 else 0)
    base=rm+(8 if rex&1 else 0);index=16;scale=1;at=op+2;rip=0
    if rm==4:
        sib=raw[at];at+=1;scale=1<<(sib>>6);ix=(sib>>3)&7;index=16 if ix==4 and not rex&2 else ix+(8 if rex&2 else 0)
        base=(sib&7)+(8 if rex&1 else 0)
        if mod==0 and sib&7==5:base=16
    elif mod==0 and rm==5:base=16;rip=1
    size=1 if mod==1 else 4 if mod==2 or base==16 else 0;displacement_at=at if size else 0
    displacement=int.from_bytes(raw[at:at+size],'little',signed=True)if size else 0;at+=size
    need(at+int(immediate)==len(raw),'finite complete byte encoding')
    target=(pc+len(raw)+displacement)&U64 if rip else 0
    description=struct.pack('<QQ6I',pc,pc+len(raw),1,1,401 if immediate else 279,len(raw),1,1)
    description+=window+bytes(16-len(window))+struct.pack('<3Q',target if rip else displacement&U64,target,raw[-1]if immediate else 0)
    description+=struct.pack('<16I',2,1,0,len(window),1,2 if immediate else 1,source_reg,base,index,scale,rip,displacement_at,size,op+1,op,0)
    blocked={0,4,12,base,index,source_reg};scratch=(0,*[r for r in range(1,16)if r not in blocked][:3]);a,e,t=scratch[1:]
    save=lambda r:bytes((0x48|((r>>3)<<2),0x89,5|((r&7)<<3)))+bytes(4)
    load=lambda r:bytes((0x48|((r>>3)<<2),0x8b,5|((r&7)<<3)))+bytes(4)
    rr=lambda code,r,b:bytes((0x48|((r>>3)<<2)|(b>>3),code,0xc0|((r&7)<<3)|(b&7)))
    mem=lambda code,r,b,d:bytes((0x48|((r>>3)<<2)|(b>>3),code,0x40|((r&7)<<3)|(b&7),d))
    branch=lambda c:b'\xe9'+bytes(4)if c==16 else bytes((15,128+c))+bytes(4)
    end=len(raw)-int(immediate);ea=bytearray(bytes((0x48|((a>>3)<<2)|(rex&3),0x8d))+raw[op+1:end]);ea[2]=(ea[2]&0xc7)|((a&7)<<3)
    restore=[b'\x04\x7f',b'\x9e',load(a),load(e),load(t),load(0)]
    pieces=[save(r)for r in scratch]+[bytes(ea),b'\x9f',b'\x0f\x90\xc0',bytes((0x48|(t>>3),0xb8+(t&7)))+struct.pack('<Q',q(table,24)[0]),
        mem(0x8d,e,a,1),rr(0x3b,e,a),branch(6),rr(0x85,t,t),branch(4),mem(0x3b,e,t,0),branch(6),mem(0x3b,a,t,8),branch(3),branch(16),
        mem(0x8b,t,t,16),branch(16),mem(0x8b,t,t,24),branch(16)]+restore+[raw,branch(16)]+restore+[b'\x0f\x0b']
    states=((0,0,0,0),(1,0,0,0),(3,0,0,0),(7,0,0,0),(15,0,0,0),(15,2,0,0),(15,3,1,0),(15,3,2,0),(15,11,2,0))+((15,15,2,0),)*14+(
        (15,15,1,0),(15,15,0,0),(15,13,0,0),(15,9,0,0),(15,1,0,0),(15,0,0,1),(15,0,0,2),(15,15,2,0),(15,15,1,0),(15,15,0,0),
        (15,13,0,0),(15,9,0,0),(15,1,0,0),(15,0,0,3))
    need(len(pieces)==len(states)==37,'independent full byte guard boundary schedule')
    offsets=[];n=0
    for piece in pieces:offsets.append(n);n+=len(piece)
    image=bytearray(b''.join(pieces))
    def rel(i,target):
        end=offsets[i]+len(pieces[i]);image[end-4:end]=struct.pack('<i',target-generated-end)
    for i in range(4):rel(i,spill+8*i)
    for first in(24,32):
        for j,slot in enumerate((1,2,3,0)):rel(first+j,spill+8*slot)
    for i,target_index in((10,30),(12,22),(14,18),(16,20),(17,30),(19,11),(21,11)):rel(i,generated+offsets[target_index])
    rel(29,successor)
    if rip:
        ea_at=2+displacement_at-(op+1);image[offsets[4]+ea_at:offsets[4]+ea_at+4]=struct.pack('<i',target-generated-offsets[4]-len(pieces[4]))
        image[offsets[28]+displacement_at:offsets[28]+displacement_at+4]=struct.pack('<i',target-generated-offsets[28]-len(raw))
    rows=b''.join(struct.pack('<6I',off,len(piece),*state)for off,piece,state in zip(offsets,pieces,states,strict=True))+bytes(27*24)
    header=struct.pack('<8I',2,1,0,len(image),37,offsets[28],offsets[36],0)
    record=header+struct.pack('<4I',*scratch)+rows
    whole=header+struct.pack('<3Q',generated,spill,successor)+struct.pack('<4I',*scratch)+description+table+rows+image+bytes(512-len(image))
    need(len(description)==144 and len(record)==1584 and len(whole)==GUARD,'independent complete BMG descriptor/record/plan')
    return bytes(whole),record,bytes(image),description

def loop_descriptions(f,h):
    ins,reg,imm=independent.ins,independent.reg,independent.imm
    arith=(0,0x8d5,0,0,0);raw=f['raw'];pc=h[11]
    branch=lambda at:ins(raw[at:at+2],176,((pc,4,0,64,1,8,0),),(64,0,0,0,0),flow=1,target=pc,condition=5)
    if h[3]<38:
        rows=(ins(raw[:3],401),ins(raw[3:7],249,(reg(0,64,3),imm(1,64,8)),arith),
              ins(raw[7:10],110,(reg(0,64,1),reg(2,64,1)),arith),branch(10))
        store=0
    else:
        rows=(ins(raw[:2],281,(reg(0,32,2),reg(2,32,1)),step=1),
            ins(raw[2:6],249,(reg(1,64,3),imm(1,64,8)),arith),
            ins(raw[6:10],2072,(reg(0,64,3),reg(6,64,1)),(0,0x801,0,0,0xd4)),
            ins(raw[10:14],384,(reg(0,64,3),imm(39,8,8)),(0,0xc5,0,0,0x810)),
            ins(raw[14:18],291,(reg(0,32,2),(0,5,0,64,7,0,0)),address=(1,2,0,1,0,64,0,7,0)),
            ins(raw[18:21],248,(reg(2,32,3),imm(17,32,8)),arith),ins(raw[21:24],279),
            ins(raw[24:30],237,(reg(2,32,1),imm(17*f['iterations'],32,32)),arith),branch(30))
        store=6
    result=[]
    for i,(row,off)in enumerate(zip(rows,f['offsets'],strict=True)):
        value=bytearray(independent.descriptor(row,pc+off,f['source'],256+off,refusal=int(i==store)))
        if h[3]>=38 and i==2:struct.pack_into('<I',value,256,3)
        result.append(bytes(value))
    return result

def plans(record,h,f):
    guard=record[GUARD_AT:COMPACT_AT];compact=record[COMPACT_AT:HISTORY_AT];image=record[IMAGE_AT:GUARD_AT]
    bank=h[10];ranges=((bank,bank+2*P),(bank+0x10000,bank+0x21000),(bank+0x40000,bank+0xa3000),(bank+0xb0000,bank+0xb1000),(bank+0xb1000,bank+0xb2000))
    table=independent.table(ranges,bank+0x40000+(TABLE if h[7]==2 else 0))
    need(bank==0x10000000 and h[11]==bank+256 and h[13]==bank+0x10000,'fixed actual isolated native bank')
    out={};heads=interiors=0
    if h[7]==0:
        need(u(guard,0,3)==(2,1,0)and q(guard,32,3)==(h[13],bank+0xb0000,h[12]),'actual BMG2 plan addresses/version')
        expected,_,_,_=byte_plan(h[11],f['raw'],f['raw'],h[13],bank+0xb0000,h[12],table)
        need(guard==expected,'all6488 independent BMG2 plan bytes')
        desc=guard[72:216];need(q(desc,0,2)==(h[11],h[11]+len(f['raw']))and u(desc,16,6)==(1,1,401 if f['raw'][-len(f['raw']):][0]==0xc6 else 279,len(f['raw']),1,1), 'exact byte-store TF description')
        # Optional REX is part of the literal original source, never discarded.
        op=1 if 0x40<=f['raw'][0]<=0x4f else 0;code=401 if f['raw'][op]==0xc6 else 279
        need(u(desc,24)[0]==code and desc[40:56]==f['raw']+bytes(16-len(f['raw']))and u(desc,80,5)==(2,1,0,len(f['raw']),1)and not u(desc,140)[0],'whole original bytes, exact width1 and descriptor domain')
        rec=guard[:32]+guard[56:72]+guard[4440:5976]
        need(image[:u(guard,12)[0]]==guard[5976:5976+u(guard,12)[0]]and image[u(guard,12)[0]:]==b'\xcc'*(len(image)-u(guard,12)[0]),'whole native emitted image and CC padding')
        n,rows,scratch=boundaries(rec,guard[5976:],4);need(h[14]==h[13]+u(guard,20)[0],'actual guarded STORE fault PC')
        zero(compact,'inactive LOOP compact');heads=len(rows);interiors=n-heads
        for off,length,valid,dirty,flags,phase in rows:out[h[13]+off]=(h[12]if phase==2 else h[11],phase,4,valid,dirty,flags,scratch)
    elif h[7]==1:
        zero(guard,'inactive BMG plan');zero(compact,'inactive LOOP compact')
        want=f['raw']+b'\xe9'+struct.pack('<i',h[12]-h[13]-9)
        need(image==want+b'\xcc'*(len(image)-len(want)),'actual copied IMUL and exact original-next E9')
        out[h[13]]=(h[11],0,1,0,0,0,());out[h[13]+4]=(h[12],2,1,0,0,0,());heads,interiors=2,7
    else:
        zero(guard,'inactive standalone BMG plan');count=len(f['offsets']);source=record[SOURCE_AT:IMAGE_AT]
        need(u(compact,0,16)==(13,COMPACT,1,0,count,1,1,len(f['raw']),1,0,0,0,count,0,0,0)and
            q(compact,64,9)==(bank,bank+P,h[11],bank+0x10000,bank+0x18000,bank+0x20000,bank+0xb1000,bank+0xb0000,bank+0xa0000),'whole LPE13 canonical header/layout')
        need(compact[136:8328]==source and compact[8328:HEAD]==image,'entire retained source and both images/stub')
        zero(compact[HEAD+count*32:ORIGINAL],'unused heads');zero(compact[ORIGINAL+count*336:FRONTIER],'unused original descriptors')
        descriptions=loop_descriptions(f,h)
        need(compact[ORIGINAL:ORIGINAL+count*336]==b''.join(descriptions),'every complete independent canonical source descriptor')
        need(compact[FRONTIER:INSTRUCTION]==descriptions[-1]+bytes(7*336),'one exact original branch-before frontier');zero(compact[INSTRUCTION+count*144:EXIT],'unused instructions')
        need(q(compact,EXIT,8)==(h[12],0,0,0,0,0,0,0),'original branch-before terminal, no synthetic target')
        zero(compact[EDGE:TABLE],'no capacity links');need(compact[TABLE:RECORD]==table,'complete independent merged exclusion table');zero(compact[RECORD+count*1584:],'unused compact guard union')
        for j,off in enumerate(f['offsets']):
            last=j==count-1;store=(j==0 if count==4 else j==6);kind=5 if last else 2 if store else 1
            length=(f['offsets'][j+1]-off)if not last else 2;head=u(compact,HEAD+32*j,8);n=head[7]
            need(head[:7]==(kind,0,256+off,length,2 if last else 1,0 if last else j+1,128 if last else 0),'whole source-derived loop BFS/head/successor')
            original=compact[ORIGINAL+336*j:ORIGINAL+336*(j+1)];need(q(original,0,2)==(h[11]+off,h[11]+off+length)and u(original,16)[0]==1 and u(original,20)[0]==0 and u(original,44,3)==(15,length,0)and original[56:72]==source[256+off:271+off]+b'\0','complete source-owned decode header/window')
            need(u(original,256)[0]==(3 if count==9 and j==2 else 1)and (u(original,260,2)==(0,1)if store else u(original,260,2)==(1,0)),'exact old/refused/new canonical descriptor domain')
            code=image[j*512:(j+1)*512];rec=compact[RECORD+1584*j:RECORD+1584*(j+1)]
            if kind==1:
                zero(compact[INSTRUCTION+j*144:INSTRUCTION+(j+1)*144],'NONE instruction union');zero(rec,'NONE guard union')
                want=source[256+off:256+off+length]+b'\xe9'+struct.pack('<i',512-length-5)
                need(n==len(want)and code==want+b'\xcc'*(512-len(want)),'whole copied scalar bytes and exact next slot')
                rows=[(0,length,0,0,0,0),(length,5,0,0,0,2)];scratch=();mapkind=1
            else:
                mapkind=4 if store else 8
                got,rows,scratch=boundaries(rec,code[:n]+bytes(512-n),4 if store else 7)
                need(got==n and code[n:]==b'\xcc'*(512-n),'whole typed slot image extent/padding')
                ins=compact[INSTRUCTION+j*144:INSTRUCTION+(j+1)*144]
                if store:
                    _,wanted_record,wanted_code,wanted_desc=byte_plan(h[11]+off,source[256+off:271+off],source[256+off:256+off+length],h[13]+j*512,bank+0xb0000,h[13]+(j+1)*512,table)
                    need(ins==wanted_desc and rec==wanted_record and code==wanted_code+b'\xcc'*(512-len(wanted_code)),'complete independent LOOP BMG2 descriptor/emission/recovery')
                else:
                    binding=struct.pack('<3Q2IQ',bank+0x40000+ORIGINAL,h[13],bank+0x18000,count,j,bank+0xa0000)
                    # The existing independent DD1 byte model is used only for
                    # this proved in-range old encoding, not as policy authority.
                    want=direct.emit(descriptions[j],h[13]+j*512,bank+0xb0000,binding,2,(h[13],0),policy=12)
                    need(want['record'][:4]==b'\x01\0\0\0'and ins==want['description']+bytes(24)and rec==want['record']and code==want['image']+b'\xcc'*(512-len(want['image'])),'entire unchanged near DD1 image/record under exact source-derived LOOP13 binding')
            heads+=len(rows);interiors+=512-len(rows)
            for delta,length,valid,dirty,flags,phase in rows:
                original_pc=h[11]+off+(head[3]if (kind==1 or store)and phase==2 else 0)
                observed_kind=3 if kind==1 and phase==2 else mapkind
                out[h[13]+j*512+delta]=(original_pc,0 if last else phase,observed_kind,valid,dirty,flags,scratch)
        need(image[count*512:]==b'\xcc'*(len(image)-count*512),'whole unused LOOP code/stub padding')
    need(h[20:24]==(heads,interiors,8,h[19]),'actual exhaustive boundary/interior/authority populations')
    return out

def check(record,stdout,stderr,status,mode):
    need(type(mode)is int and 0<=mode<40 and type(status)is int and status==(125 if mode in FAULTS else 0),'genuine mode-specific process outcome')
    need(type(record)is bytes and len(record)==WIRE and stderr==b'','whole exact fixed raw wire and empty diagnostic stderr')
    h=q(record,0,32);form=0 if mode<28 else 1 if mode<36 else 2
    need(h[:8]==(0x314650453332494c,1,32,mode,0,1,3,form)and h[24:29]==(OBS,STATE,BOUNDARY,COMPACT,GUARD),'complete success/header/ABI and three actual lanes')
    need(h[8]&0xe7==0xe7 and 576<=h[9]<=FP and h[16:18]==(int(mode in FAULTS),0 if mode in(25,27)else 1)and h[31]==(0x202 if mode&1 else 0xed7),'exact hardware domain/fault permissions/flags seed')
    f=fixture(mode,q(record,256+32)[0]);need(q(record,256,16)==f['seed']and h[12]==f['terminal']and h[15]==f['ea']and h[29:31]==(len(f['raw']),f['iterations']),'complete source-derived fixture/seed')
    need(record[SOURCE_AT:IMAGE_AT]==f['source'],'all8192 original source bytes')
    layout=tuple(q(record,384+i*24,3)for i in range(64))
    for feature,(present,offset,size)in enumerate(layout):
        if feature<2 or not h[8]>>feature&1:need((present,offset,size)==(0,0,0),'unused CPUID row')
        else:need(present==1 and offset>=576 and size>0 and offset+size<=h[9],'complete actual CPUID component')
    stats=record[1920:1968];need(stats==record[1968:2016]and u(stats,0,4)==(1,2,0,0)and q(stats,16)[0]==16<<20 and 0<q(stats,24)[0]<=16<<20,'whole postsealed allocator equality')
    need(h[18]==len(f['path'])and 0<h[18]<=256 and 0<h[19]<=4096,'fixed actual instruction history and bounded generated trace')
    zero(record[HISTORY_AT+h[18]*STATE:TRACE_AT],'whole unused original history tail');zero(record[TRACE_AT+h[19]*BOUNDARY:OBS_AT],'whole unused generated trace tail')
    history=[]
    for i,pc in enumerate(f['path']):
        b=record[HISTORY_AT+i*STATE:HISTORY_AT+(i+1)*STATE];head=q(b,0,18)
        need(head[0]==pc and not head[17]&(TF|RF)and b[8336:]==f['stack'],'actual original instruction association/physical flags/stack')
        if i==0:need(head[1:17]==f['seed']and head[17]==h[31]and b[144:8336]==f['memory'],'whole actual original initial state')
        history.append((head,b[144:8336]))
    maps=plans(record,h,f);previous=0
    for i in range(h[19]):
        b=record[TRACE_AT+i*BOUNDARY:TRACE_AT+(i+1)*BOUNDARY];pc,origin,flags=q(b,0,3);regs=q(b,24,16);index,phase,kind=q(b,152,3)
        need(pc in maps and 0<=index<h[18]and previous<=index<=previous+1 and flags&TF,'actual monotone generated instruction boundary')
        expected_pc,expected_phase,expected_kind,valid,dirty,encoding,scratch=maps[pc]
        need((origin,phase,kind)==(expected_pc,expected_phase,expected_kind)and origin==history[index][0][0],'exact recovery phase/kind/original state association')
        ref=history[index][0];blocked={scratch[k]for k in range(len(scratch))if dirty>>k&1}
        need(all(regs[r]==ref[1+r]for r in range(16)if r not in blocked),'every unmodified or restored raw GPR')
        restored=flags
        if encoding:
            need(dirty&1,'flag encoding requires dirty RAX');of=flags&0x800
            if encoding==2:need(regs[0]&255<=1,'actual SETO low byte');of=(regs[0]&1)<<11
            restored=(flags&~0x8d5)|((regs[0]>>8)&0xd5)|of
        need(physical(restored)==ref[17],'actual complete physical flags at every generated boundary')
        previous=index
    obs=[observation(record[OBS_AT+i*OBS:OBS_AT+(i+1)*OBS],h,f,layout,i)for i in range(3)];native=obs[0]
    need(native['after'][0]==tuple(history[-1][0][1:17])and native['after'][1]==history[-1][0][17]and history[-1][1]==f['after'],'whole final original history versus actual live terminal')
    for generated in obs[1:]:
        for name in('before','after','xb','xa','entry_si','data','stack'):need(generated[name]==native[name],'whole cross-lane '+name)
        need(generated['entry']['g']==native['entry']['g']and generated['entry']['fp']==native['entry']['fp']and generated['entry']['count']==native['entry']['count']and generated['end']['fp']==native['end']['fp']and generated['end']['count']==native['end']['count']and generated['meta'][4:10]==native['meta'][4:10],'complete actual entry/FP/TLS/mask cross-lane equality')
        if mode in FAULTS:need(generated['exit_si']==native['exit_si'],'all128 actual fault siginfo bytes')
        expected=list(native['end']['g']);lane=generated['meta'][0];expected[16]=h[14]if h[16]else h[12];expected[17]=physical(expected[17])|(TF if lane==1 else 0)|(RF if h[16]or lane==2 else 0)
        if not h[16]and lane==2:expected[19]=21;expected[20]=14;expected[22]=h[12]
        need(generated['end']['g']==tuple(expected),'all23 actual terminal GREGs with exact event transformations')
    expected=dict(schema=1,mode=mode,lanes=3,reference_states=h[18],generated_boundaries=h[19],full_physical_flags=True,
        fp_bytes=FP,data_bytes=DATA,stack_bytes=STACK,required_write_fault=int(h[16]),policy13_loop=int(form==2),
        loop_iterations=f['iterations'],terminal_branch_before=int(form==2),authority_controls=8,postseal_equal=True,cleanup=True,owner_execution=False)
    exact(row(stdout),expected,'complete typed canonical native stdout')
    return dict(expected,raw_sha256=digest(record),raw_bytes=len(record),head_checks=h[20],interior_refusals=h[21],
        recovery_scope='actual protected-spill reconstruction asserted in C; raw boundary association and non-dirty registers/physical flags rechecked here',
        status='observed_required_write_fault'if h[16]else'observed_component_comparison',qualification_credit=False,performance_credit=False)

def controls(record,stdout,stderr,status,mode):
    """Nonidentity mutation controls follow an actual successful read only."""
    mutations=[('header',8),('mode',24),('first_error',32),('cleanup',40),('lanes',48),('seed',256),('cpuid_unused',384),
        ('postseal',1968),('source_tail',IMAGE_AT-1),('unused_history',TRACE_AT-1),('unused_trace',OBS_AT-1),
        ('reference_pc',HISTORY_AT),('trace_origin',TRACE_AT+8)]
    for lane in range(3):
        start=OBS_AT+lane*OBS
        mutations += [(str(lane)+'_'+name,start+offset)for name,offset in
            (('before',0),('after',152),('AF',280),('entry_GREG',131392),('terminal_GREG',197184),
             ('live_FP_tail',131375),('signal_FP_tail',262975),('data_tail',271423),('stack_tail',271583),('lane_metadata',271584),('padding',271743))]
    names=[]
    for name,offset in mutations:
        value=bytearray(record);value[offset]^=16 if name.endswith('AF')else 1
        try:check(bytes(value),stdout,stderr,status,mode)
        except ValueError:names.append(name);continue
        raise ValueError('accepted supplied nonidentity mutation '+name)
    for name,args in [('truncated',(record[:-1],stdout,stderr,status,mode)),('appended',(record+b'\0',stdout,stderr,status,mode)),
        ('stdout_extension',(record,stdout+b'\n',stderr,status,mode)),('stderr',(record,stdout,b'x',status,mode)),
        ('wrong_exit',(record,stdout,stderr,0 if status else 125,mode)),('mode_bool',(record,stdout,stderr,status,bool(mode)))]:
        try:check(*args)
        except(ValueError,struct.error):names.append(name);continue
        raise ValueError('accepted supplied nonidentity mutation '+name)
    need(len(names)==52 and len(set(names))==52,'all fixed meaningful strict-reader controls')
    return dict(raw_sha256=digest(record),refusals=names)
