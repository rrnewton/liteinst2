#!/usr/bin/env python3
"""Observe sixteen typed RET cases, never resume a loaded unknown target."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
DONOR=Path(__file__).resolve().with_name('frame.py')
if hashlib.sha256(DONOR.read_bytes()).hexdigest()!='4512c512f7d1148d5cb32d46223a39ec24085b824baefd8894dbbb8689164544':raise ValueError('whole reviewed native frame/context helper projection')
spec=importlib.util.spec_from_file_location('ret_native_frame_donor',DONOR)
donor=importlib.util.module_from_spec(spec);spec.loader.exec_module(donor)
need,words,digest,flags,frame=donor.need,donor.words,donor.digest,donor.flags,donor.frame
PAGE,FP,STACK,FRAME,RECORD=4096,65536,16384,67072,368544
MAGIC,REC_MAGIC,END=0x314e524432494c,0x3152524432494c,0x3145524432494c
REG=donor.REG
MASK64,TF,RF=(1<<64)-1,0x100,0x10000

def configuration(identity,h):
    group,item,kind,row=0,identity,0,identity%3
    first=h[22]+2*PAGE+256;end=first+512;sp=h[22]+2*PAGE+512;target=h[23]+64
    status=flags(7*identity)|(0x400 if identity&1 else 0);permissions=[0,3,3,0]
    if identity<6:sp=first+(identity//2)*256
    elif identity<10:
        group,item,kind=1,identity-6,1
        target=(h[23]+192,h[23]+PAGE+64,0x0100000000000000,0x8000000000000000)[item]
    elif identity<12:group,item,kind=2,identity-10,2;sp=end+1 if item else first-1
    elif identity<14:
        group,item,kind=3,identity-12,3;permissions[2]=0
        if item:sp=h[22]+2*PAGE-4;first=sp-256;end=first+512
    else:group,item,kind=4,identity-14,4
    return group,item,kind,row,sp,target,status,permissions,first,end


def plan_model(h):
    """Independent literal machine bytes, typed rows and exact full2328-byte image."""
    pc,generated,spill,directory,window=h[21]+0x100,h[30],h[35],h[33],h[34]
    image,rows=bytearray(),[];state=[0,0,0,0];patches=[]
    def emit(raw):
        at=len(image);rows.append((at,len(raw),*state));image.extend(raw);return at
    def disp(at,n,target):return struct.pack('<i',target-(generated+at+n))
    def slot(i,load=False):
        at=len(image);emit(bytes((0x48,0x8b if load else 0x89,5|(i<<3)))+disp(at,7,spill+8*i))
        if load:state[1]&=~(1<<i)
        else:state[0]|=1<<i
    def rr(op,r,m):emit(bytes((0x48,op,0xc0|(r<<3)|m)))
    def imm(r,op,n):emit(bytes((0x48,0x81,0xc0|(op<<3)|r))+struct.pack('<I',n))
    def absolute(r,n):emit(bytes((0x48,0xb8+r))+struct.pack('<Q',n))
    def load(r,base,offset):emit(bytes((0x48,0x8b,0x40|(r<<3)|base,offset)))
    def branch(cc,label):
        at=emit(bytes((0x0f,0x80+cc))+bytes(4));patches.append((at,label));return at
    def cell(r,offset):
        at=len(image);emit(bytes((0x48,0x89,5|(r<<3)))+disp(at,7,spill+offset))
    def restore():
        emit(b'\x04\x7f');state[2]=1;emit(b'\x9e');state[2]=0
        for i in (1,2,3,0):slot(i,True)
    for i in range(4):slot(i)
    emit(b'\x9f');state[1]|=1;state[2]=1
    emit(b'\x0f\x90\xc0');state[2]=2
    absolute(1,window);state[1]|=2
    load(2,1,24);state[1]|=4;rr(0x3b,4,2);branch(2,'before')
    load(2,1,32);rr(0x3b,4,2);branch(7,'before')
    state[3]=1;guest_load=len(image);emit(b'\x48\x8b\x1c\x24');state[1]|=8;state[3]=2
    save=len(image);cell(3,40);state[3]=3
    absolute(1,directory);load(2,1,8);imm(2,7,1);branch(2,'loaded');imm(2,7,256);branch(7,'loaded')
    imm(1,0,32);emit(b'\x48\xc1\xe2\x05');rr(0x03,2,1)
    loop=len(image);emit(b'\x48\x3b\x59\0');found=branch(4,'hit')
    imm(1,0,32);rr(0x3b,1,2);again=branch(2,'loop')
    loaded=len(image);restore();loaded_miss=len(image);emit(b'\xff\x25'+disp(loaded_miss,6,generated+504))
    before=len(image);state[:]=[15,7,2,0];restore();miss=len(image);emit(b'\xe9'+disp(miss,5,pc))
    hit=len(image);state[:]=[15,15,2,3];load(1,1,8);cell(1,32);state[3]=4;restore()
    state[3]=5;commit=len(image);emit(b'\x48\x8d\x64\x24\x08')
    state[3]=6;transfer=len(image);emit(b'\xff\x25'+disp(transfer,6,spill+32))
    labels=dict(before=before,loaded=loaded,hit=hit,loop=loop)
    for at,label in patches:image[at+2:at+6]=disp(at,6,generated+labels[label])
    need((len(image),len(rows),guest_load,save,commit,transfer,miss,loaded_miss)==(285,53,68,72,274,279,227,190),
         'exact independent full emitted geometry and all53 recovery rows')
    image+=bytes(504-len(image))+struct.pack('<Q',window+128)
    record=struct.pack('<16I',1,1,0,285,53,68,72,274,279,227,190,0,0,1,2,3)
    record+=b''.join(struct.pack('<6I',*r) for r in rows)+bytes(24*(64-len(rows)))
    decoded=struct.pack('<QQ10I',pc,pc+1,1,0,396,0,16,0,0,15,1,0)+b'\xc3'+b'\xcc'*14+b'\0'
    tf=struct.pack('<QQ6I',pc,pc+1,1,1,396,1,2,5)
    descriptor=decoded+tf+struct.pack('<8I',1,1,0,15,0,0,0,0)
    binding=struct.pack('<QQQIIQQQ',h[32],h[30],h[31],1,0,h[33],h[34],h[34]+128)
    plan=record+descriptor+struct.pack('<QQ',generated,spill)+binding+image
    need(len(plan)==2328,'whole typed RET plan and zero padding')
    return plan,bytes(image),rows,dict(loop=loop,found=found,again=again,hit=hit)


def recover(raw,pc,status,spills,h,rows):
    if pc==h[34]+128:valid,dirty,mode,phase=15,0,0,7
    else:
        found=[r for r in rows if h[30]+r[0]==pc];need(len(found)==1,'exact actual initialized recovery row')
        _,_,valid,dirty,mode,phase=found[0]
    need(dirty&~valid==0,'no unread initialized spill')
    g=list(raw);f=status
    if mode:
        need(mode!=2 or raw[0]&255 in (0,1),'exact saved overflow byte')
        overflow=(raw[0]&1)<<11 if mode==2 else status&0x800
        f=(status&~0x8d5)|((raw[0]>>8)&0xd5)|overflow
    for i in range(4):
        if dirty&(1<<i):g[i]=spills[i]
    target=raw[3] if phase==2 else spills[5] if phase>=3 else 0
    original_sp=g[4]-8 if phase==6 else g[4]
    return struct.pack('<20Q4I',*g,f,h[21]+0x100,original_sp,target,phase,1,int(phase>=2),0)


def protections(h,which,kind,permissions):
    rows=[(h[21],PAGE,3,0,0),(h[30],32768,3,0,0),(h[31],32768,3,0,0),
          (h[32],PAGE,3,0,0),(h[33],12288,3,0,0),(h[34],PAGE,3,0,0),
          (h[35],PAGE,3,0,0),(h[23],2*PAGE,3,0,0),(h[22],STACK,3,0,0)]
    rows += [(h[22]+i*PAGE,PAGE,p,0,0) for i,p in enumerate(permissions)]
    rows += [(h[21],PAGE,1,0,0),(h[30],32768,1,0,0),(h[31],32768,5,0,0),
             (h[32],PAGE,1,0,0),(h[33],12288,1,0,0),(h[34],PAGE,1,0,0),
             (h[23],PAGE,5,0,0),(h[23]+PAGE,PAGE,1,0,0)]
    if which:rows.append((h[30],32768,5,1,0))
    elif kind!=2:rows.append((h[21],PAGE,5,1,0))
    rows += [(h[22],STACK,3,2,0),(h[21],PAGE,1,2,0),(h[30],32768,1,2,0),(h[31],32768,1,2,0)]
    return len(rows),b''.join(struct.pack('<5Q',*x) for x in rows)+bytes((32-len(rows))*40)


def lane(raw,h,identity,which):
    need(len(raw)==RECORD,'whole complete lane')
    r,bootstrap=words(raw,64),words(raw,23,512)
    group,item,kind,row,sp,target,status,permissions,first,end=configuration(identity,h)
    pc,entry,cached=h[21]+0x100,h[30] if which else h[21]+0x100,h[30+(identity&1)]+512
    expected_plan,image,rows,labels=plan_model(h)
    trace=[]
    if kind==4:
        # Every failed comparison executes its loop tail, followed by one actual
        # hit. This uses the real directory row index, not a one-pass shortcut.
        trace=[x[0]+x[1] for x in rows if x[0]<labels['loop']]
        for index in range(row+1):
            trace.append(labels['found'])
            if index==row:trace.append(labels['hit'])
            else:
                trace += [x[0]+x[1] for x in rows if labels['found']<=x[0]<labels['again']]
                trace.append(labels['loop'])
        trace += [x[0]+x[1] for x in rows if labels['hit']<=x[0]<279]
    count,protect=protections(h,which,kind,permissions)
    need(r[:13]==(REC_MAGIC,RECORD,identity,which,4,group,item,pc,pc+1,target,sp,status,1) and
         r[13:20]==(1,0,2,2+len(trace) if kind==4 else 2,entry,cached,len(trace)) and
         r[20:24]==tuple(permissions) and r[24:34]==(kind,item,first,end,3,row,1,
             int(bool(which) and kind in (1,3,4)),count,h[34]+128) and
         r[34:36]==((h[30]+(79 if item else 72),h[23]+192) if kind==4 else (0,0)) and not any(r[36:]),
         'complete literal16-case/24-lane header, actual events and zero unused cells')
    before_raw,after_raw,mutation_raw=raw[696:67768],raw[67768:134840],raw[134840:201912]
    before,after=frame(before_raw,h,0),frame(after_raw,h,1)
    recovery=raw[201912:202088];need(raw[202088:204416]==expected_plan,'whole actual plan/512image/53row reconstruction')
    need(raw[227968:229248]==protect,'all actual permission calls/results/order')
    mutation=words(raw,4,229248)
    initial,final=raw[229280:245664],raw[245664:262048]
    source,images,row_bytes=raw[262048:266144],raw[266144:331680],raw[331680:335776]
    directory,window,target_pages=raw[335776:348064],raw[348064:352160],raw[352160:360352]
    spill_initial,spill_final=raw[360352:364448],raw[364448:368544]
    seed=[(0x13579bdf00110000+0x100010001*i+identity)&MASK64 for i in range(16)];seed[4]=sp
    stack=bytearray((0x5a+37*i+identity)&255 for i in range(STACK));struct.pack_into('<Q',stack,sp-h[22],target)
    need(initial==stack,'whole initialized guest stack and exact original target word')
    if kind==4:struct.pack_into('<Q',stack,sp-h[22],h[23]+192)
    need(final==stack,'whole guest stack unchanged except the one explicitly observed post-load mutation')
    source_model=bytearray(b'\xcc'*PAGE);source_model[0x100]=0xc3
    need(source==source_model and images==image+b'\xcc'*(65536-512) and not any(row_bytes) and
         target_pages==b'\xcc'*(2*PAGE),'whole sealed source/generated/row/RX-NX target bytes')
    dm=bytearray(12288);struct.pack_into('<4Q',dm,0,1,3,73,0)
    for i in range(3):
        key=target if kind!=1 and i==row else h[23]+64+32*row if kind!=1 and row and i==0 else h[23]+64+32*i
        struct.pack_into('<3Q2I',dm,32+32*i,key,cached,91+i,identity&1,1)
    need(directory==dm and window==struct.pack('<8Q',1,h[32],73,first,end,0,0,0)+bytes(PAGE-64),
         'whole actual numeric directory and readonly window; no owner authority inferred')
    poison=bytes((0xa7+19*i+identity)&255 for i in range(PAGE));need(spill_initial==poison,'whole initialized poison')
    expected_spill=bytearray(poison)
    if which:
        for i in range(4):struct.pack_into('<Q',expected_spill,8*i,seed[i])
        if kind in (0,1,4):struct.pack_into('<Q',expected_spill,40,target)
        if kind in (0,4):struct.pack_into('<Q',expected_spill,32,cached)
    need(spill_final==expected_spill,'only initialized saved GPR/loaded-target/hit-cell words may change')
    need(tuple(before[1][i] for i in REG)==tuple(seed) and before[1][16]==entry and before[1][17]==status|RF and
         before[0][:4]==(11,2,0,entry) and before[1][19:21]==(21,14) and before[1][22]==entry,
         'actual initial NX event and every seeded GPR/flag')
    boot=list(before[1])
    if kind==4:boot[17]=status|TF
    else:boot[16],boot[15]=h[28:30];boot[17]&=~(RF|TF)
    need(bootstrap==tuple(boot),'unchanged original reload or exact TF signal-return bootstrap')
    need(before[2]==after[2] and before[0][4:6]==after[0][4:6] and before[0][8:10]==after[0][8:10] and
         before_raw[312:320]==after_raw[312:320],'whole FP/TLS/uc state and complete true kernel mask')
    logical=list(after[1]);expected_gpr=list(seed)
    if kind in (0,4):expected_gpr[4]+=8
    if which and kind in (1,3):
        actual= recover([after[1][i] for i in REG],after[1][16],after[1][17],words(spill_final,6),h,rows)
        need(recovery==actual,'actual helper equals independent initialized recovery')
        recovered=words(actual,20)
        for i,k in enumerate(REG):logical[k]=recovered[i]
        logical[17]=recovered[16]
    need(tuple(logical[i] for i in REG)==tuple(expected_gpr) and
         logical[17]==status|(TF if kind==4 else RF if kind in (1,2,3) else 0),
         'all logical GPR/flags and exact initialized effect state')
    if kind==0:
        need(after[0][:4]==(5,128,0,0) and after[1][16]==(cached if which else target)+1 and
             after[1][19:21]==(0,3) and after[1][22]==entry,'exact hit at actual cached/original INT3')
    elif kind in (1,2):
        endpoint=h[34]+128 if kind==1 else pc
        need(after[0][:4]==(11,2,0,endpoint) and after[1][16]==endpoint and after[1][19:21]==(21,14) and
             after[1][22]==endpoint,'distinct actual NX loaded miss or before-load original frontier')
    elif kind==3:
        need(after[0][:3]==(11,2,0) and after[1][16]==(h[30]+68 if which else pc) and
             after[1][20]==14 and after[1][19] in (4,5) and after[1][22]==after[0][3] and
             sp<=after[0][3]<sp+8,'actual stack-read fault before RSP commit; pair retains exact fault class')
    else:
        need(after[0][:4]==(5,2,0,cached) and after[1][16]==cached and after[1][19:21]==(0,1) and
             after[1][22]==entry,'actual transfer after one read and explicit word mutation')
    if kind==1:
        need(recovery==struct.pack('<20Q4I',*seed,status|RF,pc,sp,target,7,1,1,0),
             'whole typed loaded miss retains original SP and exact saved target; no resumed RET')
    elif kind==3 and which:
        need(recovery==struct.pack('<20Q4I',*seed,status|RF,pc,sp,0,1,1,0,0),
             'whole LOAD-fault recovery has no completed target read or SP effect')
    elif kind!=4:need(not any(recovery),'no fabricated helper result outside observed typed boundary')
    for i,offset in enumerate(trace):
        t=raw[204416+368*i:204416+368*(i+1)];tpc,tflags=words(t,2);g=words(t,16,16);spill=words(t,6,144)
        need(tpc==h[30]+offset and tflags&TF and not tflags&RF,'complete actual selected TRACE path, including repeated comparisons')
        recovered=recover(g,tpc,tflags,spill,h,rows);need(t[192:]==recovered,'every observed raw TRACE and independent recovery')
        row_value=next(x for x in rows if x[0]==offset);phase=row_value[5];want=list(seed)
        if phase==6:want[4]+=8
        need(recovered==struct.pack('<20Q4I',*want,status|TF,pc,sp,target if phase>=2 else 0,phase,1,int(phase>=2),0),
             'every observed before/loaded/saved/committed state is exact')
        need(spill[:4]==tuple(seed[j] if row_value[2]&(1<<j) else words(poison,4)[j] for j in range(4)),
             'every actual initialized spill subset, with unused poison retained')
        need(spill[4]==(cached if phase>=4 else words(poison,6)[4]) and
             spill[5]==(target if phase>=3 else words(poison,6)[5]),'phase-initialized target cells only')
    need(not any(raw[204416+368*len(trace):227968]),'whole unused trace storage zero')
    if kind==4:
        observed=frame(mutation_raw,h,1);at=h[30]+(79 if item else 72)
        need(mutation==(at,target,h[23]+192,1) and observed[1][16]==at and
             observed[0][:4]==(5,2,0,at) and observed[2]==before[2] and
             observed[0][8:10]==before[0][8:10] and mutation_raw[312:320]==before_raw[312:320],
             'actual full post-load mutation checkpoint, unchanged FP/TLS and true signal mask')
        t=next(raw[204416+368*i:204416+368*(i+1)] for i,x in enumerate(trace) if h[30]+x==at)
        need(tuple(observed[1][k] for k in REG)==words(t,16,16) and observed[1][17]==words(t,2)[1],
             'full mutation frame joins its actual raw TRACE GPR/flags')
        expected=struct.pack('<20Q4I',*expected_gpr,status|TF,pc,sp,target,6,1,1,0)
        need(recovery==expected,'saved post-LEA committed recovery uses original loaded target once')
    else:need(not any(mutation_raw) and mutation==(0,0,0,0),'no invented mutation/checkpoint in other cases')
    return dict(id=identity,which=which,kind=kind,row=row,pc=pc,target=target,entry=entry,
        header=r,before=before,after=after,before_raw=before_raw,after_raw=after_raw,
        logical_after=logical,initial=initial,final=final,immutable=raw[262048:360352],
        raw_sha256=digest(raw),observed_trace_events=len(trace),observed_unique_boundaries=len(set(trace)),
        observed_boundary_offsets=sorted(set(trace)),loaded_miss=kind==1,
        original_rsp=sp,actual_rsp=after[1][15],target_valid=kind in (0,1,4))


def pair(a,b):
    need(a['id']==b['id'] and a['kind']==b['kind'] and a['kind'] in (0,3) and
         a['initial']==b['initial'] and a['final']==b['final'] and a['immutable']==b['immutable'],
         'whole matched native/generated sources/stack/directory/window')
    for phase in ('before','after'):
        x,y=a[phase],b[phase];xr,yr=a[phase+'_raw'],b[phase+'_raw']
        gx=list(x[1]);gy=list(y[1]) if phase=='before' else b['logical_after'][:]
        gx[16]=gy[16]=a['pc'] if phase=='before' or a['kind']==3 else a['target']+1
        if phase=='before' or a['kind']==0:gx[22]=gy[22]=a['pc']
        need(gx==gy and x[2]==y[2] and x[0][4:6]==y[0][4:6] and x[0][7:10]==y[0][7:10] and
             xr[312:320]==yr[312:320],'all23 logical GREG/flags, full FP/TLS and true mask')
        xi,yi=bytearray(xr[440:568]),bytearray(yr[440:568])
        if phase=='before':xi[16:24]=yi[16:24]=struct.pack('<Q',a['pc'])
        need(xi==yi and bytes(xr[312:320])+bytes(xi[:120])==bytes(yr[312:320])+bytes(yi[:120]) and
             donor.normalized_context(xr,gx,xi)==donor.normalized_context(yr,gy,yi),
             'whole siginfo/context after only authenticated endpoint and initialized-recovery normalization')
    return dict(id=a['id'],kind='hit' if a['kind']==0 else 'load_fault',original_sha256=a['raw_sha256'],
                generated_sha256=b['raw_sha256'],full_state_stack_equal=True)


def read_file(path,cpu,pid,address_model='low'):
    raw=path.read_bytes();need(len(raw)==512+24*RECORD+64<16<<20,'exact complete single24-lane chunk')
    h=words(raw,64)
    need(h[:15]==(MAGIC,1,512,RECORD,FRAME,968,128,FP,STACK,PAGE,16,0,0,16,24) and
         h[15]==pid>0 and h[16]==cpu and h[19]&3==3 and 512<=h[20]<=FP and
         h[25:28]==(262144,0,24) and h[28] and h[29] and h[36:42]==(2328,176,368,64,40,32) and not any(h[42:]),
         'complete exact process/type/FP/24-lane header')
    need((h[17]==0 and h[18]==0) or h[17] in ((-22)&MASK64,(-38)&MASK64),'original CET refusal never disabled')
    spans=sorted((h[i],n) for i,n in ((21,PAGE),(22,STACK),(23,2*PAGE),(30,32768),(31,32768),
                 (32,PAGE),(33,12288),(34,PAGE),(35,PAGE)))+[(h[24]-PAGE,h[25]+2*PAGE)]
    spans.sort();need(all(a>=PAGE and a%PAGE==0 and a+n<1<<47 for a,n in spans) and
         all(spans[i][0]+spans[i][1]<=spans[i+1][0] for i in range(len(spans)-1)),
         'complete actual allocation geometry/disjointness; numeric fixture only')
    need(address_model in ('low','high'),'explicit one address cohort')
    if address_model=='low':
        need(all(h[i]+n<=1<<31 for i,n in ((21,PAGE),(23,2*PAGE),(30,32768),(31,32768),
             (32,PAGE),(33,12288),(34,PAGE),(35,PAGE))), 'all original MAP_32BIT objects remain low')
    else:
        need((h[23],h[30],h[31],h[32],h[33],h[35])==tuple(h[21]+n*PAGE for n in (1,3,11,19,20,23)) and
             h[34]+PAGE<=1<<31 and h[21]>h[34]+PAGE+0x7fffffff and h[21]+24*PAGE<1<<47 and
             h[34]+128-(h[30]+190+6)<-(1<<31),
             'one exact high cluster and low window beyond signed32 displacement; no relocation fallback')
    need(words(raw,8,len(raw)-64)==(END,1,24,len(raw),0,0,0,0),'whole exact complete footer')
    results=[];pairs=[];offset=512
    for identity in range(16):
        original=None
        if identity<6 or 12<=identity<14:
            original=lane(memoryview(raw)[offset:offset+RECORD],h,identity,0);offset+=RECORD;results.append(original)
        generated=lane(memoryview(raw)[offset:offset+RECORD],h,identity,1);offset+=RECORD;results.append(generated)
        if original is not None:pairs.append(pair(original,generated))
    need(offset==len(raw)-64 and len(pairs)==8 and len(results)==24,'no omitted/extra case or lane')
    result=dict(schema=1,status='finite_ret_adapter_observed',cases=16,native_lanes=24,
        matched_hit_pairs=6,matched_load_fault_pairs=2,typed_loaded_misses=4,before_load_misses=2,
        post_load_mutations=2,observed_trace_events=[r['observed_trace_events'] for r in results if r['kind']==4],
        observed_unique_boundaries=[r['observed_unique_boundaries'] for r in results if r['kind']==4],
        observed_boundary_union=sorted(set().union(*(set(r['observed_boundary_offsets']) for r in results if r['kind']==4))),
        component_all53_boundaries_separate=True,source=dict(bytes=len(raw),sha256=digest(raw),pid=pid,cpu=cpu),
        pairs=pairs,observations=[{k:r[k] for k in ('id','which','kind','row','raw_sha256','observed_trace_events','observed_unique_boundaries','observed_boundary_offsets',
            'loaded_miss','original_rsp','actual_rsp','target_valid')} for r in results],
        loaded_miss_resumption=False,production_owner_authority=False,qualification_credit=False,
        performance_credit=False,old_RET32_replaced=False,old_component671_replaced=False,
        scope='Actual typed RET hits, load faults and stopped loaded misses; no generic RET continuation equivalence.')
    if address_model=='high':
        result['address_geometry']=dict(model='high-cluster-low-window',cluster=h[21],cluster_bytes=24*PAGE,
            window=h[34],loaded_miss=h[34]+128,generated=h[30],loaded_jump_offset=190,
            loaded_jump_bytes=6,landing_literal_offset=504,
            signed_distance=h[34]+128-(h[30]+190+6),beyond_rel32=True)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--expect-cpu',type=int,required=True)
    p.add_argument('--expect-pid',type=int,required=True)
    p.add_argument('--expect-address-model',choices=('low','high'),default='low')
    p.add_argument('record',type=Path);args=p.parse_args()
    need(args.expect_cpu>=0 and args.expect_pid>0,'actual reserved CPU and child PID')
    print(json.dumps(read_file(args.record,args.expect_cpu,args.expect_pid,args.expect_address_model),sort_keys=True,indent=2))

if __name__=='__main__':main()
