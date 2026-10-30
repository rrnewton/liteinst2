"""Independent finite wire/result/CFG model; no application or arbitrary-PC claim."""
import hashlib,json,struct
FP=65536
OBS=296000
FRAME=65792
DESC=5256
MASK=((1<<64)-1)^sum(1<<(s-1) for s in (11,5,31,9,19))
REGS=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
POLICY=b'li2-region-v1;closed-read-only-scalar;sole-external-entry;no-resume;Legacy128;disabled-entry-ret;sealed-original-NX;generation-owned\0'
K=(0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
def need(x,message):
    if not x:raise ValueError(message)
def qs(b,n,at=0):return struct.unpack_from('<'+str(n)+'Q',b,at)
def frame(b):
    need(len(b)==FRAME and not any(b[216:256]),'whole frame header/padding')
    g=qs(b,23);mask,ptr,n,initialized=qs(b,4,184);f=b[256:]
    need(mask==MASK and ptr and ptr%16==0 and initialized==n and 512<=n<=FP and not any(f[n:]),'complete actual FP extent/unused tail')
    if n!=512:
        need(struct.unpack_from('<I',f,464)[0]==0x46505853 and struct.unpack_from('<I',f,468)[0]==n and 576<=struct.unpack_from('<I',f,480)[0]<=n-4 and struct.unpack_from('<I',f,n-4)[0]==0x46505845,'Linux extended FP magic/extent')
    return dict(g=g,mask=mask,pointer=ptr,n=n,fp=f)
def live(b):
    need(len(b)==152 and b[148:]==b'\0'*4,'whole live register/selector record')
    return dict(g=qs(b,16),flags=qs(b,1,128)[0],selectors=struct.unpack_from('<6H',b,136))
def observation(b,entry):
    need(len(b)==OBS and not any(b[131376:131392]) and not any(b[295968:]),'whole observation padding')
    return dict(before=live(b[:152]),after=live(b[152:304]),xb=b[304:65840],xa=b[65840:131376],
        entry=frame(b[131392:197184]) if entry else None,exit=frame(b[197184:262976]),
        stack=b[262976:263136],data=b[263136:295904],tail=qs(b,8,295904),raw=b)
def source_bytes(u):
    body=bytes.fromhex('488b164801d04c31c04883c608')
    b=bytearray.fromhex('31c085c97400');b+=body*u;b+=bytes.fromhex('ffc97500c3')
    b[5]=len(b)-1-6;b[-2]=(6-(len(b)-1))&255
    page=bytearray(b'\xcc'*4096);page[:len(b)]=b;page[-16]=0x90
    heads=[0,2,4]+[6+13*i+j for i in range(u) for j in (0,3,6,9)]+[6+13*u,8+13*u,10+13*u]
    return bytes(page),len(b),heads

def seed_fp(x,layout,xcr0,xbytes):
    need(len(x)==FP and not any(x[xbytes:]),'whole XSAVE suffix')
    need(struct.unpack_from('<HH',x)==(0x37f,0x3000) and x[4]==0xc0 and struct.unpack_from('<I',x,24)[0]==0x1f80,'literal x87/MXCSR seed')
    bv,compact=qs(x,2,512);need(bv&0xe7==0xe7 and bv&~xcr0==0 and compact==0 and not any(x[528:576]),'standard initialized XSTATE header')
    for r in range(32):
        for q in range(8):
            component,offset=(7,(r-16)*64+q*8) if r>=16 else (6,r*32+(q-4)*8) if q>=4 else (2,r*16+(q-2)*8) if q>=2 else (0,160+r*16+q*8)
            if component:
                active,at,n=layout[component];need(active==1 and offset+8<=n,'whole enabled vector component');offset+=at
            need(offset+8<=xbytes and qs(x,1,offset)[0]==0x3141592653589793+r*8+q+1,'every literal live ZMM lane')
    active,at,n=layout[5];need(active==1 and n>=64 and qs(x,8,at)==K,'all eight literal K seeds')

def read(raw,stdout,unroll,trips,fault,exit_code):
    need(type(raw)is bytes and len(raw)==912824,'one complete fixed component record')
    h=qs(raw,24);need(h[:7]==(0x314647435232494c,1,24,unroll,trips,fault,0),'exact selected case/no fixture error')
    need(unroll in (1,2,4) and trips in (1,16,256) and fault in (0,1,2) and (not fault or (unroll,trips)==(4,1)),'fixed population')
    need(h[7]&0xe7==0xe7 and 576<=h[8]<=FP and h[9]>0 and h[18:23]==(OBS,DESC,FRAME,0,1),'state/layout/callback/retirement header')
    seed=qs(raw,16,192);desc=raw[320:320+DESC];p=qs(desc,12);pointer=qs(desc,1,96)[0];identity=desc[104:136]
    need(p[:3]==(1,h[10],source_bytes(unroll)[1]) and p[3]%4096==0 and p[4] in (4096,8192) and p[3]<=p[5]<p[3]+p[4] and 0<p[6]<=p[4]-(p[5]-p[3]) and p[7]==h[11] and (p[6],p[8],p[9])==h[12:15] and 0<p[10]<=FP and p[11]&~h[7]==0 and pointer,'exact emitted descriptor/finite bounds')
    need(0<p[8]<=80 and 0<p[9]<=160,'bounded actual metadata population')
    bodies=[qs(desc,2,136+16*i) for i in range(p[8])];ranges=[qs(desc,3,1416+24*i) for i in range(p[9])]
    need(p[8]<=80 and p[9]<=160 and not any(desc[136+16*p[8]:1416]) and not any(desc[1416+24*p[9]:]),'unused metadata entries empty')
    at=320+DESC;blocks=[raw[at+i*OBS:at+(i+1)*OBS] for i in range(3)];at+=3*OBS
    cold=qs(raw,3,at);at+=24;hot=[qs(raw,10,at+80*l) for l in range(3)];at+=240
    events=[[qs(raw,4,at+32*(11*l+i)) for i in range(11)] for l in range(3)];at+=1056
    layout=[qs(raw,3,at+24*i) for i in range(64)];at+=1536
    source,image=raw[at:at+8192],raw[at+8192:at+16384];at+=16384;need(qs(raw,1,at)==(8,),'eight actual/supplied authority controls')
    page,n,heads=source_bytes(unroll);need(source==page+b'\0'*4096 and identity==hashlib.sha256(POLICY+struct.pack('<Q',n)+page).digest(),'whole sealed source and content/policy identity')
    need([x[0] for x in bodies]==[h[10]+i for i in heads] and len({x[1] for x in bodies})==len(heads),'all and only original instruction heads')
    need(not any(image[p[4]:]) and image[:p[5]-p[3]]==b'\xcc'*(p[5]-p[3]) and image[p[5]-p[3]+p[6]:p[4]]==b'\xcc'*(p[4]-(p[5]-p[3]+p[6])),'complete generated padding')
    for i,(original,generated) in enumerate(bodies):
        off=original-h[10];width=(heads[i+1] if i+1<len(heads) else n)-off
        need(p[5]<=generated and generated+width<=p[5]+p[6],'body inside exact generated bytes')
        ins=image[generated-p[3]:generated-p[3]+width]
        if page[off] in (0x74,0x75):
            op=page[off];b=image[generated-p[3]:generated-p[3]+6]
            if b[0]==op:dest=generated+2+int.from_bytes(b[1:2],'little',signed=True)
            else:need(b[:2]==bytes((0x0f,op+0x10)),'actual conditional encoding');dest=generated+6+int.from_bytes(b[2:6],'little',signed=True)
            target=h[10]+(n-1 if op==0x74 else 6);need(sum(a==dest and c==target for a,z,c in ranges)==1,'relocated branch enters exact target gate')
        else:need(ins==page[off:off+width],'literal scalar/memory instruction body')
    need(sum(a==p[7] and c==h[10] for a,z,c in ranges)==1 and all(p[5]<=a<z<=p[5]+p[6] for a,z,c in ranges),'entry and complete executable PC-map extents')
    for k,(active,offset,size) in enumerate(layout):
        if k>=2 and h[7]>>k&1:need(active==1 and 576<=offset<offset+size<=h[8],'actual enabled CPUID standard component')
        else:need((active,offset,size)==(0,0,0),'absent CPUID fields remain zero')
    need(seed[1]==trips and seed[4]==h[16] and seed[4]%16==8,'seed trip/SystemV entry stack')
    stack=bytearray((i*29+7)&255 for i in range(160));stack[128:136]=struct.pack('<Q',h[15])
    data=b''.join(struct.pack('<Q',(0x123456789abcdef0+i*0x102030405060708)&((1<<64)-1)) for i in range(4096))
    result=json.loads(stdout);need(type(result)is dict and result.get('schema')==1 and result.get('cleanup')==1,'actual JSON result')
    nobs=observation(blocks[0],False);need(not any(blocks[0][131392:197184]),'native has no invented entry signal')
    if fault:
        need(exit_code==125 and result==dict(schema=1,status='required_read_failure',lane=fault,qualified_fault=1,completed_operation=0,cleanup=1),'required failure, no completed-operation credit')
        need(not any(blocks[3-fault]) and cold==(0,0,0) and all(not any(x) for x in hot) and not any(v for group in events for row in group for v in row),'no unexecuted lane/timing result')
        o=observation(blocks[fault],True);ng=nobs['exit']['g'];g=o['exit']['g'];logical=h[10]+6
        entry=list(ng)
        for i,r in enumerate(REGS):entry[r]=seed[i]
        entry[16]=h[10];entry[17]=0x10202;entry[19]=21;entry[20]=14;entry[22]=h[10]
        need(o['entry']['g']==tuple(entry) and o['entry']['fp']==nobs['exit']['fp'] and o['entry']['n']==nobs['exit']['n'] and o['entry']['pointer']==nobs['exit']['pointer'],'complete failed-lane actual seeded NX entry')
        need(nobs['before']['selectors']==nobs['after']['selectors']==o['before']['selectors'],'complete native fault live selectors')
        need(nobs['tail'][4:6]==(logical,logical) and o['tail'][5]==logical and o['tail'][4]==g[16] and ng[16]==logical and ng[19]==4 and ng[20]==14,'actual load fault coordinates')
        need((fault==1 and sum(a==logical and b==g[16] for a,b in bodies)==1) or (fault==2 and g[16]==logical),'exact generated-body translation or original TF PC')
        for i in range(23):need(g[i]==(g[i] if i==16 else ng[i]|0x100 if i==17 and fault==2 else ng[i]),'complete real fault register/flag conservation')
        need(o['exit']['fp']==nobs['exit']['fp'] and o['exit']['n']==nobs['exit']['n'] and o['tail'][6:]==nobs['tail'][6:],'complete fault FP/FS/GS conservation')
        need(nobs['data']==o['data']==data and nobs['stack']==o['stack']==stack,'whole failed-operation memory unchanged')
        need(o['before']==nobs['before'] and o['xb']==nobs['xb']==nobs['xa'] and not any(blocks[fault][152:304]) and not any(o['xa']),'complete before state, no invented after capture')
        seed_fp(o['xb'],layout,h[7],h[8]);need(o['before']['g']==seed and o['before']['flags']==0x202,'failed input seed')
        want=list(seed);want[0]=0
        need(tuple(ng[r] for r in REGS)==tuple(want) and ng[17]==0x10202 and ng[22]==seed[6] and nobs['after']['g']==tuple(want) and nobs['after']['flags']==0x202,'independent native fault-prefix model')
        need(o['tail'][:4]==((1,0,0,0) if fault==1 else (4,3,3,0)) and nobs['tail'][:4]==(0,0,0,0),'actual failed-prefix counts')
        need(h[23]==(6 if fault==1 else 12),'exact required-failure real handler count')
        return dict(qualified_fault=1,completed_operations=0,authority_controls=8,timing_credit=False)
    need(exit_code==0 and result.get('status')=='passed_component','successful component exit')
    count=4+trips*(4*unroll+2);want_events=((1,0,0,1),(2,0,0,1),(count+1,count,count,1))
    expected=list(seed);value=0
    for i in range(trips*unroll):value=((value+struct.unpack_from('<Q',data,8*i)[0])&((1<<64)-1))^seed[8]
    expected[0]=value;expected[1]=0;expected[2]=struct.unpack_from('<Q',data,8*(trips*unroll-1))[0];expected[4]+=8;expected[6]+=trips*unroll*8
    need(seed[6]==h[17] and h[23]==3+11*(2*count+4),'exact physical handler scaling')
    for l,b in enumerate(blocks):
        o=observation(b,l!=0);need(o['before']['g']==seed and o['before']['flags']==0x202 and o['after']['g']==tuple(expected) and o['after']['flags']==0x246,'independent full scalar/flags result')
        need(o['before']['selectors']==o['after']['selectors']==nobs['before']['selectors'] and o['xb']==o['xa']==nobs['xb']==nobs['xa'],'whole application XSAVE/selector equality')
        seed_fp(o['xb'],layout,h[7],h[8]);seed_fp(o['xa'],layout,h[7],h[8])
        need(o['exit']['g']==nobs['exit']['g'] and o['exit']['fp']==nobs['exit']['fp'] and o['exit']['n']==nobs['exit']['n'] and o['exit']['pointer']==nobs['exit']['pointer'],'complete common guard frame')
        need(o['exit']['g'][16]==h[15] and o['exit']['g'][17]==0x10246 and o['exit']['g'][19:21]==(21,14),'real guard NX, exact flags')
        need(tuple(o['exit']['g'][r] for r in REGS)==tuple(expected) and o['stack']==stack and o['data']==data,'full memory and exit register model')
        need(o['tail'][:4]==want_events[l] and o['tail'][4:6]==(0,0) and o['tail'][6:]==nobs['tail'][6:] and events[l]==[want_events[l]]*11,'every recorded event count/FS/GS/no fault')
        if l:need(tuple(o['entry']['g'][r] for r in REGS)==seed and o['entry']['g'][16]==h[10] and o['entry']['g'][17]==0x10202 and o['entry']['fp']==o['exit']['fp'],'complete real cache/TF entry')
    need(all(x>0 for x in cold) and all(x>0 for row in hot for x in row),'all eleven actual timing samples per lane')
    need(result==dict(schema=1,status='passed_component',unroll=unroll,trips=trips,instructions=count,prepare_ns=h[9],cleanup=1,callbacks=0,cold_ns=list(cold),hot_ns=[list(x) for x in hot],events=[list(x) for x in want_events]),'exact numerical stdout/wire join')
    return dict(completed_operations=33,authority_controls=8,instructions=count,prepare_ns=h[9],cold_ns=list(cold),hot_ns=[list(x) for x in hot],events=[list(x) for x in want_events],component_timing_only=True)
