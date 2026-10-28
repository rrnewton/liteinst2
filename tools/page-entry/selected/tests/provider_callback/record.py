"""File-only callback trailer oracle; old full provider comparator is mandatory."""
import struct
MAGIC=0x314b42434332494c
TRAILER=800
FP=65536
UC=2048
MASK64=(1<<64)-1

def need(ok,message):
    if not ok:raise ValueError(message)

def encoding(case):
    _,kind,width,reg,_,_,_=case['args']
    out=[]
    if kind==4:out.append(0xf3)
    elif width==16:out.append(0x66)
    rex=(8 if width==64 and kind!=4 else 0)|(reg>=8)
    if rex:out.append(0x40|rex)
    return bytes(out+[0x0f,0xc7,(0xf0 if kind==2 else 0xf8)|(reg&7)])

def trailer(data,case,pre,pc,next_pc,normal=True):
    need(len(data)==TRAILER,'complete callback trailer')
    w=struct.unpack_from('<40Q',data)
    need(w[:2]==(MAGIC,1 if normal else 2) and w[22]==6 and not any(w[23:]),'callback trailer header/tail')
    mech,kind,width,reg,control,layout,prefix=case['args']
    called=not (reg==4 or control in (1,3,4,9,19,21,25,28,45,48,51))
    committed=normal and case['status']==0
    need(w[2]==int(called) and w[4:7]==(int(called),int(called and normal),int(committed)), 'callback entered/returned/committed')
    status=71 if control==49 else 9 if control==32 else 0
    need(w[3]==status and w[7]==(case['status'] if normal else 0) and w[8]==1,'callback status/first error')
    if called:
        need(w[9:17]==(1,kind,width,reg,pc,next_pc,pre[16],pre[reg]),'actual scalar callback input')
        value=0xc00dcafe if kind==4 else 0 if kind==3 else {16:0xbeef,32:0xface9876,64:0xfedcba9876543210}[width]
        expected=[kind,width,int(kind==2),0,value]
        if control in (53,54):
            expected=[kind,width,0 if case['cf0'] else 1,0,0 if case['cf0'] else {16:0xbeef,32:0xface9876,64:0xfedcba9876543210}[width]]
        if control==13:expected[0]=1
        if control==14:expected[1]=8
        if control==15:expected[4]=0x10000
        if control==16:expected[2]=2
        if control==17:expected[2]=0;expected[4]=1
        if control==18:expected[3]=1
        need(w[17:22]==tuple(expected),'retained complete callback script')
    else:need(not any(w[9:22]),'no callback input/result before accepted preparation')
    leaves=((0,0),(1,0),(1,7),(7,0),(7,1),(0x80000000,0))
    for i,leaf in enumerate(leaves):
        r=struct.unpack_from('<10Q',data,320+80*i)
        need(r[:2]==leaf and all(v<=0xffffffff for v in r),'actual CPUID sample extent')
        expected=list(r[2:6])
        if i in (1,2):expected[2]&=0xbfffffff
        if i==3:expected[1]&=0xfffbffff;expected[2]&=0xffbfffff
        need(r[6:]==tuple(expected),'CPUID exact three-bit policy')
    return {'callback_entered':int(called),'callback_returned':int(called and normal),'callback_completed':int(committed),'cpuid_samples':6}

def check(data,case,old):
    if case['nested']:return nested(data,case,old)
    need(len(data)>TRAILER,'complete old record and callback trailer')
    prefix=data[:-TRAILER]
    # The exact old full-register/flags/kernel/live FP/source/stack comparator
    # consumes its entire original record without any new exemptions.
    result=old.check(prefix,case);r=old.read(prefix);h=r['h']
    instruction=encoding(case);expected=instruction+bytes(16-len(instruction))
    request=bytearray(expected)
    if case['args'][4]==19:request[len(instruction)-1]^=1
    need(r['source']==expected and r['request']==bytes(request) and h[15]==len(instruction),
         'literal callback instruction and exact source-request mutation')
    need(h[13]%4096==4096-(1 if case['args'][5] else len(instruction)),'actual requested fetch geometry')
    need(bool(r['pre'][16]&0x400)==case['df'],'actual requested DF')
    extra=trailer(data[-TRAILER:],case,r['pre'],h[13],h[14])
    return {'outcome':'completed' if case['status']==0 else 'refused_before_commit','old':result,**extra}

def nested(data,case,old):
    at=0
    def take(n):
        nonlocal at
        b=data[at:at+n];at+=n;need(len(b)==n,'nested capture extent');return b
    h=struct.unpack('<24Q',take(192));t=take(TRAILER);pre=struct.unpack('<24Q',take(192))
    before,after=take(UC),take(UC);fb,fa=take(FP),take(FP)
    source_before,source_after=take(8192),take(8192);sb,sa=take(512),take(512)
    need(at==len(data),'nested complete record')
    need(h[:7]==(MAGIC,2,50,11,2,14,21) and h[7]==h[8]==h[9] and h[7]!=0,'actual callback NX metadata')
    need(h[10]<=UC and h[10]>0 and h[11]+23*8<=h[10] and h[12]+8<=h[10] and 512<=h[13]<=FP,'nested actual outer layout')
    instruction=encoding(case);offset=4096-(1 if case['args'][5] else len(instruction))
    need(h[14]%4096==offset and h[15]==h[14]+len(instruction) and
         source_before[offset:offset+len(instruction)]==instruction,'actual nested selected source and fetch geometry')
    need(h[16:20]==(1,0,0,1),'unreturned provider prefix')
    need(h[7]==h[14]-offset+128,'actual nested callback target in the selected source mapping')
    need(h[20:]==(case['args'][5],0,2,64),'nested exact case')
    need(before==after and before[h[10]:]==bytes(UC-h[10]),'entire original outer context unchanged')
    need(fb==fa and fb[h[13]:]==bytes(FP-h[13]),'entire initialized outer kernel FP unchanged')
    need(source_before==source_after and sb==sa,'complete source and application stack unchanged')
    g=struct.unpack_from('<23Q',before,h[11])
    need(tuple(g[i] for i in old.GREG)==pre[:16],'actual outer GPR source')
    need(g[16]==h[14] and g[17]==(pre[16]|0x10000) and g[19:21]==(21,14),'actual outer NX frame')
    need(bool(pre[16]&0x400)==case['df'],'actual nested requested DF')
    need(struct.unpack_from('<Q',before,h[12])[0]!=0,'actual outer kernel FP pointer')
    extra=trailer(t,case,pre,h[14],h[15],False)
    return {'outcome':'failed_callback_without_return','outer_frame_unchanged':True,**extra}
