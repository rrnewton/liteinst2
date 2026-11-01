#!/usr/bin/env python3
"""Finite same-original-PC native/TF observations; no production owner credit."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
HELPER=Path(__file__).with_name('frame.py')
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!='4512c512f7d1148d5cb32d46223a39ec24085b824baefd8894dbbb8689164544':
    raise ValueError('exact whole native frame/context donor')
spec=importlib.util.spec_from_file_location('helper_tf_native_frame',HELPER)
donor=importlib.util.module_from_spec(spec);spec.loader.exec_module(donor)
need,words,digest,frame=donor.need,donor.words,donor.digest,donor.frame
REG=donor.REG
PAGE,FP,STACK,FRAME,RECORD,CASES,CHUNK=4096,65536,16384,67072,192984,44,22
MAGIC,REC_MAGIC,END=0x314e544832494c,0x3152544832494c,0x3145544832494c
TF,RF,DF=0x100,0x10000,0x400
MASK=(1<<64)-1
MASK_SEEDS=(0x0123456789abcdef,0xfedcba9876543210,0x55aa55aa55aa55aa,0xa55aa55aa55aa55a,
            1,0x8000000000000000,0x0f0f0f0ff0f0f0f0,0x5a5a5a5aa5a5a5a5)

def configuration(identity,h):
    need(type(identity)is int and 0<=identity<CASES,'one literal helper case')
    form,kind,pending=identity,0,0
    sp,status,operand=h[22]+2*PAGE+512,0x647 if identity&1 else 0xad7,h[23]+128
    data_upper=stack_upper=3
    if 29<=identity<35:
        form=(7,8,9,10,11,12)[identity-29];pending=1;kind=2 if identity>=32 else 0
    if identity>=35:
        form=(0,0,0,2,7,8,12,20,28)[identity-35];kind=1
        if identity==35:sp=h[22]+2*PAGE+128;stack_upper=0
        else:
            operand=h[23]+PAGE+64;data_upper=1 if identity==36 else 0
            if identity in(37,42,43):operand=h[23]+PAGE-4
            if identity in(38,41):operand=h[23]+PAGE-1
    return form,kind,pending,sp,status,operand,data_upper,stack_upper

def form_bytes(form,pc,operand):
    width,family=0,7
    if form==0:prefix,code,n,width,family=b'\x8f\x05',298,6,8,2
    elif form<=6:prefix,code,n,width,family=bytes((0x8c,5+8*(form-1))),288,6,2,1
    elif form in(7,8):prefix,code,n,width=bytes((0xd9 if form==7 else 0xdd,0x3d)),520 if form==7 else 615,6,2
    elif form==9:prefix,code,n=b'\xdb\xe3',582,2
    elif form in(10,11):prefix,code,n=bytes((0xd9,0xe8 if form==10 else 0xeb)),530 if form==10 else 533,2
    elif form==12:prefix,code,n=b'\xd9\x2d',515,6
    else:
        need(13<=form<29,'one actual K0..7 memory form')
        prefix=bytes((0xc4,0xe1,0xf8,0x90 if form<21 else 0x91,5+8*((form-13)%8)))
        code,n,family,width=(1919 if form<21 else 1923),9,6,0 if form<21 else 8
    if n>2:
        delta=operand-pc-n;need(-(1<<31)<=delta<1<<31,'literal signed original RIP operand displacement')
        prefix+=struct.pack('<i',delta)
    need(len(prefix)==n,'complete independent opcode')
    return prefix,code,n,family,width

def nx(value,pc):
    h,g,_=value
    need(h[:4]==(11,2,0,pc)and g[16]==pc and g[19:21]==(21,14)and g[22]==pc,'genuine original-byte NX event')

def lane(raw,h,identity,which):
    need(type(raw)is bytes and len(raw)==RECORD,'whole helper lane')
    r,resumed=words(raw,64),words(raw,23,512)
    form,kind,pending,sp,status,operand,data_upper,stack_upper=configuration(identity,h)
    n=2 if form in(9,10,11)else 9 if form>=13 else 6
    pc,stop=h[21]+PAGE-n,h[21]+PAGE
    opcode,code,n,family,width=form_bytes(form,pc,operand)
    expected=[0]*64
    expected[:13]=[REC_MAGIC,RECORD,identity,which,form,kind,pc,stop,operand,sp,status,pending,data_upper]
    expected[13:22]=[1,0,2,2,stack_upper,n,code,family,width]
    expected[25]=10;expected[26:28]=r[26:28]
    need(r==tuple(expected),'exact complete lane/permission/operation header with literal reserved zeros')
    need(not(r[26]|r[27])&TF,'actual signal entry clears live TF before the wrapper')
    before_raw,after_raw=raw[696:67768],raw[67768:134840]
    before,after=frame(before_raw,h,0),frame(after_raw,h,1)
    decoder=struct.pack('<QQ10I',pc,stop,1,0,code,0,16,0,0,15,n,0)+opcode+b'\xcc'*(15-n)+b'\0'
    classification=struct.pack('<QQ6I',pc,stop,1,1,code,n,1,family)
    footprint=struct.pack('<4Q4I',pc,stop,operand if width else 0,operand+width if width else 0,1,2 if width else 1,code,n)
    need(raw[134840:134912]==decoder and raw[134912:134952]==classification and raw[134952:135000]==footprint,
         'whole independently reconstructed decoder, helper flow/family and complete potential write range')
    rows=[(h[21],2*PAGE,3,0,0),(h[22],STACK,3,0,0),(h[23],2*PAGE,3,0,0),
          (h[22]+2*PAGE,PAGE,stack_upper,0,0),(h[23]+PAGE,PAGE,data_upper,0,0),
          (h[21],2*PAGE,1,0,0),(h[21],PAGE,5,1,0),(h[21],2*PAGE,1,2,0),
          (h[22],STACK,3,2,0),(h[23],2*PAGE,3,2,0)]
    need(raw[135000:135640]==b''.join(struct.pack('<5Q',*x)for x in rows)+bytes(6*40),
         'exact actual mprotect results and both source pages NX before terminal recovery')
    initial,final=raw[135640:152024],raw[152024:168408]
    source,di,df=raw[168408:176600],raw[176600:184792],raw[184792:192984]
    stack=bytes((0x5a+37*i+identity)&255 for i in range(STACK))
    data=bytearray((0x39+23*i+identity)&255 for i in range(2*PAGE))
    if form==12:struct.pack_into('<H',data,operand-h[23],0x0b7f)
    code_image=bytearray(b'\xcc'*(2*PAGE));code_image[PAGE-n:PAGE]=opcode
    need(initial==stack and final==initial,'all16384 stack bytes remain literal: these helpers never write their implicit POP source')
    need(di==bytes(data)and source==bytes(code_image),'whole initialized operand and two source pages')
    bh,bg,bfp=before;ah,ag,afp=after;nx(before,pc)
    seed=[(0x13579bdf00110000+0x100010001*i+identity)&MASK for i in range(16)];seed[4]=sp
    need([bg[i]for i in REG]==seed and bg[17]==status|RF,'complete actual seeded input GPR and original flags')
    want=list(bg);want[17]|=TF if which else 0
    need(resumed==tuple(want),'only actual owned-observation TF bit changes in the original-PC resumption')
    need(bh[7]==ah[7]and bh[8:10]==ah[8:10]and bg[18]==ag[18],'complete FP extents, TLS and segment context remain actual')
    need(words(before_raw[312:440],1)[0]==words(after_raw[312:440],1)[0]==h[36],'actual fixed asynchronous-signal mask retained in both events')
    before_masks=bfp[h[39]:h[39]+64]
    need(before_masks==struct.pack('<8Q',*MASK_SEEDS),'every actual pre-instruction K-register seed')
    need(bfp[160:416]==b''.join(struct.pack('<Q',0x3141592653589793+i)for i in range(1,33)),
         'all sixteen original XMM values independently seeded')
    cw,sw=struct.unpack_from('<HH',bfp)
    need((cw,sw,bfp[4])==((0x37e,0xb081,0xc0)if pending else(0x37f,0x3000,0xc0)),
         'actual seeded x87 TOP/tags and explicit unmasked pending invalid exception')
    need(bfp[32:160]==bytes.fromhex('35c26821a2da0fc90040000000000000'
                                  '0000000000000080ff3f000000000000')+bytes(96),
         'all eight x87 payload slots: exact live PI/one and six initialized free zeros, including literal padding')
    expected_regs=list(seed)
    if not kind and form==0:expected_regs[4]+=8
    need([ag[i]for i in REG]==expected_regs,'all16 actual output GPRs including exactly one successful POP stack increment')
    if not kind:
        if which:
            need(ah[:4]==(5,2,0,stop)and ag[16]==stop and ag[19:21]==(0,1)and ag[22]==pc and ag[17]==status|TF,
                 'genuine original-next TRACE with original first-NX CR2')
        else:nx(after,stop);need(ag[17]==status|RF,'native endpoint has genuine NX RF only')
        if width:
            if form==0:value=int.from_bytes(initial[sp-h[22]:sp-h[22]+8],'little')
            elif form<=6:value=h[40+form-1]
            elif form==7:value=cw
            elif form==8:value=sw
            else:value=MASK_SEEDS[form-21]
            data[operand-h[23]:operand-h[23]+width]=value.to_bytes(width,'little')
        need(df==bytes(data),'whole exact successful application-memory result, including selector stores')
        if 13<=form<21:
            masks=list(MASK_SEEDS);masks[form-13]=int.from_bytes(di[operand-h[23]:operand-h[23]+8],'little')
            need(afp[h[39]:h[39]+64]==struct.pack('<8Q',*masks),'exact actual selected K load and seven unchanged masks')
        else:need(afp[h[39]:h[39]+64]==before_masks,'all actual mask registers unchanged by non-load forms')
        if form==12:need(struct.unpack_from('<H',afp)[0]==0x0b7f,'actual FLDCW result at original PC')
        if form==9:need(struct.unpack_from('<HH',afp)==(0x37f,0)and not afp[4],'actual no-WAIT FNINIT reset')
    elif kind==1:
        fault_address=sp if identity==35 else h[23]+PAGE if identity in(37,38,41,42,43)else operand
        fault_error=7 if identity==36 else 4 if identity in(35,41,42)else 6
        need(ah[:4]==(11,2,0,fault_address)and ag[16]==pc and ag[19:21]==(fault_error,14)and ag[22]==fault_address and
             ag[17]==status|RF|(TF if which else 0),'actual first inaccessible byte data fault, unchanged PC and TF provenance')
    else:
        need(ah[:4]==(8,7,0,pc)and ag[16]==pc and ag[19:21]==(0,16)and ag[22]==pc and
             ag[17]==status|RF|(TF if which else 0),'actual pending invalid x87 #MF at the waiting original opcode')
    if not width:need(df==di,'NONE never conceals a helper memory store')
    else:
        for i,(a,b)in enumerate(zip(di,df,strict=True)):
            need(a==b or operand<=h[23]+i<operand+width,'every actual changed byte is inside the complete potential write range')
    return dict(header=r,before=before,after=after,before_raw=before_raw,after_raw=after_raw,
        initial=initial,final=final,data_before=di,data_after=df,kind=kind,form=form,pc=pc,stop=stop)

def pair(a,b):
    need(a['initial']==b['initial']and a['final']==b['final']and a['data_before']==b['data_before']and a['data_after']==b['data_after'],
         'whole native/TF stack and operand bytes including every hardware fault prefix')
    for name in('before','after'):
        ah,ag,afp=a[name];bh,bg,bfp=b[name]
        need(afp==bfp and ah[7:10]==bh[7:10],'all65536 FP bytes, exact extent and actual TLS at the same original instruction')
        expected=list(ag)
        if name=='after':
            if a['kind']:expected[17]|=TF
            else:expected[17]=(expected[17]&~RF)|TF;expected[19]=0;expected[20]=1;expected[22]=a['pc']
        need(tuple(expected)==bg,'all23 GREGs with only independently proved TF/NX event fields changed')
        ai,bi=a[name+'_raw'][440:568],b[name+'_raw'][440:568]
        if name=='after'and not a['kind']:
            expected_info=bytearray(ai);struct.pack_into('<i',expected_info,0,5)
            need(bytes(expected_info)==bi,'complete signal-info changes only native SIGSEGV to genuine TRACE SIGTRAP')
        else:need(ai==bi,'all128 signal-info bytes for identical original event')
        expected_uc=bytearray(a[name+'_raw'][568:1536])
        expected_uc[40:224]=struct.pack('<23Q',*expected)
        struct.pack_into('<Q',expected_uc,224,bh[6]);expected_uc[304:432]=bi
        need(bytes(expected_uc)==b[name+'_raw'][568:1536],
             'all968 context bytes: only authenticated FP pointer and exact raw event/GREG transforms; no tail masking')

def read(data,exit_status,placement,chunk,pid,cpu):
    need(exit_status==0,'complete finite observational process; any incomplete fault is a failure')
    need(type(data)is bytes and len(data)==512+2*CHUNK*RECORD+64 and len(data)<16<<20,'whole fixed22-pair bounded chunk')
    need(placement in(0,1)and chunk in(0,1)and type(pid)is int and pid>0 and type(cpu)is int and cpu>=0,'actual fixed placement/chunk/process CPU')
    h=words(data,64)
    need(h[:15]==(MAGIC,1,512,RECORD,FRAME,968,128,FP,STACK,PAGE,CASES,placement,chunk*CHUNK,CHUNK,2*CHUNK),
         'literal complete observational chunk header')
    need(h[15:17]==(pid,cpu)and ((h[17:19]==(0,0))or h[17]in((-22)&MASK,(-38)&MASK)),
         'actual command identity and unchanged CET exclusion observation')
    need(h[19]&0xe7==0xe7 and 576<=h[20]<=FP and h[21]==(0x200000000 if placement else 0x41000000)and
         h[22]==0x600000000 and h[23]==h[21]+(-4*PAGE if placement else 4*PAGE),
         'two exact original-PC placements and opposite signed RIP-relative data displacements')
    need(h[24]%PAGE==0 and h[24]>0 and h[25:28]==(256*1024,47,469)and h[28]and h[29]and
         h[30:34]==(72,48,40,16)and h[34]and h[35]==40,'actual guarded altstack and every original/new descriptive control')
    allowed=sum(1<<(s-1)for s in(4,5,7,8,9,11,19,32,33))
    need(h[36]==MASK&~allowed and h[37]&0x0c000000==0x0c000000 and h[38]&0x40010000==0x40010000 and
         576<=h[39]<=h[20]-64 and h[40:46]==(0,0x33,0x2b,0,0,0)and not any(h[46:]),
         'actual observational signal mask, hardware xstate/masks and unchanged six selectors')
    successes=memory_faults=mf_faults=0
    for identity in range(chunk*CHUNK,(chunk+1)*CHUNK):
        at=512+(identity-chunk*CHUNK)*2*RECORD
        a=lane(data[at:at+RECORD],h,identity,0);b=lane(data[at+RECORD:at+2*RECORD],h,identity,1);pair(a,b)
        successes+=a['kind']==0;memory_faults+=a['kind']==1;mf_faults+=a['kind']==2
    need(words(data,8,len(data)-64)==(END,1,2*CHUNK,len(data),0,0,0,0),'complete actual terminal transport')
    expected=(22,0,0)if chunk==0 else(10,9,3)
    need((successes,memory_faults,mf_faults)==expected,'every fixed success, memory fault and waiting-x87 case retained')
    return dict(profile='helper-tf-native-v1',status='observed_unqualified',placement=placement,chunk=chunk,
        cases=CHUNK,lanes=2*CHUNK,full_frames=4*CHUNK,successful_pairs=successes,memory_fault_pairs=memory_faults,
        pending_x87_fault_pairs=mf_faults,original_tf_refusals=47,descriptor_controls=469,raw_bytes=len(data),raw_sha256=digest(data),
        instruction_execution_at_original_pc=True,runtime_owner_credit=False,production_sigfpe_capture_credit=False,
        qualification_credit=False,performance_credit=False)

def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=Path);p.add_argument('--exit-status',required=True,type=int)
    p.add_argument('--placement',required=True,type=int,choices=(0,1));p.add_argument('--chunk',required=True,type=int,choices=(0,1))
    p.add_argument('--pid',required=True,type=int);p.add_argument('--cpu',required=True,type=int)
    a=p.parse_args();print(json.dumps(read(a.raw.read_bytes(),a.exit_status,a.placement,a.chunk,a.pid,a.cpu),sort_keys=True))
if __name__=='__main__':main()
