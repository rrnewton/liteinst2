#!/usr/bin/env python3
"""Finite original/tile flags observations; no runtime-owner qualification."""
import argparse,hashlib,importlib.util,json,struct
from pathlib import Path
HELPER=Path(__file__).with_name('frame.py')
if hashlib.sha256(HELPER.read_bytes()).hexdigest()!='4512c512f7d1148d5cb32d46223a39ec24085b824baefd8894dbbb8689164544':
    raise ValueError('exact whole native frame/context donor')
spec=importlib.util.spec_from_file_location('flag_stack_frame',HELPER)
donor=importlib.util.module_from_spec(spec);spec.loader.exec_module(donor)
need,words,digest,frame,normalized_context=donor.need,donor.words,donor.digest,donor.frame,donor.normalized_context
REG=donor.REG
PAGE,FP,STACK,FRAME,RECORD,CASES=4096,65536,16384,67072,180664,18
MAGIC,REC_MAGIC,END=0x314e534632494c,0x3152534632494c,0x3145534632494c
TF,RF,DF,AC,NT,VM=0x100,0x10000,0x400,0x40000,0x4000,0x20000
MASK=(1<<64)-1

def configuration(identity,h):
    op=1 if identity<6 or identity==16 else 2
    kind,sp,status,word,upper=0,h[22]+2*PAGE+512,0x202,0x202,3
    if identity==0:status=0xed7
    elif identity==2:status|=AC
    elif identity==3:status|=AC;sp+=1;kind=1
    elif identity==4:upper=1;kind=2
    elif identity==5:sp=h[22]+2*PAGE+4;upper=0;kind=2
    elif identity==6:word=0xad7
    elif identity==7:word=0x602
    elif identity==8:word=0x40202
    elif identity==9:word=0x302;kind=3
    elif identity==10:word=0x4202;kind=4
    elif identity==11:word=0x33202
    elif identity==12:status|=AC;sp+=1;kind=1
    elif identity==13:upper=0;kind=2
    elif identity==14:sp=h[22]+2*PAGE-4;upper=0;kind=2
    elif identity==15:status|=AC
    elif identity==16:sp=0x0100000000000008;kind=5
    elif identity==17:sp=0x0100000000000000;kind=5
    return op,kind,sp,status,word,upper

def descriptor(pc,op):
    code,disposition,byte=(317,2,0x9c) if op==1 else (320,3,0x9d)
    return struct.pack('<QQ10I',pc,pc+1,1,0,code,0,16,0,disposition,15,1,0)+bytes([byte])+b'\xcc'*14+b'\0'+struct.pack('<II',1,op)

def footprint(pc,op,sp):
    first,end,policy=(sp-8,sp,2) if op==1 and sp>=8 else (0,0,0) if op==1 else (0,0,1)
    return struct.pack('<4Q4I',pc,pc+1,first,end,1,policy,317 if op==1 else 320,1)

def event(f,pc,stop,image,which):
    h,g,_=f
    if h[0]==11 and h[1]==2 and not h[2] and g[20]==14 and g[19]==21 and g[16]==stop and h[3]==stop and g[22]==stop:
        return 'original-next-nx'
    if h[0]==5 and h[1]==2 and not h[2] and g[20]==1 and not g[19] and h[3]==g[16] and g[16] in ((image+1,stop) if which else (stop,)):
        return 'post-pop-trace'
    need(g[16]==(image if which else pc), 'fault is at the actual original/tile opcode, never replayed')
    need((h[0]==11 and g[20] in (12,13,14)) or (h[0]==7 and g[20] in (12,17)),
         'actual stack fault has the native hardware trap class')
    return 'stack-fault'

def lane(raw,h,identity,which):
    need(len(raw)==RECORD,'whole complete lane')
    r,resumed=words(raw,64),words(raw,23,512)
    op,kind,sp,status,word,upper=configuration(identity,h)
    pc,stop,image=h[21]+PAGE-1,h[21]+PAGE,h[23]
    expected=[0]*64
    expected[:13]=[REC_MAGIC,RECORD,identity,which,op,kind,pc,stop,image,sp,status,word,upper]
    expected[13:17]=[1,0,2,2];expected[24]=int(kind==5);expected[25]=10
    expected[26:28]=r[26:28]
    need(r==tuple(expected),'exact fixed case/lane header, complete prefix and zero reserved words')
    need(not (r[26]|r[27])&TF,'real handler entry has no live TF before its aligned clear wrapper')
    before_raw,after_raw=raw[696:67768],raw[67768:134840]
    before,after=frame(before_raw,h,0),frame(after_raw,h,1)
    need(raw[134840:134920]==descriptor(pc,op) and raw[134920:134968]==footprint(pc,op,sp),
         'whole independent descriptor and complete potential write range')
    rows=[(h[21],2*PAGE,3,0,0),(image,PAGE,3,0,0),(h[22],STACK,3,0,0),
          (h[22]+2*PAGE,PAGE,upper,0,0),(h[21],2*PAGE,1,0,0),(image,PAGE,1,0,0),
          (image if which else h[21],PAGE,5,1,0),(h[21],2*PAGE,1,2,0),
          (image,PAGE,1,2,0),(h[22],STACK,3,2,0)]
    need(raw[134968:135608]==b''.join(struct.pack('<5Q',*x) for x in rows)+bytes(6*40),
         'exact actual permission order/results, both code mappings NX before terminal return')
    initial,final=raw[135608:151992],raw[151992:168376]
    source,generated=raw[168376:176568],raw[176568:180664]
    stack=bytearray((0x5a+37*i+identity)&255 for i in range(STACK))
    if op==2 and h[22]<=sp<=h[22]+STACK-8:struct.pack_into('<Q',stack,sp-h[22],word)
    need(initial==stack,'whole literal initialized stack, including original POP operand')
    code=bytearray(b'\xcc'*(2*PAGE));code[PAGE-1]=0x9c if op==1 else 0x9d
    tile=bytes([code[PAGE-1]])+b'\xff\x25\x01\0\0\0\xcc'+struct.pack('<Q',stop)
    need(source==code and generated==tile+b'\xcc'*(PAGE-16),'whole original and aligned16-byte tile images')
    bh,bg,bfp=before;ah,ag,afp=after
    seed=[(0x13579bdf00110000+0x100010001*i+identity)&MASK for i in range(16)];seed[4]=sp
    need([bg[i] for i in REG]==seed and bg[16]==pc and bg[17]==status|RF and bg[20]==14 and bg[19]==21 and bg[22]==pc and
         bh[:4]==(11,2,0,pc),'genuine original opcode NX with complete literal input GPR/flags')
    expected_resume=list(bg)
    if kind==5:expected_resume[16]=h[28];expected_resume[15]=h[29];expected_resume[17]&=~(TF|RF|DF|AC|NT)
    elif which:expected_resume[16]=image
    need(resumed==tuple(expected_resume),'exact recorded signal-return edit; no speculative operand read or TF injection')
    need(bh[7]==ah[7] and bfp==afp,'every full FP byte remains exact through flag-stack execution')
    need(ah[8:10]==bh[8:10] and ag[18]==bg[18], 'actual FS/GS bases and selectors remain exact')
    need(all(ag[REG[i]]==seed[i] for i in range(16) if i!=4),'all fifteen non-stack GPRs remain exact')
    observed=event(after,pc,stop,image,which)
    if kind in (1,2,5):
        need(observed=='stack-fault','fault stimulus stays a failed hardware operation')
        need(ag[15]==sp,'faulting PUSH/POP retains the original architectural RSP')
        if kind==1:need(ah[0]==7 and ag[20]==17 and not ag[19],'AC misalignment remains actual #AC')
        elif kind==2:need(ah[0]==11 and ag[20]==14 and not ag[19]&16,'data permission/page-crossing remains an actual data #PF')
        else:need(ag[20] in (12,13) and not ag[19], 'noncanonical stack retains actual #SS/#GP without LA57 guess')
        # A fault prefix has no success credit. All memory is compared to the
        # independent native lane, including any architecturally exposed store.
    else:
        need(ag[15]==sp+(-8 if op==1 else 8),'exact hardware stack update once')
        if kind==3:
            need(observed in ('original-next-nx','post-pop-trace') and ag[17]&TF,
                 'actual POPFQ TF event retained; no guessed #DB/#PF priority')
        else:need(observed=='original-next-nx','first genuine original-next NX, before its instruction')
        if op==1:
            struct.pack_into('<Q',stack,sp-h[22]-8,status&~(RF|VM))
            logical=status
        else:
            modifiable=0x244dd5
            logical=(status&~modifiable)|(word&modifiable)
        need(ag[17]&~RF==logical,'complete hardware RFLAGS including IF/IOPL/RF/VM/AC/NT behavior')
        need(final==stack,'whole final stack, precisely one PUSH write or no POP write')
    if op==2:need(final==initial,'POPFQ never writes its guest operand or other stack bytes')
    return dict(header=r,before=before,after=after,before_raw=before_raw,after_raw=after_raw,
                initial=initial,final=final,event=observed,kind=kind,op=op,sp=sp,pc=pc,stop=stop,image=image)

def pair(a,b):
    need(a['initial']==b['initial'] and a['final']==b['final'],'whole native/tile stack including every fault-prefix byte')
    for name in ('before','after'):
        ah,ag,afp=a[name];bh,bg,bfp=b[name]
        need(afp==bfp and ah[7:10]==bh[7:10], 'whole native/tile FP and actual TLS')
        left,right=list(ag),list(bg)
        ai,bi=bytearray(a[name+'_raw'][440:568]),bytearray(b[name+'_raw'][440:568])
        if name=='after' and a['kind']==3:
            # Only this unsupported TF-output observation can have different
            # #DB/fetch ordering. It receives no native-equivalence credit.
            need([ag[i] for i in REG]==[bg[i] for i in REG] and (ag[17]&~RF)==(bg[17]&~RF) and ag[18]==bg[18],
                 'actual committed TF-output GPR/flags/selector state, no stripping in raw capture')
            continue
        if name=='after' and a['event']=='stack-fault':right[16]=a['pc']
        need(left==right,'complete native/tile GREGs; only exact copied fault RIP translates')
        need(ai==bi,'all128 native/tile siginfo bytes')
        need(normalized_context(a[name+'_raw'],left,ai)==normalized_context(b[name+'_raw'],right,bi),
             'whole raw context/mask, with only independently checked FP pointer and exact fault PC projection')

def read(data,exit_status,placement,pid=None,cpu=None):
    need(exit_status==0,'complete original native diagnostic process')
    need(len(data)==512+2*CASES*RECORD+64,'exact fixed18-pair raw extent')
    h=words(data,64)
    need(h[:15]==(MAGIC,1,512,RECORD,FRAME,968,128,FP,STACK,PAGE,CASES,placement,0,CASES,2*CASES),
         'fixed complete native/tile placement header')
    need(h[15]>0 and (pid is None or h[15]==pid) and (cpu is None or h[16]==cpu),'actual command PID/CPU')
    need((h[17]==0 and h[18]==0) or h[17] in ((-22)&MASK,(-38)&MASK), 'original observed CET query contract')
    need(h[19]&3==3 and 512<=h[20]<=FP and h[21]==(0x200000000 if placement else 0x41000000) and
         h[22]==0x600000000 and h[23]==(0x42000000 if placement else 0x300000000) and
         abs(h[21]-h[23])>0x7fffffff,'two literal opposite far placements, unchanged absolute target')
    need(h[24]>0 and h[24]%PAGE==0 and h[25:28]==(256*1024,47,0) and h[28] and h[29] and
         h[30:34]==(80,48,40,16) and h[34] and h[35]==60 and not any(h[36:]),
         'actual bootstrap/alternate stack and original47 plus new60 descriptor controls')
    observations=[]
    for identity in range(CASES):
        at=512+identity*2*RECORD
        a=lane(data[at:at+RECORD],h,identity,0)
        b=lane(data[at+RECORD:at+2*RECORD],h,identity,1);pair(a,b)
        if a['kind'] in (3,4):
            observations.append(dict(case=identity,kind='unsupported_tf_output' if a['kind']==3 else 'unsupported_nt_output',
                native_event=a['event'],tile_event=b['event'],native_signal=a['after'][0][0],tile_signal=b['after'][0][0],
                native_trap=a['after'][1][20],tile_trap=b['after'][1][20],
                native_flags=a['after'][1][17],tile_flags=b['after'][1][17],
                native_stack_delta=a['after'][1][15]-a['sp'],tile_stack_delta=b['after'][1][15]-b['sp']))
    need(words(data,8,len(data)-64)==(END,1,2*CASES,len(data),0,0,0,0),'exact terminal completion')
    return dict(profile='flag-stack-native-v1',status='observed_unqualified',placement=placement,
        cases=18,lanes=36,full_frames=72,supported_pairs=8,fault_pairs=8,unsupported_state_pairs=2,
        original_tf_refusals=47,descriptor_controls=60,raw_bytes=len(data),raw_sha256=digest(data),
        observations=observations,runtime_owner_credit=False,qualification_credit=False,performance_credit=False)

def main():
    p=argparse.ArgumentParser();p.add_argument('raw',type=Path);p.add_argument('--exit-status',required=True,type=int)
    p.add_argument('--placement',required=True,type=int,choices=(0,1));p.add_argument('--pid',required=True,type=int)
    p.add_argument('--cpu',required=True,type=int)
    a=p.parse_args();print(json.dumps(read(a.raw.read_bytes(),a.exit_status,a.placement,a.pid,a.cpu),sort_keys=True))
if __name__=='__main__':main()
