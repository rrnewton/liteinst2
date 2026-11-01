"""Distinct PF native write-fault references; successful mode0 stays separate.

Native exits0 only after retaining the original write fault and stopping before
its effect. Gated counterparts must exit125 with only the exact original prefix.
No capture is converted into a successful application completion.
"""
import importlib.util,struct,hashlib
from pathlib import Path
_spec=importlib.util.spec_from_file_location('pf_app_positive',Path(__file__).with_name('read.py'))
base=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(base)
need,q,u,live=base.need,base.q,base.u,base.live
PAGE,FP,FRAME,PREFIX,SUFFIX,OBS,MAGIC=base.PAGE,base.FP,base.FRAME,base.PREFIX,base.SUFFIX,base.OBS,base.MAGIC
DATA,STACK,RSEQ,RSP,U64,TF,RF,MASK=base.DATA,base.STACK,base.RSEQ,base.RSP,base.U64,base.TF,base.RF,base.MASK
GREG,MASKS,LIVE_SEED=base.GREG,base.MASKS,base.LIVE_SEED
TRACES=(2838,6,6)
STEPS=(0,1,6)

def destination(mode,image):
    need(type(mode)is int and mode in(1,2),'one exact original fault mode')
    return DATA+8192 if mode==1 else image['page']+0x600

def fixture(mode,image):
    seed,data,stack=base.fixture(0,image);g=list(seed[0]);g[2]=destination(mode,image)-0x1000
    return (tuple(g),seed[1],seed[2]),data,stack

def trace_model(prefix):
    g=list(prefix['seed'][0]);flags=prefix['seed'][1];page=prefix['source_page_address']
    out=[(page+0x203,tuple(g),flags)]
    g[2],flags=base.arithmetic(g[2],g[12],flags);out.append((page+0x206,tuple(g),flags))
    need(q(prefix['data'],8)[0]==8,'first actual table type is8')
    _,flags=base.arithmetic(8,8,flags,True);out.append((page+0x20a,tuple(g),flags))
    need(flags&0x40,'forward branch not taken');out.append((page+0x210,tuple(g),flags))
    g[1]=q(prefix['data'],16)[0];out.append((page+0x214,tuple(g),flags))
    g[0],flags=base.arithmetic(g[0],24,flags);out.append((page+0x218,tuple(g),flags))
    g[1],flags=base.arithmetic(g[1],g[12],flags);out.append((page+0x21b,tuple(g),flags))
    need(g[2]==prefix['fault_address']and flags==0x206,'exact original before-store fault state')
    return out

def frame_pc(prefix,kind):return trace_model(prefix)[STEPS[kind]][0]
def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]
def state(seed,data,mode):
    g=list(seed);g[0]=DATA+24;g[1]=0x3141592600001000;g[2]+=0x1000
    return tuple(g)
def written(data,mode):return data

def _prefix(data,mode,native,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode in(1,2) and type(native)is bool,'typed complete persistent app prefix')
    need(mode in(1,2),'two separate original write-fault modes')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:18592],data[18592:18816],data[18816:27008]
    head=image['head'];frontier=image['symbols']['region_app_capture_high'];predecessor=head-3
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,12,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,1,image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,destination(mode,image),8,frontier,predecessor,TRACES[mode],OBS,12,40,image['page']+0x2400,image['page']+PAGE,16384,RSEQ,0x53053053,image['page']+0x20a,image['page']+0x2409,image['page']+0x223),'exact cyclic fixture and reserved header')
    need(source==image['source']and machine[0]==MASK and machine[1:3]==(0,0) and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component geometry')
    expected,want_data,want_stack=fixture(mode,image)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/stack bytes')
    registration=q(data,27008,9)
    need(registration==(U64,)+(0,)*8,'explicit registration not-attempted marker and unavailable snapshots')
    return dict(symbols=image['symbols'],header=h,mode=mode,head=head,predecessor=predecessor,source_page_address=image['page'],source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=frontier,fault_pc=image['page']+0x21b,fault_address=destination(mode,image),suffix=None,observations=[])


def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    fault=kind==2
    sig = 11 if kind==0 or fault else 5
    need(h[:5] == (1, kind, steps, attempt, sig) and h[7] == 968 and 580 <= h[9] <= FP and h[10] % PAGE == 0 and h[11] == 524288, 'native frame header')
    observations = ((h[5], si), (h[6], uc[:968]), (h[8], fp[:h[9]]))
    for a, value in observations:
        need(h[10] <= a <= h[10] + h[11] - len(value), 'actual altstack bounded view')
        for b, other in observations:
            lo, hi = max(a, b), min(a + len(value), b + len(other))
            if lo < hi:
                need(value[lo - a:hi - a] == other[lo - b:hi - b], 'complete aliased physical kernel view')
    need(h[8] % 16 == 0 and q(uc, 224)[0] == h[8] and uc[968:] == bytes(56) and fp[h[9]:] == bytes(FP - h[9]), 'actual FP pointer and full unused capacities')
    need(u(fp, 464, 2) == (0x46505853, h[9]) and u(fp, 480)[0] == h[9] - 4 and u(fp, h[9] - 4)[0] == 0x46505845 and q(fp, 520)[0] == 0, 'complete standard kernel FP geometry')
    need(q(uc, 296)[0] == prefix['machine'][0] and q(uc, 16)[0] == h[10] and u(uc, 24)[0] == 0 and q(uc, 32)[0] == h[11], 'actual application mask and altstack')
    g = q(uc, 40, 23); pc = frame_pc(prefix,kind)
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else ((6 if prefix['mode']==1 else 7), 14) if fault else (0, 1)), 'genuine native signal origin')
    if kind==0 or fault:
        address = prefix['fault_address'] if fault else pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    else:need(q(si,16)[0]==pc and g[22]==prefix['predecessor'],'actual TRACE PC and retained original NX CR2')
    expected = frame_state(prefix,kind)
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    expected_flags=trace_model(prefix)[steps][2] | (RF if kind==0 else TF|RF if fault else TF)
    need(g[17]==expected_flags,'every actual native flag including AF and causal TF/RF')
    need(h[9] <= prefix['header'][15] + 4 and q(fp, 512)[0] & ~prefix['header'][14] == 0 and q(fp, 512)[0] & 0xe7 == 0xe7, 'full bounded standard enabled state')
    for reg in range(32):
        for word in range(8):
            if reg >= 16:
                feature, offset = 7, (reg - 16) * 64 + word * 8
            elif word >= 4:
                feature, offset = 6, reg * 32 + (word - 4) * 8
            elif word >= 2:
                feature, offset = 2, reg * 16 + (word - 2) * 8
            else:
                feature, offset = 0, 160 + reg * 16 + word * 8
            if feature:
                row = prefix['hardware'][3 + feature]
                need(offset + 8 <= row[2], 'whole vector component')
                offset += row[3]
            need(offset + 8 <= h[9] - 4 and q(fp, offset)[0] == 0x3141592653589793 + reg * 8 + word + 1, 'every actual vector word')
    opmask = prefix['hardware'][8]
    need(opmask[2] >= 64 and fp[opmask[3]:opmask[3] + 64] == MASKS, 'every actual opmask byte')
    # The unchanged independent seed probe qualifies these exact zero pointers,
    # including observations before and after FNSTCW/FNSTSW. No byte is ignored.
    need(fp[8:24] == bytes(16) and struct.unpack_from('<HH', fp) == (0x37f, 0x3000) and fp[4] == 0xc0 and u(fp, 24)[0] == 0x1f80, 'independently qualified exact zero FIP/FDP and initial scalar FP')
    return dict(header=h, si=si, uc=uc, fp=fp, greg=g)


def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and mode in(1,2) and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    full=native
    need(exit_status==(0 if native else 125)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated status and complete output')
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)
    if not full:return r
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,12,mode,int(native),0,1,1,3,6,1,2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,3,6,1,int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],r['data'],mode)and after[1]==0x206,'all defined stopped-before-store GPR and flag results')
    need(value[4792:21176]==r['source']and value[21176:21400]==r['stack']and value[21400:29592]==written(r['data'],mode),'whole source/stack and exact completed store effects')
    frames=[]
    for i in range(12):
        frame=value[29592+i*FRAME:29592+(i+1)*FRAME]
        if i>=3:need(frame==bytes(FRAME),'no fabricated native signal')
        else:
            kind=i
            steps=STEPS[i]
            frames.append(reference_frame(frame,r,image,kind,steps,0))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[21400:29592],stack=value[21176:21400])]
    r['effects']=effects;r['suffix']=dict(end=end);return r


CONTROL_COUNT=16
def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)
    need(native,'the separate complete native fault reference supplies these controls')
    frame=PREFIX+400+29592+2*FRAME
    tests=(('mode',32),('destination',32*8),('seed_RDX',1992+16),('source',2208),
        ('data',18816),('before_RIP',frame+224+40+16*8),('before_flags',frame+224+40+17*8),
        ('trap',frame+224+40+20*8),('CR2',frame+224+40+22*8),('siginfo',frame+96),
        ('FP',frame+1248+160),('UC_alias',frame+224+304),('fault_count',PREFIX+9*8),
        ('whole_memory',PREFIX+400+21400),('cleanup',PREFIX+5*8),('unused_frame',frame+FRAME))
    need(len(tests)==len(set(n for n,_ in tests))==CONTROL_COUNT,'all literal native fault controls')
    refused=[]
    for name,at in tests:
        value=bytearray(data);value[at]^=1
        try:read(bytes(value),mode,native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed native PF fault '+name)
    return dict(refusals=refused,original_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)
