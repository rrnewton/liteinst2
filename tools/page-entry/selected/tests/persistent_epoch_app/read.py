"""Finite persistent-epoch application reader. Actual native frames retain every
GREG, FP byte, stack/data byte and AF; generated recovery is checked separately."""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=18888,222152,221752,66784
MAGIC=0x315050414550494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES=(23,13,0)
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)

def u(data,at=0,count=1):return struct.unpack_from('<'+'I'*count,data,at)

def elf(data, native_policy):
    need(type(data) is bytes and 64 <= len(data) <= 16 << 20, 'complete bounded ELF')
    def take(at, n):
        need(type(at) is int and type(n) is int and 0 <= at <= len(data) and 0 <= n <= len(data) - at, 'ELF range')
        return data[at:at + n]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1) and h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64 and 0 < h[12] <= 256, 'exact ET_EXEC x86-64 header')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5] + i * 56, 56)) for i in range(h[10])]
    loads = [p for p in ph if p[0] == 1]
    need(loads and all(p[5] <= p[6] and p[3] <= U64 - p[6] and p[7] in (4096, 2097152) and p[1] & 3 != 3 for p in loads), 'complete non-WX loads')
    for p in loads:
        take(p[2], p[5])
    def memory(pc, n):
        owners = [p for p in loads if p[3] <= pc and n <= p[5] and pc - p[3] <= p[5] - n]
        need(len(owners) == 1, 'one complete file backed range')
        p = owners[0]
        return p, take(p[2] + pc - p[3], n)
    interp = [p for p in ph if p[0] == 3]
    need(len(interp) == 1, 'actual system interpreter')
    path = take(interp[0][2], interp[0][5])
    need(path.startswith(b'/') and path.endswith(b'\0') and b'\0' not in path[:-1], 'complete interpreter name')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i * 64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0, 'one complete symtab')
    t = tables[0]
    need(t[6] < len(sections), 'symbol string index')
    strings = sections[t[6]]; names = take(strings[4], strings[5])
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'predecessor', 'block_b', 'second_page', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
    symbols = {}; symbol_sizes = {}
    for at in range(t[4], t[4] + t[5], 24):
        name, _, _, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'whole symbol name')
        name = names[name:names.index(b'\0', name)].decode()
        if name in wanted:
            need(name not in symbols and section != 0, 'unique defined fixture symbol')
            symbols[name] = value; symbol_sizes[name] = size
    need(set(symbols) == wanted, 'all actual fixture symbols')
    head, page = symbols['region_app_head'], symbols['region_app_page']
    p,source=memory(page,2*PAGE)
    need(page%PAGE==0 and head==page+0x200 and symbols['region_app_source_end']==page+2*PAGE and
         p[1]==5 and p[2]+page-p[3]>=PAGE,'actual two complete RX source pages outside ELF header')
    expected=bytearray(b'\xcc'*(2*PAGE));expected[0x1fe:0x200]=b'\x66\x90'
    expected[0x200:0x210]=bytes.fromhex('4889074883c0014839c80f82')+struct.pack('<i',0x1100-0x210)
    expected[0x210:0x21e]=b'\xff\x25\0\0\0\0'+struct.pack('<Q',symbols['region_app_capture_high'])
    expected[0x1100:0x1109]=bytes.fromhex('4883c708e9')+struct.pack('<i',0x200-0x1109)
    need(source==expected,'whole six-head25-byte cyclic source and every gap/frontier')
    for name,offset,size in (('head',0x200,16),('block_b',0x1100,9),('exit0',0x210,6)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,'actual typed source symbol geometry')
    need(symbols['region_app_predecessor']==page+0x1fe and symbols['region_app_second_page']==page+PAGE,
         'actual unchanged NOP and distinct second source page')
    for prefix in ('helper', 'pure'):
        address = symbols['region_app_' + prefix]
        need(address != head and address % PAGE == 0 and symbols['region_app_' + prefix + '_end'] == address + PAGE and memory(address, PAGE)[0][1] == 5 and native_policy(memory(address - 14, PAGE + 28)[1]) == 0, 'complete actual native helper plus halos, no policy exemption')
    pure = symbols['region_app_pure']
    pure_load, pure_image = memory(0x200000000, 3 * PAGE)
    need(pure == 0x200001000 and pure_load[1] == 5 and pure_load[3] == 0x200000000 and
         pure_load[5] == pure_load[6] == 3 * PAGE and
         pure_image[:PAGE] == pure_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high RX helper load with complete unchanged-policy halos')
    helper = symbols['region_app_helper']; capture = symbols['region_app_capture']
    high_capture = symbols['region_app_capture_high']; transfer = symbols['region_app_entry_jump']
    machine_load, machine_image = memory(0x200020000, 3 * PAGE)
    need(helper == 0x200021000 and machine_load[1] == 5 and machine_load[3] == 0x200020000 and
         machine_load[5] == machine_load[6] == 3 * PAGE and
         machine_image[:PAGE] == machine_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high assembly RX load and complete CC halos')
    need(PAGE <= head < 1 << 31 and PAGE <= capture < 1 << 31 and head != capture and
         capture % PAGE == 0 and symbols['region_app_return_end'] == capture + PAGE and
         memory(capture, PAGE)[0][1] == 5 and memory(capture, PAGE)[1] ==
         b'\xff\x25\0\0\0\0' + struct.pack('<Q', high_capture) + b'\xcc' * (PAGE - 14),
         'complete low return page with transparent original-PC JMP and exact immutable high target')
    ro, constants = memory(0x200010000, PAGE)
    need(ro[1] == 4 and ro[3] == 0x200010000 and ro[5] == ro[6] == PAGE and
         symbols['ua_vectors'] == ro[3] and symbols['ua_masks'] == ro[3] + 2048 and
         symbols['region_app_head_pointer'] == ro[3] + 2112 and
         constants == VECTORS + MASKS + struct.pack('<Q', head) + bytes(PAGE - 2120),
         'complete immutable nonexecuting assembly constants and actual low head pointer')
    state_loads = [x for x in loads if x[3] == 0x200030000]
    need(len(state_loads) == 1 and state_loads[0][1] == 6 and state_loads[0][5:7] == (0, 2 * PAGE),
         'separate zero-initialized nonexecuting assembly state load')
    extents = []
    for name, size in (('input', 152), ('before', 152), ('after', 152),
                       ('before_live', LIVE), ('after_live', LIVE), ('host', 64), ('host_fcw', 2), ('target',8)):
        address = symbols['ua_' + name]
        need(symbol_sizes['ua_' + name] == size and 0x200030000 <= address <= 0x200032000 - size and
             all(address + size <= a or a + n <= address for a, n in extents),
             'complete distinct assembly state objects in the exact high RW load')
        extents.append((address, size))
    displacement = symbols['ua_target'] - (transfer + 6)
    need(helper <= symbols['region_app_enter'] <= symbols['region_app_seed_x87'] - 4 and
         symbols['region_app_seed_x87'] < transfer and transfer + 6 == high_capture < helper + PAGE and
         memory(symbols['region_app_seed_x87'] - 4, 6)[1] == b'\xdb\xe3\xd9\xe8\xd9\xeb' and
         -(1 << 31) <= displacement < 1 << 31 and
         memory(transfer, 6)[1] == b'\xff\x25' + struct.pack('<i', displacement),
         'exact seed/entry/capture positions and transparent high-to-low actual mode-pointer JMP')
    return dict(symbols=symbols, head=head, page=page, exits=(page+0x210,head,head), source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10])

def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]

def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    sig = 11 if kind in (0, 3) else 5
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
    g = q(uc, 40, 23); pc = prefix['predecessor'] if kind == 0 else prefix['head'] if kind == 1 else prefix['expected_exit_pc']
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (6, 14) if kind == 3 else (0, 1)), 'genuine native signal origin')
    if kind in (0, 3):
        address = prefix['fault_address'] if kind == 3 else pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    else:need(q(si,16)[0]==pc,'actual TRACE PC signal address')
    expected = prefix['seed'][0] if kind in (0,1) else state(prefix['seed'][0], prefix['data'], prefix['mode'])
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    if kind == 0:
        need(g[17] == prefix['seed'][1] | RF, 'actual NX seed flags')
    elif kind == 1:
        need(g[17] == prefix['seed'][1] | TF, 'exact unchanged flags after actual predecessor NOP')
    else:
        need(g[17] & (TF | RF) == (TF | (RF if kind == 3 else 0)), 'actual reference observer flags')
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

def fixture(mode):
    need(type(mode)is int and mode in range(3),'fixed two pairs and protected-word rejection')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=0 if mode==2 else 1;seed[1]=5;seed[4]=RSP
    seed[7]=RSEQ+8 if mode==2 else DATA+8192-16 if mode==1 else DATA
    return (tuple(seed),0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(224))

def state(seed,data,mode):
    out=list(seed)
    if mode==0:out[0]=5;out[7]+=24
    elif mode==1:out[0]=3;out[7]+=16
    return tuple(out)

def written(data,mode):
    out=bytearray(data)
    for i in range(4 if mode==0 else 2 if mode==1 else 0):
        struct.pack_into('<Q',out,(0 if mode==0 else 8192-16)+8*i,i+1)
    return bytes(out)

def _prefix(data,mode,native,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode in range(3)and type(native)is bool,'typed complete persistent app prefix')
    need(not(native and mode==2),'protected-word rejection has no claimed native pair')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:10400],data[10400:10624],data[10624:18816]
    head=image['head'];frontier=image['page']+0x210
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode==1),image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,head-2,TRACES[mode],OBS,3,25,image['page']+0x1100,image['page']+PAGE,8192,RSEQ,0x53053053,0,0,0),'exact cyclic fixture and reserved header')
    need(source==image['source']and machine[0]==MASK and machine[1]>0 and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component geometry')
    expected,want_data,want_stack=fixture(mode)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/stack bytes')
    registration=q(data,18816,9)
    need(registration==(0,0,0,0,0,cpu|(cpu<<32),0,0,0),'actual successful registration and zero publication word')
    return dict(header=h,mode=mode,head=head,predecessor=head-2,source_page_address=image['page'],source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=head if mode==1 else frontier,fault_pc=head if mode==1 else 0,fault_address=DATA+8192 if mode==1 else 0,suffix=None,observations=[])

def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and mode in range(3)and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    full=native or mode==0
    need(exit_status==(0 if mode==0 else 125)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated status and complete output')
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)
    if not full:return r
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,1,mode,int(native),0,1,1,3 if native else 0,TRACES[mode]if native else 0,int(mode==1),0,0,0,0,0,0),'complete cleanup and invocation count')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,3 if native else 0,TRACES[mode]if native else 0,int(mode==1),int(native),0,0,image['page']+0x210,0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],r['data'],mode),'exact defined loop GPR result')
    need(value[4792:12984]==r['source']and value[12984:13208]==r['stack']and value[13208:21400]==written(r['data'],mode),'whole source/stack and exact completed store effects')
    frames=[]
    for i in range(3):
        frame=value[21400+i*FRAME:21400+(i+1)*FRAME]
        if not native:need(frame==bytes(FRAME),'no fabricated native signal')
        else:frames.append(reference_frame(frame,r,image,i if i<2 else 3 if mode==1 else 2,0 if i==0 else 1 if i==1 else TRACES[mode],0))
    if native:
        need(frames[0]['fp']==frames[1]['fp']==frames[2]['fp'],'all65536 native FP bytes conserved')
        need(after[1]==frames[2]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[13208:21400])]
    r['effects']=effects;r['suffix']=dict(end=end);return r


def pair(native,gated,owner):
    """Two real native/generated pairs, including the actual late write fault."""
    mode=native['mode']
    need(mode in(0,1)and gated['mode']==owner['mode']==mode and native['header'][5]==1 and gated['header'][5]==0,'exact actual persistent native/gated pair')
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and
         all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')
    need(len(native['observations'])==1 and len(gated['observations'])==int(mode==0),'all actual finite application observations')
    reference=native['observations'][0];frames=reference['frames'];machine=gated['machine']
    def compare(actual,ref,event):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK,'complete actual protected pair frame')
        want=list(ref['greg'])
        if event=='closed' or event=='fault':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        else:need(event=='original','only exact actual event transforms')
        need(actual['greg']==tuple(want)and actual['fp']==ref['fp'],'all23 GREG/65536 FP including actual AF')
        need((actual['fs'],actual['gs'])==tuple(machine[1:3]),'actual protected pair TLS')
    compare(owner['predecessor_before'],frames[0],'original')
    compare(owner['ingress'],frames[1],'original');compare(owner['before'],frames[1],'closed')
    compare(owner['logical'],frames[2],'fault'if mode else'nx')
    need(owner['source']==native['source']and owner['before_memory']==dict(data=native['data'],stack=native['stack'])and
         owner['after_memory']==dict(data=reference['data'],stack=native['stack']),'whole actual pair source/stack/store effects')
    need(owner['interior_signals']==0 and owner['closed_pages']==8 and owner['anchor_released']==1 and owner['word']==0 and
         owner['completed']==owner['permit']==int(mode==0)and owner['guest_data_fault']==mode and owner['guard_rejected']==0,'actual no-interior-event owner and terminal disposition')
    if mode==0:
        actual=gated['observations'][0]
        need(reference['before']==actual['before']and reference['after']==actual['after']and reference['live']==actual['live']and reference['data']==actual['data'],'entire actual application after-state')
        need(gated['effects']==native['effects']and gated['suffix']is not None,'both real registration/unregistration effects')
    else:need(gated['suffix']is None,'late fault never resumes or unregisters application')
    return dict(qualified_pair=1,invocations=1,generated_completed=int(mode==0),required_late_store_fault=mode,interior_signals=0,whole_reuse_credit=0)


APP_CONTROL_COUNTS={0:16,1:16}
PAIR_CONTROL_COUNTS={0:4,1:4}

def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    """Fixed supplied-copy refusals on the two actual native references."""
    need(native is True and mode in APP_CONTROL_COUNTS,'native-only application supplied controls')
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)
    observation=PREFIX+400;frame=observation+21400
    tests=(('version',8),('CPU',8*8),('hardware',384+8),('seed_GPR',1992),
           ('source',2208),('stack',10400),('data',10624),('registration_result',18816),
           ('publication_word',18816+6*8),('cleanup',PREFIX+5*8),
           ('after_GPR',observation+280),('after_AF',observation+408),
           ('actual_TLS',observation+496+8),('whole_live_vector',observation+2676),
           ('native_FP',frame+1248),('completed_store_bytes',observation+13208+(8176 if mode else 0)))
    need(len(tests)==APP_CONTROL_COUNTS[mode],'fixed16 native input/state/effect controls')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)


def pair_controls(native,gated,owner):
    """Four actual pair mutations; no raw record or historical outcome rewritten."""
    import copy
    pair(native,gated,owner);mode=native['mode'];refused=[]
    for name in('logical_AF','logical_CR2','full_FP','store_effect'):
        mutant=copy.deepcopy(owner)
        if name.startswith('logical_'):
            g=list(mutant['logical']['greg']);g[17 if name=='logical_AF'else 22]^=16 if name=='logical_AF'else 1;mutant['logical']['greg']=tuple(g)
        elif name=='full_FP':
            fp=bytearray(mutant['logical']['fp']);fp[160]^=1;mutant['logical']['fp']=bytes(fp)
        else:
            data=bytearray(mutant['after_memory']['data']);data[8176 if mode else 0]^=1;mutant['after_memory']['data']=bytes(data)
        expected='whole actual pair source/stack/store effects'if name=='store_effect'else'all23 GREG/65536 FP including actual AF'
        try:pair(native,gated,mutant)
        except ValueError as error:
            need(str(error)==expected,'exact causal pair refusal '+name);refused.append(name)
        else:raise ValueError('supplied pair corruption accepted '+name)
    need(len(refused)==PAIR_CONTROL_COUNTS[mode],'all four actual pair controls')
    return dict(refusals=refused,native_operations=0,mode=mode)
