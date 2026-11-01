"""Complete finite D3 original application: four cycles, five full native frames.
Only RSP uses each actual original local-stack coordinate when pairing lanes.
"""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,FRAME=2728,339232,66784
MAGIC=0x334450414132494c
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
STEPS=(0,1,29,29,30)
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
    need(len(interp) == 1, 'actual source-owned interpreter')
    path = take(interp[0][2], interp[0][5])
    need(path.startswith(b'/') and path.endswith(b'\0') and b'\0' not in path[:-1], 'complete interpreter name')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i * 64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0, 'one complete symtab')
    t = tables[0]
    need(t[6] < len(sections), 'symbol string index')
    strings = sections[t[6]]; names = take(strings[4], strings[5])
    wanted = {'region_app_'+n for n in ('head','page','predecessor','block_b','block_c','terminal','source_end',
        'helper','helper_end','enter','seed_x87','pure','pure_end','capture_high','entry_jump','head_pointer','capture_pointer')} | {'ua_'+n for n in
        ('vectors','masks','host','host_fcw','input','before','after','before_live','after_live','target')}
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
    p,source=memory(page,6*PAGE)
    need(page==0x410000 and head==page+0x200 and symbols['region_app_source_end']==page+6*PAGE and
         p[1]==5 and p[2]+page-p[3]>=PAGE,'whole actual six-page RX fixture')
    expected=bytearray(b'\xcc'*(6*PAGE));expected[0x1fe:0x200]=bytes.fromhex('ffe3')
    expected[0x200:0x209]=bytes.fromhex('4883c001e9f71f0000');expected[0x2200:0x2209]=bytes.fromhex('4883c002e9f71f0000')
    expected[0x4200:0x4211]=bytes.fromhex('4883c0044883e9010f85f2bfffff41ff23')
    need(source==expected,'all six actual source pages, direct branches and every padding byte')
    for name,offset,size in(('head',0x200,9),('predecessor',0x1fe,0),('block_b',0x2200,9),('block_c',0x4200,17),('terminal',0x420e,0)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,'exact defined finite graph symbol')
    for prefix in ('helper', 'pure'):
        address = symbols['region_app_' + prefix]
        need(address != head and address % PAGE == 0 and symbols['region_app_' + prefix + '_end'] == address + PAGE and memory(address, PAGE)[0][1] == 5 and native_policy(memory(address - 14, PAGE + 28)[1]) == 0, 'complete actual native helper plus halos, no policy exemption')
    pure = symbols['region_app_pure']
    pure_load, pure_image = memory(0x200000000, 3 * PAGE)
    need(pure == 0x200001000 and pure_load[1] == 5 and pure_load[3] == 0x200000000 and
         pure_load[5] == pure_load[6] == 3 * PAGE and
         pure_image[:PAGE] == pure_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high RX helper load with complete unchanged-policy halos')
    helper = symbols['region_app_helper']
    high_capture = symbols['region_app_capture_high']; transfer = symbols['region_app_entry_jump']
    machine_load, machine_image = memory(0x200020000, 3 * PAGE)
    need(helper == 0x200021000 and machine_load[1] == 5 and machine_load[3] == 0x200020000 and
         machine_load[5] == machine_load[6] == 3 * PAGE and
         machine_image[:PAGE] == machine_image[2 * PAGE:] == b'\xcc' * PAGE,
         'actual separate high assembly RX load and complete CC halos')
    need(PAGE<=head<1<<31,'actual original source is low')
    ro, constants = memory(0x200010000, PAGE)
    need(ro[1] == 4 and ro[3] == 0x200010000 and ro[5] == ro[6] == PAGE and
         symbols['ua_vectors'] == ro[3] and symbols['ua_masks'] == ro[3] + 2048 and
         symbols['region_app_head_pointer'] == ro[3] + 2112 and
         symbols['region_app_capture_pointer'] == ro[3] + 2120 and
         constants == VECTORS + MASKS + struct.pack('<2Q', head, high_capture) + bytes(PAGE - 2128),
         'complete immutable nonexecuting assembly constants and both exact target pointers')
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
    return dict(symbols=symbols,head=head,page=page,source=source,terminal_pc=page+0x420e,
        capture_pc=high_capture,capture_pointer=symbols['region_app_capture_pointer'],interpreter=path[:-1].decode(),
        sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),phnum=h[10])


def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    fault=kind in(0,3)
    sig = 11 if fault else 5
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
    need(h[5]==h[6]+304 and uc[304:432]==si and
         uc[296:424]==struct.pack('<Q',prefix['machine'][0])+bytes(si[:120]),
         'whole actual kernel mask8 and embedded siginfo128 overlap')
    g = q(uc, 40, 23); pc = frame_pc(prefix,kind)
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21,14)if fault else(0,1)), 'genuine native signal origin')
    if fault:
        address = pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    else:need(q(si,16)[0]==pc and g[22]==(prefix['terminal_pc']if kind==4 else prefix['predecessor']),'actual TRACE PC and causal last original NX CR2')
    expected = frame_state(prefix,kind)
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    expected_flags=trace_model(prefix)[steps][2] | (RF if fault else TF)
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


def arithmetic(a,b,flags,subtract=False):
    value=(a-b if subtract else a+b)&U64
    overflow=((a^b)&(a^value) if subtract else ~(a^b)&(a^value))>>63&1
    updated=int(a<b if subtract else a+b>U64) | (int((value&255).bit_count()%2==0)<<2)
    updated|=(a^b^value)&16;updated|=int(value==0)<<6;updated|=(value>>63)<<7;updated|=overflow<<11
    return value,(flags&~0x8d5)|updated


def trace_model(prefix):
    pc=prefix['predecessor'];g=list(prefix['seed']);flags=0xad7;out=[(pc,tuple(g),flags)]
    for ordinal in range(1,31):
        if pc==0x4101fe:pc=g[3]
        elif pc in(0x410200,0x412200,0x414200):
            g[0],flags=arithmetic(g[0],{0x410200:1,0x412200:2,0x414200:4}[pc],flags);pc+=4
        elif pc in(0x410204,0x412204):pc+=0x1ffc
        elif pc==0x414204:g[1],flags=arithmetic(g[1],1,flags,True);pc+=4
        elif pc==0x414208:pc=0x41420e if flags&0x40 else 0x410200
        elif pc==0x41420e:pc=prefix['capture_pc']
        else:raise ValueError('unmodeled finite D3 original instruction')
        out.append((pc,tuple(g),flags))
    need(out[-1][0]==prefix['capture_pc']and out[-1][1][:2]==(29,0)and flags==0x246,'exact four-cycle arithmetic and final original transfer')
    return out

def frame_pc(prefix,kind):
    need(type(kind)is int and 0<=kind<len(STEPS),'one of five explicitly retained native boundaries')
    return trace_model(prefix)[STEPS[kind]][0]
def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]


def read(data,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(native)is bool and type(exit_status)is int and exit_status==0 and len(data)==PREFIX+SUFFIX,'complete actual finite D3 application success')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)];seed=live(data[1992:2144]);machine=q(data,2144,8);stack=data[2208:2728]
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and CPU identity')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,4,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:13]==(0x410200,0x410000,24576),'actual fixed four-cycle source/process header')
    base=h[13];rsp=base+2056
    need(PAGE<=base<=(1<<47)-4096 and base%64==0 and rsp%16==8 and base<=rsp-256<rsp+264<=base+4096 and
         all(base+4096<=a or a+n<=base for a,n in((image['page'],6*PAGE),(0x200000000,0x32000))),
         'actual complete local original-stack allocation outside every fixture image interval')
    need(h[16:26]==(0,0,image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'complete actual signal ABI and XCOMP getter success')
    need(h[30:]==(1,520,0,0,image['capture_pc'],0x4101fe,30,SUFFIX,5,0,0x412200,0x414200,0x41420e,0,0,0,0,0),'exact complete finite fixture selectors and reserved header')
    need(machine==(MASK,0,0,0x33,0x2b,0,0,0),'actual freestanding machine/TLS/mask input')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all complete actual CPUID observations')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0/standard state capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU independent exact zero-pointer seed prerequisite')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'every complete enabled standard component')
    expected=[0x3141592600000000+i*0x102030405 for i in range(16)]
    expected[0]=1;expected[1]=4;expected[3]=0x410200;expected[4]=rsp;expected[11]=image['capture_pointer']
    need(seed==(tuple(expected),0xad7,bytes(12))and stack==bytes((i*29+7)&255 for i in range(520)),'all16 actual seeded registers and whole520 original stack bytes')
    result=dict(header=h,hardware=hardware,xcr0=h[14],source=image['source'],head=0x410200,source_page_address=0x410000,predecessor=0x4101fe,terminal_pc=0x41420e,capture_pc=image['capture_pc'],capture_pointer=image['capture_pointer'],symbols=image['symbols'],stack_base=base,rsp=rsp,seed=seed[0],seed_live=seed,machine=machine,stack=stack,pid=pid,cpu=cpu,role='native'if native else'gated')
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,1,4,int(native),0,1,1,5 if native else 0,30 if native else 0,image['capture_pc'],0,0,0,0,0,0),'whole actual collection/cleanup header')
    before,after=live(suffix[128:280]),live(suffix[280:432]);mb,ma=q(suffix,432,8),q(suffix,496,8);live_before,live_after=suffix[560:2676],suffix[2676:4792]
    selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0);want=list(expected);want[0]=29;want[1]=0
    need(before==(tuple(expected),0xad7,selectors)and after==(tuple(want),0x246,selectors),'every before/after register, selector and flag')
    need(mb==ma==machine and live_before==live_after==LIVE_SEED and suffix[4792:5312]==stack,'whole live vector/TLS/mask/520stack equality')
    frames=[]
    for i in range(5):
        f=suffix[5312+i*FRAME:5312+(i+1)*FRAME]
        if native:frames.append(reference_frame(f,result,image,i,STEPS[i],0))
        else:need(f==bytes(FRAME),'gated application has no invented native frame')
    if native:need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 actual FP bytes unchanged across every native event')
    result.update(before=before,after=after,live=live_before,frames=frames,end=end,complete=1)
    return result


APP_CONTROL_COUNT=80

def controls(data,native,exit_status,image,pid,cpu,seed_reference):
    """Native-only supplied-data refusals; no reader replay can produce a guest event."""
    need(native is True,'native-only application supplied controls')
    read(data,native,exit_status,image,pid,cpu,seed_reference)
    tests=[('version',8),('prefix_extent',16),('suffix_extent',24),('cycles',32),
           ('role',40),('PID',48),('TID',56),('CPU',64),('root',80),('source_page',88),
           ('source_extent',96),('stack_base',104),('XCR0',112),('xstate_extent',120),
           ('signal_ABI',19*8),('whole_hardware',384+8),('seed_RAX',1992),('seed_RCX',2000),
           ('seed_RSP',2024),('seed_R11',2080),('seed_flags',2120),('seed_selectors',2128),
           ('machine_mask',2144),('machine_FS',2152),('stack_first',2208),('stack_middle',2464),
           ('stack_last',2727),('cleanup',PREFIX+40),('collection_complete',PREFIX+48),
           ('frame_count',PREFIX+56),('TRACE_count',PREFIX+64),('after_RAX',PREFIX+280),
           ('after_RCX',PREFIX+288),('after_RSP',PREFIX+312),('after_flags',PREFIX+408),
           ('after_TLS',PREFIX+504),('before_live',PREFIX+560),('after_live',PREFIX+2676),
           ('after_stack_first',PREFIX+4792),('after_stack_last',PREFIX+5311)]
    for index in range(5):
        frame=PREFIX+5312+index*FRAME
        for name,offset in(('kind',8),('steps',16),('PC',224+40+16*8),
                          ('RSP',224+40+GREG[4]*8),('flags',224+40+17*8),
                          ('CR2',224+40+22*8),('whole_FP',1248+64),('embedded_siginfo',224+304)):
            tests.append(('frame'+str(index)+'_'+name,frame+offset))
    need(len(tests)==len({name for name,offset in tests})==APP_CONTROL_COUNT and
         len({offset for name,offset in tests})==APP_CONTROL_COUNT and
         all(type(offset)is int and 0<=offset<len(data)for name,offset in tests),
         'all80 distinct bounded causal D3 application stimuli')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0)
