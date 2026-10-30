"""Scalar application stdout/native references and full cross-lane comparison.
Protected production-owner interpretation is a separate mandatory reader.
No import or source-only check grants native/owner/performance credit.
"""
import hashlib
import struct
PAGE, FP, UC, LIVE = 4096,65536,1024,2116
PREFIX, SUFFIX, OBS, FRAME = 14720,301616,150744,66784
MAGIC = 0x315050415253494c
DATA, STACK = 0x500000000000,0x500000100000
RSP, STACK_FAULT = STACK+4096+131072-504,STACK+8192
U64, TF, RF = (1<<64)-1,0x100,0x10000
MASK = 0xffffffffbffbfae7
GRAPH=bytes.fromhex('4889c84885d20f84400100004885c9740b0fb6410583e0033c0374624c8b7c245831db410fb6871c03000083e0033c020f84ec0300004c8b5424504d89fd418bbfe403000085ff0f84d9010000')
OFFSETS=(0,3,6,12,15,17,21,24,26,28,33,35,43,46,48,54,59,62,69,71)
LENGTHS=(3,3,6,3,2,4,3,2,2,5,2,8,3,2,6,5,3,7,2,6)
GENERATED=(0,3,6,12,15,21,25,28,30,36,41,43,51,54,56,62,67,70,77,79)
EXITS=(0x73e,0x670,0xa14,0x818,0x63f)
TRACES=(3,9,11,20,20,5,9,11,15,17,17)
FAULT_HEADS=(5,9,11,15,17,17)
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1) for i in range(256))
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
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'exit1', 'exit2', 'exit3', 'exit4', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live')}
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
    p, source = memory(page, PAGE)
    need(page % PAGE == 0 and head == page + 0x5f2 and symbols['region_app_source_end'] == page + PAGE and p[1] == 5 and p[2] + page - p[3] >= PAGE, 'whole actual RX source outside ELF header')
    expected = bytearray(b'\xcc' * PAGE); expected[0x5f2:0x63f] = GRAPH
    for i, offset in enumerate((0x63f, 0x670, 0x73e, 0x818, 0xa14)):
        need(symbols['region_app_exit' + str(i)] == page + offset and symbol_sizes['region_app_exit' + str(i)] == 6, 'five exact authentic external exit symbols')
        expected[offset:offset + 14] = b'\xff\x25\0\0\0\0' + struct.pack('<Q', symbols['region_app_capture_high'])
    need(source == expected, 'whole77 graph and five transparent immutable exit stubs with complete CC fill')
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
                       ('before_live', LIVE), ('after_live', LIVE), ('host', 64), ('host_fcw', 2)):
        address = symbols['ua_' + name]
        need(symbol_sizes['ua_' + name] == size and 0x200030000 <= address <= 0x200032000 - size and
             all(address + size <= a or a + n <= address for a, n in extents),
             'complete distinct assembly state objects in the exact high RW load')
        extents.append((address, size))
    displacement = symbols['region_app_head_pointer'] - (transfer + 6)
    need(helper <= symbols['region_app_enter'] <= symbols['region_app_seed_x87'] - 4 and
         symbols['region_app_seed_x87'] < transfer and transfer + 6 == high_capture < helper + PAGE and
         memory(symbols['region_app_seed_x87'] - 4, 6)[1] == b'\xdb\xe3\xd9\xe8\xd9\xeb' and
         -(1 << 31) <= displacement < 1 << 31 and
         memory(transfer, 6)[1] == b'\xff\x25' + struct.pack('<i', displacement),
         'exact seed/entry/capture positions and transparent high-to-low immutable-pointer JMP')
    return dict(symbols=symbols, head=head, page=page, exits=tuple(page + x for x in EXITS), source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10])


def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    sig = 11 if kind in (0, 2) else 5
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
    g = q(uc, 40, 23); pc = layout['head'] if kind == 0 else prefix['expected_exit_pc']
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (4, 14) if kind == 2 else (0, 1)), 'genuine native signal origin')
    if kind in (0, 2):
        address = prefix['fault_address'] if kind == 2 else pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    expected = prefix['seed'][0] if kind == 0 else state(prefix['seed'][0], prefix['data'], prefix['stack'], prefix['base_mode'])
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    if kind == 0:
        need(g[17] == prefix['seed'][1] | RF, 'actual NX seed flags')
    else:
        need(g[17] & (TF | RF) == (TF | (RF if kind == 2 else 0)), 'actual reference observer flags')
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
    base=4 if mode>=11 else mode
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[1]=0 if base==2 else DATA+8192-6 if base==1 else DATA+123
    seed[2]=int(base!=0);seed[4]=STACK_FAULT-0x58 if base==6 else STACK_FAULT+PAGE-0x58 if base==8 else RSP
    r15=DATA+8192-4-0x3e4
    if base==2:r15=DATA+8192-1-0x31c
    if base==7:r15=DATA+8192-0x31c
    if base==9:r15=DATA+8192-0x3e4
    if base==10:r15=DATA+8192-2-0x3e4
    if base==0:seed[1]=DATA+8192
    if base==5:seed[1]=DATA+8192-5
    data=bytearray(1+(i*17)%255 for i in range(8192))
    stack=bytearray((i*29+7)&255 for i in range(224))
    if base not in (0,2,5):data[8191 if base==1 else 128]=3 if base==1 else 1
    if base not in (0,1,5,6,7):data[r15+0x31c-DATA]=2 if base==2 else 1
    if base in (3,4):struct.pack_into('<I',data,r15+0x3e4-DATA,0 if base==3 else 0x80000001)
    struct.pack_into('<QQ',stack,208,0x8877665544332211,r15)
    return (tuple(seed),0x202 if base%2 else 0xad7,bytes(12)),bytes(data),bytes(stack)


def state(seed,data,stack,mode):
    path=list(range(20))
    if mode==0:path=[0,1,2]
    elif mode==1:path=list(range(9))
    elif mode==2:path=[0,1,2,3,4,9,10,11,12,13,14]
    elif mode>=5:path=path[:FAULT_HEADS[mode-5]]
    out=list(seed)
    for i in path:
        if i==0:out[0]=out[1]
        elif i==5:out[0]=data[out[1]+5-DATA]
        elif i in (6,12):out[0]&=3
        elif i==9:out[15]=q(stack,216)[0]
        elif i==10:out[3]=0
        elif i==11:out[0]=data[out[15]+0x31c-DATA]
        elif i==15:out[10]=q(stack,208)[0]
        elif i==16:out[13]=out[15]
        elif i==17:out[7]=u(data,out[15]+0x3e4-DATA)[0]
    need(len(path)==TRACES[mode],'all original retired heads')
    return tuple(out)


def _prefix(data,mode,native,layout,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and 0<=mode<13 and type(native)is bool,'typed whole scalar application prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6) for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:6304],data[6304:6528],data[6528:]
    base=4 if mode>=11 else mode;fault=base>=5;invocations=2 if mode>=11 else 1
    fault_address=STACK_FAULT if base==6 else STACK_FAULT+PAGE-8 if base==8 else DATA+8192 if fault else 0
    endpoint=layout['head']+OFFSETS[FAULT_HEADS[base-5]] if fault else layout['page']+EXITS[base]
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu) and h[9]<=0xffffffff and h[10:14]==(layout['head'],layout['page'],DATA,STACK),'exact actual prefix/source/process')
    need(h[16:26]==(base,int(fault),layout['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16) and h[26]==h[28]==0,'actual signal geometry and successful permission observations')
    need(h[30:]==(invocations,224,fault_address,FAULT_HEADS[base-5] if fault else 0,endpoint,STACK_FAULT if base in (6,8) else 0,TRACES[base],OBS,2,77,0,0,0,0,0,0,0,0),'complete fixed scalar schedule and zero reserved fields')
    need(source==layout['source'] and machine[0]==MASK and machine[1]>0 and machine[3:5]==(0x33,0x2b) and machine[5:]==(0,0,0),'whole ELF source and actual application machine')
    need([x[:2] for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i) for i in range(64)] and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3] and 576<=h[15]<=FP,'actual XCR0 and standard capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16) and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'separate same-CPU qualified seed and actual permissions')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15] and row[4]&1==0,'standard component geometry')
    expected,want_data,want_stack=fixture(mode)
    need(seed==expected and memory==want_data and stack==want_stack,'every seeded GPR/reserved byte/data/224stack byte before protection')
    return dict(header=h,mode=mode,base_mode=base,invocations=invocations,head=layout['head'],source_page_address=layout['page'],source_page=source,source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=seed[0][4],seed=seed,machine=machine,expected_exit_pc=endpoint,fault_pc=endpoint if fault else 0,fault_address=fault_address,suffix=None,observations=[])


def control_prefix(data,control,exit_status,layout,pid,cpu,seed_reference):
    need(type(control)is int and 1<=control<=14 and type(exit_status)is int and exit_status==125,'all14 distinct required owner refusals')
    return _prefix(data,0,False,layout,pid,cpu,seed_reference)


def read(data,mode,native,exit_status,layout,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and 0<=mode<13 and type(native)is bool and type(exit_status)is int,'typed actual scalar application outcome')
    base=4 if mode>=11 else mode;fault=base>=5;full=native or not fault
    need(exit_status==(125 if fault else 0) and len(data)==PREFIX+(SUFFIX if full else 0),'exact actual required outcome and complete output')
    result=_prefix(data[:PREFIX],mode,native,layout,pid,cpu,seed_reference)
    if not full:return result
    suffix=data[PREFIX:];end=q(suffix,0,16);invocations=result['invocations']
    need(end==(MAGIC^1,1,mode,int(native),0,1,invocations,2*invocations if native else 0,TRACES[base]*invocations if native else 0,int(fault),int(mode==12),0,0,int(mode==12),0,0),'whole final cleanup/generation/observation counters')
    selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    for attempt in range(2):
        value=suffix[128+attempt*OBS:128+(attempt+1)*OBS]
        if attempt>=invocations:
            need(value==bytes(OBS),'whole unused observation capacity');continue
        h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432])
        a,b=value[432:2548],value[2548:4664]
        need(h==(1,attempt,2 if native else 0,TRACES[base] if native else 0,int(fault),int(native),int(base in (6,8)),0,result['expected_exit_pc'],0,0,0,0,0,0,0),'complete actual per-invocation capture and readback observations')
        need(before==(result['seed'][0],result['seed'][1],selectors) and after[2]==selectors and not after[1]&(TF|RF) and a==b==LIVE_SEED,'whole actual live GPR/flags/selectors/vector state')
        need(after[0]==state(result['seed'][0],result['data'],result['stack'],base),'independent defined scalar results without AF prediction')
        need(value[4664:8760]==result['source'] and value[8760:8984]==result['stack'] and value[8984:17176]==result['data'],'all actual post-invocation source/224stack/data bytes')
        frames=[]
        for index in range(2):
            frame=value[17176+index*FRAME:17176+(index+1)*FRAME]
            if not native:need(frame==bytes(FRAME),'gated path has no fabricated native frame')
            else:frames.append(reference_frame(frame,result,layout,0 if index==0 else 2 if fault else 1,0 if index==0 else TRACES[base],attempt))
        if native:
            need(frames[0]['fp']==frames[1]['fp'],'whole65536 native frame conservation')
            need(after[1]==frames[1]['greg'][17]&~(TF|RF),'all actual flags including undefined AF')
        result['observations'].append(dict(before=before,after=after,live=a,frames=frames,header=h))
    result['suffix']=dict(end=end)
    return result


def pair(native,gated,owner):
    need(native['header'][5]==1 and gated['header'][5]==0 and native['mode']==gated['mode'] and owner['control']==0,'actual original/generated pair')
    mode=native['mode'];base=native['base_mode'];fault=base>=5
    need(native['header'][8:19]==gated['header'][8:19] and native['hardware']==gated['hardware'] and all(native[k]==gated[k] for k in ('seed','source','stack','data','invocations','rsp')),'same complete source/hardware/input')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:],'actual common mask/selectors')
    entries=owner['entries'];need(len(entries)==native['invocations']==len(native['observations']),'all real original/generated invocations')
    def compare(actual,reference,failed=False):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==reference['header'][9] and actual['mask']==MASK,'typed whole actual owner frame')
        want=list(reference['greg'])
        if failed:want[16]=actual['greg'][16];want[17]&=~TF
        else:want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want) and actual['fp']==reference['fp'],'all23 GREG/full65536FP and actual AF, only exact event association')
        need((actual['fs'],actual['gs'])==gated['machine'][1:3],'owner actual TLS matches conserved gated application')
    for index,entry in enumerate(entries):
        reference=native['observations'][index]
        need(entry['source_page']==entry['terminal_source_page']==native['source'],'full original page throughout actual ownership')
        for stage,memory in enumerate((entry['before_memory'],entry['after_memory'])):
            need(memory['data']==native['data'] and len(memory['stack'])==224 and len(memory['stack_observed'])==224,'complete actual diagnostic memory extents')
            observed=bytes(0 if stage==0 and base in (6,8) and STACK_FAULT<=native['rsp']-128+i<STACK_FAULT+PAGE else 1 for i in range(224))
            need(memory['stack_observed']==observed and memory['stack']==bytes(native['stack'][i] if observed[i] else 0 for i in range(224)),'every observed byte and exact absent pre-entry bytes; all terminal bytes required')
        compare(entry['before'],reference['frames'][0])
        end=entry['unexpected'] if fault else entry['after']
        need((entry['after'] is None)==fault and (entry['unexpected'] is not None)==fault,'required fault has no successful after')
        if fault:
            head=FAULT_HEADS[base-5];offset=GENERATED[head]
            expected=dict(version=1,ready=1,head_index=head,kind=1,source_offset=0x5f2+OFFSETS[head],source_length=LENGTHS[head],generated_offset=offset,generated_length=LENGTHS[head],original_pc=native['head']+OFFSETS[head],generated_pc=entry['entry']+offset)
            need(entry['mapped']==expected and end['greg'][16]==expected['generated_pc'],'complete exact actual generated-load PC association')
        compare(end,reference['frames'][1],fault)
        if not fault:
            actual=gated['observations'][index]
            need(reference['before']==actual['before'] and reference['after']==actual['after'] and reference['live']==actual['live'],'entire actual common post-exit state including AF')
            need(actual['after'][0]==tuple(end['greg'][r] for r in GREG) and actual['after'][1]==end['greg'][17]&~RF,'transparent actual exit-to-capture state')
    need((gated['suffix'] is None)==fault,'no application completion after generated fault')
    # The owner reader binds the real fresh ticket and immutable plan. Require
    # the actual cache/generation distinction, not the app syscall intent alone.
    if mode==11:need(entries[0]['key']==entries[1]['key'] and entries[0]['slot']==entries[1]['slot'] and owner['focal'][:4]==(1,1,2,2),'actual repeat uses one immutable publication and a fresh-ticket hit')
    elif mode==12:need(entries[0]['key']!=entries[1]['key'] and entries[0]['generation']!=entries[1]['generation'] and entries[0]['slot']!=entries[1]['slot'] and owner['focal'][:4]==(2,0,2,2),'actual generation mutation requires new authenticated publication')
    return dict(qualified_case=1,completed_application=int(not fault),required_read_failure=int(fault),application_entries=len(entries),completed_regions=0 if fault else len(entries),reference_steps=TRACES[base]*len(entries),repeat=int(mode==11),generation=int(mode==12))


def control_reference(native,gated,owner,control):
    """Actual native mode0 joins; all fourteen outcomes remain refused125."""
    need(type(control)is int and 1<=control<=14 and owner['control']==control and
         native['header'][4:6]==(0,1) and gated['header'][4:6]==(0,0),
         'same actual mode0 hardware reference and required refusal')
    need(native['header'][8:19]==gated['header'][8:19] and native['hardware']==gated['hardware'] and
         all(native[k]==gated[k] for k in ('seed','source','stack','data')),
         'all actual control/reference input and hardware bytes')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:] and
         len(native['observations'])==1 and gated['suffix']is None,
         'actual control launch and no application completion')
    reference=native['observations'][0]['frames']
    def compare(actual,expected,observed_tls=True):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and
             len(actual['fp'])==FP and actual['fp_bytes']==expected['header'][9] and actual['mask']==MASK,
             'complete typed actual control frame')
        want=list(expected['greg']);want[17]=(want[17]&~TF)|RF
        want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want) and actual['fp']==expected['fp'],
             'whole actual control GPR/flags/AF/FP joins original hardware reference')
        need((actual['fs'],actual['gs'])==(gated['machine'][1:3] if observed_tls else (0,0)),
             'actual observed TLS or source-exact pre-TLS empty fields')
    entries=owner['entries'];need(len(entries)==(0 if control==6 else 1),'all real focal control prefixes')
    if control==6:compare(owner['supplied_before'],reference[0],False)
    else:
        entry=entries[0];compare(entry['before'],reference[0])
        need(entry['source_page']==entry['terminal_source_page']==native['source'],'complete actual control source')
        for memory in (entry['before_memory'],entry['after_memory']):
            need(memory['data']==native['data'] and memory['stack']==native['stack'] and
                 memory['stack_observed']==bytes([1])*224,'complete actual control data/224stack observations')
        if control in (3,7):compare(entry['after'] if control==3 else entry['unexpected'],reference[1])
    return dict(native_entry_joins=1,native_endpoint_joins=int(control in (3,7)),
                completed_applications=0,required_owner_refusals=1)


def controls(check_pair,native_output,gated_output,mode):
    """Only supplied negatives after the original actual pair passed.

    check_pair re-runs both stdout readers, the full protected-owner reader and
    pair against unchanged identities and the original owner record. It must
    refuse with ValueError; no successful or native result is manufactured.
    """
    need(type(mode)is int and 0<=mode<13,'fixed application control mode')
    def flip(data,offset,value=1):
        changed=bytearray(data);changed[offset]^=value;return bytes(changed)
    first=PREFIX+128
    native_mutations=[('version',8),('mode',32),('pid',48),('source_tail',6303),
        ('input_stack_tail',6527),('input_data_tail',PREFIX-1),('seed_RDX',1992+16),
        ('hardware',384),('mask',2144),('cleanup',PREFIX+40),
        ('after_GPR',first+280),('after_AF',first+408),('selector',first+416),
        ('before_live',first+432),('after_live',first+4663),('after_stack',first+8983),
        ('after_data',first+17175),('frame_UC_tail',first+17176+1247),
        ('frame_FP_tail',first+17176+FRAME-1),('frame_FIP',first+17176+1248+8)]
    trials=[(name,flip(native_output,at,0x10 if name=='after_AF' else 1),gated_output)
            for name,at in native_mutations]
    trials += [('native_truncated',native_output[:-1],gated_output),
        ('gated_truncated',native_output,gated_output[:-1]),
        ('gated_appended',native_output,gated_output+b'\0'),
        ('gated_data',native_output,flip(gated_output,PREFIX-1))]
    changed=bytearray(native_output)
    for attempt in range(2 if mode>=11 else 1):
        for index in range(2):changed[first+attempt*OBS+17176+index*FRAME+1248+48]^=1
    trials.append(('coherent_native_FP',bytes(changed),gated_output))
    if mode<5 or mode>=11:
        trials.append(('gated_actual_AF',native_output,flip(gated_output,first+408,0x10)))
    else:trials.append(('actual_fault_CR2',flip(native_output,first+17176+FRAME+224+40+22*8),gated_output))
    if mode>=11:
        second=first+OBS
        trials += [('second_actual_AF',native_output,flip(gated_output,second+408,0x10)),
            ('second_R10',flip(native_output,second+280+10*8),gated_output),
            ('second_FP_tail',flip(native_output,second+17176+FRAME-1),gated_output),
            ('second_ordinal',flip(native_output,second+8),gated_output),
            ('generation_or_repeat_counter',flip(native_output,PREFIX+80),gated_output)]
    count=31 if mode>=11 else 26
    need(len(trials)==count and len({name for name,_,_ in trials})==count,'all fixed unique application refusals')
    for name,n,g in trials:
        rejected=False
        try:check_pair(n,g)
        except ValueError:rejected=True
        need(rejected,'application reader accepted '+name)
    return dict(supplied_refusals=count,native_operations=0)
