"""Actual linked-epoch native/output reader. No implementation is imported from
an execution or decoder model. Native flags (including AF) remain hardware
observations; generated outputs must equal them at exact boundaries."""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=14720,1306880,217656,66784
MAGIC=0x31505041454c494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES=(13,12,5,8,14,13)
EXITS=(0x600,0x620,0x300,0x500,0x602,0x600)
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')
FRAGMENTS={0x200:bytes.fromhex('b80700000085f60f84f3010000e9ee000000'),0x300:bytes.fromhex('448b07488d444802e9f3010000'),0x400:bytes.fromhex('448b074531c94801d0e9f2000000'),0x500:bytes.fromhex('458b12448b1df601000083f80f0f850d010000e9e8000000')}
HEADS=(0x200,0x205,0x207,0x20d,0x300,0x303,0x308,0x400,0x403,0x406,0x409,0x500,0x503,0x50a,0x50d,0x513)
LENGTHS=(5,2,6,5,3,5,5,3,3,3,5,3,7,3,6,5)

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
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'exit1', 'predecessor', 'block_b', 'block_c', 'block_d', 'frontier_next', 'constant', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
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
    need(page % PAGE == 0 and head == page + 0x200 and symbols['region_app_source_end'] == page + PAGE and p[1] == 5 and p[2] + page - p[3] >= PAGE, 'whole actual RX source outside ELF header')
    expected=bytearray(b'\xcc'*PAGE);expected[0x1fe:0x200]=b'\x66\x90'
    for offset,fragment in FRAGMENTS.items():expected[offset:offset+len(fragment)]=fragment
    need(symbols['region_app_predecessor']==page+0x1fe and symbol_sizes['region_app_head']==18,
         'actual genuine predecessor and first fragment')
    for name,offset,size in (('block_b',0x300,13),('block_c',0x400,14),('block_d',0x500,24),('exit0',0x600,2),('frontier_next',0x602,6),('exit1',0x620,6),('constant',0x700,4)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,'exact noncontiguous source symbol')
    expected[0x600:0x602]=b'\x66\x90'
    for offset in (0x602,0x620):expected[offset:offset+14]=b'\xff\x25\0\0\0\0'+struct.pack('<Q',symbols['region_app_capture_high'])
    expected[0x700:0x704]=struct.pack('<I',0x89abcdef)
    need(sum(map(len,FRAGMENTS.values()))==69 and source==expected,'whole actual16-head69-byte noncontiguous graph and every gap/exit')
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
    return dict(symbols=symbols, head=head, page=page, exits=tuple(page + x for x in EXITS), source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10])


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
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (4, 14) if kind == 3 else (0, 1)), 'genuine native signal origin')
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
    need(type(mode)is int and mode in range(6),'fixed six actual application modes')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[1]=3;seed[2]=1;seed[4]=RSP;seed[6]=0 if mode==1 else 1
    seed[7]=DATA+8192 if mode==2 else DATA+4092;seed[10]=DATA+8192-(3 if mode==3 else 4)
    return (tuple(seed),0x202 if mode%2 else 0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(224))

def state(seed,data,mode):
    out=list(seed);out[0]=7
    if mode==2:return tuple(out)
    out[8]=u(data,seed[7]-DATA)[0]
    if mode==1:out[9]=0;out[0]=8
    else:out[0]=15
    if mode!=3:out[10]=u(data,seed[10]-DATA)[0];out[11]=0x89abcdef
    return tuple(out)

def _prefix(data,mode,native,layout,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and 0<=mode<6 and type(native)is bool,'typed whole TRACE application prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6) for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:6304],data[6304:6528],data[6528:]
    head=layout['head'];endpoint=layout['exits'][mode]
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu) and h[9]<=0xffffffff and h[10:14]==(head,layout['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode in(2,3)),layout['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16) and h[26]==h[28]==0,'actual signal geometry and successful permission observations')
    need(h[30:]==(6 if mode==5 else 1,224,DATA+8192 if mode in(2,3)else 0,3 if mode in(2,3)else 0,endpoint,head-2,TRACES[mode],OBS,3,69,layout['page']+0x300,layout['page']+0x400,layout['page']+0x700,RSEQ,layout['page']+0x500,0,0,0),'whole fixed linked schedule and reserved fields')
    need(source==layout['source'] and machine[0]==MASK and machine[1]>0 and machine[3:5]==(0x33,0x2b) and machine[5:]==(0,0,0),'whole ELF source and actual application machine')
    need([x[:2] for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i) for i in range(64)] and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3] and 576<=h[15]<=FP,'actual XCR0 and standard capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16) and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'separate same-CPU qualified seed and actual permissions')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15] and row[4]&1==0,'standard component geometry')
    expected,want_data,want_stack=fixture(mode)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/224stack bytes')
    return dict(header=h,mode=mode,head=head,predecessor=head-2,source_page_address=layout['page'],source_page=source,source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=endpoint,fault_pc=endpoint if mode in(2,3)else 0,fault_address=DATA+8192 if mode in(2,3)else 0,suffix=None,observations=[])


def effects(data,mode,page,machine,cpu):
    rows=[q(data,i*136,17)for i in range(6)]
    if mode!=5:need(data==bytes(816),'unused lifecycle ledger whole zero');return rows
    for i,row in enumerate(rows):
        args=(page,4096,1 if i==0 else 5,0,0,0)if i<2 else (0x1001,RSEQ+128 if i==2 else machine[2],0,0,0,0)if i<4 else(RSEQ,32,int(i==5),0x53053053,0,0)
        need(row[:9]==(i+1,10 if i<2 else 158 if i<4 else 334,*args,0),'actual exact lifecycle syscall/arguments/zero result')
        before,after=row[9:13],row[13:17]
        if i<4:need(before==after==(0,0,0,0),'unregistered zero rseq memory before registration')
        elif i==4:need(before==(0,0,0,0)and after==(cpu|(cpu<<32),0,0,0),'actual successful registration and kernel CPU words')
        else:need(before==rows[4][13:17]and after==(0xffffffff00000000,0,0,0),'actual unregister CPU words and zero rseq_cs/flags')
    return rows

def read(data,mode,native,exit_status,layout,pid,cpu,seed_reference,*,control=0):
    need(type(data)is bytes and type(mode)is int and mode in range(6)and type(native)is bool and type(exit_status)is int and type(control)is int and control in range(5),'typed actual linked outcome')
    need(not control or(not native and mode==(5 if control==2 else 0)),'terminal controls require gated mode0')
    full=native or(mode not in(2,3)and not control)
    need(exit_status==(125 if mode in(2,3)or control else 0)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated outcome and complete output')
    result=_prefix(data[:PREFIX],mode,native,layout,pid,cpu,seed_reference)
    if not full:return result
    suffix=data[PREFIX:];end=q(suffix,0,16);count=6 if mode==5 else 1
    need(end==(MAGIC^1,1,mode,int(native),0,1,count,3 if native else 0,TRACES[mode]if native else 0,int(mode in(2,3)),0,0,0,0,0,0),'whole terminal cleanup/counts')
    result['effects']=effects(suffix[128:944],mode,layout['page'],result['machine'],cpu)
    for attempt in range(6):
        value=suffix[944+attempt*OBS:944+(attempt+1)*OBS]
        if attempt>=count:need(value==bytes(OBS),'whole unused invocation capacity');continue
        h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
        a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
        want_machine=list(result['machine']);want_machine[2]=RSEQ+128 if mode==5 and attempt==2 else want_machine[2]
        need(mb==ma==tuple(want_machine),'actual FS/GS/mask bracket for each invocation')
        need(h==(1,attempt,3 if native else 0,TRACES[mode]if native else 0,int(mode in(2,3)),int(native),0,0,result['expected_exit_pc'],0,0,0,0,0,0,0),'whole invocation header')
        need(before==(result['seed'][0],result['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all live inputs/selectors/vector bytes')
        need(after[0]==state(result['seed'][0],result['data'],mode),'independent defined GPR result; no undefined flags prediction')
        need(value[4792:8888]==result['source']and value[8888:9112]==result['stack']and value[9112:17304]==result['data'],'whole source/data/224stack conservation')
        frames=[];context=dict(result,machine=mb)
        for i in range(3):
            frame=value[17304+i*FRAME:17304+(i+1)*FRAME]
            if not native:need(frame==bytes(FRAME),'no fabricated native signal in gated application')
            else:frames.append(reference_frame(frame,context,layout,i if i<2 else 3 if mode in(2,3)else 2,0 if i==0 else 1 if i==1 else TRACES[mode],attempt))
        if native:
            need(frames[0]['fp']==frames[1]['fp']==frames[2]['fp'],'whole native FP before/after graph')
            need(after[1]==frames[2]['greg'][17]&~(TF|RF),'all observed flags including undefined AF')
        result['observations'].append(dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb))
    result['suffix']=dict(end=end);return result

def pair(native,gated,owner):
    need(native['header'][5]==1 and gated['header'][5]==0 and native['mode']==gated['mode']and owner['control']==0,'actual native/linked pair')
    mode=native['mode'];count=6 if mode==5 else 1
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'all actual source/seed/hardware inputs')
    need(len(owner['entries'])==len(native['observations'])==count,'every actual invocation retained')
    def compare(actual,ref,event,machine):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK,'complete protected actual frame')
        want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        elif event=='fault':want[17]&=~TF;want[16]=actual['greg'][16]
        else:need(event=='trace','only source-derived event transform')
        need(actual['greg']==tuple(want)and actual['fp']==ref['fp'],'all23 GREG/65536 FP, including actual AF')
        need((actual['fs'],actual['gs'])==tuple(machine[1:3]),'actual per-invocation TLS')
    for i,(reference,entry)in enumerate(zip(native['observations'],owner['entries'],strict=True)):
        machine=list(gated['machine']);machine[2]=RSEQ+128 if mode==5 and i==2 else machine[2]
        compare(entry['ingress'],reference['frames'][1],'trace',machine);compare(entry['before'],reference['frames'][1],'closed',machine)
        compare(entry['predecessor_before'],reference['frames'][0],'trace',machine)
        need(entry['source']==entry['terminal_source']==native['source'],'whole original source per generation')
        for mem in(entry['before_memory'],entry['after_memory']):need(mem['data']==native['data']and mem['stack']==native['stack'],'all actual data/stack')
        if mode in(2,3):
            need(entry['disposition']=='fault'and entry['mapped']['original_pc']==native['fault_pc']and entry['unexpected']['greg'][16]==entry['mapped']['generated_pc'],'exact real failed-load head')
            compare(entry['unexpected'],reference['frames'][2],'fault',machine)
        elif mode==4:
            need(entry['disposition']=='completed'and entry['frontier_closed']==1,'actual epoch release then ordinary successor completion')
            # CR2 is the last hardware page-fault address, not a TRACE result.
            # Native runs continuously from its predecessor NX. Gated executes
            # the same no-effect6690 only after a real graph-frontier NX.
            initial,final=reference['frames'][0]['greg'],reference['frames'][2]['greg']
            nx,trace=entry['after']['greg'],entry['frontier_exit']['greg']
            frontier=native['source_page_address']+0x600
            need(initial[19:21]==(21,14)and initial[16]==initial[22]==native['predecessor']and
                 final[22]==initial[22],'native frontier CR2 is actual predecessor NX history')
            need(nx[19:21]==(21,14)and nx[16]==nx[22]==frontier and
                 native['source'][0x600:0x602]==b'\x66\x90',
                 'gated prior CR2 is exact actual epoch frontier NX')
            need(trace[22]==nx[22],'gated frontier CR2 retains actual epoch NX history')
            prior=list(final);prior[16]=frontier
            compare(entry['after'],dict(reference['frames'][2],greg=tuple(prior)),'nx',machine)
            expected=list(final);expected[22]=nx[22]
            compare(entry['frontier_exit'],dict(reference['frames'][2],greg=tuple(expected)),'trace',machine)
        else:need(entry['disposition']=='completed','actual epoch completion');compare(entry['after'],reference['frames'][2],'nx',machine)
        if mode not in(2,3):
            actual=gated['observations'][i]
            need(reference['before']==actual['before']and reference['after']==actual['after']and reference['live']==actual['live'],'complete actual post-exit state')
    need((gated['suffix']is None)==(mode in(2,3)),'fault never resumes application')
    return dict(qualified_pair=1,invocations=count,generated_completed=0 if mode in(2,3)else count,required_fault=int(mode in(2,3)),frontier_completed=int(mode==4),lifecycle_effects=6 if mode==5 else 0)


FRONTIER_PAIR_CONTROL_COUNT=4

def pair_controls(native,gated,owner):
    """Four mode4 supplied-copy refusals; no capture bytes are rewritten."""
    import copy
    need(native['mode']==gated['mode']==4 and owner['control']==0,
         'exact mode4 native/gated frontier controls')
    pair(native,gated,owner)
    tests=(('native_final_CR2','native frontier CR2 is actual predecessor NX history'),
           ('gated_final_CR2','gated frontier CR2 retains actual epoch NX history'),
           ('coherent_gated_CR2','gated prior CR2 is exact actual epoch frontier NX'),
           ('coherent_gated_NX_PC_CR2','gated prior CR2 is exact actual epoch frontier NX'))
    refused=[]
    for name,error in tests:
        n,o=copy.deepcopy(native),copy.deepcopy(owner)
        def change(frame,index):
            values=list(frame['greg']);values[index]^=1;frame['greg']=tuple(values)
        if name=='native_final_CR2':change(n['observations'][0]['frames'][2],22)
        else:
            entry=o['entries'][0];change(entry['frontier_exit'],22)
            if name.startswith('coherent_'):change(entry['after'],22)
            if name=='coherent_gated_NX_PC_CR2':change(entry['after'],16)
        try:pair(n,gated,o)
        except ValueError as failure:
            need(str(failure)==error,'exact causal frontier refusal '+name)
            refused.append(name)
        else:raise ValueError('supplied frontier history accepted '+name)
    need(len(refused)==FRONTIER_PAIR_CONTROL_COUNT,'all four frontier history refusals')
    return dict(refusals=refused,native_operations=0,mode=4)


def control_reference(native,gated,owner):
    """Actual before-state joins for required failures; no completion credit."""
    c=owner['control'];mode=5 if c==2 else 0
    need(c in(1,2,3,4)and native['mode']==gated['mode']==mode and native['header'][5]==1 and gated['header'][5]==0,'exact required-control native context')
    need(gated['suffix']is None and native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'actual controlled-prefix inputs and no false returned suffix')
    count=2 if c==2 else 1
    need(len(owner['entries'])==count and len(native['observations'])==(6 if mode==5 else 1),'exact real required-control invocation prefix')
    for i,entry in enumerate(owner['entries']):
        reference=native['observations'][i];machine=gated['machine']
        for key,ref,clear in(('predecessor_before',reference['frames'][0],False),('ingress',reference['frames'][1],False),('before',reference['frames'][1],True)):
            actual=entry[key];want=list(ref['greg'])
            if clear:want[17]&=~TF
            need(actual['greg']==tuple(want)and actual['fp']==ref['fp']and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK and(actual['fs'],actual['gs'])==machine[1:3],'complete controlled native ingress GPR/AF/FP/TLS/mask')
        need(entry['source']==entry['terminal_source']==native['source'],'whole controlled source generation bytes')
        for mem in(entry['before_memory'],entry['after_memory']):need(mem['data']==native['data']and mem['stack']==native['stack'],'whole controlled actual data/224stack')
        if i<count-1 or c==4:
            actual=entry['after'];ref=reference['frames'][2];want=list(ref['greg']);want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
            need(actual['greg']==tuple(want)and actual['fp']==ref['fp']and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK and(actual['fs'],actual['gs'])==machine[1:3],'complete actual generated exit before required control failure')
        need((entry['disposition']=='completed')==(i<count-1),'no required failure is relabelled completed')
    return dict(qualified_control=1,control=c,invocations=count,completed_prefix=count-1,generated_owner_credit=0)


APP_CONTROL_COUNTS={mode:32+(6 if mode==5 else 0)for mode in range(6)}

def controls(data,mode,native,exit_status,layout,pid,cpu,seed_reference):
    """Fixed supplied-copy refusals on each of the six complete native rows."""
    need(native is True,'application supplied controls require actual native reference')
    baseline=read(data,mode,native,exit_status,layout,pid,cpu,seed_reference)
    first=PREFIX+944;frame=first+17304
    tests=[('prefix_'+str(i),i*8)for i in(0,1,2,4,5,6,8,10,14,16,30,31)]
    tests += [('hardware',384),('seed_GPR',1992),('source',2208),('stack',6304),('data',6528),
              ('suffix_complete',PREFIX+5*8),('invocation_identity',first+8),
              ('live_before_GPR',first+128),('live_after_GPR',first+280),
              ('live_after_AF',first+280+128),('actual_TLS',first+432+8),
              ('full_vector',first+560),('full_after_vector',first+2676),
              ('source_readback',first+4792),('stack_readback',first+8888),('data_readback',first+9112),
              ('native_origin',frame+8),('native_GPR',frame+224+40),
              ('native_FP',frame+1248),('native_final_AF',frame+2*FRAME+224+40+17*8)]
    need(len(tests)==32,'fixed32 complete native supplied controls')
    if mode==5:tests += [('actual_effect_result_'+str(i),PREFIX+128+i*136+8*8)for i in range(6)]
    need(len(tests)==APP_CONTROL_COUNTS[mode],'fixed full native supplied population')
    refused=[]
    for name,at in tests:
        changed=bytearray(data);changed[at]^=0x10 if name in('live_after_AF','native_final_AF')else 1
        try:read(bytes(changed),mode,native,exit_status,layout,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied linked native output accepted '+name)
    return dict(refusals=refused,native_operations=0,original_sha256=hashlib.sha256(data).hexdigest(),actual_invocations=len(baseline['observations']))


def refault_read(data,mode,native,exit_status,layout,pid,cpu,seed_reference,*,refault_control):
    """Separate actual terminal prefix after a completed focal graph."""
    need(type(refault_control)is int and refault_control in range(1,5)and mode==0 and native is False and type(exit_status)is int and exit_status==125 and type(data)is bytes and len(data)==PREFIX,'exact additional retry-control process/prefix')
    return _prefix(data,mode,native,layout,pid,cpu,seed_reference)


def refault_control_reference(native,gated,owner):
    need(owner['refault_control']in range(1,5)and owner['control']==0 and native['mode']==gated['mode']==0 and native['header'][5]==1 and gated['header'][5]==0,'exact additional retry-control native context')
    need(gated['suffix']is None and native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'retry-control whole original native inputs and no returned suffix')
    need(len(owner['entries'])==len(native['observations'])==1,'one actually completed graph before helper retry failure')
    entry=owner['entries'][0];ref=native['observations'][0];machine=gated['machine']
    need(entry['disposition']=='completed','actual focal graph completed before additional retry refusal')
    for key,index,event in(('ingress',1,'trace'),('before',1,'closed'),('predecessor_before',0,'trace'),('after',2,'nx')):
        actual=entry[key];reference=ref['frames'][index];want=list(reference['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want)and actual['fp']==reference['fp']and actual['fp_bytes']==reference['header'][9]and actual['mask']==MASK and(actual['fs'],actual['gs'])==tuple(machine[1:3]),'all23 GREG/65536FP/AF/TLS at actual completed prefix before retry refusal')
    need(entry['source']==entry['terminal_source']==native['source'],'whole source remains exact before retry refusal')
    for key in('before_memory','after_memory'):need(entry[key]['data']==native['data']and entry[key]['stack']==native['stack'],'whole actual completed-prefix data/stack before retry refusal')
    return dict(qualified_retry_control=1,refault_control=owner['refault_control'],completed_prefix=1,native_operations=0)


def hint_read(data,mode,native,exit_status,layout,pid,cpu,seed_reference,*,hint_control):
    """Separate actual terminal prefix after a completed focal graph."""
    need(type(hint_control)is int and hint_control in range(1,4)and mode==0 and native is False and type(exit_status)is int and exit_status==125 and type(data)is bytes and len(data)==PREFIX,'exact additional advisory-control process/prefix')
    return _prefix(data,mode,native,layout,pid,cpu,seed_reference)


def hint_control_reference(native,gated,owner):
    need(owner['hint_control']in range(1,4)and owner['control']==0 and native['mode']==gated['mode']==0 and native['header'][5]==1 and gated['header'][5]==0,'exact additional advisory-control native context')
    need(gated['suffix']is None and native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'advisory-control whole original native inputs and no returned suffix')
    need(len(owner['entries'])==len(native['observations'])==1,'one actually completed graph before helper advisory failure')
    entry=owner['entries'][0];ref=native['observations'][0];machine=gated['machine']
    need(entry['disposition']=='completed','actual focal graph completed before additional advisory refusal')
    for key,index,event in(('ingress',1,'trace'),('before',1,'closed'),('predecessor_before',0,'trace'),('after',2,'nx')):
        actual=entry[key];reference=ref['frames'][index];want=list(reference['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want)and actual['fp']==reference['fp']and actual['fp_bytes']==reference['header'][9]and actual['mask']==MASK and(actual['fs'],actual['gs'])==tuple(machine[1:3]),'all23 GREG/65536FP/AF/TLS at actual completed prefix before advisory refusal')
    need(entry['source']==entry['terminal_source']==native['source'],'whole source remains exact before advisory refusal')
    for key in('before_memory','after_memory'):need(entry[key]['data']==native['data']and entry[key]['stack']==native['stack'],'whole actual completed-prefix data/stack before advisory refusal')
    return dict(qualified_hint_control=1,hint_control=owner['hint_control'],completed_prefix=1,native_operations=0)
