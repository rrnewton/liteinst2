"""Genuine TRACE span application stdout/native references and full cross-lane comparison.
Protected production-owner interpretation is a separate mandatory reader.
No import or source-only check grants native/owner/performance credit.
"""
import hashlib
import struct
PAGE, FP, UC, LIVE = 4096,65536,1024,2116
PREFIX, SUFFIX, OBS, FRAME = 14720,217656,217528,66784
MAGIC = 0x315050415453494c
DATA, STACK = 0x500000000000,0x500000100000
RSP, STACK_FAULT = STACK+4096+131072-504,STACK+8192
U64, TF, RF = (1<<64)-1,0x100,0x10000
MASK = 0xffffffffbffbfae7
GRAPH=bytes.fromhex('b807000000488d5448034801d0448b07448b0d690000004883f80f7453eb31')
OFFSETS=(0,5,10,13,16,23,27,29)
LENGTHS=(5,5,3,3,7,4,2,2)
TRACES=(9,8,2,4)
EXITS=(0x250,0x270,0x302,0x20d)
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
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'exit1', 'predecessor', 'miss_predecessor', 'miss_head', 'miss_exit', 'constant', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
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
    expected = bytearray(b'\xcc' * PAGE)
    expected[0x1fe:0x200]=b'\x66\x90';expected[0x200:0x21f]=GRAPH
    expected[0x2fe:0x302]=b'\x66\x90\x66\x90'
    need(symbols['region_app_predecessor']==page+0x1fe and symbols['region_app_miss_predecessor']==page+0x2fe and
         symbols['region_app_miss_head']==page+0x300 and symbol_sizes['region_app_miss_head']==2 and
         symbol_sizes['region_app_head']==31, 'exact immutable predecessor and typed heads')
    for name, offset in (('exit0',0x250),('exit1',0x270),('miss_exit',0x302)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==6,'three exact transparent exit symbols')
        expected[offset:offset+14]=b'\xff\x25\0\0\0\0'+struct.pack('<Q',symbols['region_app_capture_high'])
    need(symbols['region_app_constant']==page+0x280 and symbol_sizes['region_app_constant']==4,'actual immutable RIP-relative operand')
    expected[0x280:0x284]=struct.pack('<I',0x89abcdef)
    need(source==expected,'whole actual31-byte span, NOP refusal, RIP data, exits and all CC fill')
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
    return dict(symbols=symbols, head=head, miss=page+0x300, page=page, exits=tuple(page + x for x in EXITS), source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10])



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
    need(type(mode)is int and 0<=mode<4,'fixed four actual application modes')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[1]=U64 if mode==1 else 3;seed[4]=RSP;seed[7]=DATA+8192 if mode==3 else DATA+128
    return (tuple(seed),0x202 if mode%2 else 0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(224))


def state(seed,data,mode):
    out=list(seed)
    if mode!=2:
        out[0]=7;out[2]=(out[0]+2*out[1]+3)&U64;out[0]=(out[0]+out[2])&U64
        if mode!=3:out[8]=u(data,out[7]-DATA)[0];out[9]=0x89abcdef
    return tuple(out)


def _prefix(data,mode,native,layout,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and 0<=mode<4 and type(native)is bool,'typed whole TRACE application prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6) for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:6304],data[6304:6528],data[6528:]
    head=layout['miss'] if mode==2 else layout['head'];endpoint=layout['exits'][mode]
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu) and h[9]<=0xffffffff and h[10:14]==(head,layout['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode==3),layout['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16) and h[26]==h[28]==0,'actual signal geometry and successful permission observations')
    need(h[30:]==(1,224,DATA+8192 if mode==3 else 0,3 if mode==3 else 0,endpoint,head-2,TRACES[mode],OBS,3,31,layout['head'],layout['miss'],layout['page']+0x280,0,0,0,0,0),'whole fixed TRACE schedule and reserved fields')
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
    return dict(header=h,mode=mode,head=head,predecessor=head-2,source_page_address=layout['page'],source_page=source,source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=endpoint,fault_pc=endpoint if mode==3 else 0,fault_address=DATA+8192 if mode==3 else 0,suffix=None,observations=[])


def read(data,mode,native,exit_status,layout,pid,cpu,seed_reference,*,control=0):
    need(type(data)is bytes and type(mode)is int and 0<=mode<4 and type(native)is bool and type(exit_status)is int and type(control)is int and control in (0,1),'typed actual TRACE outcome')
    need(not control or (not native and mode==0),'nested owner control uses genuine mode0 input')
    full=native or (mode!=3 and not control)
    need(exit_status==(125 if mode==3 or control else 0) and len(data)==PREFIX+(SUFFIX if full else 0),'exact actual required outcome and complete output')
    result=_prefix(data[:PREFIX],mode,native,layout,pid,cpu,seed_reference)
    if not full:return result
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,1,mode,int(native),0,1,1,3 if native else 0,TRACES[mode] if native else 0,int(mode==3),0,0,0,0,0,0),'whole terminal cleanup and observation counters')
    value=suffix[128:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);a,b=value[432:2548],value[2548:4664]
    selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(h==(1,0,3 if native else 0,TRACES[mode] if native else 0,int(mode==3),int(native),0,0,result['expected_exit_pc'],0,0,0,0,0,0,0),'complete actual invocation')
    need(before==(result['seed'][0],result['seed'][1],selectors) and after[2]==selectors and not after[1]&(TF|RF) and a==b==LIVE_SEED,'all actual live GPR/flags/selectors/vector state')
    need(after[0]==state(result['seed'][0],result['data'],mode),'independent defined GPR outputs without flag prediction')
    need(value[4664:8760]==result['source'] and value[8760:8984]==result['stack'] and value[8984:17176]==result['data'],'full source/stack/data after invocation')
    frames=[]
    for index in range(3):
        frame=value[17176+index*FRAME:17176+(index+1)*FRAME]
        if not native:need(frame==bytes(FRAME),'gated fixture does not fabricate native frames')
        else:frames.append(reference_frame(frame,result,layout,index if index<2 else 3 if mode==3 else 2,0 if index==0 else 1 if index==1 else TRACES[mode],0))
    if native:
        need(frames[0]['fp']==frames[1]['fp']==frames[2]['fp'],'all65536 FP bytes across native boundaries')
        need(after[1]==frames[2]['greg'][17]&~(TF|RF),'all actual result flags including undefined AF')
    result['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h)]
    result['suffix']=dict(end=end);return result


def pair(native,gated,owner):
    need(native['header'][5]==1 and gated['header'][5]==0 and native['mode']==gated['mode'] and owner['control']==0,'actual original/TRACE-owner pair')
    mode=native['mode'];reference=native['observations'][0]
    need(native['header'][8:19]==gated['header'][8:19] and native['hardware']==gated['hardware'] and all(native[k]==gated[k] for k in ('seed','source','stack','data','rsp','predecessor')),'whole same actual inputs and hardware')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:],'actual mask/selectors')
    def compare(actual,ref,event):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==ref['header'][9] and actual['mask']==MASK,'whole typed actual frame')
        want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        elif event=='fault':want[17]&=~TF;want[16]=actual['greg'][16]
        else:need(event=='trace','exact event transform')
        need(actual['greg']==tuple(want) and actual['fp']==ref['fp'],'all23 GREG/all65536 FP including AF, exact event-only conversion')
        need((actual['fs'],actual['gs'])==gated['machine'][1:3],'actual gated TLS bracket')
    entry=owner['entry'];compare(entry['ingress'],reference['frames'][1],'trace');compare(entry['before'],reference['frames'][1],'closed')
    compare(entry['predecessor_before'],reference['frames'][0],'trace')
    need(entry['source']==entry['terminal_source']==native['source'],'whole original source conserved')
    for memory in (entry['before_memory'],entry['after_memory']):
        need(memory['data']==native['data'] and memory['stack']==native['stack'],'full actual data/224stack observations')
    if mode==2:
        need(entry['disposition']=='resumed' and entry['resumed_route']==1 and entry['redirected']==0 and entry['generated_entry']==0,'actual ordinary successor installed; no generated credit')
        compare(entry['resumed'],reference['frames'][1],'trace')
        compare(entry['resumed_exit'],reference['frames'][2],'trace')
    elif mode==3:
        need(entry['disposition']=='fault' and entry['mapped']['original_pc']==native['head']+13 and entry['mapped']['head_index']==3 and entry['unexpected']['greg'][16]==entry['mapped']['generated_pc'],'exact failed generated load association')
        compare(entry['unexpected'],reference['frames'][2],'fault')
    else:
        need(entry['disposition']=='completed','actual generated region completion');compare(entry['after'],reference['frames'][2],'nx')
    if mode!=3:
        actual=gated['observations'][0]
        need(reference['before']==actual['before'] and reference['after']==actual['after'] and reference['live']==actual['live'],'complete actual post-exit GPR/flags/AF/selectors/vector equality')
    need((gated['suffix']is None)==(mode==3),'no application completion after generated fault')
    return dict(qualified_case=1,generated_completed=int(mode<2),ordinary_resumed=int(mode==2),required_read_failure=int(mode==3),reference_steps=TRACES[mode])


def control_reference(native,gated,owner):
    need(owner['control']==1 and native['mode']==gated['mode']==0 and native['header'][5]==1 and gated['header'][5]==0 and gated['suffix']is None,'required actual nested refusal')
    need(native['hardware']==gated['hardware'] and all(native[k]==gated[k] for k in ('seed','source','stack','data','rsp')),'full actual nested reference inputs')
    ref=native['observations'][0]['frames'][1];entry=owner['entry'];want=list(ref['greg']);want[17]&=~TF
    need(entry['before']['greg']==tuple(want) and entry['before']['fp']==ref['fp'] and entry['before']['mask']==MASK and (entry['before']['fs'],entry['before']['gs'])==gated['machine'][1:3],'all actual outer state before genuine nesting')
    need(entry['ingress']['greg']==ref['greg'] and entry['ingress']['fp']==ref['fp'] and entry['disposition']=='nested' and entry['redirected']==1 and not entry['completed'],'genuine TRACE origin and no nested completion credit')
    return dict(native_entry_joins=1,required_nested_refusals=1,completed_application=0)


def controls(check_pair,native_output,gated_output,mode):
    need(type(mode)is int and 0<=mode<4,'fixed TRACE control mode')
    def flip(data,at,value=1):
        out=bytearray(data);out[at]^=value;return bytes(out)
    first=PREFIX+128
    rows=[('version',8),('mode',32),('pid',48),('source_tail',6303),('stack_tail',6527),('data_tail',PREFIX-1),('seed_RCX',2000),('hardware',384),('mask',2144),('cleanup',PREFIX+40),('after_GPR',first+280),('after_AF',first+408),('selector',first+416),('before_live',first+432),('after_live',first+4663),('after_stack',first+8983),('after_data',first+17175),('frame_UC_tail',first+17176+1247),('frame_FP_tail',first+17176+FRAME-1),('frame_FIP',first+17176+1248+8),('TRACE_PC',first+17176+FRAME+224+40+16*8),('terminal_FP_tail',first+17176+3*FRAME-1)]
    trials=[(name,flip(native_output,at,0x10 if name=='after_AF' else 1),gated_output)for name,at in rows]
    trials += [('native_truncated',native_output[:-1],gated_output),('gated_truncated',native_output,gated_output[:-1]),('gated_appended',native_output,gated_output+b'\0'),('gated_data',native_output,flip(gated_output,PREFIX-1))]
    changed=bytearray(native_output)
    for i in range(3):changed[first+17176+i*FRAME+1248+48]^=1
    trials.append(('coherent_native_FP',bytes(changed),gated_output))
    trials.append(('actual_fault_CR2',flip(native_output,first+17176+2*FRAME+224+40+22*8),gated_output) if mode==3 else ('gated_AF',native_output,flip(gated_output,first+408,0x10)))
    need(len(trials)==28 and len({x[0]for x in trials})==28,'fixed complete supplied refusal set')
    for name,n,g in trials:
        rejected=False
        try:check_pair(n,g)
        except ValueError:rejected=True
        need(rejected,'TRACE app reader accepted '+name)
    return dict(supplied_refusals=28,native_operations=0)
