"""Additive CACHE8 ABC169 native/full-state oracle. Three independent source
pairs, two actual eight-cycle phases and an ordinary reset between them.
No generated-runtime, qualification or timing credit follows from this reader.
"""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=35272,839592,839192,66784
MAGIC=0x384350414132494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES=(169,)
STEPS=(0,1,4,7,82,83,85,88,91,166,167,169)
REFERENCE=(1,169,STEPS)
REFERENCE255=(3,255,(0,1,3,4,6,7,82,84,167,169,253,255))

def reference_profile(name):
    if type(name)is str and name=='cache8-abc255':return REFERENCE255
    need(type(name) is str and name=='cache8-abc169','explicit exact CACHE8 ABC169 native reference')
    return REFERENCE


GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)

def u(data,at=0,count=1):return struct.unpack_from('<'+'I'*count,data,at)

def elf(data, native_policy, *, reference='cache8-abc169', variant=None):
    if reference!='cache8-abc169':reference_profile(reference)
    need(variant is None or reference=='cache8-abc169','distinct descriptor or real-effect ELF reference')
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
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'predecessor', 'block_b', 'second_page', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end', 'a_exit', 'b_exit', 'b_branch', 'b_move', 'pair_b', 'b_second_page', 'a_store', 'b_store')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
    wanted |= {'region_app_repeat_'+n for n in ('page','setup','site','next','end','buffer')}
    wanted -= {'region_app_b_branch','region_app_b_move'}
    wanted |= {'region_app_'+n for n in ('a_direct','b_direct','block_c','pair_c','c_second_page','c_store','c_repeat','c_reset','c_exit','reset','reset_jump','reset_end')}
    if reference=='cache8-abc255':wanted.add('region_app_reset_tail')
    if variant is not None:wanted |= set(variant['symbols'])
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
         p[1]==5 and p[2]+page-p[3]>=PAGE,'actual six complete RX source pages outside ELF header')
    expected=bytearray(b'\xcc'*(6*PAGE));expected[0x1fe:0x200]=b'\x66\x90'
    expected[0x200:0x20c]=bytes.fromhex('4883c001488907e9')+struct.pack('<i',0x2400-0x20c)
    expected[0x2400:0x240d]=bytes.fromhex('4883c00248894708e9')+struct.pack('<i',0x4600-0x240d)
    expected[0x4600:0x4621]=(bytes.fromhex('4883c004488947104883e9010f85')+struct.pack('<i',0x200-0x4612)+
        bytes.fromhex('4983e8010f85')+struct.pack('<i',0x6000-0x461c)+bytes.fromhex('e9')+struct.pack('<i',0x7000-0x4621))
    if reference=='cache8-abc255':expected[0x4618:0x461c]=struct.pack('<i',0x6ffa-0x461c)
    need(source==expected,'whole disjoint A/B/C source pairs and exact near DIRECT encodings')
    for name,offset,size in (('head',0x200,12),('block_b',0x2400,13),('block_c',0x4600,33),
        ('a_store',0x204,0),('b_store',0x2404,0),('c_store',0x4604,0),
        ('a_exit',0x207,0),('b_exit',0x2408,0),('exit0',0x207,0),
        ('a_direct',0x207,0),('b_direct',0x2408,0),('c_repeat',0x460c,0),('c_reset',0x4616,0),('c_exit',0x461c,0),
        ('pair_b',0x2000,0),('b_second_page',0x3000,0),('pair_c',0x4000,0),('c_second_page',0x5000,0)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,
             'actual complete three-pair source symbol geometry')
    need(symbols['region_app_predecessor']==page+0x1fe and symbols['region_app_second_page']==page+PAGE,
         'actual NOP predecessor and complete second source page')
    if variant is None:
        reset=bytes.fromhex('48c7c108000000e9')+struct.pack('<i',0x200-0x600c)
        if reference=='cache8-abc255':
            need(symbols['region_app_reset_tail']==page+0x6ffa and symbol_sizes['region_app_reset_tail']==5,
                 'exact original page-tail DIRECT outside all cached head lists')
            reset+=b'\xcc'*(0xffa-len(reset))+b'\xe9'+struct.pack('<i',0x6000-0x6fff)
        need(symbols['region_app_reset']==page+0x6000 and symbol_sizes['region_app_reset']==12 and
             symbols['region_app_reset_jump']==page+0x6007 and symbols['region_app_reset_end']==page+0x7000 and
             memory(page+0x6000,PAGE)[0][1]==5 and memory(page+0x6000,PAGE)[1]==reset+b'\xcc'*(PAGE-len(reset)),
             'whole original reset frontier outside both measured generated intervals')
    else:variant['reset'](symbols,symbol_sizes,memory,loads)
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
         capture == page+7*PAGE and symbols['region_app_return_end'] == capture + PAGE and
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
    repeat_page=symbols['region_app_repeat_page'];repeat_buffer=symbols['region_app_repeat_buffer']
    repeat_load,repeat_image=memory(repeat_page,PAGE)
    repeat_body=bytes.fromhex('fcb90800000048b81122334455667788f348abc3')
    need(PAGE<=repeat_page<0x200000000 and repeat_page%PAGE==0 and repeat_load[1]==5 and
         symbols['region_app_repeat_setup']==repeat_page and symbol_sizes['region_app_repeat_setup']==len(repeat_body)and
         symbols['region_app_repeat_site']==repeat_page+16 and symbols['region_app_repeat_next']==repeat_page+19 and
         symbols['region_app_repeat_end']==repeat_page+PAGE and
         repeat_image==repeat_body+b'\xcc'*(PAGE-len(repeat_body)),
         'whole low original RX positive REP setup page and exact canonical STOSQ site')
    need(repeat_buffer%8==0 and symbol_sizes['region_app_repeat_buffer']==80 and
         sum(p[1]==6 and p[3]<=repeat_buffer<=p[3]+p[6]-80 for p in loads)==1,
         'complete separate RW eight-word REP destination and both sentinel words')
    repeat_setup=dict(pc=repeat_page+16,next_pc=repeat_page+19,
        file_offset=repeat_load[2]+repeat_page+16-repeat_load[3],
        destination=repeat_buffer+8,count=8,width=8,value=0x8877665544332211)
    return dict(symbols=symbols,head=head,page=page,exits=(page+0x207,page+0x2408,page+0x4616,page+0x461c),
        source=source,source_pairs=tuple(source[i*2*PAGE:(i+1)*2*PAGE]for i in range(3)),
        reset_pair=memory(page+6*PAGE,2*PAGE)[1],
        source_offsets=tuple(memory(page+i*2*PAGE,2*PAGE)[0][2]+page+i*2*PAGE-memory(page+i*2*PAGE,2*PAGE)[0][3] for i in range(4)),
        roots=(head,page+0x2400,page+0x4600),page_b=page+2*PAGE,page_c=page+4*PAGE,
        interpreter=path[:-1].decode(),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),phnum=h[10],repeat_setup=repeat_setup)


def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]

def reference_frame(data, prefix, layout, kind, steps, attempt, *, reference='cache8-abc169', spec=None):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    fault=False
    sig = (11 if kind==0 or fault else 5) if spec is None else spec['signal']
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
    g = q(uc, 40, 23); pc = frame_pc(prefix,kind, reference=reference) if spec is None else spec['pc']
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] ==
         (((21, 14) if kind == 0 else (6, 14) if fault else (0, 1)) if spec is None else spec['exception']),
         'genuine native signal origin')
    if spec is None:
        if kind==0 or fault:
            address = prefix['fault_address'] if fault else pc
            need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
        else:need(q(si,16)[0]==pc and g[22]==prefix['predecessor'],'actual TRACE PC and retained original NX CR2')
        expected = frame_state(prefix,kind, reference=reference)
        need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
        expected_flags=trace_model(prefix, reference=reference)[steps][2] | (RF if kind==0 else TF)
        need(g[17]==expected_flags,'every actual native flag including AF and causal TF/RF')
    else:
        need(q(si,16)[0]==spec['address'] and g[22]==spec['cr2'],'exact real-effect native signal and CR2')
        need(tuple(g[i]for i in GREG)==spec['greg'] and g[18]==0x2b000000000033 and g[21]==MASK,
             'whole actual real-effect native GPR model')
        need(g[17]==spec['flags'],'every real-effect native flag including exact TF/RF')
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

def fixture(mode,image, *, reference='cache8-abc169'):
    need(type(mode)is int and mode==0,'explicit three-root/two-phase success only')
    reference_profile(reference)
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=1;seed[1]=8;seed[2]=image['symbols']['region_app_block_b'];seed[3]=image['head'];seed[8]=2
    if reference=='cache8-abc255':seed[8]=3
    seed[4]=RSP;seed[6]=image['symbols']['region_app_capture'];seed[7]=DATA
    data=bytes(1+(i*17)%255 for i in range(8192))
    return (tuple(seed),0xad7,bytes(12)),data,bytes((i*29+7)&255 for i in range(224))

def arithmetic(a,b,flags,subtract=False):
    value=(a-b if subtract else a+b)&U64
    overflow=((a^b)&(a^value) if subtract else ~(a^b)&(a^value))>>63&1
    updated=int(a<b if subtract else a+b>U64) | (int((value&255).bit_count()%2==0)<<2)
    updated|=(a^b^value)&16;updated|=int(value==0)<<6;updated|=(value>>63)<<7;updated|=overflow<<11
    return value,(flags&~0x8d5)|updated

def instruction(pc,g,flags,data,stack,prefix,*,reference='cache8-abc169'):
    page=prefix['source_page_address']
    off=pc-page
    if off==0x1fe:pc+=2
    elif off in(0x200,0x2400,0x4600):
        g[0],flags=arithmetic(g[0],{0x200:1,0x2400:2,0x4600:4}[off],flags);pc+=4
    elif off in(0x204,0x2404,0x4604):
        displacement={0x204:0,0x2404:8,0x4604:16}[off];address=g[7]+displacement
        need(DATA<=address<=DATA+8192-8,'whole modeled guarded store range')
        changed=bytearray(data);struct.pack_into('<Q',changed,address-DATA,g[0]);data=bytes(changed)
        pc+=3 if off==0x204 else 4
    elif off==0x207:pc=page+0x2400
    elif off==0x2408:pc=page+0x4600
    elif off==0x4608:g[1],flags=arithmetic(g[1],1,flags,True);pc+=4
    elif off==0x460c:pc=page+(0x200 if not flags&0x40 else 0x4612)
    elif off==0x4612:g[8],flags=arithmetic(g[8],1,flags,True);pc+=4
    elif off==0x4616:pc=page+(0x6000 if not flags&0x40 else 0x461c)
    elif off==0x461c:pc=page+0x7000
    elif off==0x6000:g[1]=8;pc+=7
    elif off==0x6007:pc=page+0x200
    elif reference=='cache8-abc255' and off==0x6ffa:pc=page+0x6000
    elif off==0x7000:pc=prefix['symbols']['region_app_capture_high']
    else:raise ValueError('unmodelled original instruction')
    if reference=='cache8-abc255' and off==0x4616 and pc==page+0x6000:pc=page+0x6ffa
    return pc,g,flags,data,stack

def trace_model(prefix, *, reference='cache8-abc169'):
    """All169 original instructions and exact writes, including reset/final JMP."""
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    page=prefix['source_page_address'];data=prefix['data'];stack=prefix['stack']
    out=[(pc,tuple(g),flags,data,stack)]
    for _ in range(reference_profile(reference)[1]):
        pc,g,flags,data,stack=instruction(pc,g,flags,data,stack,prefix,reference=reference)
        out.append((pc,tuple(g),flags,data,stack))
    need(out[-1][0]==prefix['expected_exit_pc'],'actual model ends at high capture suffix')
    if reference=='cache8-abc255':
        need(tuple(out[i][0]-page for i in(1,3,4,6,7,82,83,84,167,168,169,253,254))==
             (0x200,0x207,0x2400,0x2408,0x4600,0x4616,0x6ffa,0x6000,0x4616,0x6ffa,0x6000,0x461c,0x7000),
             'exact three-phase roots, both real resets and final exit')
    else:
        need(tuple(out[i][0]-page for i in(1,4,7,82,83,85,88,91,166,167))==
             (0x200,0x2400,0x4600,0x4616,0x6000,0x200,0x2400,0x4600,0x4616,0x461c),
             'exact two-phase original roots and both genuine exit boundaries')
    return out

def frame_pc(prefix,kind, *, reference='cache8-abc169'):
    steps=reference_profile(reference)[2]
    need(type(kind)is int and 0<=kind<len(steps),'one of12 explicitly retained native boundaries')
    return trace_model(prefix, reference=reference)[steps[kind]][0]

def frame_state(prefix,kind, *, reference='cache8-abc169'):return trace_model(prefix, reference=reference)[reference_profile(reference)[2][kind]][1]

def state(seed,data,mode, *, reference='cache8-abc169'):
    need(mode==0,'only the explicit two-phase loop result');reference_profile(reference)
    out=list(seed);out[0]+=112;out[1]=0;out[8]=0
    if reference=='cache8-abc255':out[0]+=56
    return tuple(out)

def written(data,mode, *, reference='cache8-abc169'):
    if reference!='cache8-abc169':
        reference_profile(reference)
        need(mode==0,'three exact full-width final store effects')
        out=bytearray(data);struct.pack_into('<3Q',out,0,163,165,169);return bytes(out)
    need(mode==0,'three exact full-width final store effects')
    out=bytearray(data);struct.pack_into('<3Q',out,0,107,109,113);return bytes(out)

def _prefix(data,mode,native,image,pid,cpu,seed_reference, *, reference='cache8-abc169', variant=None):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode==0 and type(native)is bool,'typed complete persistent app prefix')
    need(mode==0,'no unvalidated fault mode')
    profile=reference_profile(reference) if variant is None else variant['profile']
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:26784],data[26784:27008],data[27008:35200]
    head=image['head'];frontier=image['symbols']['region_app_capture_high'];predecessor=head-2
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,profile[0],PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode==1),image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,predecessor,profile[1],OBS,12,45 if variant is None else variant['kind'],image['page']+0x2400,image['page']+0x4600,24576,RSEQ,0x53053053,image['page']+0x207,image['page']+0x2408,image['page']+0x4616),'exact cyclic fixture and reserved header')
    need(source==image['source']and machine[0]==MASK and machine[1:3]==(0,0) and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component geometry')
    expected,want_data,want_stack=fixture(mode,image, reference=reference)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/stack bytes')
    registration=q(data,35200,9)
    need(registration==(U64,)+(0,)*8,'explicit registration not-attempted marker and unavailable snapshots')
    return dict(symbols=image['symbols'],header=h,mode=mode,head=head,predecessor=predecessor,source_page_address=image['page'],source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=head if mode==1 else frontier,fault_pc=head if mode==1 else 0,fault_address=DATA+8192 if mode==1 else 0,suffix=None,observations=[])

def read(data,mode,native,exit_status,image,pid,cpu,seed_reference, *, reference='cache8-abc169', variant=None):
    need(type(data)is bytes and type(mode)is int and mode==0 and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    full=native or mode==0
    need(exit_status==(0 if mode==0 else 125)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated status and complete output')
    profile=reference_profile(reference) if variant is None else variant['profile']
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference, reference=reference, variant=variant)
    if not full:return r
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,profile[0],mode,int(native),0,1,1,12 if native else 0,profile[1]if native else 0,int(mode==1),2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,12 if native else 0,profile[1]if native else 0,int(mode==1),int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],r['data'],mode, reference=reference)and after[1]==0x246,'all defined loop GPR and flag results')
    need(value[4792:29368]==r['source']and value[29368:29592]==r['stack']and value[29592:37784]==written(r['data'],mode, reference=reference),'whole source/stack and exact completed store effects')
    frames=[]
    for i in range(12):
        frame=value[37784+i*FRAME:37784+(i+1)*FRAME]
        if not native or(mode==1 and i>=3):need(frame==bytes(FRAME),'no fabricated native signal')
        else:
            kind=i
            steps=profile[2][i]
            frames.append(reference_frame(frame,r,image,kind,steps,0, reference=reference,
                spec=None if variant is None else variant['frame'](r,kind)))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[29592:37784],stack=value[29368:29592])]
    r['effects']=effects;r['suffix']=dict(end=end);return r


APP_CONTROL_COUNTS={0:45}

def control_sites(*,reference='cache8-abc169'):
    observation=PREFIX+400;frame=observation+37784
    tests=(('version',8),('CPU',8*8),('hardware',384+8),('seed_GPR',1992),
           ('source',2208),('stack',26784),('data',27008),('registration_result',35200),
           ('publication_word',35200+6*8),('cleanup',PREFIX+5*8),
           ('after_GPR',observation+280),('after_AF',observation+408),
           ('actual_TLS',observation+496+8),('whole_live_vector',observation+2676),
           ('native_FP',frame+1248),('completed_store_bytes',observation+29592),
           ('A_to_B_flags',frame+2*FRAME+224+40+17*8),
           ('cold_C_entry_PC',frame+3*FRAME+224+40+16*8),
           ('first_joint_exit_RAX',frame+4*FRAME+224+40+GREG[0]*8),
           ('reset_entry_RCX',frame+5*FRAME+224+40+GREG[1]*8),
           ('second_A_entry_PC',frame+6*FRAME+224+40+16*8),
           ('second_B_entry_PC',frame+7*FRAME+224+40+16*8),
           ('final_C_exit_RBX',frame+10*FRAME+224+40+GREG[3]*8),
           ('last_TRACE_PC',frame+11*FRAME+224+40+16*8),
           ('no_prefix_registration_before',35208),('no_prefix_registration_after',35240),
           ('collection_lifetime',PREFIX+80),('collection_completed',PREFIX+88),
           ('later_registration_result',PREFIX+128+64),('later_registration_word',PREFIX+128+13*8),
           ('later_unregistration_word',PREFIX+264+13*8),('second_store_bytes',observation+29592+8),
           ('peer_source_pair',2208+2*PAGE),('peer_second_page',2208+3*PAGE),
           ('six_source_extent',42*8),('observed_peer_source',observation+4792+2*PAGE),
           ('second_phase_R8',frame+6*FRAME+224+40+GREG[8]*8),
           ('known_arm_flags',frame+7*FRAME+224+40+17*8),
           ('final_condition_RCX',frame+9*FRAME+224+40+GREG[1]*8),
           ('final_unknown_PC',frame+10*FRAME+224+40+16*8),
           ('third_source_pair',2208+4*PAGE),('third_second_page',2208+5*PAGE),
           ('observed_third_source',observation+4792+4*PAGE),
           ('third_store_bytes',observation+29592+16),('third_root_header',41*8))
    if reference=='cache8-abc255':
        labels={'A_to_B_flags':'first_A_exit_flags','cold_C_entry_PC':'first_B_entry_PC',
            'first_joint_exit_RAX':'first_B_exit_RAX','reset_entry_RCX':'first_C_entry_RCX',
            'second_A_entry_PC':'first_joint_exit_PC','second_B_entry_PC':'first_reset_entry_PC',
            'second_phase_R8':'first_joint_exit_R8','known_arm_flags':'first_reset_entry_flags',
            'final_condition_RCX':'second_reset_entry_RCX'}
        tests=tuple((labels.get(name,name),offset)for name,offset in tests)
    return tests

def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference, *, reference='cache8-abc169', variant=None):
    """Sixteen complete-state classes plus eight active-domain checkpoint checks."""
    need(native is True and mode in APP_CONTROL_COUNTS,'native-only application supplied controls')
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference, reference=reference, variant=variant)
    tests=control_sites(reference=reference)
    need(len(tests)==APP_CONTROL_COUNTS[mode],'all40 inherited state corruption classes plus five actual third-root classes')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference, reference=reference, variant=variant)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    if reference=='cache8-abc255':
        frame=PREFIX+400+37784
        reference_tests=(('second_reset_R8',frame+9*FRAME+224+40+GREG[8]*8),('phase_seed',1992+8*8),
            ('prefix_trace_total',36*8),('suffix_trace_total',PREFIX+8*8),
            ('final_checkpoint_R8',frame+11*FRAME+224+40+GREG[8]*8))
        need(len({offset for _,offset in tests+reference_tests})==50,
             'all45 original and five reference corruption offsets are distinct')
        extra=[]
        for name,offset in reference_tests:
            mutant=bytearray(data);mutant[offset]^=1
            try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference,reference=reference)
            except ValueError:extra.append(name)
            else:raise ValueError('supplied actual ABC255 reference corruption accepted '+name)
        need(len(extra)==len(set(extra))==5,'five separate exact ABC255 reference controls')
        return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,
                    reference_refusals=extra,native_operations=0,mode=mode)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)


def application_pair(native,gated):
    """One shared full application-state comparison, no owner/permission credit."""
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')
    need(len(native['observations'])==len(gated['observations'])==1,'actual complete application observations')
    reference=native['observations'][0]
    actual=gated['observations'][0]
    need(all(reference[k]==actual[k]for k in('before','after','live','data','stack'))and gated['effects']==native['effects']and gated['suffix']is not None,'whole actual application state and later registration lifecycle')
    return dict(full_application_state_equal=True, interior_owner_state_observed=False)
