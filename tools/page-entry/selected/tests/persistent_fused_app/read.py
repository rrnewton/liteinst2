"""Separate version12 PF native/application state: cold141-store loop, repair,
warm142-store loop and real unsupported16-bit root. Full inherited state,
context and supplied-corruption checks remain; no performance credit."""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=27080,831400,831000,66784
MAGIC=0x414450414132494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES=(2838,)
STEPS=(0,1,7,1412,1413,1416,1417,1423,2834,2835,2836,2838)
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
    wanted = {'region_app_' + n for n in ('head', 'page', 'exit0', 'predecessor', 'block_b', 'second_page', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end', 'a_exit', 'b_exit', 'b_branch', 'b_move', 'pair_b', 'b_second_page', 'a_store', 'b_store')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
    wanted |= {'region_app_repeat_'+n for n in ('page','setup','site','next','end','buffer')}
    wanted |= {'region_app_'+n for n in ('a_direct','a_reset','b_condition','b_tail_jump','a_final')}
    wanted |= {'region_app_probe_'+n for n in ('load','page','second','end','setup','one_page','graph','return')}
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
    p,source=memory(page,4*PAGE)
    need(page==0x410000 and head==page+0x206 and symbols['region_app_source_end']==page+4*PAGE and
         p[1]==5 and p[2]+page-p[3]>=PAGE,'actual four complete RX source pages outside ELF header')
    expected=bytearray(b'\xcc'*(4*PAGE))
    expected[0x200:0x228]=(bytes.fromhex('488b104c01e2837808080f85')+
        struct.pack('<i',0x2400-0x210)+bytes.fromhex('488b48104883c0184c01e148890a4839d872dd668907ffe6'))
    expected[0x2400:0x240e]=bytes.fromhex('4d891a4889f84c89eae9')+struct.pack('<i',0x206-0x240e)
    need(source==expected,'whole disjoint A/B source pairs and exact near direct branch encodings')
    for name,offset,size in (('head',0x206,29),('block_b',0x2400,14),
                             ('a_store',0x21b,0),('b_store',0x2400,0),
                             ('a_exit',0x20a,0),('b_exit',0x223,0),('exit0',0x20a,0),
                             ('b_branch',0x2409,0),('b_move',0x223,0),
                             ('a_direct',0x20a,0),('a_reset',0x21e,0),
                             ('b_condition',0x2409,0),('b_tail_jump',0x226,0),('a_final',0x221,0),
                             ('pair_b',0x2000,0),('b_second_page',0x3000,0)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,
             'actual complete cross-pair source symbol geometry')
    need(symbols['region_app_predecessor']==page+0x203 and symbols['region_app_second_page']==page+PAGE,
         'actual ADD predecessor and complete second source page')
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
         capture == page+4*PAGE and symbols['region_app_return_end'] == capture + PAGE and
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
    probe_load,probe_image=memory(0x200040000,4*PAGE)
    probe_page=0x200041000
    probe_expected=bytearray(b'\xcc'*(4*PAGE))
    probe_expected[PAGE+16:PAGE+27]=bytes.fromhex('48b81122334455667788c3')
    probe_expected[PAGE+4090:PAGE+4100]=bytes.fromhex('662e0f1f84000000000000')
    probe_expected[PAGE+4100:PAGE+4103]=bytes.fromhex('0f1f00')
    probe_expected[PAGE+4103:PAGE+4108]=bytes.fromhex('e904f0ffff')
    need(probe_load[1]==5 and probe_load[3]==0x200040000 and
         probe_load[5]==probe_load[6]==4*PAGE and probe_image==bytes(probe_expected),
         'whole separate RX probe load, both source pages and unchanged-policy CC halos')
    for name,offset,size in (('setup',4090,10),('one_page',4100,3),('graph',4103,5),('return',16,11),('page',0,8192)):
        need(symbols['region_app_probe_'+name]==probe_page+offset and
             symbol_sizes['region_app_probe_'+name]==size,'exact actual high probe instruction/source extent')
    need(symbols['region_app_probe_load']==probe_page-PAGE and
         symbols['region_app_probe_second']==probe_page+PAGE and
         symbols['region_app_probe_end']==probe_page+2*PAGE and
         probe_page+4108+struct.unpack('<i',probe_image[PAGE+4104:PAGE+4108])[0]==probe_page+16,
         'actual out-of-page linked GRAPH target and complete source geometry')
    for address in (probe_page,probe_page+PAGE):
        need(native_policy(memory(address-14,PAGE+28)[1])==0,
             'each actual complete probe source page and both halos pass unchanged native policy')
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
    return dict(symbols=symbols, head=head, page=page, exits=(page+0x20a,page+0x2409,page+0x221), source=source, source_pairs=(source[:2*PAGE],source[2*PAGE:]), page_b=page+2*PAGE, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10],repeat_setup=repeat_setup)

def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]

def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    fault=False
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
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (6, 14) if fault else (0, 1)), 'genuine native signal origin')
    if kind==0 or fault:
        address = prefix['fault_address'] if fault else pc
        need(q(si, 16)[0] == address and g[22] == address, 'real source NX/data fault address')
    else:need(q(si,16)[0]==pc and g[22]==prefix['predecessor'],'actual TRACE PC and retained original NX CR2')
    expected = frame_state(prefix,kind)
    need(tuple(g[i] for i in GREG) == expected and g[18] == 0x2b000000000033 and g[21] == MASK, 'complete actual native GPR model')
    expected_flags=trace_model(prefix)[steps][2] | (RF if kind==0 else TF)
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

def fixture(mode,image):
    need(type(mode)is int and mode==0,'explicit cross-pair success only')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=DATA;seed[2]=DATA;seed[3]=DATA+142*24
    seed[4]=RSP;seed[6]=image['symbols']['region_app_capture'];seed[7]=DATA
    seed[10]=DATA+141*24+8;seed[11]=8;seed[12]=0x1000;seed[13]=DATA+4096
    data=bytearray(1+(i*17)%255 for i in range(8192))
    for i in range(142):struct.pack_into('<3Q',data,24*i,DATA+8*i,7 if i==141 else 8,0x3141592600000000+17*i)
    return (tuple(seed),0xad7,bytes(12)),bytes(data),bytes((i*29+7)&255 for i in range(224))

def arithmetic(a,b,flags,subtract=False):
    value=(a-b if subtract else a+b)&U64
    overflow=((a^b)&(a^value) if subtract else ~(a^b)&(a^value))>>63&1
    updated=int(a<b if subtract else a+b>U64) | (int((value&255).bit_count()%2==0)<<2)
    updated|=(a^b^value)&16;updated|=int(value==0)<<6;updated|=(value>>63)<<7;updated|=overflow<<11
    return value,(flags&~0x8d5)|updated

def trace_model(prefix):
    """All2838 original instruction states and whole8192-byte data effects.

    The first ADD predecessor is real. Entry at CMP skips the first two
    source heads until the actual backedge; no synthetic initial load occurs.
    """
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    page=prefix['source_page_address'];data=prefix['data'];stack=prefix['stack']
    out=[(pc,tuple(g),flags,data,stack)];stores=[0,0];repaired=False
    def read64(address):
        need(DATA<=address<=DATA+8192-8,'actual entire model load range')
        return q(data,address-DATA)[0]
    for _ in range(2838):
        off=pc-page
        if off==0x200:g[2]=read64(g[0]);pc+=3
        elif off==0x203:g[2],flags=arithmetic(g[2],g[12],flags);pc+=3
        elif off==0x206:
            value=read64(g[0]+8)&0xffffffff
            # The exact type operands are7 or8; their32-bit CMP flags equal
            # this64-bit subtraction, with no sign/overflow ambiguity.
            need(value in(7,8),'literal type table at each actual CMP')
            _,flags=arithmetic(value,8,flags,True);pc+=4
        elif off==0x20a:pc=page+(0x2400 if not flags&0x40 else 0x210)
        elif off==0x210:g[1]=read64(g[0]+16);pc+=4
        elif off==0x214:g[0],flags=arithmetic(g[0],24,flags);pc+=4
        elif off==0x218:g[1],flags=arithmetic(g[1],g[12],flags);pc+=3
        elif off==0x21b:
            need(DATA+4096<=g[2]<=DATA+4096+141*8 and not(g[2]&7),'actual output row write')
            changed=bytearray(data);struct.pack_into('<Q',changed,g[2]-DATA,g[1]);data=bytes(changed);pc+=3;stores[int(repaired)]+=1
        elif off==0x21e:_,flags=arithmetic(g[0],g[3],flags,True);pc+=3
        elif off==0x221:pc=page+(0x200 if flags&1 else 0x223)
        elif off==0x2400:
            need(g[10]==DATA+141*24+8 and g[11]==8,'actual B repair destination/value')
            changed=bytearray(data);struct.pack_into('<Q',changed,g[10]-DATA,g[11]);data=bytes(changed);pc+=3
            need(stores==[141,0]and not repaired,'exact first141 guarded stores before the original repair');repaired=True
        elif off==0x2403:g[0]=g[7];pc+=3
        elif off==0x2406:g[2]=g[13];pc+=3
        elif off==0x2409:pc=page+0x206
        elif off==0x223:
            need(g[7]==DATA,'actual fixed complete ordinary16-bit store destination')
            changed=bytearray(data);struct.pack_into('<H',changed,0,g[0]&0xffff);data=bytes(changed);pc+=3
        elif off==0x226:pc=g[6]
        elif off==0x4000:pc=prefix['symbols']['region_app_capture_high']
        else:raise ValueError('unmodelled original PF puzzle instruction')
        out.append((pc,tuple(g),flags,data,stack))
    need(stores==[141,142]and repaired and out[-1][0]==prefix['expected_exit_pc'],
         'actual141+142 generated-store source steps, one repair, and high capture suffix')
    return out

def frame_pc(prefix,kind):
    need(type(kind)is int and 0<=kind<len(STEPS),'one of12 explicitly retained native boundaries')
    return trace_model(prefix)[STEPS[kind]][0]

def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]

def state(seed,data,mode):
    need(mode==0,'only the explicit loop result')
    out=list(seed);out[0]=DATA+142*24;out[1]=0x3141592600001000+17*141;out[2]=DATA+4096+8*141
    return tuple(out)

def written(data,mode):
    need(mode==0,'exact full-loop store, repair and original16-bit store effects')
    out=bytearray(data);struct.pack_into('<Q',out,141*24+8,8)
    for i in range(142):struct.pack_into('<Q',out,4096+8*i,0x3141592600001000+17*i)
    struct.pack_into('<H',out,0,(DATA+142*24)&0xffff)
    return bytes(out)

def _prefix(data,mode,native,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode==0 and type(native)is bool,'typed complete persistent app prefix')
    need(mode==0,'no unvalidated fault mode')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:18592],data[18592:18816],data[18816:27008]
    head=image['head'];frontier=image['symbols']['region_app_capture_high'];predecessor=head-3
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,12,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode==1),image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,predecessor,TRACES[mode],OBS,12,40,image['page']+0x2400,image['page']+PAGE,16384,RSEQ,0x53053053,image['page']+0x20a,image['page']+0x2409,image['page']+0x223),'exact cyclic fixture and reserved header')
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
    return dict(symbols=image['symbols'],header=h,mode=mode,head=head,predecessor=predecessor,source_page_address=image['page'],source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=head if mode==1 else frontier,fault_pc=head if mode==1 else 0,fault_address=DATA+8192 if mode==1 else 0,suffix=None,observations=[])

def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and mode==0 and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    full=native or mode==0
    need(exit_status==(0 if mode==0 else 125)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated status and complete output')
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)
    if not full:return r
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,12,mode,int(native),0,1,1,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],r['data'],mode)and after[1]==0x246,'all defined loop GPR and flag results')
    need(value[4792:21176]==r['source']and value[21176:21400]==r['stack']and value[21400:29592]==written(r['data'],mode),'whole source/stack and exact completed store effects')
    frames=[]
    for i in range(12):
        frame=value[29592+i*FRAME:29592+(i+1)*FRAME]
        if not native or(mode==1 and i>=3):need(frame==bytes(FRAME),'no fabricated native signal')
        else:
            kind=i
            steps=STEPS[i]
            frames.append(reference_frame(frame,r,image,kind,steps,0))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[21400:29592],stack=value[21176:21400])]
    r['effects']=effects;r['suffix']=dict(end=end);return r


APP_CONTROL_COUNTS={0:40}

def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    """Sixteen complete-state classes plus eight active-domain checkpoint checks."""
    need(native is True and mode in APP_CONTROL_COUNTS,'native-only application supplied controls')
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)
    observation=PREFIX+400;frame=observation+29592
    tests=(('version',8),('CPU',8*8),('hardware',384+8),('seed_GPR',1992),
           ('source',2208),('stack',18592),('data',18816),('registration_result',27008),
           ('publication_word',27008+6*8),('cleanup',PREFIX+5*8),
           ('after_GPR',observation+280),('after_AF',observation+408),
           ('actual_TLS',observation+496+8),('whole_live_vector',observation+2676),
           ('native_FP',frame+1248),('completed_store_bytes',observation+21400),
           ('cold_A_exit_flags',frame+2*FRAME+224+40+17*8),
           ('cold_B_entry_PC',frame+3*FRAME+224+40+16*8),
           ('cold_B_exit_RAX',frame+4*FRAME+224+40+GREG[0]*8),
           ('domain_entry_RCX',frame+5*FRAME+224+40+GREG[1]*8),
           ('first_internal_B_PC',frame+6*FRAME+224+40+16*8),
           ('next_internal_A_PC',frame+7*FRAME+224+40+16*8),
           ('final_dispatch_RBX',frame+10*FRAME+224+40+GREG[3]*8),
           ('last_TRACE_PC',frame+11*FRAME+224+40+16*8),
           ('no_prefix_registration_before',27016),('no_prefix_registration_after',27048),
           ('collection_lifetime',PREFIX+80),('collection_completed',PREFIX+88),
           ('later_registration_result',PREFIX+128+64),('later_registration_word',PREFIX+128+13*8),
           ('later_unregistration_word',PREFIX+264+13*8),('second_store_bytes',observation+21400+8),
           ('peer_source_pair',2208+2*PAGE),('peer_second_page',2208+3*PAGE),
           ('four_source_extent',42*8),('observed_peer_source',observation+4792+2*PAGE),
           ('direct_reset_R8',frame+6*FRAME+224+40+GREG[8]*8),
           ('known_arm_flags',frame+7*FRAME+224+40+17*8),
           ('final_condition_RCX',frame+9*FRAME+224+40+GREG[1]*8),
           ('final_unknown_PC',frame+10*FRAME+224+40+16*8))
    need(len(tests)==APP_CONTROL_COUNTS[mode],'all36 inherited state controls plus4 direct branch checkpoint controls')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)


def pair(native,gated,owner):
    """Two real cold epochs and one cross-pair lifetime; every compared frame
    retains all23 GREG and all65536 FP bytes with causal TF/RF/CR2 only."""
    need(native['mode']==gated['mode']==owner['mode']==0 and native['header'][5]==1 and gated['header'][5]==0,'exact cross-pair native/generated pair')
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')
    need(len(native['observations'])==len(gated['observations'])==1,'actual complete application observations')
    reference=native['observations'][0];frames=reference['frames'];machine=gated['machine'];attempts=owner['attempts'];page=gated['source_page_address'];model=trace_model(native)
    def compare(actual,ref,event,cr2=None):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK,'complete actual protected pair frame')
        want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        else:need(event=='original','exact genuine event transforms')
        if cr2 is not None:want[22]=cr2
        need(actual['greg']==tuple(want)and actual['fp']==ref['fp'],'all23 GREG/65536 FP including actual AF and exact CR2 history')
        need((actual['fs'],actual['gs'])==tuple(machine[1:3]),'actual protected pair TLS')
    need(len(attempts)==3 and [x['kind']for x in attempts]==['cold','cold','domain'],'two cold activations followed by one shared active domain')
    a,b,d=attempts
    compare(a['predecessor_before'],frames[0],'original');compare(a['ingress'],frames[1],'original');compare(a['before'],frames[1],'closed');compare(a['logical'],frames[3],'nx')
    compare(b['predecessor_before'],frames[3],'nx');compare(b['ingress'],frames[4],'original',page+0x20a);compare(b['before'],frames[4],'closed',page+0x20a);compare(b['logical'],frames[5],'nx')
    compare(d['predecessor_before'],frames[5],'nx');compare(d['ingress'],frames[6],'original',page+0x2409);compare(d['before'],frames[6],'closed',page+0x2409);compare(d['logical'],frames[8],'nx');compare(d['next_trace'],frames[9],'original',page+0x221)
    need(a['slot']!=b['slot']and a['generation']!=b['generation']and
         (d['slot'],d['generation'],d['build_serial'])==(a['slot'],a['generation'],a['build_serial']),'actual retained A primary identity after B')
    need(d['members']==[(a['slot'],a['generation'],a['build_serial']),(b['slot'],b['generation'],b['build_serial'])],'both exact retained generations share the active domain')
    need(d['shared_lifetime']==1 and d['completion_id']>0 and d['claim_members']==(0,1)and d['joint_complete']==1,'one genuine shared lifetime and two immutable joint-completion claims')
    prior=[x['prior_generation_installed']for x in(a,b)]
    need(all(type(x)is int and x in(0,1)for x in prior)and owner['cold_publications']==2 and owner['warm_entries']==1 and owner['dual_entries']==1 and owner['replacements']==sum(prior)and owner['permit_claims']==sum(prior)+2,'actual focal publications and primary/peer completion-claim accounting')
    for attempt,first,last in((a,1,1412),(b,1413,1416),(d,1417,2834)):
        need(attempt['before_memory']==dict(data=model[first][3],stack=model[first][4])and attempt['after_memory']==dict(data=model[last][3],stack=model[last][4]),'whole actual pair source/stack/store effects')
    need(owner['source']==native['source']and len(owner['source'])==4*PAGE,'whole actual four-page source custody')
    need(owner['interior_signals']==0 and
         [x['closed_pages']for x in attempts]==[17,17,34]and [x['domain_members']for x in attempts]==[1,1,2]and
         all(x['anchor_released']==x['completed']==x['permit']==1 and x['interior_signals']==0 for x in attempts),'actual17/17/34-page closures with no interior event')
    need(owner['lifetime_mode']==2 and owner['registration_epoch']==owner['registration_calls']==0 and owner['word_observed']==0 and owner['word_available']is False and owner['tls_complete']==1,'actual unregistered epoch0 no-call lifetime and unavailable word')
    need(b['begin']==a['terminal_ordinal']+1 and d['begin']==b['terminal_ordinal']+1 and d['next_trace_ordinal']==d['terminal_ordinal']+1,'actual immediate original-JMP successor chronology')
    need(d['frontier_member']==0 and d['frontier_arm']==1 and
         d['frontier_pc']==page+0x221 and d['frontier_target']==page+0x223,
         'actual peer conditional unknown arm and exact original target')
    cancelled=owner['cancellation']
    need((cancelled['reason'],cancelled['detail'],cancelled['source_released'],cancelled['generated_entries'],cancelled['publications'],cancelled['completion_permits'],cancelled['ordinary_store_executed'])==(1,1,1,0,0,0,1),'actual unsupported-store miss cancels without publication or completion authority')
    need(cancelled['ordinal']==d['next_trace_ordinal']and cancelled['next_ordinal']==cancelled['ordinal']+1,'same-handler cancellation precedes its next actual TRACE')
    compare(cancelled['before'],frames[9],'closed',page+0x221)
    compare(cancelled['returned'],frames[9],'original',page+0x221)
    post=frames[10]
    compare(cancelled['next'],post,'original',page+0x221)
    actual=gated['observations'][0]
    need(all(reference[k]==actual[k]for k in('before','after','live','data','stack'))and gated['effects']==native['effects']and gated['suffix']is not None,'whole actual application state and later registration lifecycle')
    def context(actual,ref,event,cr2=None):
        # Join whole native/protected contexts after the original state checks.
        # Only independently authenticated coordinates and causal event fields
        # change; flags/link/reserved bytes and every other byte stay literal.
        want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        else:need(event=='original','exact genuine context event transforms')
        if cr2 is not None:want[22]=cr2
        si=bytearray(ref['si']);struct.pack_into('<i',si,0,11 if event=='nx'else 5);struct.pack_into('<Q',si,16,want[16])
        need(actual['si']==bytes(si),'all128 native siginfo bytes with exact causal event transforms')
        uc=actual['uc'];native_uc=ref['uc'];h=ref['header'];alt,cap=actual['altstack'];fp=actual['fp_address']
        need(len(uc)==968 and len(native_uc)==1024 and native_uc[968:]==bytes(56)and h[7]==968,
             'whole native and protected context extents')
        need(cap==h[11]==524288 and 0<alt<(1<<47)-cap and alt%PAGE==0 and fp%16==0 and
             alt<=fp<=alt+cap-actual['fp_bytes']and h[10]<=h[8]<=h[10]+h[11]-h[9]and
             fp-alt==h[8]-h[10], 'same independently bounded kernel FP position on each actual altstack')
        need(q(uc,16)[0]==alt and q(uc,32)[0]==cap and q(uc,224)[0]==fp and
             q(native_uc,16)[0]==h[10]and q(native_uc,32)[0]==h[11]and q(native_uc,224)[0]==h[8],
             'actual native and protected altstack and FP pointer aliases')
        expected=bytearray(native_uc[:968]);struct.pack_into('<Q',expected,16,alt);struct.pack_into('<Q',expected,224,fp)
        struct.pack_into('<23Q',expected,40,*want);expected[304:432]=si
        need(uc==bytes(expected),'all968 native ucontext bytes with authenticated coordinates and causal events')
    for value,ref,event,cr2 in (
        (a['ingress'],frames[1],'original',None),(a['before'],frames[1],'closed',None),(a['logical'],frames[3],'nx',None),
        (b['ingress'],frames[4],'original',page+0x20a),(b['before'],frames[4],'closed',page+0x20a),(b['logical'],frames[5],'nx',None),
        (d['ingress'],frames[6],'original',page+0x2409),(d['before'],frames[6],'closed',page+0x2409),(d['logical'],frames[8],'nx',None),
        (d['next_trace'],frames[9],'original',page+0x221),(cancelled['before'],frames[9],'closed',page+0x221),
        (cancelled['returned'],frames[9],'original',page+0x221),(cancelled['next'],post,'original',page+0x221)):
        context(value,ref,event,cr2)
    return dict(observed_bounded_fused=1,plan_version=11,unsupported_root_cancellations=1,ordinary_resumptions=1,invocations=1,generated_completed=3,cold_publications=2,warm_entries=1,dual_entries=1,retained_generations=2,shared_domain_lifetimes=1,joint_source_pairs=2,joint_source_pages=4,joint_closed_pages=34,modeled_joint_retired_instructions=1417,modeled_final_frontier_instructions=1,modeled_cross_certificate_transfers=0,measured_interior_signals=0,native_instructions=2838,native_full_frames=12,lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,word_available=False,qualification_credit=False)

PAIR_CONTROL_COUNTS={0:36}
def pair_controls(native,gated,owner):
    import copy
    pair(native,gated,owner);refused=[]
    names=('logical_AF','logical_CR2','full_FP','store_effect','next_trace_PC','next_trace_AF','B_before_RAX','A_cold_exit_RAX','primary_generation','peer_generation','joint_claim','joint_extent',
           'cold_A_store','cold_B_store','domain_before_store','domain_stack','four_source_pages','peer_source_byte',
           'lifetime_mode','registration_epoch','registration_calls','word_observed','word_available','tls_complete',
           'frontier_member','frontier_arm','frontier_pc','frontier_target',
           'cancel_reason','cancel_detail','cancel_source_released','cancel_generated_entries','cancel_publications','cancel_completion_permits','cancel_next_PC','cancel_next_FP')
    for name in names:
        mutant=copy.deepcopy(owner);last=mutant['attempts'][-1]
        expected='all23 GREG/65536 FP including actual AF and exact CR2 history'
        if name.startswith('cancel_'):
            c=mutant['cancellation'];field=name[7:]
            if field=='next_PC':
                g=list(c['next']['greg']);g[16]^=1;c['next']['greg']=tuple(g)
            elif field=='next_FP':
                f=bytearray(c['next']['fp']);f[160]^=1;c['next']['fp']=bytes(f)
            else:c[field]^=1;expected='actual unsupported-store miss cancels without publication or completion authority'
        elif name.startswith('frontier_'):
            last[name]^=1;expected='actual peer conditional unknown arm and exact original target'
        elif name.startswith('next_trace_'):
            g=list(last['next_trace']['greg']);g[16 if name=='next_trace_PC'else 17]^=1 if name=='next_trace_PC'else 16;last['next_trace']['greg']=tuple(g)
        elif name.startswith('logical_'):
            g=list(last['logical']['greg']);g[17 if name=='logical_AF'else 22]^=16 if name=='logical_AF'else 1;last['logical']['greg']=tuple(g)
        elif name=='full_FP':
            fp=bytearray(last['logical']['fp']);fp[160]^=1;last['logical']['fp']=bytes(fp)
        elif name in('store_effect','cold_A_store','cold_B_store','domain_before_store','domain_stack'):
            row=mutant['attempts'][0]if name=='cold_A_store'else mutant['attempts'][1]if name=='cold_B_store'else last
            memory=row['before_memory']if name=='domain_before_store'else row['after_memory'];field='stack'if name=='domain_stack'else'data'
            data=bytearray(memory[field]);data[8 if name=='cold_B_store'else 0]^=1;memory[field]=bytes(data);expected='whole actual pair source/stack/store effects'
        elif name=='primary_generation':last['generation']+=1;expected='actual retained A primary identity after B'
        elif name=='peer_generation':
            slot,gen,serial=last['members'][1];last['members'][1]=(slot,gen+1,serial);expected='both exact retained generations share the active domain'
        elif name=='joint_claim':last['claim_members']=(0,0);expected='one genuine shared lifetime and two immutable joint-completion claims'
        elif name=='joint_extent':last['closed_pages']=17;expected='actual17/17/34-page closures with no interior event'
        elif name in('four_source_pages','peer_source_byte'):
            data=bytearray(mutant['source']);data=data[:2*PAGE]if name=='four_source_pages'else data
            if name=='peer_source_byte':data[2*PAGE]^=1
            mutant['source']=bytes(data);expected='whole actual four-page source custody'
        elif name in('lifetime_mode','registration_epoch','registration_calls','word_observed','word_available','tls_complete'):
            mutant[name]=True if name=='word_available'else mutant[name]^1;expected='actual unregistered epoch0 no-call lifetime and unavailable word'
        else:
            f=mutant['attempts'][1]['before']if name=='B_before_RAX'else mutant['attempts'][0]['logical'];g=list(f['greg']);g[GREG[0]]^=1;f['greg']=tuple(g)
        try:pair(native,gated,mutant)
        except ValueError as error:need(str(error)==expected,'exact causal pair refusal '+name);refused.append(name)
        else:raise ValueError('supplied pair corruption accepted '+name)
    need(len(refused)==len(set(refused))==PAIR_CONTROL_COUNTS[0],'all exact cross-pair controls')
    return dict(refusals=refused,native_operations=0,mode=0)
