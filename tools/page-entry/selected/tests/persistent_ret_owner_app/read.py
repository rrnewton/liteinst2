"""Three finite RET owner application cases with all ten original frames.
Each lane authenticates its original stack coordinate. The poison case records
one exact post-RET-load write; every stack byte and full native frame remains
literal. Owner/resume pairing is a distinct subsequent typed reader contract.
No owner, warm-reuse, whole-program or performance credit follows from this module.
"""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=23280,695136,694736,66784
MUTATION_OFFSET,MUTATION_BYTES=693632,1104
POISON=0xa5a55a5af0f00f0f
MAGIC=0x414450414132494c
DATA,RSEQ=0x500000000000,0x500000200000
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES=(9,9,9)
STEPS=tuple(range(10))
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
    wanted = {'region_app_' + n for n in ('head','page','predecessor','block_b','second_page','source_end',
        'helper','helper_end','enter','capture','seed_x87','pure','pure_end','capture_high','entry_jump',
        'head_pointer','capture_pointer','return_end','branch','call','call_next','b_exit',
        'unknown_page','unknown','unknown_exit','unknown_end',
        'miss_head','miss_predecessor','miss_branch','miss_call','miss_return','miss_exit',
        'b_branch','ret','return_exit')} | {'ua_' + n for n in
        ('vectors','masks','host','host_fcw','input','before','after','before_live','after_live','target')}
    wanted |= {'region_app_repeat_'+n for n in ('page','setup','site','next','end','buffer')}
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
    need(page==0x410000 and head==page+0x200 and symbols['region_app_source_end']==page+2*PAGE and
         p[1]==5 and p[2]+page-p[3]>=PAGE,'actual complete RX source pair outside ELF header')
    expected=bytearray(b'\xcc'*(2*PAGE))
    expected[0x1fe:0x200]=expected[0x5fe:0x600]=bytes.fromhex('ffe3')
    expected[0x200:0x214]=bytes.fromhex('4883c0010f84f600000041ffd44883c00941ff23')
    expected[0x300:0x30b]=bytes.fromhex('4883c0050f8403ffffffc3')
    expected[0x600:0x614]=bytes.fromhex('4883c0010f84f6fcffff41ffd44883c00941ff23')
    need(source==expected,'whole RET source pair and both complete root/return programs')
    unknown,continuation=memory(page+2*PAGE,PAGE)
    outside=bytearray(b'\xcc'*PAGE);outside[0x100:0x107]=bytes.fromhex('4883c00941ff23')
    need(unknown[1]==5 and continuation==outside,'whole outside-directory RX U page')
    for name,offset,size in (('head',0x200,20),('branch',0x204,0),('call',0x20a,0),
        ('call_next',0x20d,0),('return_exit',0x211,0),
        ('block_b',0x300,11),('b_branch',0x304,0),('b_exit',0x30a,0),('ret',0x30a,0),
        ('miss_predecessor',0x5fe,0),('miss_head',0x600,20),('miss_branch',0x604,0),
        ('miss_call',0x60a,0),('miss_return',0x60d,0),('miss_exit',0x611,0),
        ('unknown_page',0x2000,0),('unknown',0x2100,7),('unknown_exit',0x2104,0),('unknown_end',0x3000,0)):
        need(symbols['region_app_'+name]==page+offset and symbol_sizes['region_app_'+name]==size,
             'actual complete RET fixture symbol geometry')
    need(symbols['region_app_predecessor']==page+0x1fe and symbols['region_app_second_page']==page+PAGE,
         'actual canonical JMP predecessor and complete second source page')
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
    return dict(symbols=symbols,head=head,page=page,entries=(head,page+0x600),
        exits=((page+0x20a,page+0x30a,page+0x211),(page+0x60a,page+0x30a,page+0x211)),
        source=source,continuation=continuation,interpreter=path[:-1].decode(),
        sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),phnum=h[10],repeat_setup=repeat_setup)

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
    need(h[5]==h[6]+304 and uc[304:432]==si and
         uc[296:424]==struct.pack('<Q',prefix['machine'][0])+bytes(si[:120]),
         'whole actual kernel mask8 and embedded siginfo128 overlap')
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

def fixture(mode,image,rsp):
    need(type(mode)is int and mode in (0,1,2),'explicit RET hit, clean loaded miss, or poisoned loaded miss')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=1;seed[1]=3;seed[3]=image['entries'][bool(mode)];seed[4]=rsp;seed[7]=DATA
    seed[11]=image['symbols']['region_app_capture_pointer']
    seed[12]=image['symbols']['region_app_block_b']
    return (tuple(seed),0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(520))

def arithmetic(a,b,flags,subtract=False):
    value=(a-b if subtract else a+b)&U64
    overflow=((a^b)&(a^value) if subtract else ~(a^b)&(a^value))>>63&1
    updated=int(a<b if subtract else a+b>U64) | (int((value&255).bit_count()%2==0)<<2)
    updated|=(a^b^value)&16;updated|=int(value==0)<<6;updated|=(value>>63)<<7;updated|=overflow<<11
    return value,(flags&~0x8d5)|updated

def trace_model(prefix):
    """Nine original instructions; one CALL push, one RET load/pop, then ADD9."""
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    page=prefix['source_page_address'];data=prefix['data'];stack=prefix['stack'];rsp=prefix['rsp']
    root=0x600 if prefix['mode'] else 0x200
    out=[(pc,tuple(g),flags,data,stack)]
    for ordinal in range(1,10):
        off=pc-page
        if off==root-2:pc=g[3]
        elif off in (root,0x300,root+13):
            g[0],flags=arithmetic(g[0],{root:1,0x300:5,root+13:9}[off],flags);pc+=4
        elif off==root+4:pc=page+(0x300 if flags&0x40 else root+10)
        elif off==root+10:
            need(g[4]==rsp,'actual CALL uses the original observed stack pointer')
            g[4]-=8;changed=bytearray(stack);struct.pack_into('<Q',changed,248,page+root+13);stack=bytes(changed);pc=g[12]
        elif off==0x304:pc=page+(0x20d if flags&0x40 else 0x30a)
        elif off==0x30a:
            need(ordinal==7 and g[4]==rsp-8,'single RET load at the exact pushed operand')
            pc=q(stack,248)[0];g[4]+=8
            need(pc==page+root+13,'actual saved original CALL return target')
            if prefix['mode']==2:
                changed=bytearray(stack);struct.pack_into('<Q',changed,248,POISON);stack=bytes(changed)
        elif off==root+17:
            need(g[11]==prefix['symbols']['region_app_capture_pointer'],'exact immutable memory-JMP operand')
            pc=prefix['symbols']['region_app_capture_high']
        else:raise ValueError('unmodelled original RET fixture instruction')
        out.append((pc,tuple(g),flags,data,stack))
    need(out[-1][0]==prefix['expected_exit_pc'],'actual model ends at high capture suffix')
    return out

def frame_pc(prefix,kind):
    need(type(kind)is int and 0<=kind<len(STEPS),'one of10 explicitly retained native boundaries')
    return trace_model(prefix)[STEPS[kind]][0]

def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]

def state(seed,data,mode):
    need(mode in (0,1,2),'only the three explicit RET results')
    out=list(seed);out[0]=16;return tuple(out)

def written(stack,page,mode):
    out=bytearray(stack);struct.pack_into('<Q',out,248,POISON if mode==2 else page+(0x60d if mode else 0x20d));return bytes(out)

def _prefix(data,mode,native,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode in (0,1,2) and type(native)is bool,'typed complete RET app prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,continuation,stack,memory=data[2208:10400],data[10400:14496],data[14496:15016],data[15016:23208]
    head=image['entries'][bool(mode)];frontier=image['symbols']['region_app_capture_high'];predecessor=head-2
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,13,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and
         h[10:13]==(head,image['page'],DATA),'exact source/process/entry')
    stack_base=h[13];rsp=stack_base+2056
    need(PAGE<=stack_base<=(1<<47)-4096 and stack_base%64==0 and rsp%16==8 and
         stack_base<=rsp-256<rsp+264<=stack_base+4096 and
         all(stack_base+4096<=a or a+n<=stack_base for a,n in
             ((DATA,12288),(RSEQ,PAGE),(image['page'],5*PAGE),(0x200000000,0x32000))),
         'actual aligned local stack array and complete prospective capture interval')
    need(h[16:26]==(mode,0,image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,520,0,0,frontier,predecessor,9,OBS,10,8,image['page']+0x300,
         image['page']+PAGE,8192,RSEQ,0x53053053,head+10,image['page']+0x30a,head+13),
         'exact three-case RET fixture and reserved header')
    need(source==image['source']and continuation==image['continuation']and machine[0]==MASK and
         machine[1:3]==(0,0)and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component geometry')
    expected,want_data,want_stack=fixture(mode,image,rsp)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/stack bytes')
    registration=q(data,23208,9)
    need(registration==(U64,)+(0,)*8,'explicit registration not-attempted marker and unavailable snapshots')
    return dict(symbols=image['symbols'],header=h,mode=mode,head=head,predecessor=predecessor,
        source_page_address=image['page'],source=source,continuation=continuation,hardware=hardware,xcr0=h[14],
        data=memory,stack=stack,stack_base=stack_base,rsp=rsp,seed=seed,machine=machine,
        expected_exit_pc=frontier,fault_pc=0,fault_address=0,suffix=None,observations=[])

def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and mode in (0,1,2) and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    need(exit_status==0 and len(data)==PREFIX+SUFFIX,'exact native/gated success and complete output')
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,13,mode,int(native),0,1,1,10 if native else 0,9 if native else 0,0,2,1,0,0,0,0),
         'complete cleanup and collection-before-registration chronology')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),
             'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,10 if native else 0,9 if native else 0,0,int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],r['data'],mode)and after[1]==0x212,'all defined RET GPR and flag results')
    need(value[4792:12984]==r['source']and value[12984:17080]==r['continuation']and
         value[17080:17600]==written(r['stack'],r['source_page_address'],mode)and value[17600:25792]==r['data'],
         'whole source/U/data and exact original-return or declared poison stack bytes')
    frames=[]
    for i in range(10):
        frame=value[25792+i*FRAME:25792+(i+1)*FRAME]
        if not native:need(frame==bytes(FRAME),'no fabricated native signal')
        else:frames.append(reference_frame(frame,r,image,i,STEPS[i],0))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual AF and all terminal flags')
    mutation=value[MUTATION_OFFSET:]
    need(len(mutation)==MUTATION_BYTES,'complete declared RET mutation extent')
    if native:
        fields=q(mutation,0,8);before_stack=mutation[64:584];after_stack=mutation[584:]
        return_pc=r['head']+13;original_rsp=r['rsp']-8
        need(fields==(1,int(mode==2),original_rsp,original_rsp,return_pc,return_pc,
             POISON if mode==2 else return_pc,8 if mode==2 else 0),
             'actual RET TRACE mutation fields and saved target before target arithmetic')
        model=trace_model(r)
        need(before_stack==model[6][4] and after_stack==model[7][4] and
             after_stack==value[17080:17600] and
             [i for i,(x,y) in enumerate(zip(before_stack,after_stack))if x!=y]==
             (list(range(248,256))if mode==2 else []),
             'whole520 mutation bracket and exact declared consumed-word change')
        mutation=dict(fields=fields,before_stack=before_stack,after_stack=after_stack)
    else:
        need(mutation==bytes(MUTATION_BYTES),'no fabricated gated application mutation observation')
        mutation=None
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,
        data=value[17600:25792],stack=value[17080:17600],mutation=mutation)]
    r['effects']=effects;r['suffix']=dict(end=end);return r


APP_CONTROL_COUNTS={0:60,1:60,2:60}

def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    """Whole application, all ten actual frames and exact poison chronology."""
    need(native is True and mode in APP_CONTROL_COUNTS,'native-only application supplied controls')
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)
    observation=PREFIX+400;frame=observation+25792
    tests=(('version',8),('CPU',8*8),('hardware',384+8),('seed_GPR',1992),
           ('source',2208),('stack',14496),('data',15016),('registration_result',23208),
           ('publication_word',23208+6*8),('cleanup',PREFIX+5*8),
           ('after_GPR',observation+280),('after_AF',observation+408),
           ('actual_TLS',observation+496+8),('whole_live_vector',observation+2676),
           ('native_FP',frame+1248),('actual_return_word',observation+17080+248),
           ('predecessor_RSP',frame+224+40+GREG[4]*8),
           ('A_entry_PC',frame+FRAME+224+40+16*8),
           ('branch_flags',frame+2*FRAME+224+40+17*8),
           ('CALL_PC',frame+3*FRAME+224+40+16*8),
           ('callee_RSP',frame+4*FRAME+224+40+GREG[4]*8),
           ('callee_RAX',frame+5*FRAME+224+40+GREG[0]*8),
           ('memory_JMP_PC',frame+8*FRAME+224+40+16*8),
           ('last_TRACE_PC',frame+9*FRAME+224+40+16*8),
           ('no_prefix_registration_before',23216),('no_prefix_registration_after',23248),
           ('collection_lifetime',PREFIX+80),('collection_completed',PREFIX+88),
           ('later_registration_result',PREFIX+128+64),('later_registration_word',PREFIX+128+13*8),
           ('later_unregistration_word',PREFIX+264+13*8),('return_word_high_byte',observation+17080+255),
           ('second_source_page',2208+PAGE),('outside_U_page',10400),
           ('two_source_extent',42*8),('observed_U_page',observation+12984),
           ('actual_stack_base',13*8),('before_live_RSP',observation+128+4*8),
           ('unchanged_stack_tail',observation+17080+519),('whole_embedded_siginfo',frame+224+304),
           ('RET_PC',frame+6*FRAME+224+40+16*8),
           ('RET_operand_RSP',frame+6*FRAME+224+40+GREG[4]*8),
           ('RET_target_PC',frame+7*FRAME+224+40+16*8),
           ('RET_committed_RSP',frame+7*FRAME+224+40+GREG[4]*8),
           ('before_target_RAX',frame+7*FRAME+224+40+GREG[0]*8),
           ('return_ADD_RAX',frame+8*FRAME+224+40+GREG[0]*8),
           ('mutation_complete',observation+MUTATION_OFFSET),
           ('mutation_applied',observation+MUTATION_OFFSET+8),
           ('mutation_original_rsp',observation+MUTATION_OFFSET+16),
           ('mutation_word_address',observation+MUTATION_OFFSET+24),
           ('mutation_saved_target',observation+MUTATION_OFFSET+32),
           ('mutation_before_word',observation+MUTATION_OFFSET+40),
           ('mutation_after_word',observation+MUTATION_OFFSET+48),
           ('mutation_change_count',observation+MUTATION_OFFSET+56),
           ('mutation_before_stack_first',observation+MUTATION_OFFSET+64),
           ('mutation_before_stack_word',observation+MUTATION_OFFSET+64+248),
           ('mutation_before_stack_last',observation+MUTATION_OFFSET+64+519),
           ('mutation_after_stack_first',observation+MUTATION_OFFSET+584),
           ('mutation_after_stack_word',observation+MUTATION_OFFSET+584+248),
           ('mutation_after_stack_last',observation+MUTATION_OFFSET+584+519))
    need(len(tests)==len({x[0]for x in tests})==APP_CONTROL_COUNTS[mode],'all60 distinct application control stimuli')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)
