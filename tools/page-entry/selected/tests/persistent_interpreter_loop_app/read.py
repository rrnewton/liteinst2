"""Exact unchanged interpreter MOV loop before the first real registration.
All52 original PCs and12 full native frames; one actual compiled activation.
No fabricated descriptor/word evidence and no old registered-reader changes."""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=19176,823496,823096,66784
MAGIC=0x314c4d524132494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
BP=STACK+4096+131072-1024
RSP=BP-120
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
TRACES={2:52}
STEPS=(0,1,11,12,22,23,25,31,32,44,51,52)
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
    wanted = {'region_app_' + n for n in ('head', 'page', 'predecessor', 'second_page', 'source_end', 'helper', 'helper_end', 'enter', 'capture', 'seed_x87', 'pure', 'pure_end', 'capture_high', 'entry_jump', 'head_pointer', 'return_end')} | {'ua_' + n for n in ('vectors', 'masks', 'host', 'host_fcw', 'input', 'before', 'after', 'before_live', 'after_live', 'target')}
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
    need(page%PAGE==0 and head==page+0x2c8 and symbols['region_app_source_end']==page+2*PAGE and
         p[1]==5 and p[2]+page-p[3]>=PAGE,'actual complete RX interpreter pair outside ELF header')
    need(len(source)==8192 and hashlib.sha256(source).hexdigest()==
         'd581910c998f52887ed76623d2280e52d178a4d25d46001d64586bd2c8ddf7ab',
         'whole pinned interpreter pair including every alternate branch and byte')
    need(symbol_sizes['region_app_head']==4 and symbols['region_app_predecessor']==page+0x2c1 and
         symbols['region_app_second_page']==page+PAGE,'actual original NOP/root/second-page geometry')
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
    return dict(symbols=symbols, head=head, page=page, exits=(page+0xa0,), source=source, interpreter=path[:-1].decode(), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), phnum=h[10],repeat_setup=repeat_setup)

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

# The pinned source includes all alternate edges; this model executes only the
# independently seeded two-row fixture, not a substituted reduced program.
PATH=(0x2c8,0x2cc,0x2d1,0x2d4,0x2d8,0x2da,0x2de,0x2e4,0x2e9,0x2ed,0x2f0,0x2f3,0x2f6,
      0x2c8,0x2cc,0x2d1,0x2d4,0x2d8,0x2e4,0x2e9,0x2ed,0x2f0,0x2f3,0x2f6,
      0x2f8,0x2ff,0x302,0xc06,0xc11,0xc18,0xa0,0xa8,0xaf,0xb6,0xbc,0xc2,0xc5,0xc7,
      0xcd,0xd4,0xda,0xe2,0xea,0xf0,0xf4,0xf5,0xf7,0xf9,0xfb,0xfd,0xfe)
CODE={0x2c1:'0f1f8000000000',0x2c8:'498b1424',0x2cc:'418b442408',0x2d1:'4c01d2',
      0x2d4:'4883f826',0x2d8:'740a',0x2da:'4883f808',0x2de:'0f857c1a0000',
      0x2e4:'498b442410',0x2e9:'4983c418',0x2ed:'4c01d0',0x2f0:'488902',0x2f3:'4c39e3',
      0x2f6:'77d0',0x2f8:'4d8b9fd0010000',0x2ff:'4d85db',0x302:'0f84fe080000',
      0xc06:'48c78540ffffff00000000',0xc11:'48399d68ffffff',0xc18:'0f8682f4ffff',
      0xa0:'48838548ffffff20',0xa8:'488b8548ffffff',0xaf:'483b8520ffffff',
      0xb6:'0f856c0a0000',0xbc:'8b8538ffffff',0xc2:'4d89fe',0xc5:'85c0',
      0xc7:'0f85e30c0000',0xcd:'80bd1fffffff00',0xd4:'0f85d60c0000',
      0xda:'41808e1c03000004',0xe2:'4883bd10ffffff00',0xea:'0f853b180000',
      0xf0:'488d65d8',0xf4:'5b',0xf5:'415c',0xf7:'415d',0xf9:'415e',0xfb:'415f',0xfd:'5d',0xfe:'c3'}
RESTORED=(0x4370010102030405,0x4371020304050607,0x4372030405060709,
          0x437304050607080b,0x437405060708090d,0x4375060708090a0f)

def fixture(mode,image):
    need(mode==2,'explicit before-registration interpreter fixture')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[3]=DATA+0x130;seed[4]=RSP;seed[5]=BP;seed[10]=DATA;seed[12]=DATA+0x100;seed[15]=DATA+0x1000
    data=bytearray(1+(i*17)%255 for i in range(8192));stack=bytearray((i*29+7)&255 for i in range(512))
    for off,value in((0x100,0x800),(0x108,8),(0x110,0x123),(0x118,0x808),(0x120,38),(0x128,0x321),(0x11d0,0)):
        struct.pack_into('<Q',data,off,value)
    data[0x131c]=0x81
    for off,value in((256-0x98,DATA+0x130),(256-0xb8,0),(256-0xe0,32),(256-0xf0,0)):
        struct.pack_into('<Q',stack,off,value)
    struct.pack_into('<I',stack,256-0xc8,0);stack[256-0xe1]=0
    for i,value in enumerate(RESTORED):struct.pack_into('<Q',stack,216+8*i,value)
    struct.pack_into('<Q',stack,264,image['symbols']['region_app_capture'])
    return (tuple(seed),0xad7,bytes(12)),bytes(data),bytes(stack)

def arithmetic(a,b,flags,subtract=False,width=64):
    mask=(1<<width)-1;a&=mask;b&=mask;value=(a-b if subtract else a+b)&mask
    overflow=((a^b)&(a^value) if subtract else ~(a^b)&(a^value))>>(width-1)&1
    updated=int(a<b if subtract else a+b>mask)|(int((value&255).bit_count()%2==0)<<2)
    updated|=(a^b^value)&16;updated|=int(value==0)<<6;updated|=(value>>(width-1))<<7;updated|=overflow<<11
    return value,(flags&~0x8d5)|updated

def logical(value,flags,width):
    value&=(1<<width)-1
    # Exact AF=0 is a native observation requirement, not an allowed-value set.
    return (flags&~0x8d5)|(int((value&255).bit_count()%2==0)<<2)|(int(value==0)<<6)|((value>>(width-1))<<7)

def trace_model(prefix):
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    page=prefix['source_page_address'];data=bytearray(prefix['data']);stack=bytearray(prefix['stack'])
    def memory(address,n):
        ranges=((DATA,data),(BP-256,stack));matches=[(a,b)for a,b in ranges if a<=address and address+n<=a+len(b)]
        need(len(matches)==1,'model whole actual guest memory access');a,b=matches[0];return b,address-a
    def ld(address,n=8):b,i=memory(address,n);return int.from_bytes(b[i:i+n],'little')
    def st(address,value,n=8):b,i=memory(address,n);b[i:i+n]=(value&((1<<(n*8))-1)).to_bytes(n,'little')
    def snap():return (pc,tuple(g),flags,bytes(data),bytes(stack))
    out=[snap()]
    for step in range(52):
        off=pc-page;need(off in CODE,'one exact model instruction');raw=bytes.fromhex(CODE[off])
        need(prefix['source'][off:off+len(raw)]==raw,'actual original instruction bytes');next_pc=pc+len(raw)
        if off==0x2c1:pass
        elif off==0x2c8:g[2]=ld(g[12])
        elif off==0x2cc:g[0]=ld(g[12]+8,4)
        elif off==0x2d1:g[2],flags=arithmetic(g[2],g[10],flags)
        elif off in(0x2d4,0x2da):_,flags=arithmetic(g[0],38 if off==0x2d4 else 8,flags,True)
        elif off==0x2d8:next_pc=page+0x2e4 if flags&64 else next_pc
        elif off==0x2de:next_pc=page+0x1d60 if not flags&64 else next_pc
        elif off==0x2e4:g[0]=ld(g[12]+16)
        elif off==0x2e9:g[12],flags=arithmetic(g[12],24,flags)
        elif off==0x2ed:g[0],flags=arithmetic(g[0],g[10],flags)
        elif off==0x2f0:st(g[2],g[0])
        elif off==0x2f3:_,flags=arithmetic(g[3],g[12],flags,True)
        elif off==0x2f6:next_pc=page+0x2c8 if not flags&65 else next_pc
        elif off==0x2f8:g[11]=ld(g[15]+0x1d0)
        elif off==0x2ff:flags=logical(g[11],flags,64)
        elif off==0x302:next_pc=page+0xc06 if flags&64 else next_pc
        elif off==0xc06:st(g[5]-0xc0,0)
        elif off==0xc11:_,flags=arithmetic(ld(g[5]-0x98),g[3],flags,True)
        elif off==0xc18:next_pc=page+0xa0 if flags&65 else next_pc
        elif off==0xa0:
            value,flags=arithmetic(ld(g[5]-0xb8),32,flags);st(g[5]-0xb8,value)
        elif off==0xa8:g[0]=ld(g[5]-0xb8)
        elif off==0xaf:_,flags=arithmetic(g[0],ld(g[5]-0xe0),flags,True)
        elif off==0xb6:next_pc=page+0xb28 if not flags&64 else next_pc
        elif off==0xbc:g[0]=ld(g[5]-0xc8,4)
        elif off==0xc2:g[14]=g[15]
        elif off==0xc5:flags=logical(g[0],flags,32)
        elif off in(0xc7,0xd4):next_pc=page+0xdb0 if not flags&64 else next_pc
        elif off==0xcd:_,flags=arithmetic(ld(g[5]-0xe1,1),0,flags,True,8)
        elif off==0xda:
            value=ld(g[14]+0x31c,1)|4;st(g[14]+0x31c,value,1);flags=logical(value,flags,8)
        elif off==0xe2:_,flags=arithmetic(ld(g[5]-0xf0),0,flags,True)
        elif off==0xea:next_pc=page+0x192b if not flags&64 else next_pc
        elif off==0xf0:g[4]=g[5]-40
        elif off in(0xf4,0xf5,0xf7,0xf9,0xfb,0xfd):
            reg={0xf4:3,0xf5:12,0xf7:13,0xf9:14,0xfb:15,0xfd:5}[off];g[reg]=ld(g[4]);g[4]+=8
        elif off==0xfe:next_pc=ld(g[4]);g[4]+=8
        else:raise ValueError('missing exact original semantic rule')
        pc=next_pc
        need(pc==(page+PATH[step]if step<51 else prefix['expected_exit_pc']),'all52 independently computed original next PCs')
        out.append(snap())
    return out

def frame_pc(prefix,kind):
    need(type(kind)is int and 0<=kind<len(STEPS),'one of12 exact native checkpoints')
    return trace_model(prefix)[STEPS[kind]][0]

def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]

def _prefix(data,mode,native,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode==2 and type(native)is bool,'typed complete before-registration prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:10400],data[10400:10912],data[10912:19104]
    head=image['head'];frontier=image['symbols']['region_app_capture'];predecessor=head-7
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,2,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,0,image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,512,0,0,frontier,predecessor,52,OBS,12,51,DATA+0x100,image['page']+PAGE,8192,RSEQ,0x53053053,image['page']+0xa0,image['page']+0x2f0,DATA+0x1000),'exact whole original loop geometry')
    need(source==image['source']and machine[0]==MASK and machine[1]>0 and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component geometry')
    expected,want_data,want_stack=fixture(mode,image)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/stack bytes')
    need(q(data,19104,9)==(U64,)+(0,)*8,'explicit not-attempted registration marker and unavailable prefix snapshots')
    return dict(header=h,mode=mode,head=head,predecessor=predecessor,source_page_address=image['page'],source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,expected_exit_pc=frontier,fault_pc=0,fault_address=0,suffix=None,observations=[])

def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and type(mode)is int and mode==2 and type(native)is bool and type(exit_status)is int,'typed before-registration actual outcome')
    need(exit_status==0 and len(data)==PREFIX+SUFFIX,'exact native/gated success and complete output')
    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference);model=trace_model(r)
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,2,mode,int(native),0,1,1,12 if native else 0,52 if native else 0,0,2,1,0,0,0,0),'actual collection precedes both later registration effects and complete cleanup')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual later rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual later kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,12 if native else 0,52 if native else 0,0,int(native),0,0,image['symbols']['region_app_capture'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[:2]==model[-1][1:3],'all16 original final GPR and exact status flags')
    need(value[4792:12984]==r['source']and value[12984:13496]==model[-1][4]and value[13496:21688]==model[-1][3],'whole source/stack and every completed original memory effect')
    frames=[]
    for i in range(12):
        frame=value[21688+i*FRAME:21688+(i+1)*FRAME]
        if not native:need(frame==bytes(FRAME),'no fabricated native signal')
        else:frames.append(reference_frame(frame,r,image,i,STEPS[i],0))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[13496:21688],stack=value[12984:13496])]
    r['effects']=effects;r['suffix']=dict(end=end);return r

APP_CONTROL_COUNTS={2:32}

def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):
    need(native is True and mode==2,'native-only supplied original-loop controls')
    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)
    observation=PREFIX+400;frame=observation+21688
    tests=(('version',8),('CPU',64),('hardware',392),('seed_GPR',1992),('source',2208),
           ('stack',10400),('data',10912),('not_attempted_marker',19104),('absent_prefix_before',19112),
           ('absent_prefix_after',19144),('cleanup',PREFIX+40),('collection_mode',PREFIX+80),
           ('collection_completed',PREFIX+88),('later_registration_result',PREFIX+128+64),
           ('later_registration_word',PREFIX+128+13*8),('later_unregistration_word',PREFIX+264+13*8),
           ('after_GPR',observation+280),('after_AF',observation+408),('actual_TLS',observation+504),
           ('whole_live_vector',observation+2676),('native_FP',frame+1248),('relocation1',observation+13496+0x800),
           ('relocation2',observation+13496+0x808),('tail_stack_write',observation+12984+256-0xb8),
           ('first_store_before',frame+2*FRAME+224+40+GREG[0]*8),('first_store_after',frame+3*FRAME+224+40+16*8),
           ('second_store_before',frame+4*FRAME+224+40+GREG[2]*8),('second_store_after',frame+5*FRAME+224+40+16*8),
           ('compiled_exit_AF',frame+7*FRAME+224+40+17*8),('ordinary_tail_PC',frame+8*FRAME+224+40+16*8),
           ('stack_return_RSP',frame+10*FRAME+224+40+GREG[4]*8),('last_TRACE_PC',frame+11*FRAME+224+40+16*8))
    need(len(tests)==APP_CONTROL_COUNTS[mode],'literal32 supplied original-loop controls')
    refused=[]
    for name,offset in tests:
        mutant=bytearray(data);mutant[offset]^=1
        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied actual app corruption accepted '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=mode)

def pair(native,gated,owner):
    need(native['mode']==gated['mode']==owner['mode']==2 and native['header'][5]==1 and gated['header'][5]==0,'exact before-registration native/generated pair')
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')
    need(len(native['observations'])==len(gated['observations'])==1 and len(owner['attempts'])==1,'one real complete compiled activation')
    reference=native['observations'][0];frames=reference['frames'];machine=gated['machine'];attempt=owner['attempts'][0];model=trace_model(native)
    def compare(actual,ref,event,cr2=None):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and len(actual['fp'])==FP and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK,'complete actual protected pair frame')
        want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        else:need(event=='original','exact genuine event transforms')
        if cr2 is not None:want[22]=cr2
        need(actual['greg']==tuple(want)and actual['fp']==ref['fp'],'all23 GREG/65536 FP including AF and exact CR2 history')
        need((actual['fs'],actual['gs'])==tuple(machine[1:3]),'actual protected pair TLS')
    compare(attempt['predecessor_before'],frames[0],'original')
    compare(attempt['ingress'],frames[1],'original');compare(attempt['before'],frames[1],'closed')
    compare(attempt['logical'],frames[7],'nx')
    compare(attempt['next_trace'],frames[8],'original',gated['source_page_address']+0xa0)
    need(attempt['kind']=='cold'and attempt['domain_members']==1 and attempt['closed_pages']==17 and
         attempt['anchor_released']==attempt['completed']==attempt['permit']==1 and attempt['interior_signals']==0,
         'actual one-member17-page closed completed lifetime')
    prior=attempt['prior_generation_installed']
    need(type(prior)is int and prior in(0,1)and owner['cold_publications']==1 and owner['warm_entries']==0 and
         owner['dual_entries']==0 and owner['replacements']==prior and owner['permit_claims']==prior,
         'actual focal publication and any prior completed replacement')
    need(owner['lifetime_mode']==2 and owner['registration_epoch']==owner['registration_calls']==0 and
         owner['word_observed']==0 and owner['word_available']is False and owner['tls_complete']==1,
         'actual unregistered epoch0 no-call lifetime and unavailable word')
    need(owner['source']==native['source']and attempt['before_memory']==dict(data=model[1][3],stack=model[1][4])and
         attempt['after_memory']==dict(data=model[31][3],stack=model[31][4]),'whole actual compiled source/stack/two-relocation effects')
    need(attempt['next_trace_ordinal']==attempt['terminal_ordinal']+1 and owner['interior_signals']==0,
         'actual immediate original frontier instruction chronology')
    actual=gated['observations'][0]
    need(all(reference[k]==actual[k]for k in('before','after','live','data','stack'))and gated['effects']==native['effects']and
         gated['suffix']is not None,'whole actual final application state and later registration lifecycle')
    return dict(observed_startup_pair=1,invocations=1,generated_completed=1,cold_publications=1,warm_entries=0,
                dual_entries=0,closed_pages=17,lifetime_mode=2,registration_epoch=0,registration_calls=0,
                word_observed=0,word_available=False,architectural_compiled_instructions=30,
                measured_interior_signals=0,native_instructions=52,native_full_frames=12,qualification_credit=False)

PAIR_CONTROL_COUNTS={2:14}

def pair_controls(native,gated,owner):
    import copy
    pair(native,gated,owner);refused=[]
    for name in('logical_AF','logical_CR2','full_FP','compiled_store','compiled_stack','next_trace_PC','next_trace_AF',
                 'entry_RDX','predecessor_RSP','closed_pages','lifetime_mode','registration_epoch','registration_calls','word_available'):
        mutant=copy.deepcopy(owner);a=mutant['attempts'][0]
        expected='all23 GREG/65536 FP including AF and exact CR2 history'
        if name.startswith('next_trace_'):
            g=list(a['next_trace']['greg']);g[16 if name=='next_trace_PC'else 17]^=1 if name=='next_trace_PC'else 16;a['next_trace']['greg']=tuple(g)
        elif name.startswith('logical_'):
            g=list(a['logical']['greg']);g[17 if name=='logical_AF'else 22]^=16 if name=='logical_AF'else 1;a['logical']['greg']=tuple(g)
        elif name=='full_FP':
            b=bytearray(a['logical']['fp']);b[160]^=1;a['logical']['fp']=bytes(b)
        elif name in('compiled_store','compiled_stack'):
            key='data'if name=='compiled_store'else'stack';b=bytearray(a['after_memory'][key]);b[0]^=1;a['after_memory'][key]=bytes(b)
            expected='whole actual compiled source/stack/two-relocation effects'
        elif name in('entry_RDX','predecessor_RSP'):
            f=a['before']if name=='entry_RDX'else a['predecessor_before'];g=list(f['greg']);g[GREG[2 if name=='entry_RDX'else 4]]^=1;f['greg']=tuple(g)
        elif name=='closed_pages':a['closed_pages']=34;expected='actual one-member17-page closed completed lifetime'
        else:
            mutant[name]=True if name=='word_available'else mutant[name]+1
            expected='actual unregistered epoch0 no-call lifetime and unavailable word'
        try:pair(native,gated,mutant)
        except ValueError as error:need(str(error)==expected,'exact causal pair refusal '+name);refused.append(name)
        else:raise ValueError('supplied pair corruption accepted '+name)
    need(len(refused)==PAIR_CONTROL_COUNTS[2],'literal14 original-loop pair controls')
    return dict(refusals=refused,native_operations=0,mode=2)
