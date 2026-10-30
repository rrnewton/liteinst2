"""Dedicated pre-edge primitive: actual native before/after-cut observations.
No decoder or runtime implementation supplies expected results. This four-pair
oracle does not qualify cache replacement, nested/fault cleanup or whole LS.
"""
import hashlib,struct
PAGE,FP,UC,LIVE=4096,65536,1024,2116
PREFIX,SUFFIX,OBS,FRAME=14720,284568,284440,66784
MAGIC=0x315050414550494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
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
    wanted = {'region_app_'+n for n in ('head','page','source_end','predecessor','cut','taken','fallthrough',
        'next_page','next_head','next_predecessor','next_cut','next_target','next_end',
        'unsupported_page','unsupported_head','unsupported_predecessor','unsupported_cut','unsupported_target','unsupported_end',
        'helper','helper_end','enter','capture','seed_x87','pure','pure_end','capture_high','entry_jump','head_pointer','return_end')} | {'ua_'+n for n in ('vectors','masks','host','host_fcw','input','before','after','before_live','after_live','target')}
    symbols = {}; symbol_sizes = {}
    for at in range(t[4], t[4] + t[5], 24):
        name, _, _, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'whole symbol name')
        name = names[name:names.index(b'\0', name)].decode()
        if name in wanted:
            need(name not in symbols and section != 0, 'unique defined fixture symbol')
            symbols[name] = value; symbol_sizes[name] = size
    need(set(symbols) == wanted, 'all actual fixture symbols')
    head,page=symbols['region_app_head'],symbols['region_app_page'];sources=[];heads=[];cuts=[];targets=[]
    high=symbols['region_app_capture_high'];stub=b'\xff\x25\0\0\0\0'+struct.pack('<Q',high)
    for index,prefix in enumerate(('', 'next_', 'unsupported_')):
        pg=symbols['region_app_'+prefix+'page'];hd=symbols['region_app_'+prefix+'head'];off=4060 if index==0 else 4064
        cut=symbols['region_app_'+prefix+'cut'];p,source=memory(pg,PAGE)
        end='source_end'if not index else prefix+'end';target='fallthrough'if not index else prefix+'target'
        need(pg==page+index*8192 and pg%PAGE==0 and hd==pg+off and off<=4081 and cut==hd+30 and symbols['region_app_'+end]==pg+PAGE and symbols['region_app_'+target]==pg+PAGE and p[1]==5 and p[2]+pg-p[3]>=PAGE,'whole original source and real in-page singleton entry')
        need(symbols['region_app_'+prefix+'predecessor']==hd-2 and symbol_sizes['region_app_'+prefix+'head']==30 and symbol_sizes['region_app_'+prefix+'cut']==(6 if not index else 2),'exact predecessor/prefix/cut symbol extents')
        expected=bytearray(b'\xcc'*PAGE);expected[off-2:off]=b'\x66\x90';expected[off:off+30]=bytes.fromhex('b807000000')*6
        if not index:
            need(symbols['region_app_taken']==pg+3968 and symbol_sizes['region_app_taken']==6,'actual in-page conditional target')
            expected[3968:3982]=stub;expected[4090:]=b'\x0f\x85'+struct.pack('<i',3968-4096)
        else:expected[4094:]=b'\x31\xc0'if index==1 else b'\x66\x90'
        need(source==bytes(expected),'whole original page including unexecuted cut and all gaps')
        need(memory(pg+PAGE,PAGE)[0][1]==5 and memory(pg+PAGE,PAGE)[1]==stub+b'\xcc'*(PAGE-14)and symbol_sizes['region_app_'+target]==6,'whole actual next-page target and transparent return')
        sources.append(source);heads.append(hd);cuts.append(cut);targets.append(pg+PAGE)
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
    return dict(symbols=symbols,head=head,page=page,heads=tuple(heads),cuts=tuple(cuts),sources=tuple(sources),
        targets=(page+3968,targets[0],targets[1],targets[2]),interpreter=path[:-1].decode(),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),phnum=h[10])

def live(data):
    need(len(data) == 152 and data[148:] == bytes(4), 'complete live state and reserved tail')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def reference_frame(data, prefix, layout, kind, steps, attempt):
    need(len(data) == FRAME, 'complete native reference frame')
    h = q(data, 0, 12); si = data[96:224]; uc = data[224:1248]; fp = data[1248:]
    sig = 11 if kind == 0 else 5
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
    g = q(uc, 40, 23); pc = (prefix['predecessor'],prefix['head'],prefix['cut_pc'],prefix['expected_exit_pc'])[kind]
    need(u(si, 0, 3) == (sig, 0, 2) and g[16] == pc and g[19:21] == ((21, 14) if kind == 0 else (0, 1)), 'genuine native signal origin')
    need(q(si,16)[0]==pc and g[22]==prefix['predecessor'],'actual native NX followed by unchanged CR2 through all TRACE frames')
    expected=prefix['seed'][0] if kind<2 else state(prefix['seed'][0],prefix['mode'],after=kind==3)
    need(tuple(g[i]for i in GREG)==expected and g[18]==0x2b000000000033 and g[21]==MASK,'complete actual native GPR model')
    if kind==0:need(g[17]==prefix['seed'][1]|RF,'actual NX seed flags')
    elif kind<3 or prefix['mode']!=2:need(g[17]==prefix['seed'][1]|TF,'whole cut has not changed flags before actual execution')
    else:need(g[17]&~0x10==(prefix['seed'][1]&~0x8d5)|0x44|TF,'actual XOR defined flags; AF remains a fully compared hardware observation')
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
    need(type(mode)is int and mode in range(4),'fixed four primitive cases')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[1]=3;seed[2]=1;seed[4]=RSP;seed[6]=1;seed[7]=DATA+4092;seed[10]=DATA+8188
    return (tuple(seed),0x202 if mode==0 else 0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(224))

def state(seed,mode,*,after=False):
    out=list(seed);out[0]=0 if after and mode==2 else 7;return tuple(out)

def _prefix(data,mode,native,layout,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode in range(4)and type(native)is bool,'typed entire primitive prefix')
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=live(data[1992:2144]);machine=q(data,2144,8);source,stack,memory=data[2208:6304],data[6304:6528],data[6528:]
    i=max(0,mode-1);head=layout['heads'][i];page=head&-PAGE;cut=layout['cuts'][i];endpoint=layout['targets'][mode]
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,1,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,page,DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,0,layout['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,0,0,endpoint,head-2,8,OBS,4,30,cut,1 if mode==3 else 2,6 if mode<2 else 2,RSEQ,endpoint&-PAGE,0,0,0),'whole fixed native/cut schedule')
    need(source==layout['sources'][i]and machine[0]==MASK and machine[1]>0 and machine[3:5]==(0x33,0x2b)and machine[5:]==(0,0,0),'whole ELF source and actual machine')
    need([x[:2]for x in hardware]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)]and hardware[0][2]>=13 and hardware[1][4]&0x0c000000==0x0c000000 and hardware[2][3]&0x40010000==0x40010000,'all actual CPUID rows')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<=FP,'actual XCR0 and standard capacity')
    seed_probe,xstate,profile,facts=seed_reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'separate same-CPU qualified seed and permissions')
    for i in range(2,64):
        if h[14]>>i&1:
            row=hardware[3+i];need(row[2]>0 and row[3]>=576 and row[3]+row[2]<=h[15]and row[4]&1==0,'complete standard component')
    expected,want_data,want_stack=fixture(mode)
    need(seed==expected and memory==want_data and stack==want_stack,'all actual seeded GPR/data/224stack bytes')
    return dict(header=h,mode=mode,head=head,capture_high=layout['symbols']['region_app_capture_high'],predecessor=head-2,source_page_address=page,source_page=source,source=source,hardware=hardware,xcr0=h[14],data=memory,stack=stack,rsp=RSP,seed=seed,machine=machine,cut_pc=cut,frontier_kind=h[41],expected_exit_pc=endpoint,suffix=None,observations=[])

def read(data,mode,native,exit_status,layout,pid,cpu,seed_reference,*,control=0):
    need(type(data)is bytes and type(exit_status)is int and exit_status==0 and type(control)is int and control==0 and len(data)==PREFIX+SUFFIX,'whole successful primitive output; no failed subject relabel')
    result=_prefix(data[:PREFIX],mode,native,layout,pid,cpu,seed_reference)
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,1,mode,int(native),0,1,1,4 if native else 0,8 if native else 0,0,0,0,0,0,0,0),'whole terminal cleanup/counts')
    value=suffix[128:];h=q(value,0,16);before,after=live(value[128:280]),live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==result['machine'],'actual per-lane FS/GS/mask bracket')
    need(h==(1,0,4 if native else 0,8 if native else 0,0,int(native),0,0,result['expected_exit_pc'],0,0,0,0,0,0,0),'whole primitive observation')
    need(before==(result['seed'][0],result['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all actual live inputs/selectors/vector bytes')
    need(after[0]==state(result['seed'][0],mode,after=True),'actual post-cut defined GPR result')
    need(value[4792:8888]==result['source']and value[8888:9112]==result['stack']and value[9112:17304]==result['data'],'whole source/data/224stack conservation')
    frames=[]
    for i,steps in enumerate((0,1,7,8)):
        frame=value[17304+i*FRAME:17304+(i+1)*FRAME]
        if native:frames.append(reference_frame(frame,result,layout,i,steps,0))
        else:need(frame==bytes(FRAME),'no fabricated native signal in gated application')
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'whole native FP across every boundary')
        need(after[1]==frames[3]['greg'][17]&~TF,'all flags including hardware AF after actual cut')
    result['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb)];result['suffix']=dict(end=end);return result

def pair(native,gated,owner):
    need(native['header'][5]==1 and gated['header'][5]==0 and native['mode']==gated['mode']==owner['mode']and owner['control']==0,'actual native/gated primitive pair')
    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor','cut_pc','expected_exit_pc')),'all source/seed/hardware inputs')
    need(len(owner['entries'])==len(native['observations'])==len(gated['observations'])==1,'one real completed primitive per process')
    reference=native['observations'][0];entry=owner['entries'][0];frames=reference['frames'];machine=gated['machine']
    def compare(actual,index,event):
        ref=frames[index];want=list(ref['greg'])
        if event=='closed':want[17]&=~TF
        elif event=='nx':want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        elif event=='post':want[22]=gated['cut_pc']
        else:need(event=='trace','only exact source-derived event transforms')
        need(actual['greg']==tuple(want)and actual['fp']==ref['fp']and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK,'all23GREG/65536FP/AF/mask at exact real boundaries')
        need((actual['fs'],actual['gs'])==tuple(machine[1:3]),'actual lane-local FS/GS bracketing')
    compare(entry['predecessor_before'],0,'trace');compare(entry['ingress'],1,'trace');compare(entry['before'],1,'closed');compare(entry['after'],2,'nx');compare(entry['post_cut'],3,'post')
    need(frames[3]['greg'][22]==frames[0]['greg'][22]==native['predecessor'],'native post-cut CR2 is actual predecessor NX history')
    need(entry['post_cut']['greg'][22]==entry['after']['greg'][22]==gated['cut_pc'],'gated post-cut CR2 is actual cut NX history')
    need(entry['disposition']=='completed'and entry['frontier_kind']==native['frontier_kind'],'typed completed original-NX frontier')
    for key in('before_memory','after_memory','post_memory'):need(entry[key]['data']==native['data']and entry[key]['stack']==native['stack'],'whole actual data/stack at all boundaries')
    actual=gated['observations'][0];need(reference['before']==actual['before']and reference['after']==actual['after']and reference['live']==actual['live'],'complete actual returned application state')
    return dict(qualified_pair=1,invocations=1,generated_completed=1,cut_kind=entry['frontier_kind'],post_cut_completed=1,whole_profile_qualified=0)

APP_CONTROL_COUNTS={m:36 for m in range(4)}
def controls(data,mode,native,exit_status,layout,pid,cpu,seed_reference):
    need(native is True,'supplied controls use complete actual native reference')
    read(data,mode,native,exit_status,layout,pid,cpu,seed_reference)
    first=PREFIX+128;frame=first+17304
    tests=[('prefix_'+str(i),i*8)for i in(0,1,2,4,5,6,8,10,14,16,30,31)]
    tests += [('hardware',384),('seed_GPR',1992),('source',2208),('stack',6304),('data',6528),('suffix_complete',PREFIX+5*8),('invocation_identity',first+8),('live_before_GPR',first+128),('live_after_GPR',first+280),('live_after_AF',first+408),('actual_TLS',first+440),('full_vector',first+560),('full_after_vector',first+2676),('source_readback',first+4792),('stack_readback',first+8888),('data_readback',first+9112),('native_origin',frame+8),('native_GPR',frame+264),('native_FP',frame+1248),('native_final_AF',frame+3*FRAME+400),('cut_PC',frame+2*FRAME+392),('cut_before_flags',frame+2*FRAME+400),('cut_descriptor',40*8),('post_target',34*8)]
    need(len(tests)==APP_CONTROL_COUNTS[mode],'fixed36 native supplied refusals')
    refused=[]
    for name,at in tests:
        changed=bytearray(data);changed[at]^=0x10 if name in('live_after_AF','native_final_AF','cut_before_flags')else 1
        try:read(bytes(changed),mode,native,exit_status,layout,pid,cpu,seed_reference)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied primitive native output accepted '+name)
    return dict(refusals=refused,native_operations=0,original_sha256=hashlib.sha256(data).hexdigest())


PAIR_CONTROL_COUNTS={m:4 for m in range(4)}
def pair_controls(native,gated,owner):
    import copy
    pair(native,gated,owner);refused=[]
    tests=('native_post_CR2','gated_post_CR2','coherent_gated_CR2','coherent_cut_RAX')
    for name in tests:
        n,o=copy.deepcopy(native),copy.deepcopy(owner)
        def flip(frame,index):
            values=list(frame['greg']);values[index]^=1;frame['greg']=tuple(values)
        if name=='native_post_CR2':flip(n['observations'][0]['frames'][3],22)
        elif name=='gated_post_CR2':flip(o['entries'][0]['post_cut'],22)
        elif name=='coherent_gated_CR2':
            flip(o['entries'][0]['after'],22);flip(o['entries'][0]['post_cut'],22)
        else:flip(o['entries'][0]['after'],13)
        try:pair(n,gated,o)
        except ValueError:refused.append(name)
        else:raise ValueError('supplied pre-edge pair accepted '+name)
    need(len(refused)==PAIR_CONTROL_COUNTS[native['mode']],'fixed four cross-lane refusals')
    return dict(refusals=refused,native_operations=0)
