"""Explicit two-root/146-step native reference; old arena/descriptor cohorts stay separate.

No captured source bytes, frame versions, or outcomes are normalized. The common
reader supplies its complete kernel FP/frame validator and application comparator.
"""
import hashlib,struct
from functools import partial
from types import SimpleNamespace
PAGE,FP,UC,LIVE=4096,65536,1024,2116
SOURCE=4*PAGE
PREFIX,SUFFIX,OBS,FRAME=27080,831400,831000,66784
MAGIC=0x384350414132494c
DATA,STACK,RSEQ=0x500000000000,0x500000100000,0x500000200000
RSP=STACK+4096+131072-504
U64,TF,RF=(1<<64)-1,0x100,0x10000
MASK=0xffffffffbffbfae7
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
REFERENCE='cached-direct-ab146'
STEPS=(0,1,3,4,5,9,10,14,77,136,144,146)
PROFILE=(5,146,STEPS)
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)
def u(data,at=0,count=1):return struct.unpack_from('<'+'I'*count,data,at)

def _reference(reference):
    need(type(reference)is str and reference==REFERENCE,'explicit exact two-root cached DIRECT reference')
    return PROFILE

def source_bytes():
    """Literal original bytes only; not a planner or admission decoder."""
    result=bytearray(b'\xcc'*SOURCE);result[0x1fe:0x200]=b'\x66\x90'
    a=bytes.fromhex('4883c001488907e9')+struct.pack('<i',0x2ffa-0x20c)
    b=bytes.fromhex('4883c002488947084883e9010f85')+struct.pack('<i',0xffa-0x2212)
    b+=b'\xe9'+struct.pack('<i',0x4000-0x2217)
    need(len(a)==12 and len(b)==23,'two exact complete original bodies')
    result[0x200:0x20c]=a;result[0x2200:0x2217]=b
    for at,target in ((0xffa,0x200),(0x2ffa,0x2200)):
        result[at:at+5]=b'\xe9'+struct.pack('<i',target-(at+5))
    return bytes(result)

def _elf(common,data,native_policy, *, reference=REFERENCE):
    _reference(reference)
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
    wanted={'region_app_'+n for n in ('head','page','predecessor','second_page','source_end',
        'helper','helper_end','enter','capture','seed_x87','pure','pure_end','capture_high','entry_jump',
        'head_pointer','return_end','tail_a','tail_b')} | {'ua_'+n for n in
        ('vectors','masks','host','host_fcw','input','before','after','before_live','after_live','target')}
    wanted|={'region_app_repeat_'+n for n in ('page','setup','site','next','end','buffer')}
    wanted|={'region_app_node'+str(i)+suffix for i in range(2) for suffix in ('','_store','_exit')}
    wanted.add('region_app_node1_repeat')
    symbols = {}; symbol_sizes = {}
    for at in range(t[4], t[4] + t[5], 24):
        name, _, _, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'whole symbol name')
        name = names[name:names.index(b'\0', name)].decode()
        if name in wanted:
            need(name not in symbols and section != 0, 'unique defined fixture symbol')
            symbols[name] = value; symbol_sizes[name] = size
    need(set(symbols) == wanted, 'all actual fixture symbols')
    head,page=symbols['region_app_head'],symbols['region_app_page']
    segment,source=memory(page,SOURCE)
    need(page==0x410000 and head==page+0x200 and symbols['region_app_source_end']==page+SOURCE and
         segment[1]==5 and segment[2]+page-segment[3]>=PAGE,
         'actual four complete original RX source pages outside ELF header')
    need(source==source_bytes(),'both independent whole source pairs and literal branch displacements')
    for node in range(2):
        root=page+node*2*PAGE+0x200;size=12 if node==0 else 23
        exit_offset=7 if node==0 else 18
        for suffix,offset,extent in (('',0,size),('_store',4,0),('_exit',exit_offset,0)):
            name='region_app_node'+str(node)+suffix
            need(symbols[name]==root+offset and symbol_sizes[name]==extent,'both original root symbols and exact footprints')
    need(symbols['region_app_node1_repeat']==page+0x220c and symbol_sizes['region_app_node1_repeat']==0,
         'actual B conditional site independent of planner output')
    need(symbols['region_app_predecessor']==page+0x1fe and symbols['region_app_second_page']==page+PAGE and
         symbols['region_app_tail_a']==page+0xffa and symbol_sizes['region_app_tail_a']==5 and
         symbols['region_app_tail_b']==page+0x2ffa and symbol_sizes['region_app_tail_b']==5,
         'actual initial predecessor and both original near-page-end transit branches')
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
    return dict(symbols=symbols,head=head,page=page,source=source,
        roots=tuple(page+2*PAGE*i+0x200 for i in range(2)),
        source_pairs=tuple(source[i*2*PAGE:(i+1)*2*PAGE] for i in range(2)),
        source_offsets=tuple(memory(page+i*2*PAGE,2*PAGE)[0][2]+page+i*2*PAGE-memory(page+i*2*PAGE,2*PAGE)[0][3] for i in range(2)),
        tails=(page+0xffa,page+0x2ffa),exits=(page+0x207,page+0x220c,page+0x2212),
        interpreter=path[:-1].decode(),sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),phnum=h[10],repeat_setup=repeat_setup)


def fixture(mode,image):
    need(type(mode)is int and mode==0,'literal finite positive cached DIRECT application')
    seed=[0x3141592600000000+i*0x102030405 for i in range(16)]
    seed[0]=1;seed[1]=16;seed[2]=image['symbols']['region_app_node1'];seed[3]=image['head'];seed[8]=3
    seed[4]=RSP;seed[6]=image['symbols']['region_app_capture'];seed[7]=DATA
    return (tuple(seed),0xad7,bytes(12)),bytes(1+(i*17)%255 for i in range(8192)),bytes((i*29+7)&255 for i in range(224))

def instruction(common,pc,g,flags,data,stack,prefix):
    page=prefix['source_page_address'];off=pc-page
    if off==0x1fe:pc+=2
    elif off in (0xffa,0x2ffa):pc=page+(0x200 if off==0xffa else 0x2200)
    elif off==0x4000:pc=prefix['expected_exit_pc']
    elif off in (0x200,0x2200):g[0],flags=common.arithmetic(g[0],1 if off==0x200 else 2,flags);pc+=4
    elif off in (0x204,0x2204):
        address=g[7]+(0 if off==0x204 else 8)
        need(DATA<=address<=DATA+8192-8,'whole modeled guest store range')
        changed=bytearray(data);struct.pack_into('<Q',changed,address-DATA,g[0]);data=bytes(changed)
        pc+=3 if off==0x204 else 4
    elif off==0x207:pc=page+0x2ffa
    elif off==0x2208:g[1],flags=common.arithmetic(g[1],1,flags,True);pc+=4
    elif off==0x220c:pc=page+(0xffa if not flags&0x40 else 0x2212)
    elif off==0x2212:pc=page+0x4000
    else:raise ValueError('unmodelled original cached DIRECT instruction')
    return pc,g,flags,data,stack

def trace_model(common,prefix, *, reference=REFERENCE):
    _reference(reference)
    pc=prefix['predecessor'];g=list(prefix['seed'][0]);flags=prefix['seed'][1]
    data,stack=prefix['data'],prefix['stack'];out=[(pc,tuple(g),flags,data,stack)]
    for _ in range(146):
        pc,g,flags,data,stack=instruction(common,pc,g,flags,data,stack,prefix)
        out.append((pc,tuple(g),flags,data,stack))
    need(out[-1][0]==prefix['expected_exit_pc'],'literal146-instruction model ends at high capture')
    keys=(1,4,5,9,10,14,73,77,136,140,143,144,145)
    want=(0x200,0x2ffa,0x2200,0xffa,0x200,0x2200,0x200,0x2200,0x200,0x2200,0x220c,0x2212,0x4000)
    need(tuple(out[i][0]-prefix['source_page_address']for i in keys)==want,
         'first, middle and final roots/tails plus actual fallthrough/capture')
    need(out[-1][1]==state(prefix['seed'][0],0)and out[-1][3]==written(prefix['data'],0),
         'independent full instruction model and literal final result agree')
    return out

def frame_spec(common,prefix,index,model):
    pc,g,flags,_,_=model[STEPS[index]];nx=index==0
    return dict(signal=11 if nx else 5,pc=pc,greg=g,flags=flags|(RF if nx else TF),address=pc,
                cr2=prefix['predecessor'],exception=(21,14)if nx else(0,1))

def state(seed,mode):
    need(mode==0,'literal complete cached DIRECT result')
    out=list(seed);out[0]+=48;out[1]=0;return tuple(out)

def written(data,mode):
    need(mode==0,'two literal final full-width guest stores')
    out=bytearray(data);struct.pack_into('<2Q',out,0,47,49);return bytes(out)

def _prefix(common,data,mode,native,image,pid,cpu,seed_reference, *, reference=REFERENCE):
    _reference(reference)
    need(type(data)is bytes and len(data)==PREFIX and type(mode)is int and mode==0 and type(native)is bool,'typed complete two-root cached DIRECT app prefix')
    need(mode==0,'no unvalidated fault mode')
    profile=PROFILE
    h=q(data,0,48);hardware=[u(data,384+i*24,6)for i in range(67)]
    seed=common.live(data[1992:2144]);machine=q(data,2144,8)
    source,stack,memory=data[2208:18592],data[18592:18816],data[18816:27008]
    head=image['head'];frontier=image['symbols']['region_app_capture_high'];predecessor=head-2
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    need(h[:9]==(MAGIC,profile[0],PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')
    need(h[16:26]==(mode,int(mode==1),image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and h[26]==h[28]==0,'actual complete signal geometry')
    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,predecessor,profile[1],OBS,12,2,image['page']+0x2200,image['page']+0xffa,SOURCE,RSEQ,0x53053053,image['page']+0x207,image['page']+0x220c,image['page']+0x2212),'exact version5 cached DIRECT fixture header')
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

def _read(common,data,mode,native,exit_status,image,pid,cpu,seed_reference, *, reference=REFERENCE):
    _reference(reference)
    need(type(data)is bytes and type(mode)is int and mode==0 and type(native)is bool and type(exit_status)is int,'typed actual outcome')
    full=native or mode==0
    need(exit_status==(0 if mode==0 else 125)and len(data)==PREFIX+(SUFFIX if full else 0),'exact native/gated status and complete output')
    profile=PROFILE
    r=_prefix(common,data[:PREFIX],mode,native,image,pid,cpu,seed_reference, reference=reference)
    if not full:return r
    suffix=data[PREFIX:];end=q(suffix,0,16)
    need(end==(MAGIC^1,profile[0],mode,int(native),0,1,1,12 if native else 0,profile[1]if native else 0,int(mode==1),2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')
    effects=[q(suffix,128+i*136,17)for i in range(2)]
    for i,row in enumerate(effects):
        need(row[:9]==(i+1,334,RSEQ,32,i,0x53053053,0,0,0),'actual rseq lifecycle arguments and zero result')
        before,after=row[9:13],row[13:17]
        need(before==((0,0,0,0)if i==0 else(cpu|(cpu<<32),0,0,0))and after==((cpu|(cpu<<32),0,0,0)if i==0 else(0xffffffff00000000,0,0,0)),'actual kernel registration/unregistration words')
    value=suffix[400:];h=q(value,0,16);before,after=common.live(value[128:280]),common.live(value[280:432]);mb,ma=q(value,432,8),q(value,496,8)
    a,b=value[560:2676],value[2676:4792];selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(mb==ma==r['machine'],'whole actual FS/GS/mask bracket')
    need(h==(1,0,12 if native else 0,profile[1]if native else 0,int(mode==1),int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')
    need(before==(r['seed'][0],r['seed'][1],selectors)and after[2]==selectors and not after[1]&(TF|RF)and a==b==LIVE_SEED,'all inputs/selectors/live vector bytes')
    need(after[0]==state(r['seed'][0],mode)and after[1]==0x246,'all defined loop GPR and flag results')
    need(value[4792:21176]==r['source']and value[21176:21400]==r['stack']and value[21400:29592]==written(r['data'],mode),'whole source/stack and exact completed store effects')
    frames=[];model=trace_model(common,r)
    for i in range(12):
        frame=value[29592+i*FRAME:29592+(i+1)*FRAME]
        if not native or(mode==1 and i>=3):need(frame==bytes(FRAME),'no fabricated native signal')
        else:
            kind=i
            steps=profile[2][i]
            frames.append(common.reference_frame(frame,r,image,kind,steps,0,spec=frame_spec(common,r,kind,model)))
    if native:
        need(all(f['fp']==frames[0]['fp']for f in frames),'all65536 native FP bytes conserved')
        need(after[1]==frames[-1]['greg'][17]&~(TF|RF),'actual undefined AF and all terminal flags')
    r['observations']=[dict(before=before,after=after,live=a,frames=frames,header=h,machine=mb,data=value[21400:29592],stack=value[21176:21400])]
    r['effects']=effects;r['suffix']=dict(end=end);return r

CONTROL_COUNTS=dict(base=45,reference=5,context=10)

def control_sites():
    observation=PREFIX+400;frame=observation+29592
    base=(('version',8),('CPU',8*8),('hardware',384+8),('seed_GPR',1992),
        ('source',2208),('stack',18592),('data',18816),('registration_result',27008),
        ('publication_word',27008+6*8),('cleanup',PREFIX+5*8),('after_GPR',observation+280),
        ('after_AF',observation+408),('actual_TLS',observation+496+8),('whole_live_vector',observation+2676),
        ('native_FP',frame+1248),('completed_store0',observation+21400),
        ('first_A_exit_flags',frame+2*FRAME+224+40+17*8),
        ('first_tail_B_PC',frame+3*FRAME+224+40+16*8),
        ('first_B_entry_RAX',frame+4*FRAME+224+40+GREG[0]*8),
        ('first_tail_A_RCX',frame+5*FRAME+224+40+GREG[1]*8),
        ('second_A_entry_PC',frame+6*FRAME+224+40+16*8),
        ('second_B_entry_PC',frame+7*FRAME+224+40+16*8),
        ('last_B_fallthrough_RBX',frame+10*FRAME+224+40+GREG[3]*8),('last_TRACE_PC',frame+11*FRAME+224+40+16*8),
        ('no_prefix_registration_before',27016),('no_prefix_registration_after',27048),
        ('collection_lifetime',PREFIX+80),('collection_completed',PREFIX+88),
        ('later_registration_result',PREFIX+128+64),('later_registration_word',PREFIX+128+13*8),
        ('later_unregistration_word',PREFIX+264+13*8),('completed_store1',observation+21400+8),
        ('source_pair1',2208+2*PAGE),('source_second_page1',2208+3*PAGE),('source_extent',42*8),
        ('observed_pair1',observation+4792+2*PAGE),('second_A_entry_R8',frame+6*FRAME+224+40+GREG[8]*8),
        ('second_B_entry_flags',frame+7*FRAME+224+40+17*8),('last_A_entry_RCX',frame+9*FRAME+224+40+GREG[1]*8),
        ('last_B_fallthrough_PC',frame+10*FRAME+224+40+16*8),('tail_B_opcode',2208+0x2ffa),
        ('tail_A_displacement',2208+0xffb),('observed_tail_B',observation+4792+0x2ffa),
        ('untouched_data_word',observation+21400+16),('tail_A_header',41*8))
    reference=(('last_A_entry_R8',frame+9*FRAME+224+40+GREG[8]*8),('unchanged_R8_seed',1992+8*8),
        ('prefix_trace_total',36*8),('suffix_trace_total',PREFIX+8*8),('final_checkpoint_R8',frame+11*FRAME+224+40+GREG[8]*8))
    context=(('first_second_page',2208+PAGE),('observed_first_pair',observation+4792),
        ('tail_A_opcode',2208+0xffa),('tail_B_displacement',2208+0x2ffb),('observed_tail_A',observation+4792+0xffa),
        ('root_count',39*8),('B_root',40*8),('A_direct',45*8),('B_conditional',46*8),('B_final_exit',47*8))
    need((len(base),len(reference),len(context))==(45,5,10)and
         len({offset for _,offset in base+reference+context})==60,'all60 native corruption offsets distinct')
    return base,reference,context

def _controls(common,data,mode,native,exit_status,image,pid,cpu,seed_reference, *, reference=REFERENCE):
    need(native is True and mode==0,'native-only complete cached DIRECT supplied controls')
    _read(common,data,mode,native,exit_status,image,pid,cpu,seed_reference,reference=reference)
    groups=[]
    for tests in control_sites():
        refused=[]
        for name,offset in tests:
            changed=bytearray(data);changed[offset]^=1
            try:_read(common,bytes(changed),mode,native,exit_status,image,pid,cpu,seed_reference,reference=reference)
            except ValueError:refused.append(name)
            else:raise ValueError('actual full native cached DIRECT corruption accepted '+name)
        groups.append(refused)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=groups[0],reference_refusals=groups[1],
                context_refusals=groups[2],native_operations=0,mode=mode)

def configured(common):
    need((common.FRAME,common.FP,common.LIVE,common.MAGIC,common.GREG)==(FRAME,FP,LIVE,MAGIC,GREG),
         'same full kernel-frame ABI and independent native state comparator')
    return SimpleNamespace(PREFIX=PREFIX,SUFFIX=SUFFIX,OBS=OBS,FRAME=FRAME,FP=FP,MASK=MASK,TF=TF,RF=RF,
        GREG=GREG,PAGE=PAGE,SOURCE=SOURCE,REFERENCE=REFERENCE,STEPS=STEPS,CONTROL_COUNTS=CONTROL_COUNTS,
        elf=partial(_elf,common),read=partial(_read,common),_prefix=partial(_prefix,common),controls=partial(_controls,common),
        application_pair=common.application_pair,trace_model=partial(trace_model,common),model=partial(trace_model,common),
        frame_pc=lambda prefix,index:trace_model(common,prefix)[STEPS[index]][0],
        frame_state=lambda prefix,index:trace_model(common,prefix)[STEPS[index]][1],source_bytes=source_bytes)
