"""Strict distinct lifecycle native/application wire, no owner authority.

This checks the complete actual native trace and maintained final application
state. Every returned actual flag/UC/FP byte is retained. Owner lifecycle,
directory, generation and cancellation require the separate schema15 reader.
No candidate decoder/planner is used to derive the original instruction path.
"""
import hashlib,struct
PAGE,FP,UC,LIVE,FRAME=4096,65536,1024,2116,66784
PREFIX,SUFFIX,FRAMES=18944,4834328,64
FRAME_DATA,FRAME_STACK=4295704,4819992
MAGIC=0x31434c5032494c
DATA,STACK=0x500000000000,0x500000100000
GUARD=DATA+8192
RSP=STACK+4096+131072-504
U64,TF,RF,MASK=(1<<64)-1,0x100,0x10000,0xffffffffbffbfae7
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
SOURCE_PAGE=(0x4000000,0x700000000000)
ENTRY,STEPS=(512,256),(50,42)
A=bytes.fromhex('4883e9014883f9020f84f2feffff4885c975ed66894f084983ea0175faff2500000000')
B=bytes.fromhex('4c890f4983e9014c89c9e9f1000000')
A5=(0,4,8,14,17);A8=A5+(0,4,8);B4=(-256,-253,-249,-246)
PATH=((-5,)+A8+B4+A8+B4+(0,4,8)+B4+A5+A5+(19,)+(23,27)*3+(29,),
      (-261,)+B4+A8+B4+(0,4,8)+B4+A5+A5+(19,)+(23,27)*3+(29,))
COUNTS=((3,3,3,2,3,1),(2,2,3,2,3,1))
# Actual observed full-frame positions at each generated entry/exit-before
# branch. These follow the literal original path; no captured counter is used.
EPOCH_STEPS=((1,8,9,12,13,41,42,43,48,49),(1,4,5,12,13,33,34,35,40,41))
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,
    0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')
SOURCE_FACTS={'tunables_lifecycle_app/main.c': (16049, '17556bb1ac061b4f7937837033437283d3a60add9a190d37586e12cc895c27a0'), 'tunables_lifecycle_app/reference.c': (3835, '9d81692069e333ba5d58cf598043fdf0571c78c29177b54586fb15937258a68f'), 'tunables_lifecycle_app/fixture.h': (1948, '2cc516cc52cbc2b55afa314e584ca91454243be8dbf81c2e63c73f8f9b11a842'), 'tunables_lifecycle_app/machine.S': (3608, 'c991bc67d26a3687aa6a37a307f7ab89a49a930dc9f9bea3b55f30402b963ac4'), 'persistent_direct_frontier_app/app.h': (2003, 'fe2c25a22730bed0e9aaa4e449bfdc216f8aa37bddc27c2ea9ac6bf43263b8a0'), 'persistent_direct_frontier_app/pure.c': (2037, '414fefc072e723051c020eab0736e1cd9e383898ef0cb8a221250b3be6fc6018'), 'persistent_direct_frontier_app/entry.S': (910, 'f13b2dd061af3eadd3e709f6a0d3884700e92b81361211566f486e8f3f7c1eff')}

def need(ok,why):
    if not ok:raise ValueError(why)

def q(data,at=0,count=1):return struct.unpack_from('<'+'Q'*count,data,at)

def u(data,at=0,count=1):return struct.unpack_from('<'+'I'*count,data,at)

def sha(data):return hashlib.sha256(data).hexdigest()

def canonical(at,n=1):return type(at)is int and type(n)is int and 0<n and PAGE<=at<(1<<47)and n<=(1<<47)-at

def identical(a,b):
    """Complete value and type equality; JSON true never aliases integer1."""
    if type(a)is not type(b):return False
    if type(a)is dict:return a.keys()==b.keys()and all(identical(a[k],b[k])for k in a)
    if type(a)in(tuple,list):return len(a)==len(b)and all(identical(x,y)for x,y in zip(a,b))
    return a==b

def live(data):
    need(len(data)==152 and data[148:]==bytes(4),'complete live state and reserved tail')
    return q(data,0,16),q(data,128)[0],data[136:148]

def expected_layout():
    # Independent declarations, subsequently required to match actual DWARF.
    fields={
      'ua_live':(152,{'g':(0,128,8),'flags':(128,8,8),'selectors':(136,12,2),'reserved':(148,4,4)}),
      'ua_frame':(FRAME,{'h':(0,96,8),'si':(96,128,1),'uc':(224,1024,1),'fp':(1248,FP,1)}),
      'lc_prefix':(PREFIX,{'h':(0,512,8),'hardware':(512,1608,4),'seed':(2120,152,8),
        'machine':(2272,64,8),'source':(2336,8192,1),'data':(10528,8192,1),'stack':(18720,224,1)}),
      'lc_suffix':(SUFFIX,{'h':(0,256,8),'before':(256,152,8),'after':(408,152,8),
        'machine_before':(560,64,8),'machine_after':(624,64,8),'before_live':(688,LIVE,1),
        'after_live':(2804,LIVE,1),'source':(4920,8192,1),'data':(13112,8192,1),'stack':(21304,224,1),
        'frame':(21528,FRAMES*FRAME,8),'frame_data':(FRAME_DATA,FRAMES*8192,1),'frame_stack':(FRAME_STACK,FRAMES*224,1)})}
    types={name:dict(bytes=n,alignment=8,fields={k:dict(offset=a,bytes=z,alignment=l)for k,(a,z,l)in row.items()})for name,(n,row)in fields.items()}
    edges={'ua_live':{},'ua_frame':{},'lc_prefix':{'seed':'ua_live'},
        'lc_suffix':{'before':'ua_live','after':'ua_live','frame':'ua_frame'}}
    uc=dict(offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),
        widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8))
    si=dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16),widths=dict(signo=4,errno=4,code=4,addr=8))
    return types,edges,uc,si

def layout_join(layout,symbols,sizes,headers):
    need(type(layout)is dict and set(layout)=={'record','types','edges','objects','uc_bytes','uc','si'},'complete native DWARF schema')
    types,edges,uc,si=expected_layout()
    need(type(layout['record'])is str and layout['record']=='lc_lifecycle_v1'and
         identical(layout['types'],types)and identical(layout['edges'],edges)and
         type(layout['uc_bytes'])is int and layout['uc_bytes']==968 and identical(layout['uc'],uc)and identical(layout['si'],si),
         'all actual declared native types and kernel ABI')
    need(type(headers)is dict and all(type(k)is str and type(v)is dict and set(v)=={'bytes','sha256'}and
         type(v['bytes'])is int and v['bytes']>=0 and type(v['sha256'])is str and len(v['sha256'])==64 and
         all(c in '0123456789abcdef'for c in v['sha256'])for k,v in headers.items()),
         'actual compiler-M source facts')
    paths={}
    for suffix,(n,digest)in SOURCE_FACTS.items():
        matches=[p for p in headers if p.endswith('/tools/page-entry/selected/tests/'+suffix)]
        need(len(matches)==1 and headers[matches[0]]==dict(bytes=n,sha256=digest),'whole fixture source dependency '+suffix)
        paths[suffix]=matches[0]
    need(type(layout['objects'])is dict and set(layout['objects'])=={'prefix','suffix'},'both actual wire objects')
    for name,tag,n in(('prefix','lc_prefix',PREFIX),('suffix','lc_suffix',SUFFIX)):
        d=layout['objects'][name]
        need(type(d)is dict and set(d)=={'address','bytes','alignment','tag','source'}and
             type(d['address'])is int and type(d['bytes'])is int and type(d['alignment'])is int and
             (d['address'],d['bytes'],d['alignment'],d['tag'],d['source'])==
             (symbols[name],n,8,tag,paths['tunables_lifecycle_app/main.c'])and sizes[name]==n,
             'actual wire ELF/DWARF/source object '+name)

def elf(data,native_policy,layout,headers):
    """Pure ELF/DWARF/source join. native_policy is the unchanged authenticated
    native-halo checker supplied by the collector; no exemption or subprocess.
    The collector must bind the entire compiler argv/M closure and raw DWARF
    command/capture before supplying these values, exactly as in PF admission.
    """
    need(type(data)is bytes and 64<=len(data)<=16<<20,'complete bounded ELF')
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\2\1\1'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'exact ET_EXEC x86-64 header')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    loads=[p for p in ph if p[0]==1]
    need(loads and all(p[5]<=p[6]and p[3]<=U64-p[6]and p[7]in(4096,2097152)and p[1]&3!=3 for p in loads)and
         not any(p[0]==7 for p in ph),'complete non-WX loads and no TLS')
    for p in loads:take(p[2],p[5])
    def memory(pc,n):
        owners=[p for p in loads if p[3]<=pc and n<=p[5]and pc-p[3]<=p[5]-n]
        need(len(owners)==1,'one complete file-backed range');p=owners[0]
        return p,take(p[2]+pc-p[3],n)
    interp=[p for p in ph if p[0]==3];need(len(interp)==1,'actual source-owned interpreter')
    path=take(interp[0][2],interp[0][5])
    need(path.startswith(b'/')and path.endswith(b'\0')and b'\0'not in path[:-1],'complete interpreter name')
    sh=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[s for s in sh if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0,'one complete symbol table')
    t=tables[0];need(t[6]<len(sh)and sh[t[6]][1]==3,'actual symbol strings')
    names=take(sh[t[6]][4],sh[t[6]][5])
    wanted={'prefix','suffix','lc_a_template','lc_b_template','lc_entry','lc_steps','lc_a_back','lc_a_to_b',
        'lc_source_page','lc_base_offset','lc_b_offset','lc_cancel_offset','lc_c_offset','lc_stub_offset','lc_predecessor_offset',
        'main','lc_inputs','lc_model_init','lc_advance','copy','same','ua_data_pattern','ua_stack_pattern'}
    wanted|={'region_app_'+x for x in('helper','helper_end','enter','capture_high','seed_x87','entry_jump','pure','pure_end')}
    wanted|={'ua_'+x for x in('input','before','after','before_live','after_live','target','host','host_fcw','vectors','masks')}
    symbols,sizes,kinds={},{},{}
    for at in range(t[4],t[4]+t[5],24):
        n,info,_,section,value,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'whole symbol name')
        name=names[n:names.index(0,n)].decode('ascii')
        need(not name or section!=0,'no imported application symbol')
        if name in wanted:
            need(section!=0 and name not in symbols,'unique defined fixture symbol')
            symbols[name]=value;sizes[name]=size;kinds[name]=info&15
    need(set(symbols)==wanted,'all actual native fixture symbols')
    for name in('main','lc_inputs','lc_model_init','lc_advance','copy','same','ua_data_pattern','ua_stack_pattern','region_app_enter','region_app_capture_high'):
        need(kinds[name]==2 and sizes[name]>0 and memory(symbols[name],sizes[name])[0][1]==5,'whole actual executable function '+name)
    for name,literal in (('lc_a_template',A),('lc_b_template',B)):
        need(sizes[name]==len(literal)and kinds[name]==1 and
             memory(symbols[name],len(literal))[0][1]==4 and memory(symbols[name],len(literal))[1]==literal,
             'whole literal lifecycle source template '+name)
    for name,values in(('lc_entry',ENTRY),('lc_steps',STEPS),('lc_a_back',(3,2)),('lc_a_to_b',(3,2)),
                      ('lc_base_offset',(512,)),('lc_b_offset',(256,)),('lc_cancel_offset',(19,)),
                      ('lc_c_offset',(23,)),('lc_stub_offset',(29,))):
        literal=struct.pack('<'+'I'*len(values),*values)
        need(sizes[name]==len(literal)and kinds[name]==1 and memory(symbols[name],len(literal))[0][1]==4 and
             memory(symbols[name],len(literal))[1]==literal,'literal independent lifecycle table '+name)
    for name,literal in(('lc_source_page',struct.pack('<2Q',*SOURCE_PAGE)),
                        ('lc_predecessor_offset',struct.pack('<i',-5))):
        need(sizes[name]==len(literal)and kinds[name]==1 and memory(symbols[name],len(literal))[0][1]==4 and
             memory(symbols[name],len(literal))[1]==literal,'whole actual lifecycle geometry '+name)
    for name,at in(('pure',0x200001000),('helper',0x200021000)):
        p,b=memory(at-PAGE,3*PAGE)
        need(symbols['region_app_'+name]==at and symbols['region_app_'+name+'_end']==at+PAGE and
             p[1]==5 and p[3]==at-PAGE and p[5]==p[6]==3*PAGE and
             b[:PAGE]==b[2*PAGE:]==b'\xcc'*PAGE,'whole actual high helper and CC halos')
        need(native_policy(memory(at-14,PAGE+28)[1])==0,'whole unchanged native-policy helper admission')
    ro,b=memory(0x200010000,PAGE)
    need(ro[1]==4 and ro[3]==0x200010000 and ro[5]==ro[6]==PAGE and
         symbols['ua_vectors']==ro[3]and symbols['ua_masks']==ro[3]+2048 and
         b==VECTORS+MASKS+bytes(PAGE-2112),'whole nonexecuting vector/mask constants')
    state=[p for p in loads if p[3]==0x200030000]
    need(len(state)==1 and state[0][1]==6 and state[0][5:7]==(0,2*PAGE),'complete zero-initialized assembly state load')
    extents=[]
    for name,n in(('input',152),('before',152),('after',152),('before_live',LIVE),('after_live',LIVE),('target',8),('host',64),('host_fcw',2)):
        a=symbols['ua_'+name]
        need(sizes['ua_'+name]==n and 0x200030000<=a<=0x200032000-n and
             all(a+n<=x or x+z<=a for x,z in extents),'complete distinct assembly state object')
        extents.append((a,n))
    helper=symbols['region_app_helper'];entry=symbols['region_app_entry_jump'];end=symbols['region_app_capture_high']
    seed=symbols['region_app_seed_x87'];disp=symbols['ua_target']-entry-6
    need(helper<=symbols['region_app_enter']<=seed-4<seed<entry and entry+6==end<helper+PAGE and
         memory(seed-4,6)[1]==bytes.fromhex('dbe3d9e8d9eb')and -(1<<31)<=disp<1<<31 and
         memory(entry,6)[1]==b'\xff\x25'+struct.pack('<i',disp),'actual seed and transparent entry/capture geometry')
    for name,n in(('prefix',PREFIX),('suffix',SUFFIX)):
        a=symbols[name];owners=[p for p in loads if p[1]==6 and p[3]+p[5]<=a<=p[3]+p[6]-n]
        need(kinds[name]==1 and sizes[name]==n and a%8==0 and len(owners)==1,'whole native wire BSS object '+name)
    need(symbols['prefix']+PREFIX<=symbols['suffix']or symbols['suffix']+SUFFIX<=symbols['prefix'],'disjoint native wire objects')
    layout_join(layout,symbols,sizes,headers)
    return dict(symbols=symbols,sizes=sizes,layout=layout,headers=headers,sha256=sha(data),bytes=len(data),
        interpreter=path[:-1].decode(),templates=(A,B),profile='lc_lifecycle_v1',policy12_owner_verified=False)

def arithmetic(a,b,flags,bits=64,sub=False):
    mask=(1<<bits)-1;a&=mask;b&=mask;v=(a-b if sub else a+b)&mask
    cf=int(a<b if sub else a+b>mask)
    of=(((a^b)if sub else ~(a^b))&(a^v))>>(bits-1)&1
    f=cf|(int((v&255).bit_count()%2==0)<<2)|((a^b^v)&16)|(int(v==0)<<6)|((v>>(bits-1))<<7)|(of<<11)
    return v,(flags&~0x8d5)|f

def seed_join(reference,hardware,h,cpu):
    # One extra raw input, already captured by the existing seed probe. No new
    # child is required, and the original seed.require predicate remains whole.
    need(type(reference)is tuple and len(reference)==5,'whole existing seed prerequisite plus retained raw seed')
    seed_probe,xstate,profile,facts,raw=reference
    need(seed_probe.require(profile,facts,cpu=cpu)==bytes(16)and
         xstate.profile(hardware,h[14],h[27],h[29],cpu,h[9])==facts,'same-CPU qualified seed and complete format')
    need(type(raw)is bytes and len(raw)==5792 and sha(raw)==profile['record_sha256'],'whole retained authenticated seed record')
    slots=tuple(raw[a:a+512]for a in(3672,4184,4768,5280))
    need(slots[1:]==(slots[0],)*3 and sha(slots[0])==profile['full_fxsave_sha256'],'four literal seed FXSAVE observations')
    legacy=bytearray(slots[0][:464]);legacy[160:416]=b''.join(VECTORS[64*i:64*i+16]for i in range(16))
    return facts,bytes(legacy)

def frame(raw,prefix,kind,steps,expected,causal,legacy):
    need(type(raw)is bytes and len(raw)==FRAME,'complete native frame')
    h=q(raw,0,12);si=raw[96:224];uc=raw[224:1248];fp=raw[1248:]
    sig=5 if kind==1 else 11;pc=expected[2];fault=kind==2
    need(h[:5]==(1,kind,steps,prefix['mode'],sig)and h[7]==968 and
         h[9]==prefix['facts']['extent']+4 and h[10]%PAGE==0 and h[11]==524288 and canonical(h[10],h[11]),
         'exact native frame identity and extent')
    views=((h[5],si),(h[6],uc[:968]),(h[8],fp[:h[9]]))
    for a,b in views:
        need(canonical(a,len(b))and h[10]<=a<=h[10]+h[11]-len(b),'actual bounded physical frame view')
        for c,d in views:
            lo,hi=max(a,c),min(a+len(b),c+len(d))
            if lo<hi:need(b[lo-a:hi-a]==d[lo-c:hi-c],'all physical SI UC FP aliases')
    need(h[8]%16==0 and q(uc,224)[0]==h[8]and uc[968:]==bytes(56)and fp[h[9]:]==bytes(FP-h[9]),
         'actual FP pointer and full unused native capacities')
    need(uc[304:432]==si,'whole embedded native siginfo')
    need(q(uc,0,2)==(7,0)and q(uc,16)[0]==h[10]and u(uc,24)[0]==0 and uc[28:32]==bytes(4)and
         q(uc,32)[0]==h[11]and q(uc,296)[0]==MASK,'actual native context header mask and altstack')
    address=GUARD if fault else pc
    want_si=struct.pack('<iiiIQ',sig,0,2,0,address)+bytes(104)
    need(si==want_si,'whole actual native siginfo and causal address')
    g=q(uc,40,23)
    err,trap=(4,14)if fault else(21,14)if kind==0 else(0,1)
    cr2=GUARD if fault else prefix['predecessor']
    need(g[16]==pc and g[18:]==(0x2b000000000033,err,trap,MASK,cr2),'all native PC selectors event and CR2 words')
    need(tuple(g[i]for i in GREG)==expected[0],'all16 native GPR values and aliases')
    undefined=expected[3]
    need(((g[17]^(expected[1]|causal))&~undefined)==0,'all defined and propagated actual flags with causal TF RF')
    extent=prefix['facts']['extent'];mask=prefix['facts']['mask']
    need(fp[:464]==legacy,'every actual seeded legacy FP byte')
    need(u(fp,464,2)==(0x46505853,extent+4)and q(fp,472)[0]==mask and u(fp,480)[0]==extent and
         fp[484:512]==bytes(28)and u(fp,extent)[0]==0x46505845,'whole standard Linux XSAVE envelope')
    need(q(fp,520)[0]==0 and fp[528:576]==bytes(48)and q(fp,512)[0]&~mask==0 and
         q(fp,512)[0]&0xe7==0xe7,'whole active standard XSAVE header')
    for reg in range(16):
        row=prefix['hardware'][5];a=row[3]+16*reg
        need(a+16<=extent and fp[a:a+16]==VECTORS[64*reg+16:64*reg+32],'every actual YMM high byte')
        row=prefix['hardware'][9];a=row[3]+32*reg
        need(a+32<=extent and fp[a:a+32]==VECTORS[64*reg+32:64*reg+64],'every actual ZMM high byte')
        row=prefix['hardware'][10];a=row[3]+64*reg
        need(a+64<=extent and fp[a:a+64]==VECTORS[64*(reg+16):64*(reg+17)],'every actual high ZMM byte')
    a=prefix['hardware'][8][3]
    need(a+64<=extent and fp[a:a+64]==MASKS,'every actual mask register byte')
    return dict(header=h,si=si,uc=uc,fp=fp,greg=g,actual_flags=g[17]&~(TF|RF),undefined=undefined)


def fixture():
    g=[(0x3141592600000000+i*0x102030405)&U64 for i in range(16)]
    g[1]=4;g[4]=RSP;g[7]=DATA;g[9]=5;g[10]=3
    return (tuple(g),0xad7,bytes(12)),bytes(1+(17*i)%255 for i in range(8192)),bytes((29*i+7)&255 for i in range(224))

def sources(endpoint):
    need(canonical(endpoint),'actual ELF-owned final capture target')
    page=bytearray(b'\xcc'*8192)
    for start,code in((512,A),(256,B)):
        page[start-5:start]=b'\xe9'+bytes(4)
        page[start:start+len(code)]=code
    page[547:555]=struct.pack('<Q',endpoint)
    return bytes(page)

def advance(g,flags,pc,base,endpoint,memory,counts):
    """Independent literal original semantics, retaining every actual AF bit."""
    g=list(g);memory=bytearray(memory);off=pc-base;undefined=0
    if off in(-5,-261):pc+=5
    elif off==29:pc=endpoint
    elif off in(0,23,-253):
        reg={0:1,23:10,-253:9}[off];g[reg],flags=arithmetic(g[reg],1,flags,sub=True);pc+=4
    elif off==4:_,flags=arithmetic(g[1],2,flags,sub=True);pc+=4
    elif off==8:
        if flags&64:pc=base-256;counts[1]+=1
        else:pc+=6
    elif off==14:
        v=g[1];flags=(flags&~0x8c5)|(int((v&255).bit_count()%2==0)<<2)|(int(v==0)<<6)|((v>>63)<<7)
        undefined=16;pc+=3
    elif off in(17,27):
        if not flags&64:pc=base+(0 if off==17 else 23);counts[0 if off==17 else 3]+=1
        else:pc+=2
    elif off in(19,-256):
        width=2 if off==19 else 8;address=g[7]+(8 if off==19 else 0);value=g[1]if off==19 else g[9]
        need(DATA<=address<=DATA+8192-width,'exact original store destination')
        memory[address-DATA:address-DATA+width]=(value&((1<<(8*width))-1)).to_bytes(width,'little')
        counts[5 if off==19 else 4]+=1;pc+=4 if off==19 else 3
    elif off==-249:g[1]=g[9];pc+=3
    elif off==-246:pc=base;counts[2]+=1
    else:raise ValueError('one literal lifecycle original instruction')
    return tuple(g),flags,pc,undefined,bytes(memory)

def prefix(data,lane,mode,placement,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX and type(lane)is int and lane in(0,1)and
         type(mode)is int and mode in(0,1)and type(placement)is int and placement in(0,1)and
         type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'typed whole lifecycle prefix')
    need(type(image)is dict and image.get('profile')=='lc_lifecycle_v1'and
         image.get('policy12_owner_verified')is False,'actual lifecycle ELF admission, no owner authority')
    layout_join(image['layout'],image['symbols'],image['sizes'],image['headers'])
    h=q(data,0,64);hardware=tuple(u(data,512+24*i,6)for i in range(67))
    seed=live(data[2120:2272]);machine=q(data,2272,8)
    source=data[2336:10528];memory=data[10528:18720];stack=data[18720:]
    page=SOURCE_PAGE[placement];base=page+512;end=image['symbols']['region_app_capture_high']
    entry=page+ENTRY[mode];predecessor=entry-5
    need(h[:14]==(MAGIC,1,PREFIX,SUFFIX,mode,int(lane==0),pid,pid,cpu,h[9],base,page,DATA,STACK)and h[9]<=0xffffffff,
         'whole lifecycle process CPU lane and placement')
    need(h[16:26]==(placement,0,image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and
         h[26]==h[28]==0,'actual lifecycle signal geometry and hardware success')
    need(h[30:]==(ENTRY[mode],224,base,page+256,end,predecessor,STEPS[mode],FRAMES,8192,8192,
         base+19,base+23,base+29,page+4096,8192,entry,U64-4,5,lane,STEPS[mode]-1,STEPS[mode]+1)+(0,)*13,
         'whole lifecycle source geometry and unused header')
    need(machine==(MASK,0,0,0x33,0x2b,0,0,0),'complete lifecycle TLS mask and selectors')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<FP,'actual bounded XCR0 geometry')
    facts,legacy=seed_join(seed_reference,hardware,h,cpu)
    want,initial,stack_pattern=fixture()
    need(seed==want and memory==initial and stack==stack_pattern,'whole literal lifecycle seed/data/stack')
    need(source==sources(end),'one whole actual source pair with disjoint B-before-A and transparent predecessors')
    return dict(header=h,lane=lane,mode=mode,placement=placement,hardware=hardware,facts=facts,seed=seed,
        machine=machine,source=source,data=memory,stack=stack,base=base,page=page,entry=entry,
        predecessor=predecessor,endpoint=end,owner_validated=False,mixed_policy_validated=False,
        qualification_credit=False,performance_credit=False)

def read(data,lane,mode,placement,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX+SUFFIX and type(exit_status)is int and exit_status==0,
         'actual whole successful lifecycle application stream')
    r=prefix(data[:PREFIX],lane,mode,placement,image,pid,cpu,seed_reference)
    _,legacy=seed_join(seed_reference,r['hardware'],r['header'],cpu)
    seed=r['seed'];s=data[PREFIX:];tail=q(s,0,32)
    before,after=live(s[256:408]),live(s[408:560]);selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(before==(seed[0],seed[1],selectors)and after[2]==selectors,'whole lifecycle entry and terminal selectors')
    need(q(s,560,8)==q(s,624,8)==r['machine'],'whole lifecycle machine bracket')
    need(s[688:2804]==s[2804:4920]==LIVE_SEED,'every actual vector/x87 bracket byte')
    need(s[4920:13112]==r['source']and s[21304:21528]==r['stack'],'whole source and stack preserved')
    need(len(PATH[mode])==STEPS[mode],'literal complete original instruction schedule')
    g,flags=seed[:2];pc=r['predecessor'];memory=r['data'];counts=[0]*6;unknown=0;undefined_events=0
    frames=[];timeline=[];count=STEPS[mode]+1 if lane==0 else 0
    for index in range(STEPS[mode]+1):
        if index:
            off=PATH[mode][index-1];need(pc==r['base']+off,'literal actual original instruction path')
            g,flags,pc,undefined,memory=advance(g,flags,pc,r['base'],r['endpoint'],memory,counts)
            if off==14:unknown=16
            elif off in(0,4,23,-253):unknown=0
        else:undefined=0
        if lane==0:
            kind=0 if index==0 else 1;causal=RF if index==0 else TF
            f=frame(s[21528+index*FRAME:21528+(index+1)*FRAME],r,kind,index,(g,flags,pc,undefined),causal,legacy)
            if frames:
                first=frames[0]
                need(f['header'][5:12]==first['header'][5:12],'same complete native physical signal-frame position')
                need(f['fp']==first['fp'],'all65536 actual native FP bytes preserved')
                want=bytearray(first['uc']);want[40:224]=f['uc'][40:224];want[304:432]=f['si']
                need(f['uc']==bytes(want),'every non-event native UC byte preserved')
            actual_data=s[FRAME_DATA+8192*index:FRAME_DATA+8192*(index+1)]
            actual_stack=s[FRAME_STACK+224*index:FRAME_STACK+224*(index+1)]
            need(actual_data==memory and actual_stack==r['stack'],'whole actual native per-frame data and stack')
            f.update(data=actual_data,stack=actual_stack)
            flags=f['actual_flags'];frames.append(f);undefined_events+=int(undefined!=0)
        timeline.append(dict(pc=pc,greg=g,flags=flags,undefined=undefined,data=memory,stack=r['stack']))
    need(pc==r['endpoint']and unknown==0 and flags==0x246 and tuple(counts)==COUNTS[mode],
         'all exact actual original loop/cut/store path postconditions and defined final flags')
    need(after==(g,flags,selectors)and s[13112:21304]==memory,'all terminal GPR/flags/data bytes')
    need(s[21528+count*FRAME:FRAME_DATA]==bytes((FRAMES-count)*FRAME)and
         s[FRAME_DATA+count*8192:FRAME_STACK]==bytes((FRAMES-count)*8192)and
         s[FRAME_STACK+count*224:]==bytes((FRAMES-count)*224),
         'all unused native frame and memory cells remain zero')
    if lane==0:
        need(undefined_events==(4,3)[mode],'exact actual TEST AF observations')
        want=(MAGIC^1,1,mode,placement,0,1,1,count,STEPS[mode],0,1,0)+COUNTS[mode]+(0,0,undefined_events,0,0,0)+(0,)*8
    else:
        need(not frames and not undefined_events,'maintained success invents no native observation')
        want=(MAGIC^1,1,mode,placement,0,1)+(0,)*18+(1,)+(0,)*7
    need(tail==want,'whole actual cleanup, lane-specific observations and reserved terminal cells')
    r.update(before=before,after=after,live=LIVE_SEED,frames=frames,suffix=tail,raw_sha256=sha(data),
        native_reference_complete=lane==0,application_complete=True,actual_fault=False,
        native_instructions=STEPS[mode]if lane==0 else 0,native_frames=count,
        model_timeline=timeline,final_data=memory)
    return r

def pair(*args,**kwargs):
    raise ValueError('schema15 actual owner lifecycle/fullstate pairing is a separate mandatory provider')
