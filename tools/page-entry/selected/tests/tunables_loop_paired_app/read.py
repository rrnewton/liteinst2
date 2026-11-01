"""Distinct paired-v2 application reference. No owner ABI or pairing authority.

The caller supplies retained compiler-M/ELF/DWARF evidence and the existing
same-CPU B2/x87 prerequisites. This module never runs a child or decoder. Every
native undefined flag bit is retained literally. Maintained output contains
no native frames; its final flags must be fully defined before exact comparison.
"""
import hashlib
import struct

PAGE,FP,UC,LIVE,FRAME=4096,65536,1024,2116,66784
PREFIX,SUFFIX,FRAMES=18944,8569880,128
MAGIC=0x32504c5032494c
DATA,STACK=0x500000000000,0x500000100000
ROW,KEY,GUARD=DATA+512,DATA+4096,DATA+8192
RSP=STACK+4096+131072-504
U64,TF,RF,MASK=(1<<64)-1,0x100,0x10000,0xffffffffbffbfae7
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
OFF=(0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,56,59,61,63,65,67,71,75,79,81,83,86)
ENTRY=(0,0,23,59,59,18,52)
STEPS=(106,25,35,13,13,1,2)
BACK=((1,1,0,1,1,1),(0,0,1,0,0,0),(0,0,0,0,1,0),*((0,)*6,)*4)
CUT=((0,1),(1,0),(0,1),(0,1),(0,1),(0,0),(0,0))
# Executed original offsets, including the actual transparent cut jump.
# This literal schedule is independent of both C's model and candidate APIs.
PATH=(OFF[:7]+OFF[:10]+OFF[:21]+OFF+OFF[:26]+OFF[16:]+(88,),
      OFF[:19]+OFF[:4]+(-124,),OFF[5:26]+OFF[16:]+(88,),
      OFF[17:]+(88,),OFF[17:]+(88,),(),(52,))
PATH=tuple((-5,)+path for path in PATH)
SOURCE_PAGE=(0x4000000,0x4000000,0x700000000000,0x700000000000)
BASE_OFFSET=(512,4022,512,4022)
TEMPLATE=bytes.fromhex(
    '4983c1014983e8804983f9250f8472ffffff418078f8004d63d175e4410fb6384084ff74db'
    '4c89cd4c89c64889d889f948c1e5070f1f40000fb61084d274c138ca75bd0fb64e01'
    '4883c6014883c00184c975e580383d75a84585db7411418b40fc85c00f841303000083f8027592'
    '49c1e207488d05470f020042837c1030030f84e9020000488b3c2431f6e8b05fffff')
VECTORS=b''.join(struct.pack('<Q',0x3141592653589793+i+1)for i in range(256))
MASKS=struct.pack('<8Q',0x0123456789abcdef,0xfedcba9876543210,0xaaaaaaaa55555555,
    0x0f0ff0f0a5a55a5a,0x1111222233334444,0x8877665544332211,0xffff00000000ffff,0x5a5a5a5aa5a5a5a5)
LIVE_SEED=VECTORS+MASKS+bytes.fromhex('7f030030')
SOURCE_FACTS={
 'tunables_loop_paired_app/main.c':(17510,'e0dd930ec9fe7d5a8c578dbe9a36f2d63b9934a55e7f1e64f5edd280dbfcbdbf'),
 'tunables_loop_paired_app/reference.c':(7517,'c3dddd0bf26fd3212695adfcb82f1956320243c761576ac8b59853b98b0dc53e'),
 'tunables_loop_paired_app/fixture.h':(2063,'37715f311bf4d7b6c6255e5495962c5bee2c364c6e353905bab6b439da18c54e'),
 'tunables_loop_paired_app/machine.S':(3608,'c991bc67d26a3687aa6a37a307f7ab89a49a930dc9f9bea3b55f30402b963ac4'),
 'tunables_loop_paired_app/loop_bytes.S':(1161,'1c1ddde263e35b0d02dd89f345aef806baafc1374dbc1603a2ecdda38290ea42'),
 'persistent_direct_frontier_app/app.h':(2003,'fe2c25a22730bed0e9aaa4e449bfdc216f8aa37bddc27c2ea9ac6bf43263b8a0'),
 'persistent_direct_frontier_app/pure.c':(2037,'414fefc072e723051c020eab0736e1cd9e383898ef0cb8a221250b3be6fc6018'),
 'persistent_direct_frontier_app/entry.S':(910,'f13b2dd061af3eadd3e709f6a0d3884700e92b81361211566f486e8f3f7c1eff')}

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
      'lp_prefix':(PREFIX,{'h':(0,512,8),'hardware':(512,1608,4),'seed':(2120,152,8),
        'machine':(2272,64,8),'source':(2336,8192,1),'data':(10528,8192,1),'stack':(18720,224,1)}),
      'lp_suffix':(SUFFIX,{'h':(0,256,8),'before':(256,152,8),'after':(408,152,8),
        'machine_before':(560,64,8),'machine_after':(624,64,8),'before_live':(688,LIVE,1),
        'after_live':(2804,LIVE,1),'source':(4920,8192,1),'data':(13112,8192,1),'stack':(21304,224,1),
        'frame':(21528,128*FRAME,8)})}
    types={name:dict(bytes=n,alignment=8,fields={k:dict(offset=a,bytes=z,alignment=l)for k,(a,z,l)in row.items()})for name,(n,row)in fields.items()}
    edges={'ua_live':{},'ua_frame':{},'lp_prefix':{'seed':'ua_live'},
        'lp_suffix':{'before':'ua_live','after':'ua_live','frame':'ua_frame'}}
    uc=dict(offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),
        widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8))
    si=dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16),widths=dict(signo=4,errno=4,code=4,addr=8))
    return types,edges,uc,si

def layout_join(layout,symbols,sizes,headers):
    need(type(layout)is dict and set(layout)=={'record','types','edges','objects','uc_bytes','uc','si'},'complete native DWARF schema')
    types,edges,uc,si=expected_layout()
    need(type(layout['record'])is str and layout['record']=='lp_paired_v2'and
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
    for name,tag,n in(('prefix','lp_prefix',PREFIX),('suffix','lp_suffix',SUFFIX)):
        d=layout['objects'][name]
        need(type(d)is dict and set(d)=={'address','bytes','alignment','tag','source'}and
             type(d['address'])is int and type(d['bytes'])is int and type(d['alignment'])is int and
             (d['address'],d['bytes'],d['alignment'],d['tag'],d['source'])==
             (symbols[name],n,8,tag,paths['tunables_loop_paired_app/main.c'])and sizes[name]==n,
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
    wanted={'prefix','suffix','loop_native_template','loop_native_template_end','lp_entry','lp_steps','lp_backwards','lp_cuts',
        'lp_source_page','lp_base_offset','lp_predecessor_offset',
        'main','lp_inputs','lp_model_init','lp_advance','copy','same','ua_data_pattern','ua_stack_pattern'}
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
    for name in('main','lp_inputs','lp_model_init','lp_advance','copy','same','ua_data_pattern','ua_stack_pattern','region_app_enter','region_app_capture_high'):
        need(kinds[name]==2 and sizes[name]>0 and memory(symbols[name],sizes[name])[0][1]==5,'whole actual executable function '+name)
    need(sizes['loop_native_template']==144 and symbols['loop_native_template_end']==symbols['loop_native_template']+144 and
         memory(symbols['loop_native_template'],144)[1]==TEMPLATE and memory(symbols['loop_native_template'],144)[0][1]==4,
         'whole original144-byte nonexecuting loader reference')
    for name,values in(('lp_entry',ENTRY),('lp_steps',STEPS),('lp_backwards',sum(BACK,())),('lp_cuts',sum(CUT,()))):
        literal=struct.pack('<'+'I'*len(values),*values)
        need(sizes[name]==len(literal)and memory(symbols[name],len(literal))[0][1]==4 and
             memory(symbols[name],len(literal))[1]==literal,'literal independent native case table '+name)
    for name,literal in(('lp_source_page',struct.pack('<4Q',*SOURCE_PAGE)),
                         ('lp_base_offset',struct.pack('<4I',*BASE_OFFSET)),
                         ('lp_predecessor_offset',struct.pack('<i',-5))):
        need(sizes[name]==len(literal)and kinds[name]==1 and
             memory(symbols[name],len(literal))[0][1]==4 and
             memory(symbols[name],len(literal))[1]==literal,
             'whole actual paired geometry table '+name)
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
        interpreter=path[:-1].decode(),template=TEMPLATE,profile='lp_paired_v2',policy12_owner_verified=False)

def fixture(mode):
    g=[0x3141592600000000+i*0x102030405 for i in range(16)];flags=0xad7
    data=bytearray(1+(17*i)%255 for i in range(8192))
    for i in range(5):
        at=512+128*i;data[at-8]=0;data[at:at+3]=b'ab\0'
    data[4096:4100]=b'ab=\0'
    g[0]=g[3]=KEY;g[4]=RSP;g[6]=ROW;g[8]=ROW-128;g[9]=30
    if mode==0:data[504]=1;data[640]=0;data[768]=ord('x');data[897]=0
    elif mode==1:data[4096]=0;g[9]=35
    elif mode==2:g[8]=ROW;g[9]=0x89abcdef80000000
    elif mode in(3,4):
        data[4097:4099]=b'=\0';data[513]=0
        g[1]=0x123456789abcde61;g[2]=0xfedcba9876543261
        if mode==3:flags^=16
    elif mode==5:g[8]=GUARD+8
    elif mode==6:g[0]=GUARD
    else:raise ValueError('exact native case')
    return (tuple(g),flags,bytes(12)),bytes(data),bytes((29*i+7)&255 for i in range(224))

def arithmetic(a,b,flags,bits=64,sub=False):
    mask=(1<<bits)-1;a&=mask;b&=mask;v=(a-b if sub else a+b)&mask
    cf=int(a<b if sub else a+b>mask)
    of=(((a^b)if sub else ~(a^b))&(a^v))>>(bits-1)&1
    f=cf|(int((v&255).bit_count()%2==0)<<2)|((a^b^v)&16)|(int(v==0)<<6)|((v>>(bits-1))<<7)|(of<<11)
    return v,(flags&~0x8d5)|f

def advance(g,flags,pc,base,endpoint,data,back,cut,entry):
    """One independently named original instruction, not a candidate decode."""
    g=list(g);off=pc-base;undefined=0
    def byte(a):
        need(DATA<=a<DATA+8192,'original read stays inside exact initialized data')
        return data[a-DATA]
    def test(v):
        v&=255
        return (flags&~0x8c5)|(int(v.bit_count()%2==0)<<2)|(int(v==0)<<6)|((v>>7)<<7)
    def branch(take,next_pc,target,slot):
        if take:back[slot]+=1
        return base+(target if take else next_pc)
    if off==-5:
        need(entry in tuple(base+x for x in ENTRY),'actual paired predecessor target')
        return tuple(g),flags,entry,0
    if off in(-124,88):return tuple(g),flags,endpoint,0
    if off==0:g[9],flags=arithmetic(g[9],1,flags);pc+=4
    elif off==4:g[8],flags=arithmetic(g[8],U64-127,flags,sub=True);pc+=4
    elif off==8:_,flags=arithmetic(g[9],37,flags,sub=True);pc+=4
    elif off==12:
        if flags&64:cut[0]+=1;pc=base-124
        else:pc+=6
    elif off==18:_,flags=arithmetic(byte(g[8]-8),0,flags,8,True);pc+=5
    elif off==23:g[10]=(g[9]&0xffffffff)|((U64^0xffffffff)if g[9]&(1<<31)else 0);pc+=3
    elif off==26:pc=branch(not flags&64,28,0,0)
    elif off==28:g[7]=byte(g[8]);pc+=4
    elif off==32:flags=test(g[7]);undefined=16;pc+=3
    elif off==35:pc=branch(bool(flags&64),37,0,1)
    elif off==37:g[5]=g[9];pc+=3
    elif off==40:g[6]=g[8];pc+=3
    elif off==43:g[0]=g[3];pc+=3
    elif off==46:g[1]=g[7]&0xffffffff;pc+=2
    elif off==48:
        old=g[5];g[5]=old<<7&U64
        flags=(flags&~0xc5)|((old>>57)&1)|(int((g[5]&255).bit_count()%2==0)<<2)|(int(g[5]==0)<<6)|((g[5]>>63)<<7)
        undefined=0x810;pc+=4
    elif off==52:pc+=4
    elif off==56:g[2]=byte(g[0]);pc+=3
    elif off==59:flags=test(g[2]);undefined=16;pc+=2
    elif off==61:pc=branch(bool(flags&64),63,0,2)
    elif off==63:_,flags=arithmetic(g[2],g[1],flags,8,True);pc+=2
    elif off==65:pc=branch(not flags&64,67,0,3)
    elif off==67:g[1]=byte(g[6]+1);pc+=4
    elif off==71:g[6],flags=arithmetic(g[6],1,flags);pc+=4
    elif off==75:g[0],flags=arithmetic(g[0],1,flags);pc+=4
    elif off==79:flags=test(g[1]);undefined=16;pc+=2
    elif off==81:pc=branch(not flags&64,83,56,4)
    elif off==83:_,flags=arithmetic(byte(g[0]),61,flags,8,True);pc+=3
    elif off==86:
        if not flags&64:pc=branch(True,88,0,5)
        else:cut[1]+=1;pc+=2
    else:raise ValueError('one exact original instruction')
    return tuple(g),flags,pc,undefined

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

def prefix(data,lane,mode,placement,image,pid,cpu,seed_reference):
    """Authenticate only an actual paired-v2 prefix, never a terminal outcome.
    A failed maintained subject needs its separate strict owner/fault gate.
    """
    need(type(data)is bytes and len(data)==PREFIX and type(lane)is int and lane in(0,1)and
         type(mode)is int and 0<=mode<7 and type(placement)is int and 0<=placement<4 and
         type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,
         'typed complete paired prefix')
    need(type(image)is dict and image.get('profile')=='lp_paired_v2'and
         image.get('policy12_owner_verified')is False,'paired-v2 ELF admission without owner credit')
    layout_join(image['layout'],image['symbols'],image['sizes'],image['headers'])
    h=q(data,0,64);hardware=tuple(u(data,512+24*i,6)for i in range(67))
    seed=live(data[2120:2272]);machine=q(data,2272,8)
    source,memory,stack=data[2336:10528],data[10528:18720],data[18720:PREFIX]
    page=SOURCE_PAGE[placement];base=page+BASE_OFFSET[placement]
    end=image['symbols']['region_app_capture_high'];entry=base+ENTRY[mode];predecessor=base-5
    need(h[:14]==(MAGIC,2,PREFIX,SUFFIX,mode,int(lane==0),pid,pid,cpu,h[9],base,page,DATA,STACK)and h[9]<=0xffffffff,
         'exact paired source process CPU lane and placement')
    need(h[16:26]==(placement,int(mode>=5),image['symbols']['region_app_seed_x87'],968,FRAME,40,224,296,16,16)and
         h[26]==h[28]==0,'actual native signal geometry and hardware query success')
    need(h[30:]==(ENTRY[mode],224,GUARD if mode>=5 else 0,1 if mode>=5 else 0,end,predecessor,STEPS[mode],FRAMES,
         8192,8192,KEY,ROW,GUARD,base-124,base+88,entry,U64-4,5,lane,STEPS[mode]-1,STEPS[mode]+1+int(mode>=5))+(0,)*13,'whole paired source header and reserved words')
    need(machine==(MASK,0,0,0x33,0x2b,0,0,0),'complete native TLS mask and selectors')
    need(h[14]&0xe7==0xe7 and h[15]==hardware[3][3]and 576<=h[15]<FP,'actual bounded XCR0 geometry')
    facts,legacy=seed_join(seed_reference,hardware,h,cpu)
    expected_seed,expected_data,expected_stack=fixture(mode)
    need(seed==expected_seed and memory==expected_data and stack==expected_stack,'whole literal native seed data and stack')
    expected_source=bytearray(b'\xcc'*8192);at=base-page;expected_source[at:at+88]=TEMPLATE[:88]
    stub=b'\xff\x25\0\0\0\0'+struct.pack('<Q',end)
    expected_source[at-124:at-110]=stub;expected_source[at+88:at+102]=stub
    expected_source[at-5:at]=b'\xe9'+struct.pack('<i',ENTRY[mode])
    need(source==bytes(expected_source),'whole actual paired source including E9 and both transparent cuts')
    r=dict(header=h,lane=lane,mode=mode,placement=placement,hardware=hardware,facts=facts,seed=seed,machine=machine,
        source=source,data=memory,stack=stack,base=base,page=page,entry=entry,predecessor=predecessor,endpoint=end)
    r.update(owner_validated=False,mixed_policy_validated=False,qualification_credit=False,performance_credit=False)
    return r


def read(data,lane,mode,placement,exit_status,image,pid,cpu,seed_reference):
    need(type(data)is bytes and len(data)==PREFIX+SUFFIX and type(lane)is int and lane in(0,1)and
         type(mode)is int and 0<=mode<7 and type(placement)is int and 0<=placement<4 and
         type(exit_status)is int and exit_status==0 and type(pid)is int and 0<pid<1<<31 and
         type(cpu)is int and cpu>=0,'typed complete paired success outcome')
    need(lane==0 or mode<5,'maintained read faults cannot become application success')
    r=prefix(data[:PREFIX],lane,mode,placement,image,pid,cpu,seed_reference)
    seed,memory,stack,source,machine=(r[k]for k in('seed','data','stack','source','machine'))
    base,entry,predecessor,end=(r[k]for k in('base','entry','predecessor','endpoint'))
    _,legacy=seed_join(seed_reference,r['hardware'],r['header'],cpu)
    s=data[PREFIX:];tail=q(s,0,32);before,after=live(s[256:408]),live(s[408:560])
    selectors=struct.pack('<6H',0x33,0x2b,0,0,0,0)
    need(before==(seed[0],seed[1],selectors)and after[2]==selectors,'whole actual entry and terminal selectors')
    need(q(s,560,8)==q(s,624,8)==machine,'whole native machine bracket')
    need(s[688:2804]==s[2804:4920]==LIVE_SEED,'whole actual native vector and x87 bracket')
    need(s[4920:13112]==source and s[13112:21304]==memory and s[21304:21528]==stack,'whole unchanged source data and stack')
    if lane==1:
        # These calculations are final-state postconditions, never observations.
        # No native frame, event ordinal or owner counter is synthesized.
        g,flags=seed[:2];pc=predecessor;back=[0]*6;cut=[0]*2;unknown=0
        need(len(PATH[mode])==STEPS[mode],'literal complete paired path population')
        for off in PATH[mode]:
            need(pc==base+off,'literal paired source path before every instruction')
            g,flags,pc,undefined=advance(g,flags,pc,base,end,memory,back,cut,entry)
            if off in(0,4,8,18,63,71,75,83):unknown=0
            elif off in(32,59,79):unknown=(unknown&~0x8c5)|16
            elif off==48:unknown=(unknown&~0xc5)|0x810
            need(undefined==(16 if off in(32,59,79)else 0x810 if off==48 else 0),
                 'paired independent undefined-flag classification')
        need(pc==end and unknown==0,'maintained final flags are fully defined by original instructions')
        need(tuple(back)==BACK[mode]and tuple(cut)==CUT[mode],'literal paired branch and cut postconditions')
        need(after==(g,flags,selectors),'whole maintained terminal GPR and literal defined flags')
        need(s[21528:]==bytes(FRAMES*FRAME),'maintained application cannot fabricate native frames')
        need(tail==(MAGIC^1,2,mode,placement,0,1)+(0,)*18+(1,)+(0,)*7,
             'complete maintained cleanup with zero observed native counters')
        r.update(before=before,after=after,live=LIVE_SEED,frames=[],suffix=tail,raw_sha256=sha(data),
            native_reference_complete=False,application_complete=True,actual_fault=False,
            native_instructions=0,native_frames=0)
        return r
    need(len(PATH[mode])==STEPS[mode],'literal complete source path population')
    count=STEPS[mode]+1+int(mode>=5);back=[0]*6;cut=[0]*2
    g,flags=seed[:2];pc=predecessor;frames=[];undefined_events=0
    for index in range(count):
        if index==0:kind,completed,undefined=0,0,0;causal=RF
        elif index<=STEPS[mode]:
            need(pc==base+PATH[mode][index-1],'literal source path before every instruction')
            g,flags,pc,undefined=advance(g,flags,pc,base,end,memory,back,cut,entry)
            kind,completed,causal=1,index,TF
        else:
            need(mode in(5,6)and pc==base+(18 if mode==5 else 56)and
                 (g[8]-8 if mode==5 else g[0])==GUARD,'actual read fault before any completed memory access')
            kind,completed,undefined,causal=2,STEPS[mode],0,TF|RF
        f=frame(s[21528+index*FRAME:21528+(index+1)*FRAME],r,kind,completed,(g,flags,pc,undefined),causal,legacy)
        if frames:
            first=frames[0]
            need(f['header'][5:12]==first['header'][5:12],'same complete native physical signal-frame position')
            need(f['fp']==first['fp'],'every byte of all65536 native FP slots preserved')
            want=bytearray(first['uc']);want[40:224]=f['uc'][40:224];want[304:432]=f['si']
            need(f['uc']==bytes(want),'every non-event native ucontext byte preserved')
        flags=f['actual_flags'];undefined_events+=int(undefined!=0);frames.append(f)
    need(s[21528+count*FRAME:]==bytes((FRAMES-count)*FRAME),'all unused native frames are literal zero')
    need(tuple(back)==BACK[mode]and tuple(cut)==CUT[mode],'all six actual backward branches and both cuts')
    need(after==(g,flags,selectors),'all terminal native GPRs and actual flags including undefined bits')
    if mode<5:need(pc==end,'genuine successful cut jump reached capture')
    else:need(pc!=end,'native fault remains a stopped instruction before explicit recovery')
    expected_tail=(MAGIC^1,2,mode,placement,0,1,1,count,STEPS[mode],int(mode>=5),1,0)+tuple(back)+tuple(cut)+(
        undefined_events,0,0,int(mode>=5))+(0,)*8
    need(tail==expected_tail,'complete native termination recovery counters cleanup and reserved words')
    r.update(before=before,after=after,live=LIVE_SEED,frames=frames,suffix=tail,raw_sha256=sha(data),
        native_reference_complete=True,application_complete=True,actual_fault=bool(mode>=5),
        native_instructions=STEPS[mode],native_frames=count,owner_validated=False,mixed_policy_validated=False,
        qualification_credit=False,performance_credit=False)
    return r

def pair(*args,**kwargs):
    raise ValueError('policy14 owner capture and mixed-policy pairing are unimplemented')
