"""Literal CPUID effects, genuine frames and whole retained before/after state."""
import hashlib,json,struct
from pathlib import Path
from page_selected import need
MAIN,DATA=0x200401000,0x200420000
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
VECTOR=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
MASK=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
Q=lambda b:struct.unpack('<'+'Q'*(len(b)//8),b)
W=lambda b,o:struct.unpack_from('<Q',b,o)[0]

def image(data,interpreter,program,native_policy):
    need(type(data)is bytes and program in range(1,9),'literal CPUID fixture input')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[4]==MAIN and h[8:10]==(64,56)and h[11]==64,'actual high fixed entry ELF')
    def extent(a,n):
        need(0<=a<=len(data)and 0<=n<=len(data)-a,'whole actual file extent');return data[a:a+n]
    ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])];loads=[p for p in ph if p[0]==1]
    need(len(loads)==3 and [p[1]for p in loads]==[4,5,6]and loads[0][2:4]==(0,MAIN-4096)and loads[0][5]<=4096 and
         loads[1][2:4]==(4096,MAIN)and loads[1][5:7]==(65536,65536)and loads[2][3]==DATA and loads[2][5]>=32768 and
         all(p[7]==4096 and p[5]<=p[6]for p in loads)and not any(p[0]==7 for p in ph),'exact nonoverlapping RX source/RW data; no TLS')
    ip=[p for p in ph if p[0]==3]
    need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual lexical custom interpreter')
    ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])]
    need(not any(s[1]in(4,9)and s[5]for s in ss),'no runtime relocations')
    tables=[s for s in ss if s[1]==2];need(len(tables)==1 and tables[0][9]==24,'actual symbol table')
    t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
        if n:
            name=names[n:names.index(b'\0',n)].decode();need(name not in symbols,'unique actual named symbol');symbols[name]=value
    def read(a,n):
        p=next((p for p in loads if p[3]<=a and a+n<=p[3]+p[5]),None)
        need(p is not None,'actual mapped file extent');return extent(p[2]+a-p[3],n)
    def address(name):
        words=name.split('+');return symbols[words[0]]+(int(words[1])if len(words)==2 else 0)
    cases=json.loads(Path(__file__).with_name('CASES.json').read_bytes())['programs']
    case=cases[program-1]if program<=6 else dict(id=program,name='app-control',slots=['nx_plain0'],cpuid=['nx_plain0'])
    pcs=[address(n)for n in case['cpuid']]
    need(read(MAIN,2)==b'\x0f\xa2'and all(read(pc,2)==b'\x0f\xa2'for pc in pcs),'literal entry and every intended CPUID')
    need(symbols['nx_ending']%4096==4094 and symbols['nx_split']%4096==4095 and
         symbols['nx_boundary_call']%4096==4091 and symbols['nx_boundary_return']==symbols['nx_boundary_call']+5 and
         read(symbols['nx_boundary_call'],1)==b'\xe8'and symbols['nx_boundary_call']+5+struct.unpack('<i',read(symbols['nx_boundary_call']+1,4))[0]==symbols['nx_boundary_target'],
         'both fetch tails and real original CALL target/return')
    need(symbols['nx_straddler']%4096==4093 and symbols['nx_straddler_end']==symbols['nx_straddler']+10 and
         read(symbols['nx_straddler'],10)==bytes.fromhex('49bc8877665544332211')and
         symbols['nx_straddler_cpuid']==symbols['nx_straddler_end']+9 and read(symbols['nx_straddler_end'],9)==b'\x90'*9,
         'real 3+7 MOVABS split and selected guard beyond native halo')
    for key in ('nx_embedded_direct','nx_embedded_indirect','nx_embedded_ret'):
        a=symbols[key];b=read(a,10)
        need(b[:5]==bytes.fromhex('48b80fa2e9')and b[9]==0x90 and a+9+struct.unpack('<i',b[5:9])[0]==symbols['pl_capture'],'real embedded selected stream and enclosing MOVABS')
    for n in (0,1):
        need(read(symbols['nx_trace'+str(n)],4)==bytes.fromhex('4983c201')and symbols['nx_trace_cpuid'+str(n)]==symbols['nx_trace'+str(n)]+4,'literal real ADD predecessor')
        need(read(symbols['nx_run'+str(n)],6)==bytes.fromhex('4d89d34d89dc')and symbols['nx_run_cpuid'+str(n)]==symbols['nx_run'+str(n)]+6,'two real copyable MOVs and complete guard')
    need(symbols['pl_seed']==MAIN+4096 and native_policy(read(MAIN+4096-14,4096+28))==0,'whole actual seed/capture page plus halos is admissible')
    if program==4:
        for name in ('nx_boundary_call','nx_straddler'):
            a=symbols[name]&~4095;need(native_policy(read(a-14,4096+28))==0,'whole real native predecessor page '+name)
    need(symbols['pl_data']==DATA and symbols['pl_data_end']==DATA+32768 and symbols['pl_stack_top']==DATA+32704 and
         symbols['nx_output']==DATA+7680 and read(DATA+512,2112)==VECTOR+MASK,'literal complete data/stack/seed geometry')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    first=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp)==8192 and ih[1:4]==(3,62,1)and ih[4]==4096 and interp[4096:4096+len(first)]==first and not any(interp[4096+len(first):]),'genuine first interpreter CPUID followed by literal main handoff')
    return dict(program=program,case=case,pcs=pcs,slots=[address(n)for n in case['slots']],symbols=symbols,
        source=read(MAIN,65536).hex(),initial_data=read(DATA,32768).hex(),interpreter=interp[4096:].hex(),
        enclosing_value=int.from_bytes(read(symbols['nx_embedded_direct']+2,8),'little'))

def seeded(image,slot):
    g=[0x1122334455667700+i for i in range(16)];g[4]=DATA+32704
    g[0]=0xa501020300000000+(1 if slot%2==0 else 7);g[1]=0xb608090a00000000;flags=0xed7
    p=image['program']
    if p==3 and slot==2:g[4]+=8
    if p==4 and slot==0:g[4]-=8
    if p==4 and slot==1:g[12]=0x1122334455667788
    if p==5:g[10]+=1;flags&=~0x8d5
    if p==6:g[11]=g[12]=g[10]
    return g,flags

def output(data,image):
    need(len(data)==9728 and Q(data[:16])==(0x3154554f584e5043,image['program'])and data[16:512]==bytes(496),'complete source-produced native/gated output header')
    count=len(image['slots']);slots=[data[512+i*2304:512+(i+1)*2304]for i in range(4)]
    for i,b in enumerate(slots):
        if i>=count:need(b==bytes(2304),'unexecuted live slots stay exactly zero');continue
        need(b[:2112]==VECTOR+MASK and b[2260:]==bytes(44),'live all32 ZMM/all8K and all reserved bytes')
        g,flags=seeded(image,i)
        if image['program']==4 and i==0:g[4]+=8 # actual RET, after CPUID snapshot
        actual=Q(b[2112:2240]);selectors=struct.unpack('<6H',b[2248:2260])
        if image['program']==3 and i==3:g[0]=image['enclosing_value'];writes=set()
        else:writes={0,1,2,3};need(all(actual[j]<1<<32 for j in writes),'native zero-extended CPUID outputs')
        need(all(actual[j]==g[j]for j in range(16)if j not in writes)and W(b,2240)==flags and selectors==(0x33,0x2b,0,0,0,0),'live nonoutputs/DF/fullflags/selectors exact')
    return slots

def compare_lanes(native,gated,image,configured):
    a,b=output(native,image),output(gated,image)
    expected=bytearray(native)
    if configured:
        for i in range(len(image['case']['cpuid'])):
            leaf=1 if i%2==0 else 7;start=512+i*2304+2112
            if leaf==1:struct.pack_into('<Q',expected,start+8,W(expected,start+8)&~(1<<30))
            else:
                struct.pack_into('<Q',expected,start+24,W(expected,start+24)&~(1<<18))
                struct.pack_into('<Q',expected,start+8,W(expected,start+8)&~(1<<22))
    need(bytes(expected)==gated,'whole native/live output exact except the three named configured CPUID bits')
    return dict(live_captures=len(image['slots']),output_bytes=len(gated),sha256=hashlib.sha256(gated).hexdigest())

def early(data,layout,code,configured):
    """The old gate refusal must contain no target sample or terminal copy."""
    rt,st=layout['types']['nx_record'],layout['types']['nx_sample']
    need(code in (236,238)and len(data)==rt['bytes']<16<<20,'complete actual early-failure record')
    h=Q(data[:512])
    need(h[:6]==(0x3151454449555043,1,len(data),layout['uc_bytes'],st['bytes'],1)and
         h[6:20]==(125,code,0,0,0,0,0,0,0,0,0,0,0,0)and h[20]&0xe7==0xe7 and
         h[21]==h[22]+4096 and h[22]>0 and h[22]%4096==0 and h[23:25]==(0,int(configured))and not any(h[25:]),
         'initialized hardware profile with exact failed prefix and no target entry')
    for name in ('samples','terminal_data','terminal_source'):
        f=rt['fields'][name];b=data[f['offset']:f['offset']+f['bytes']]
        need(len(b)==f['bytes']and not any(b),'whole untouched early-failure '+name)
    return dict(status='failed',failure_code=code,target_entered=False,record_bytes=len(data))

def check(data,layout,image,nx,configured,stdout,expected_status=0,expected_code=0,expected_detail=0):
    types=layout['types'];rt,st=types['nx_record'],types['nx_sample'];ucn=layout['uc_bytes'];go=layout['offsets']['greg'];fo=layout['offsets']['fp_pointer']
    need(len(data)==rt['bytes']<16<<20 and 0<ucn<=2048 and go+23*8<=ucn and fo+8<=ucn,'actual complete DWARF/UC extents')
    def field(b,t,n):
        f=t['fields'][n];v=b[f['offset']:f['offset']+f['bytes']];need(len(v)==f['bytes'],'whole actual '+n);return v
    for t in (rt,st):
        spans=sorted((f['offset'],f['offset']+f['bytes'])for f in t['fields'].values())
        need(spans[0][0]==0 and spans[-1][1]==t['bytes']and all(a[1]==b[0]for a,b in zip(spans,spans[1:])),'whole record/no omitted padding')
    h=Q(field(data,rt,'h'));count=2+len(image['pcs'])
    need(h[:6]==(0x3151454449555043,1,len(data),ucn,st['bytes'],1)and h[6:11]==(expected_status,expected_code,expected_detail,count,0)and
         h[11:18]==(0,count,0,0,0,0,0)and h[18:20]==(1,0)and h[21]==h[22]+4096 and h[22]>0 and h[22]%4096==0 and
         h[23:25]==(int(nx),int(configured))and not any(h[25:])and h[20]&0xe7==0xe7,'actual complete profile/observation prefix')
    hw=struct.unpack('<14I',field(data,rt,'hardware'));need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual prearm hardware capability')
    xs=Q(field(data,rt,'xstate'));components={}
    for i,(bit,size)in enumerate(((2,256),(5,64),(6,512),(7,1024))):
        row=xs[4*i:4*i+4];need(row[0]==bit and row[2]==size and row[1]>=576 and row[1]+size<=65532 and row[3]&1==0,'actual standard user XSAVE component');components[bit]=(row[1],size)
    spans=sorted((o,o+n)for o,n in components.values());need(all(a[1]<=b[0]for a,b in zip(spans,spans[1:])),'disjoint actual XSAVE components')
    samples=field(data,rt,'samples');need(len(samples)==6*st['bytes']and not any(samples[count*st['bytes']:]),'all actual rows and exact unused tail')
    source=bytes.fromhex(image['source']);interp=bytes.fromhex(image['interpreter']);pcs=[h[21],MAIN]+image['pcs'];post=[];sizes=[]
    for i,pc in enumerate(pcs):
        s=samples[i*st['bytes']:(i+1)*st['bytes']];v=Q(field(s,st,'h'));ub,ua=field(s,st,'before_uc'),field(s,st,'after_uc');fb,fa=field(s,st,'before_fp'),field(s,st,'after_fp');db,da=field(s,st,'before_data'),field(s,st,'after_data')
        need(v[:13]==(2,i,pc,pc+2,1,0,16,1948,2,11,11,2,0)and pc<=v[13]<pc+2 and v[14]==W(ub,go+17*8)&~0x10000 and v[15]==i and v[18:20]==(1,i+1),'genuine original-PC #PF CPUID input/counts')
        need(512<=v[16]==v[17]<=65536 and fb==fa and not any(fb[v[16]:])and W(ub,fo)==W(ua,fo)!=0,'complete unchanged actual kernel FP and pointer')
        if v[16]>512:need(struct.unpack_from('<I',fb,464)[0]==0x46505853 and struct.unpack_from('<I',fb,468)[0]==v[16]and struct.unpack_from('<I',fb,v[16]-4)[0]==0x46505845,'kernel FP extent markers')
        need(ub[ucn:]==ua[ucn:]==bytes(2048-ucn)and W(ub,go+16*8)==pc and W(ub,go+20*8)==14 and W(ub,go+19*8)==21,'complete actual kernel UC/trap/error')
        need(field(s,st,'before_source')==field(s,st,'after_source')==source and field(s,st,'before_interpreter')==field(s,st,'after_interpreter')==interp and db==da,'whole source/interpreter/data/stack equality')
        before=[W(ub,go+8*j)for j in GREG];flags=v[14]
        need(v[30:32]==(before[0]&0xffffffff,before[1]&0xffffffff)and all(x<1<<32 for x in v[32:40]),'actual low input and u32 sample/results')
        if i==1:
            prior=[W(post[0],go+8*j)for j in GREG];prior[0]=MAIN
            need(before==prior and flags==W(post[0],go+17*8),'genuine inherited interpreter-to-main state')
        if i>=2:
            expected,ef=seeded(image,i-2);need(before==expected and flags==ef,'literal actual seeded GPR/flags predecessor effects')
            need(db[512:2624]==VECTOR+MASK and W(fb,512)&0xe7==0xe7 and W(fb,520)==0 and all(o+n<=v[16]-4 for o,n in components.values()),'active complete seeded XSAVE layout')
            for reg in range(32):
                if reg<16:
                    off=components[2][0]+reg*16;off2=components[6][0]+reg*32
                    value=fb[160+reg*16:176+reg*16]+fb[off:off+16]+fb[off2:off2+32]
                else:off=components[7][0]+(reg-16)*64;value=fb[off:off+64]
                need(value==VECTOR[reg*64:(reg+1)*64],'entire actual before ZMM '+str(reg))
            off,n=components[5];need(fb[off:off+n]==MASK,'all actual before K registers')
        if nx:
            need(v[25:29]==(3,i+1,i+1,i+1)and v[40:44]==(1,0,0,0)and v[44:48]==v[32:36]and v[68:72]==(pc,pc+2,*v[30:32])and v[72:76]==v[36:40],'real NX attempted/sample/commit and raw tuple; no fabricated enable/rearm')
        else:need(v[25:29]==(0,0,0,0)and v[40:44]==(1,7,0,0)and v[32:36]==v[44:48]and not any(v[68:76]),'unchanged actual faulted sample/rearm/commit')
        need(v[29]==0 and v[50:52]==(0,0)and not any(v[76:]),'all reserved observation words zero')
        result=list(v[32:36])
        if configured:
            need(v[20:25]==(0,1,1,1,0)and v[48:50]==(i+1,i+1),'actual scalar callback returned and committed once')
            if v[30]==1:result[2]&=~(1<<30)
            if v[30:32]==(7,0):result[1]&=~(1<<18);result[2]&=~(1<<22)
        else:need(v[20:25]==(0,0,0,0,0)and v[48:50]==(0,0),'raw lane has no callback claim')
        need(tuple(result)==v[36:40],'only exact configured mask or native tuple')
        wanted=bytearray(ub)
        for reg,value in zip((0,3,1,2),result):struct.pack_into('<Q',wanted,go+8*GREG[reg],value)
        struct.pack_into('<Q',wanted,go+16*8,pc+2);struct.pack_into('<Q',wanted,go+17*8,flags)
        need(bytes(wanted)==ua,'whole genuine ucontext exact CPUID architectural write set')
        need(v[52]==(2 if pc%4096==4095 else 1),'actual complete split/single-page source borrow')
        if i>=2 and image['program']==4 and i==2:
            need(W(db,32704-8)==image['symbols']['nx_boundary_return'],'actual original boundary CALL return word')
        if i>=2 and image['program']==4 and i==3:need(v[66]>=1,'actual native straddler retry retained')
        if i>=2 and image['program']==5:
            need(v[53]>0 and v[55:60]==(pc-4,5,1,1,pc),'genuine completed/released TRACE predecessor before CPUID')
        if i>=2 and image['program']==6:
            need(v[60]>0 and v[61:66]==(7,pc-6,pc,2,1),'genuine two-MOV copied run completed before original guard')
        post.append(ua);sizes.append(v[16])
    terminal=field(data,rt,'terminal_data');need(field(data,rt,'terminal_source')==source,'all source bytes remain original at terminal')
    if expected_status==0:
        slots=output(stdout,image);need(terminal[7680:7680+9728]==stdout,'actual output equals complete retained live memory')
        for i in range(len(image['pcs'])):
            live=slots[i];expected=[W(post[i+2],go+8*j)for j in GREG]
            if image['program']==4 and i==0:expected[4]+=8
            need(Q(live[2112:2240])==tuple(expected)and W(live,2240)==W(post[i+2],go+17*8),'live sigreturn and real intervening RET preserve actual committed GPR/flags')
    else:need(stdout==b''and W(terminal,7680+16)==0,'denied application operation did not reach following write')
    return dict(cpuid=count,seeded=len(image['pcs']),live=len(image['slots'])if expected_status==0 else 0,full_kernel_fp_bytes=sizes,
                source_bytes=65536,data_stack_bytes=32768,nx=nx,configured=configured,source_patches=0)
