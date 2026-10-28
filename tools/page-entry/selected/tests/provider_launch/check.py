"""Independent literal effects and complete retained carrier record checks."""
import hashlib,struct
from page_selected import need
MAIN,DATA=0x200401000,0x200403000
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
U64=(1<<64)-1
MARKER=b'LI2-PROVIDER-OK!'
ROWS=[('cpuid1',1,0,16,'0fa2'),('cpuid7',1,0,16,'0fa2')]
for prefix,kind,ext in (('rand',2,0xf0),('seed',3,0xf8)):
    for width in (16,32,64):
        for suffix,dst in (('lo',0),('hi',15)):
            b=bytes([0x66]if width==16 else [])
            rex=(8 if width==64 else 0)|(1 if dst>=8 else 0)
            if rex:b+=bytes([0x40|rex])
            b+=bytes([0x0f,0xc7,ext|(dst&7)])
            ROWS.append((prefix+str(width)+suffix,kind,width,dst,b.hex()))
ROWS += [('pidlo',4,64,0,'f30fc7f8'),('pidhi',4,64,15,'f3410fc7ff')]
ENTRY={1:'0fa2',2:'490fc7f7',3:'490fc7ff',4:'f3410fc7ff'}
SITES=('pl_time0','pl_time1','pl_write_self','pl_write_time','pl_write_output','pl_exit')

def elf(data,interpreter,variant,native_policy):
    need(type(data)is bytes and len(data)>=64 and variant in ENTRY,'actual ELF input')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(2,62,1) and h[4]==MAIN and h[8:10]==(64,56) and h[11]==64,'actual fixed high entry ELF')
    def extent(a,n):
        need(0<=a<=len(data) and 0<=n<=len(data)-a,'file extent');return data[a:a+n]
    ph=[struct.unpack('<IIQQQQQQ',extent(h[5]+56*i,56))for i in range(h[10])]
    loads=[p for p in ph if p[0]==1]
    need(len(loads)==3 and [p[1]for p in loads]==[4,5,6] and loads[0][2:4]==(0,MAIN-4096) and
         loads[0][5]<=4096 and loads[1][2:4]==(4096,MAIN) and loads[1][5:7]==(8192,8192) and
         loads[2][2:4]==(12288,DATA) and loads[2][5]>=16384 and
         all(p[7]==4096 and p[5]<=p[6]for p in loads) and not any(p[0]==7 for p in ph),'three actual nonoverlapping load domains/no TLS')
    ip=[p for p in ph if p[0]==3]
    need(len(ip)==1 and extent(ip[0][2],ip[0][5])==str(interpreter).encode()+b'\0','actual custom interpreter')
    ss=[struct.unpack('<IIQQQQIIQQ',extent(h[6]+64*i,64))for i in range(h[12])]
    need(not any(s[1]in(4,9) and s[5]for s in ss),'no instruction fixups or relocations')
    tables=[s for s in ss if s[1]==2];need(len(tables)==1 and tables[0][9]==24,'one actual symbol table')
    t=tables[0];strings=ss[t[6]];names=extent(strings[4],strings[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,index,value,size=struct.unpack('<IBBHQQ',extent(at,24))
        if n:
            name=names[n:names.index(b'\0',n)].decode()
            need(name not in symbols,'unique actual symbol');symbols[name]=value
    def read(a,n):
        out=bytearray()
        while n:
            p=next((p for p in loads if p[3]<=a<p[3]+p[5]),None);need(p is not None,'mapped retained bytes')
            k=min(n,p[3]+p[5]-a);out+=extent(p[2]+a-p[3],k);a+=k;n-=k
        return bytes(out)
    need(symbols['_start']==MAIN and read(MAIN,len(bytes.fromhex(ENTRY[variant])))==bytes.fromhex(ENTRY[variant]),'literal actual first-main instruction')
    rows=[dict(name='entry',kind=variant,width=0 if variant==1 else 64,destination=16 if variant==1 else 15,pc=MAIN,encoding=ENTRY[variant])]
    for name,kind,width,dst,encoding in ROWS:
        pc=symbols['site_'+name];b=bytes.fromhex(encoding)
        need(MAIN<pc<MAIN+4096-len(b) and read(pc,len(b))==b,'each actual selected encoding '+name)
        rows.append(dict(name=name,kind=kind,width=width,destination=dst,pc=pc,encoding=encoding))
    sites=[symbols[n]for n in SITES]
    need(len(set(sites))==6 and all(MAIN<=p<=MAIN+4096-5 for p in sites),'six distinct same-page sources')
    for i,p in enumerate(sites):need(read(p,5)==bytes.fromhex('0f31'if i<2 else'0f05')+b'\x90'*3,'actual original publication bytes')
    need(symbols['pl_seed']==MAIN+4096 and MAIN+4096<symbols['pl_capture']<DATA and
         native_policy(read(MAIN+4096-14,4096+28))==0 and native_policy(read(MAIN,4096))!=0,'actual clean native helper and dirty selected page')
    expected={'pl_data':DATA,'pl_data_end':DATA+16384,'pl_output':DATA+128,'pl_vectors':DATA+512,
              'pl_masks':DATA+2560,'pl_live_vectors':DATA+4096,'pl_live_masks':DATA+6144,
              'pl_live_gpr':DATA+6208,'pl_live_flags':DATA+6336,'pl_live_selectors':DATA+6344,'pl_stack_top':DATA+16320}
    need(all(symbols[k]==v for k,v in expected.items()),'actual named data/capture/stack geometry')
    vectors=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
    masks=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
    need(read(DATA+512,2112)==vectors+masks and read(DATA+128,48)==MARKER+bytes(32),'independent full seed and stdout literals')
    interp=interpreter.read_bytes();ih=struct.unpack_from('<16sHHIQQQIHHHHHH',interp)
    entry_code=bytes.fromhex('0fa248b8')+struct.pack('<Q',MAIN)+bytes.fromhex('ffe0')
    need(len(interp)==8192 and ih[1:4]==(3,62,1) and ih[4]==4096 and interp[4096:4096+len(entry_code)]==entry_code and
         not any(interp[4096+len(entry_code):]),'actual first-interpreter selected CPUID then literal main handoff')
    return dict(entry=MAIN,variant=variant,rows=rows,sites=sites,interpreter_source_hex=interp[4096:].hex(),source_sha256=hashlib.sha256(read(MAIN,8192)).hexdigest(),
                source_hex=read(MAIN,8192).hex(),data_sha256=hashlib.sha256(read(DATA,16384)).hexdigest(),symbols=expected)

def output(data):
    need(len(data)==58 and data[:10]==bytes.fromhex('0f059090900f31909090') and data[10:26]==MARKER,'actual kernel reads restored source and stable marker')
    clocks=struct.unpack_from('<4Q',data,26)
    need(all(x<1<<32 for x in clocks) and (clocks[0]|clocks[1]) and (clocks[2]|clocks[3]),'actual zero-extended RDTSC words')
    need((clocks[1]<<32|clocks[0])<(clocks[3]<<32|clocks[2]),'two genuine sequential time observations; no tolerance or performance threshold')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),clock_words=list(clocks))

def check(data,layout,image):
    types=layout['types'];rt,st=types['pl_record'],types['pl_sample'];ucn=layout['uc_bytes'];go=layout['offsets']['greg'];fo=layout['offsets']['fp_pointer']
    need(len(data)==rt['bytes']<16<<20 and 0<ucn<=2048 and go+23*8<=ucn and fo+8<=ucn,'actual DWARF record and UC bounds')
    def field(b,t,n):
        f=t['fields'][n];out=b[f['offset']:f['offset']+f['bytes']];need(len(out)==f['bytes'],'actual complete field '+n);return out
    def q(b):need(len(b)%8==0,'qword extent');return struct.unpack('<'+'Q'*(len(b)//8),b)
    def word(b,at):return struct.unpack_from('<Q',b,at)[0]
    def shape(t):
        spans=sorted((f['offset'],f['offset']+f['bytes'])for f in t['fields'].values())
        need(spans[0][0]==0 and spans[-1][1]==t['bytes'] and all(a[1]==b[0]for a,b in zip(spans,spans[1:])),'whole serialized structure/no omitted padding')
    shape(rt);shape(st)
    h=q(field(data,rt,'h'))
    need(h[:6]==(0x314e55414c565250,1,len(data),ucn,st['bytes'],1) and h[6:12]==(0,0,0,18,0,6) and h[12:14]==(18,0) and h[18]==1 and h[19]==0 and h[21]==h[22]+4096 and h[22]>0 and h[22]%4096==0 and not any(h[23:]) and h[20]&0xe7==0xe7,'actual successful complete observation prefix/XCR0')
    hw=struct.unpack('<14I',field(data,rt,'hardware'));need(hw[:2]==(1,0) and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and hw[11]&0x40010000==0x40010000,'actual pre-arm AVX/OSXSAVE/AVX512F/BW hardware')
    xs=q(field(data,rt,'xstate'));components={}
    for i,(bit,size)in enumerate(((2,256),(5,64),(6,512),(7,1024))):
        row=xs[i*4:(i+1)*4]
        need(row[0]==bit and row[2]==size and row[1]>=576 and row[1]+size<=65532 and row[3]&1==0,'actual user standard XSAVE component')
        components[bit]=(row[1],size)
    ranges=sorted((o,o+n)for o,n in components.values());need(all(a[1]<=b[0]for a,b in zip(ranges,ranges[1:])),'disjoint actual standard XSAVE components')
    samples=field(data,rt,'samples');need(len(samples)==18*st['bytes'],'all eighteen complete selected samples')
    original=bytes.fromhex(image['source_hex']);interp=bytes.fromhex(image['interpreter_source_hex']);counts=[0]*4;previous=None;entry_post=None;sizes=[]
    vector_seed=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
    mask_seed=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
    def live(b,post,flags):
        need(b[4096:6208]==vector_seed+mask_seed,'actual live all32 ZMM/all8 K after sigreturn')
        need(q(b[6208:6336])==tuple(word(post,go+8*s)for s in GREG) and word(b,6336)==flags,'actual live all GPR and DF/full logical flags')
        packed=word(post,go+18*8)
        selectors=struct.unpack_from('<6H',b,6344)
        need(selectors[0]==packed&0xffff and selectors[1]==packed>>48 and selectors[4]==(packed>>32)&0xffff and selectors[5]==(packed>>16)&0xffff,'live CS/SS/FS/GS match actual kernel frame')
        need(selectors[2:4]==(0,0),'actual flat DS/ES selectors')
    specs=[dict(name='interpreter-entry',kind=1,width=0,destination=16,pc=h[21],encoding='0fa2')]+image['rows']
    for i,spec in enumerate(specs):
        s=samples[i*st['bytes']:(i+1)*st['bytes']];v=q(field(s,st,'h'));ub=field(s,st,'before_uc');ua=field(s,st,'after_uc')
        fb,fa=field(s,st,'before_fp'),field(s,st,'after_fp');db,da=field(s,st,'before_data'),field(s,st,'after_data')
        kind,width,dst=spec['kind'],spec['width'],spec['destination'];pc=spec['pc'];length=len(bytes.fromhex(spec['encoding']))
        code=1948 if kind==1 else 2207 if kind==4 else ({16:2199,32:2200,64:2201}[width]+(4 if kind==3 else 0))
        need(v[:8]==(2,i,pc,pc+length,kind,width,dst,code) and v[8:15]==(length,11,11,2,0,pc,word(ub,go+17*8)&~0x10000),'genuine original-PC NX metadata and typed instruction')
        need(v[15]==i and v[18:24]==(1,i+1,0,1,1,1) and v[24]==0 and not any(v[52:]),'one entered/returned/committed callback; clean retained tails')
        need(512<=v[16]==v[17]<=65536 and fb==fa and not any(fb[v[16]:]) and word(ub,fo)==word(ua,fo)!=0,'complete actual kernel FP, unchanged pointer and zero unused extent')
        if v[16]>512:need(struct.unpack_from('<I',fb,464)[0]==0x46505853 and struct.unpack_from('<I',fb,468)[0]==v[16] and struct.unpack_from('<I',fb,v[16]-4)[0]==0x46505845,'actual kernel XSAVE extent markers')
        need(ub[ucn:]==ua[ucn:]==bytes(2048-ucn) and word(ub,go+16*8)==pc and word(ub,go+20*8)==14 and word(ub,go+19*8)==21,'complete real UC, #PF and error')
        need(field(s,st,'before_source')==field(s,st,'after_source')==original and
             field(s,st,'before_interpreter')==field(s,st,'after_interpreter')==interp and db==da,
             'whole main/interpreter source and fixture memory/stack unchanged by provider')
        before=[word(ub,go+8*x)for x in GREG];flags=v[14]
        if i==1:
            inherited=[word(entry_post,go+8*x)for x in GREG];inherited[0]=MAIN
            need(before==inherited and flags==word(entry_post,go+17*8),'actual interpreter result through MOV/JMP to first main instruction')
        if i>=2:
            expected=[0x1122334455667700+j for j in range(16)];expected[4]=DATA+16320
            if i in(2,3):expected[0]=0xa501020300000000+(1 if i==2 else 7);expected[1]=0xb608090a00000000
            need(before==expected and flags==0xed7,'actual independently seeded all GPRs and DF=1')
            need(db[512:2624]==vector_seed+mask_seed,'immutable full initialized vector seeds')
            need(word(fb,512)&0xe7==0xe7 and word(fb,520)==0 and all(o+n<=v[16]-4 for o,n in components.values()),'all seeded kernel components active in actual standard layout')
            for reg in range(32):
                if reg<16:
                    z=fb[160+reg*16:176+reg*16]
                    off=components[2][0]+reg*16;z+=fb[off:off+16]
                    off=components[6][0]+reg*32;z+=fb[off:off+32]
                else:
                    off=components[7][0]+(reg-16)*64;z=fb[off:off+64]
                need(z==vector_seed[reg*64:(reg+1)*64],'actual full seeded kernel ZMM '+str(reg))
            off,size=components[5];need(fb[off:off+size]==mask_seed,'actual full seeded kernel K state')
        if previous is not None:live(db,*previous)
        wanted=bytearray(ub);resultflags=flags
        if kind==1:
            need(v[25:30]==(0,0,0,0,0) and v[30:32]==(before[0]&0xffffffff,before[1]&0xffffffff) and v[40:44]==(1,7,0,0) and v[32:36]==v[44:48],'actual CPUID sample and successful gate rearm before policy')
            expected=list(v[32:36]);need(all(x<1<<32 for x in expected),'actual CPUID u32 sample')
            if v[30]==1:expected[2]&=~(1<<30)
            if v[30:32]==(7,0):expected[1]&=~(1<<18);expected[2]&=~(1<<22)
            need(tuple(expected)==v[36:40],'only three named CPUID bits changed')
            for reg,value in zip((0,3,1,2),expected):struct.pack_into('<Q',wanted,go+8*GREG[reg],value)
        else:
            value=0xc00dcafe if kind==4 else ({16:0xbeef,32:0xface9876,64:0xfedcba9876543210}[width]if kind==2 else 0)
            carry=int(kind==2);value_out=(before[dst]&~0xffff)|value if width==16 else value
            resultflags=flags if kind==4 else (flags&~0x8d5)|carry
            need(v[25:30]==(0,4,0,0,2) and v[30:43]==(1,kind,width,dst,pc,pc+length,flags,before[dst],kind,width,carry,0,value),'actual validated scalar callback input and literal named result')
            need(v[43:47]==(before[dst],value_out,value,resultflags) and v[47]==0,'old commit output and no extra callback payload')
            struct.pack_into('<Q',wanted,go+8*GREG[dst],value_out)
        struct.pack_into('<Q',wanted,go+16*8,pc+length);struct.pack_into('<Q',wanted,go+17*8,resultflags)
        need(bytes(wanted)==ua,'entire actual ucontext exact architectural write set')
        counts[kind-1]+=1;need(tuple(counts)==v[48:52],'each committed kind count')
        if i==0:entry_post=ua
        previous=(ua,resultflags)if i>=2 else None;sizes.append(v[16])
    terminal=field(data,rt,'terminal_data');live(terminal,*previous)
    need(field(data,rt,'terminal_source')==original and tuple(counts)==h[14:18],'all original bytes restored and final configured counts')
    owners=q(field(data,rt,'owners'));need(len(owners)==6*32,'all six owner rows')
    for i,pc in enumerate(image['sites']):
        o=owners[i*32:(i+1)*32];kind=2 if i<2 else 1
        literal=bytes.fromhex('0f31'if i<2 else'0f05')+b'\x90'*3
        need(o[:7]==(8 if i<5 else 7,1,1,0,pc,pc+2,kind) and o[7]>0 and o[8:14]==(31,31,31,31,1,int(i<5)) and
             o[14]==o[15]==int.from_bytes(literal,'little') and not any(o[16:]),'real complete restore before effect; nonreturning exit remains RESTORED')
    return dict(selected_effects=18,first_interpreter_kind=1,first_main_kind=image['variant'],cpuid=counts[0],rdrand=counts[1],rdseed=counts[2],rdpid=counts[3],
                full_kernel_fp_bytes=sizes,seeded_live_captures=16,source_bytes=8192,interpreter_source_bytes=4096,memory_stack_bytes=16384,
                published=6,restored=6,effect_started=6,effect_returned=5,completed=5,exit_phase=7)
