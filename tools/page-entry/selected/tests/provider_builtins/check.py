"""Actual-frame builtin qualification; no native random or fabricated NX reference."""
import hashlib,importlib.util,struct
from pathlib import Path
from page_selected import need
_spec=importlib.util.spec_from_file_location('li2_builtin_effects',Path(__file__).with_name('effects.py'))
effects=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(effects)
U64=(1<<64)-1;MAIN=0x200401000;DATA=0x200403000
GREG=effects.GREG;MARKER=b'LI2-BUILTINS-OK!'
TARGET=(99,0,7,0,0,3,10,3,5,11,10,10,3)
ERROR=(0,1612,1612,1612,218,1615,1615,1615,1615,1615,1615,1561,240)
KINDS=(5,5,6,7,7,7,7,5,6,5,7,7,7,7,7,7)
NUMBERS=(0,0,0,39,186,1,1,0,0,0,39,186,1,1,1,231)
OWNER_ROWS=(7,9,10,11,12,13,14,15)
MASK=U64
for _sig in (11,5,31,4,9,19):MASK&=~(1<<(_sig-1))


def output(data,negative=0):
    need(type(data)is bytes and type(negative)is int and 0<=negative<=12,'literal output arguments')
    wanted=(MARKER+bytes.fromhex('0f059090900f31909090')+MARKER)if not negative else(MARKER if TARGET[negative]>5 else b'')
    need(data==wanted,'exact actual kernel stdout and original source bytes; no clock normalization')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def check(data,layout,image,configured=True,negative=0,pid=None):
    need(type(configured)is bool and type(negative)is int and 0<=negative<=12 and
         (configured or negative==0) and type(pid)is int and pid>0,'actual policy/finite negative/process identity')
    need(image['negative']==negative and image['variant']in(1,2),'actual emitted selector/entry variant')
    types=layout['types'];rt,st,bt=(types[x]for x in('pb_record','pb_sample','pb_state'))
    ucn=layout['uc_bytes'];go=layout['offsets']['greg'];fo=layout['offsets']['fp_pointer'];mo=layout['offsets']['mask']
    need(type(data)is bytes and len(data)==rt['bytes']<16<<20 and 0<ucn<=2048 and
         0<=go<=ucn-23*8 and 0<=fo<=ucn-8 and 0<=mo<=ucn-8,'actual complete DWARF layout and record extent')
    def shape(t):
        spans=sorted((v['offset'],v['offset']+v['bytes'])for v in t['fields'].values())
        need(spans[0][0]==0 and spans[-1][1]==t['bytes'] and all(a[1]==b[0]for a,b in zip(spans,spans[1:])),
             'complete named structure with no omitted padding')
    for t in (rt,st,bt):shape(t)
    def field(b,t,n):
        f=t['fields'][n];v=b[f['offset']:f['offset']+f['bytes']];need(len(v)==f['bytes'],'complete '+n);return v
    def q(b):need(len(b)%8==0,'complete qwords');return struct.unpack('<'+'Q'*(len(b)//8),b)
    def word(b,offset):return struct.unpack_from('<Q',b,offset)[0]
    def g(b,n):return word(b,go+n*8)
    h=q(field(data,rt,'h'));target=TARGET[negative]if negative else 15
    count=target+1
    need(h[0]==0x314e49544c554250 and h[1:6]==(1,len(data),ucn,st['bytes'],1),'actual fixed record identity')
    need(h[6:8]==((125,ERROR[negative])if negative else(0,0)) and h[9:11]==(target,1) and
         h[19]==1 and h[21]==h[22]+4096 and h[22]>0 and not h[22]%4096 and
         h[23:25]==(negative,int(configured)) and h[25]>0 and h[28]>0 and not h[28]%4096 and
         h[29]>0 and not h[29]%4096 and h[30]==512<<10 and not any(h[31:]) and h[20]&0xe7==0xe7,'actual terminal outcome, prefix and interpreter context')
    need(h[26]==h[28]+image['callback_symbols']['pb_clock_fault'] and
         h[27]==h[28]+image['callback_symbols']['pb_syscall_fault'],'actual fault labels bound to retained bridge ELF')
    expected_detail=7 if negative in(1,5)else 4 if negative in(4,11)else 0x31425364758697a8 if negative==12 else 0
    need(h[8]==expected_detail,'exact initiating error detail')
    hw=struct.unpack('<14I',field(data,rt,'hardware'))
    need(hw[:2]==(1,0)and hw[2]>=13 and hw[8]&0x18000000==0x18000000 and
         hw[11]&0x40010000==0x40010000,'actual raw hardware independent of application policy')
    xs=q(field(data,rt,'xstate'));components={}
    for i,(bit,size)in enumerate(((2,256),(5,64),(6,512),(7,1024))):
        row=xs[i*4:(i+1)*4]
        need(row[0]==bit and row[2]==size and row[1]>=576 and row[1]+size<=65532 and not row[3]&1,
             'actual user standard XSAVE component')
        components[bit]=(row[1],size)
    ranges=sorted((o,o+n)for o,n in components.values())
    need(all(a[1]<=b[0]for a,b in zip(ranges,ranges[1:])),'disjoint actual standard XSAVE components')
    sources=bytes.fromhex(image['main']['source_hex'])+bytes.fromhex(image['interpreter']['source_hex'])
    need(len(sources)==16384,'both complete emitted source domains')
    initial_data=bytes.fromhex(image['main']['data_hex'])+bytes.fromhex(image['interpreter']['data_hex'])
    need(len(initial_data)==32768,'both complete independent initial data/stack images')
    bases=(DATA,h[22]+12288);specs=[]
    for domain,key in((1,'interpreter'),(0,'main')):
        for spec in image[key]['rows']:
            v=dict(spec,domain=domain);v['pc']=spec['pc']+(h[22]if domain else 0);specs.append(v)
    need(len(specs)==16 and len(image['main']['sites'])==8 and specs[0]['pc']==h[21] and specs[7]['pc']==MAIN,
         'two actual first instructions and complete fixed effect order')
    vector_seed=bytes(1+(r*17+i*13)%255 for r in range(32)for i in range(64))
    mask_seed=b''.join(struct.pack('<Q',0x1020304050607080+r*0x0101010101010101)for r in range(8))
    def state(blob):
        v=q(field(blob,bt,'h'));uc=field(blob,bt,'uc');fp=field(blob,bt,'fp')
        need(len(v)==8 and v[0]>0 and v[1]==ucn and 512<=v[2]<=65536 and v[3:5]==(h[25],1) and
             not any(v[5:]) and len(uc)==2048 and not any(uc[ucn:])and len(fp)==65536 and
             not any(fp[v[2]:])and h[29]<=v[0]<=h[29]+h[30]-ucn and
             h[29]<=word(uc,fo)<=h[29]+h[30]-v[2] and not word(uc,fo)%16,'complete actual frame/FP and initialized unused storage')
        if v[2]>512:
            need(struct.unpack_from('<I',fp,464)[0]==0x46505853 and struct.unpack_from('<I',fp,468)[0]==v[2] and
                 576<=struct.unpack_from('<I',fp,480)[0]<=v[2]-4 and struct.unpack_from('<I',fp,v[2]-4)[0]==0x46505845 and
                 word(fp,520)==0,'actual initialized standard XSAVE extent markers')
        need(field(blob,bt,'source')==sources and len(field(blob,bt,'data'))==32768 and
             len(field(blob,bt,'startup_stack'))==256,'whole actual source, both data/stack domains and explicit startup window')
        return dict(raw=blob,h=v,uc=uc,fp=fp,data=field(blob,bt,'data'),startup=field(blob,bt,'startup_stack'))
    def vector_state(s):
        fp=s['fp'];active=word(fp,512)if s['h'][2]>512 else 3
        def comp(bit,start,n):
            if not active&(1<<bit):return bytes(n)
            need(start+n<=s['h'][2]-(4 if s['h'][2]>512 else 0),'actual present component extent')
            return fp[start:start+n]
        out=[]
        for r in range(32):
            if r<16:
                z=comp(1,160+r*16,16)+comp(2,components[2][0]+r*16,16)+comp(6,components[6][0]+r*32,32)
            else:z=comp(7,components[7][0]+(r-16)*64,64)
            out.append(z)
        return b''.join(out),comp(5,components[5][0],64)
    def live(memory,domain,prior):
        b=memory[domain*16384:(domain+1)*16384];uc=prior['uc']
        vs,ks=vector_state(prior)
        need(b[4096:6208]==vs+ks and q(b[6208:6336])==tuple(g(uc,s)for s in GREG) and
             word(b,6336)==g(uc,17),'actual live all32 ZMM/8K/all16 GPR/full flags after sigreturn')
        selectors=struct.unpack_from('<6H',b,6344);packed=g(uc,18)
        need(selectors==(packed&0xffff,packed>>48,0,0,(packed>>32)&0xffff,(packed>>16)&0xffff),
             'actual live CS/SS/DS/ES/FS/GS')
    samples=field(data,rt,'samples');need(len(samples)==16*st['bytes'],'all fixed sample slots')
    counts=[0,0,0,0];prior=None;prior_domain=None;owner_pcs=[];fullsizes=[];clockvalues=[];afterlast=None;last_clock=None;last_syscall=None
    for i,spec in enumerate(specs[:count]):
        sample=samples[i*st['bytes']:(i+1)*st['bytes']];v=q(field(sample,st,'h'));landing=q(field(sample,st,'landing'));p=q(field(sample,st,'policy'))
        nx,entry,after=(state(field(sample,st,k))for k in('nx','effect','after'))
        kind=KINDS[i]if i else(5 if image['variant']==1 else 6);pc=spec['pc'];length=3 if kind==6 else 2
        need(spec['kind']==kind and spec['encoding']==('0f31'if kind==5 else'0f01f9'if kind==6 else'0f05'),
             'independent literal kind and actual emitted opcode')
        need(v[:6]==(3 if i==target else 2,i,pc,pc+length,kind,length) and v[6]=={5:1162,6:852,7:870}[kind] and
             v[8:13]==(11,11,2,0,pc) and v[15]==1 and not any(v[19:]),'genuine NX typed row and exact complete/terminal prefix')
        flags=v[7];need(flags==g(nx['uc'],17)&~0x10000 and not flags&0x10100 and
             (g(nx['uc'],16),g(nx['uc'],20),g(nx['uc'],19),g(nx['uc'],22))==(pc,14,21,pc) and
             g(nx['uc'],18)&0xffff==0x33 and word(nx['uc'],mo)==MASK,'actual original NX frame/RF/CR2/mask')
        need(v[13]==(i if configured else 0) and v[14]==len(owner_pcs),'actual prior attempt and owner prefix')
        restored=i in OWNER_ROWS
        if restored:
            owner_pcs.append(pc)
            need(landing[:4]==(4,4,2,0) and landing[4]==landing[5]>0 and landing[6:10]==(7,1,pc,pc+2) and
                 landing[10]>0 and landing[11:14]==(flags,31,31) and landing[14:]==(entry['h'][0],1),
                 'authentic UD2 after complete restoration and typed original continuation')
            need((g(entry['uc'],16),g(entry['uc'],20),g(entry['uc'],19))==(landing[5],6,0) and
                 all(g(entry['uc'],j)==g(nx['uc'],j)for j in range(23)if j not in(16,19,20)) and
                 word(entry['uc'],mo)==word(nx['uc'],mo) and entry['fp']==nx['fp'] and entry['h'][2]==nx['h'][2],
                 'unchanged old one-shot full GREG/CR2/RF/mask/initialized FP landing contract')
        else:need(not any(landing)and entry['raw']==nx['raw'],'ordinary effect uses its authentic unchanged NX context')
        need(nx['data']==entry['data']==after['data'] and nx['startup']==entry['startup']==after['startup'],
             'all complete application data/stack domains and bounded startup stack window unchanged by selected effect')
        domain=spec['domain'];before=[g(entry['uc'],s)for s in GREG]
        if i==0:need(nx['data']==initial_data,'genuine first interpreter precedes all application data writes')
        if i==7:need(nx['data'][:16384]==initial_data[:16384],'first main entry retains its complete independent initial data/stack')
        if prior is not None:live(nx['data'],prior_domain,prior)
        if i==7:
            want=[g(prior['uc'],s)for s in GREG];want[0]=MAIN
            need(before==want and flags==g(prior['uc'],17) and vector_state(entry)==vector_state(prior),
                 'real main inherited state from interpreter capture and literal MOV/JMP, including interpreter RSP')
        elif i>0:
            want=[0x1122334455667700+j for j in range(16)]
            want[0]=0xa501020304050607 if kind!=7 else(157 if negative==12 and i==3 else NUMBERS[i]);want[1]=0xb608090a0b0c0d0e
            want[4]=bases[domain]+16320
            for j in(2,6,7,8,9,10):want[j]=0x31425364758697a8
            if kind==7 and NUMBERS[i]==1:
                want[7]=U64 if i==6 else 1;want[2]=5 if i in(12,13)else 16
                want[6]=pc if i==12 else MAIN if i==13 else bases[domain]+128
            if i==15:want[7]=0
            need(before==want and flags==0xed7,'independently literal all-GPR six-argument/DF seed')
            need(vector_state(entry)==(vector_seed,mask_seed)and word(entry['fp'],512)&0xe7==0xe7 and
                 nx['data'][domain*16384+512:domain*16384+2624]==vector_seed+mask_seed,'actual full seeded vectors/masks')
        frame_layout=dict(uc_bytes=ucn,greg_offset=go,fp_offset=fo,fp_bytes=entry['h'][2])
        failed=i==target
        need(entry['h'][2]==after['h'][2]and entry['h'][0]==after['h'][0],'same actual live outer frame and FP extent')
        if kind!=7:
            last_clock=p
            ordinal=counts[0]+counts[1]+1
            inputs=[1,kind,pc,pc+length,flags,ordinal]
            if configured:
                result=list(p[24:27]);need(p[16:22]==tuple(inputs) and not any(p[14:16]+p[22:24]+p[27:]),'exact retained scalar clock ABI and zero payload tail')
                status=7 if negative==1 and failed else 0
                need(p[10:14]==(1,0 if negative==4 and failed else 1,0 if failed else 1,status),'actual clock entered/returned/commit prefix')
                expected=[effects.CLOCK_BASE+(ordinal<<8),effects.AUX if kind==6 else 0,0]
                if failed and negative==2:expected[2]=1
                if failed and negative==3:expected[1]=1
                need(result==expected,'actual literal callback result, including named malformed field')
            else:
                need(not any(p[:32]+p[40:])and p[32:36]==(kind,7,0,0)and all(x<1<<32 for x in p[36:40]),'genuine one native sample and successful old gate restoration')
                result=[p[39]<<32|p[36],p[38]if kind==6 else 0,0]
            if failed:effects.failed_frame(entry['uc'],after['uc'],entry['fp'],after['fp'],frame_layout,kind,pc+length,flags,False)
            else:
                effects.clock(entry['uc'],after['uc'],entry['fp'],after['fp'],frame_layout,inputs,result,configured)
                counts[int(kind==6)]+=1;clockvalues.append(result)
        else:
            last_syscall=p
            number=157 if negative==12 and i==3 else NUMBERS[i]
            inputs=[1,0,pc,pc+2,flags,number,*[before[j]for j in(7,6,2,10,8,9)],before[1],before[11]]
            replaced=configured and number in(39,186)
            if configured:
                need(p[24:38]==tuple(inputs) and not any(p[23:24]+p[38:40]+p[43:]),'all original syscall inputs/RCX/R11 and clean scalar tail')
                decision=[int(replaced),0,effects.PID if number==39 else effects.TID if number==186 else 0]
                if failed:
                    if negative==6:decision[1]=1
                    if negative==7:decision=[0,0,1]
                    if negative==8:decision=[1,0,effects.PID]
                    if negative==9:decision[2]=effects.PID
                    if negative==10:decision[0]=2
                need(tuple(decision)==p[40:43],'exact native/replacement decision or named malformed result')
                if failed:
                    pre=1 if negative==12 else 0
                    expected=[1,1,0 if negative==11 else 1,pre,pre,0,0,0,0,0,int(not negative),7 if negative==5 else 0,0]
                    need(p[10:23]==tuple(expected),'actual failed/nonreturning syscall prefix; no native effect/return invented')
                else:
                    expected=[1,1,1,1,int(not replaced),int(not replaced),int(not replaced),int(replaced),1,1,0,0]
                    need(p[10:22]==tuple(expected),'actual complete replacement or raw forwarding progression')
            else:
                need(not any(p),'explicit native policy has no configured callback prefix')
                decision=[0,0,0]
            if failed:effects.failed_frame(entry['uc'],after['uc'],entry['fp'],after['fp'],frame_layout,kind,pc+2,flags,True)
            else:
                actual=g(after['uc'],13)
                literal=(effects.PID if number==39 else effects.TID)if replaced else(pid if number in(39,186)else U64-8 if i==6 else before[2])
                need(actual==literal and (not configured or p[22]==actual),'literal tagged ID or actual native PID/write/EBADF result')
                effects.syscall(entry['uc'],after['uc'],entry['fp'],after['fp'],frame_layout,inputs,decision,actual,replaced)
                counts[2 if replaced else 3]+=1
        if configured:
            first=ERROR[negative]if failed and negative not in(4,11,12)else 0
            detail=7 if failed and negative in(1,5)else 0
            need(p[:9]==(int(failed),first,detail,i+1,*counts,int(bool(negative and failed)))and p[9]==1,
                 'truthful actual configured cumulative counts and first policy error')
        need(v[16]==(7 if restored else 0) and v[18]==0 and
             v[17]==(301 if kind!=7 else 0),'actual source/owner effect boundary')
        if not failed:prior=after;prior_domain=domain
        afterlast=after;fullsizes.append(entry['h'][2])
    need(not any(samples[count*st['bytes']:]),'every unused row remains completely zero')
    need(h[11]==len(owner_pcs) and h[12:19]==((count,1,*counts,int(bool(negative)))if configured else(0,0,0,0,0,0,0)),
         'terminal aggregate prefix bound to every retained effect')
    need(field(data,rt,'terminal_source')==sources and field(data,rt,'terminal_data')==afterlast['data'],
         'whole final original source and actual application memory retained')
    owners=q(field(data,rt,'owners'));need(len(owners)==256,'exact eight never-reused owner slots')
    for i,pc in enumerate(owner_pcs):
        o=owners[i*32:(i+1)*32];idx=next(j for j in OWNER_ROWS if specs[j]['pc']==pc);returned=idx<target
        kind=2 if KINDS[idx]==5 else 1;literal=bytes.fromhex('0f31'if kind==2 else'0f05')+b'\x90'*3
        need(o[:7]==(8 if returned else 7,1,1,0,pc,pc+2,kind)and o[7]>0 and
             o[8:14]==(31,31,31,31,1,int(returned))and o[14]==o[15]==int.from_bytes(literal,'little')and not any(o[16:]),
             'genuine complete restoration and precise returned/nonreturning owner prefix')
    need(not any(owners[len(owner_pcs)*32:]),'all unused owner slots zero')
    nested=q(field(data,rt,'nested'));nu=field(data,rt,'nested_uc');nf=field(data,rt,'nested_fp')
    if negative in(4,11):
        fault=h[26 if negative==4 else 27]
        need(nested[:6]==(1,4,4,2,0,fault)and nested[6]>0 and 512<=nested[7]<=65536 and not any(nested[8:])and
             h[29]<=nested[6]<=h[29]+h[30]-ucn and h[29]<=word(nu,fo)<=h[29]+h[30]-nested[7] and
             g(nu,16)==fault and g(nu,20)==6 and g(nu,19)==0 and not any(nu[ucn:])and not any(nf[nested[7]:]),
             'genuine nested callback UD2 frame, exact emitted PC and retained complete initialized FP')
        if nested[7]>512:
            need(struct.unpack_from('<I',nf,464)[0]==0x46505853 and struct.unpack_from('<I',nf,468)[0]==nested[7] and
                 struct.unpack_from('<I',nf,nested[7]-4)[0]==0x46505845,'actual nested initialized kernel XSAVE extent')
    else:need(not any(nested)and not any(nu)and not any(nf),'no fabricated nested event')
    terminal_report={}
    if configured:
        terminal_report=dict(version=1,status=125 if negative else 0,failure_code=ERROR[negative],
            first_error=ERROR[negative]if negative and negative not in(4,11,12)else 0,busy=1,attempts=count,
            rdtsc_completed=counts[0],rdtscp_completed=counts[1],syscall_replaced=counts[2],syscall_forwarded_returned=counts[3])
        for name,at in (('clock_entered',10),('clock_returned',11),('clock_committed',12)):
            terminal_report[name]=last_clock[at]if last_clock else 0
        names=('syscall_prepared','syscall_entered','syscall_returned','syscall_pre_dispatch_guards_complete',
            'native_dispatch_entered','raw_entered','raw_returned','replacement_selected','dispatch_returned','syscall_committed','exit_selected')
        for at,name in enumerate(names,10):terminal_report[name]=last_syscall[at]if last_syscall else 0
    return dict(terminal_report=terminal_report,selected_attempts=count,returned_effects=target,failed_operations=int(bool(negative)),nonreturning_exit=int(not negative),
        clock_completed=counts[:2],syscall_replacements=counts[2],native_syscalls_returned=counts[3],
        configured=configured,negative=negative,full_kernel_fp_bytes=fullsizes,clock_observations=clockvalues,
        syscall_attempts=sum(KINDS[j]==7 for j in range(count)),source_bytes=16384,data_stack_bytes=32768,startup_stack_window_bytes=256,
        published=len(owner_pcs),restored=len(owner_pcs),completed=sum(i<target for i in OWNER_ROWS),
        retained_initial_frames=2 if target>=7 else 1,first_interpreter_kind=KINDS[0]if image['variant']==1 else 6,
        first_main_kind=5 if target>=7 else None)
