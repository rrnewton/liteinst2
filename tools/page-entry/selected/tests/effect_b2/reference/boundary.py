"""Strict bridge from the retained Rust reference to actual C signal snapshots.

The old full ptrace/XSTATE predicates run before reference.bin exists. This
adapter does not synthesize orig_rax or reinterpret pointer-bearing registers.
It supports standard, equal-extent XSAVE only; unknown/different layouts refuse.
"""
from pathlib import Path
import hashlib,struct
U64=(1<<64)-1
BASE,DATA,N,STACK,FLAGS,MASK=0x200400000,0x200600000,8192,0x200601f80,0xed7,18446744072635546343
REGS=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
GPRS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
# Independently transcribed original case scripts and actual selected head
# offsets. These are literal reply bindings, not a second semantic model.
LITERALS=(
 ('masked_cpuid_random',((4097,'0fa2',1,[0,0,0,0],0),(4126,'0fa2',1,[0,0,0,0],0),(4135,'0fc7f0',2,[0x99887766,0,0,0],1),(4145,'0fc7fa',3,[0,0,0,0],0))),
 ('timestamps_processor_syscall',((4097,'0f31',5,[0x8877665544332211,0,0,0],0),(4143,'0f01f9',6,[0x123456789abcdef0,0xabbacafe,0,0],0),(4153,'f3410fc7f9',4,[0xfacebabe,0,0,0],0),(4175,'0f05',7,[173,0,0,0],0))),
 ('prefixed_suffix',((4097,'66410fc7f1',2,[0xbeef,0,0,0],1),(4109,'480fc7fb',3,[0,0,0,0],0),(4120,'f30fc7fa',4,[0xaabbccdd,0,0,0],0),(4121,'0fc7fa',3,[0x12345678,0,0,0],1))),
 ('embedded_alternate',((4114,'0f31',5,[0x1122334455667788,0,0,0],0),(4100,'0fc7f8',3,[0xfedcba98,0,0,0],1),(4114,'0f31',5,[0x8877665544332211,0,0,0],0))),
 ('cross_page_call',((8192,'f30fc7fa',4,[0x12345678,0,0,0],0),(8203,'0f31',5,[0x9988776655443322,0,0,0],0))),
)
TYPES=(( (0,16),(0,16),(32,0),(32,2) ),
       ( (0,16),(0,16),(64,9),(0,16) ),
       ( (16,9),(64,3),(64,2),(32,2) ),
       ( (0,16),(32,0),(0,16) ),
       ( (64,2),(0,16) ))
def need(ok,reason):
    if not ok:raise ValueError(reason)
def q(b,o=0):return struct.unpack_from('<Q',b,o)[0]
def u32(b,o):return struct.unpack_from('<I',b,o)[0]
def reference(data):
    need(type(data)is bytes and len(data)<16<<20 and data[:8]==b'B2DYN001','bounded exact reference wire')
    at=8
    def take(n):
        nonlocal at
        need(type(n)is int and 0<=n<=len(data)-at,'complete reference extent');b=data[at:at+n];at+=n;return b
    h=struct.unpack('<12Q',take(96));version,count,slen,nh,nb,marker,base,db,dn,stack,flags,mask=h
    need(version==1 and 2<=count<=4 and (slen,base,db,dn,stack,flags,mask)==(20480,BASE,DATA,N,STACK,FLAGS,MASK) and marker==BASE+4096 and 1<=nb<=nh<=128,'exact reference geometry')
    source=take(slen);heads=struct.unpack('<'+'Q'*nh,take(8*nh));blocks=struct.unpack('<'+'Q'*nb,take(8*nb))
    need(tuple(sorted(set(heads)))==heads and tuple(sorted(set(blocks)))==blocks and set(blocks)<=set(heads),'exact finite head/block census')
    def state():
        r=dict(zip(REGS,struct.unpack('<27Q',take(216))));m,xn=struct.unpack('<2Q',take(16))
        need(m==MASK and 512<=xn<65536 and r['orig_rax']==U64 and not r['eflags']&0x10100,'reference full-state origin')
        return dict(registers=r,mask=m,xstate=take(xn),data=take(N))
    rows=[]
    for i in range(count):
        kind,width,dst,n,*tail=struct.unpack('<9Q',take(72));encoding=take(16)
        need(1<=kind<=7 and 1<=n<=15 and not any(encoding[n:]) and tail[-1]in(0,1),'exact typed reference row')
        need((kind in(1,5,6,7) and (width,dst)==(0,16)) or (kind in(2,3) and width in(16,32,64) and dst<16) or (kind==4 and width==64 and dst<16),'explicit class/width/destination')
        before,after=state(),state();pc=before['registers']['rip']
        need(pc in heads and source[pc-BASE:pc-BASE+n]==encoding[:n] and after['registers']['rip']==pc+n,'literal selected original/next PC')
        need(before['xstate']==after['xstate'] and before['data']==after['data'] and before['mask']==after['mask'],'selected operation preserves full reference FP/memory/mask')
        rows.append(dict(index=i,kind=kind,width=width,destination=dst,encoding=encoding[:n],values=tail[:4],carry=tail[4],before=before,after=after))
    need(at==len(data),'no unparsed reference suffix')
    actual=tuple((r['before']['registers']['rip']-BASE,r['encoding'].hex(),r['kind'],r['values'],r['carry'])for r in rows)
    matched=[name for name,items in LITERALS if items==actual]
    need(len(matched)==1,'one complete original literal trajectory, including every reply')
    case_index=next(i for i,(name,_)in enumerate(LITERALS)if name==matched[0])
    need(tuple((r['width'],r['destination'])for r in rows)==TYPES[case_index],'literal encoded operand widths and destinations')
    return dict(case=matched[0],rows=rows,source=source,heads=heads,blocks=blocks,sha256=hashlib.sha256(data).hexdigest())

def fixture(path,ref):
    """Actual emitted high ET_EXEC + unchained ET_DYN, with no compiler guesses."""
    path=Path(path);b=path.read_bytes();need(b==ref['source']+b'\x5a'*N,'exact generated main plus initial data')
    eh=struct.Struct('<16sHHIQQQIHHHHHH');ph=struct.Struct('<IIQQQQQQ');h=eh.unpack_from(b)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(2,62,1) and h[4:6]==(BASE+16384,64) and h[6:]==(0,0,64,56,6,0,0,0),'literal ET_EXEC header/no hidden section authority')
    ps=[ph.unpack_from(b,64+i*56)for i in range(6)]
    need(ps[0]==(6,4,64,BASE+64,BASE+64,336,336,8) and ps[1]==(1,5,0,BASE,BASE,20480,20480,4096) and
         ps[2]==(1,6,20480,DATA,DATA,N,N,4096) and ps[4]==(2,4,1280,BASE+1280,BASE+1280,64,64,8) and
         ps[5]==(0x6474e551,6,0,0,0,0,0,16),'exact nonoverlapping RX/RW-NX program domains')
    ip=ps[3];need(ip[:5]==(3,4,1792,BASE+1792,BASE+1792) and ip[5]==ip[6] and 2<=ip[5]<=2048 and ip[7]==1,'actual PT_INTERP extent')
    name=b[1792:1792+ip[5]];need(name[:1]==b'/' and name[-1:]==b'\0' and b'\0'not in name[:-1],'exact lexical interpreter path')
    interp=Path(name[:-1].decode());ib=interp.read_bytes();ih=eh.unpack_from(ib)
    need(len(ib)==8192 and ih[0][:7]==h[0][:7] and ih[1:6]==(3,62,1,4096,64) and ih[6:]==(0,0,64,56,4,0,0,0),'actual unchained ET_DYN interpreter')
    ips=[ph.unpack_from(ib,64+i*56)for i in range(4)]
    need(ips==[(1,4,0,0,0,4096,4096,4096),(1,5,4096,4096,4096,4096,4096,4096),(2,4,1280,1280,1280,64,64,8),(0x6474e551,6,0,0,0,0,0,16)],'exact interpreter read-only header/executable page and no PT_INTERP/TLS')
    code=bytes.fromhex('48b8')+struct.pack('<Q',BASE+16384)+bytes.fromhex('ffe0')
    need(ib[4096:4096+len(code)]==code and not any(ib[4096+len(code):]),'literal genuine interpreter handoff')
    for source,base,tag in((b,BASE,1),(ib,0,14)):
        need(struct.unpack_from('<8Q',source,1280)==(5,base+1536,10,21,tag,1,0,0) and source[1536:1557]==b'\0li2-b2-reference.so\0','exact DT_NEEDED/SONAME graph')
    return dict(main_bytes=len(b),main_sha256=hashlib.sha256(b).hexdigest(),interpreter_bytes=len(ib),interpreter_sha256=hashlib.sha256(ib).hexdigest())

def corpus(directory):
    rows=[]
    for i,(name,items)in enumerate(LITERALS):
        p=Path(directory)/('case'+str(i));r=reference((p/'reference.bin').read_bytes())
        need(r['case']==name,'exact five-program order')
        need((p/'reference-complete.txt').read_text()==name+'\nselected='+str(len(items))+'\nraw_reaped=1\ntrap_reaped=1\nmodel_equal=1\n','post-reaping reference terminal marker')
        rows.append((r,fixture(p/'image',r)))
    need(sum(len(r['rows'])for r,_ in rows)==17,'all seventeen selected transitions')
    return rows

HEADER_BYTES=16*8+128
SNAPSHOT_BYTES=HEADER_BYTES+2048+65536+20480+8192
def snapshot(data,layout):
    need(type(data)is bytes and len(data)==SNAPSHOT_BYTES,'full actual C snapshot')
    h=struct.unpack_from('<16Q',data);ucn,fn,ua,fa,fsb,gsb,ds,es,go,fo,mo,reserved=h[:12]
    # layout comes from actual retained ELF DWARF, independently authenticated by
    # the enclosing evaluator. Self-described offsets alone are never accepted.
    need(set(layout)=={'uc_bytes','greg','fp_pointer','sigmask'} and all(type(x)is int for x in layout.values()),'actual DWARF layout required')
    need((ucn,go,fo,mo)==tuple(layout[k]for k in('uc_bytes','greg','fp_pointer','sigmask')) and 0<ucn<=2048 and go+23*8<=ucn and fo+8<=ucn and mo+8<=ucn and not reserved,'exact actual signal layout')
    need(ua>0 and fa>0 and 512<=fn<=65536 and fa%16==0 and ds<=65535 and es<=65535,'actual frame/FP/base/selector observations')
    si=data[128:256]
    need(h[12]==11 and h[13]>0 and h[14:]==(128,0) and struct.unpack_from('<3i',si)==(11,0,2),'actual complete SIGSEGV/SEGV_ACCERR siginfo')
    at=HEADER_BYTES;uc=data[at:at+ucn];need(not any(data[at+ucn:at+2048]),'unused UC storage stays zero');at+=2048
    fp=data[at:at+fn];need(not any(data[at+fn:at+65536]),'unused FP storage stays zero');at+=65536
    source=data[at:at+20480];at+=20480;memory=data[at:at+N]
    need(q(uc,fo)==fa,'actual fpregs pointer, not a relocated synthetic context')
    g=struct.unpack_from('<23Q',uc,go);r={name:g[index]for name,index in zip(GPRS,GREG)}
    r.update(rip=g[16],eflags=g[17],cs=g[18]&65535,gs=(g[18]>>16)&65535,fs=(g[18]>>32)&65535,ss=g[18]>>48,fs_base=fsb,gs_base=gsb,ds=ds,es=es)
    return dict(raw=data,header=h,si=si,uc=uc,fp=fp,registers=r,mask=q(uc,mo),source=source,data=memory)

def fp_payload(nt,signal):
    need(len(nt)>=576 and len(signal)>=580,'standard XSAVE required; FXSAVE-only refuses')
    need(u32(signal,464)==0x46505853 and u32(signal,468)==len(signal) and u32(signal,480)==len(nt) and len(signal)==len(nt)+4 and u32(signal,len(signal)-4)==0x46505845,'exact signal XSAVE envelope/extent')
    need(not any(signal[484:512]) and q(nt,520)==q(signal,520)==0,'zero envelope padding and uncompacted standard layout')
    need(not any(nt[528:576]) and not any(signal[528:576]),'reserved XSAVE header')
    need(q(signal,472)&q(signal,512)==q(signal,512),'signal envelope owns every present feature')
    # The only format translation is the documented Linux software envelope
    # [464,512) and trailing magic. All architectural bytes, including FIP/FDP,
    # MXCSR, XSTATE_BV and every extended payload byte compare exactly.
    need(nt[:464]==signal[:464] and nt[512:]==signal[512:-4],'complete equal-extent architectural XSAVE payload')

def compare(ref,actual,layout):
    """actual = one dictionary per selected row, with complete before/after bytes.

    Actual before is the genuine NX frame at the common provider boundary.
    Its hardware RF bit remains present; it is never erased in this record. The separate genuine
    entry snapshot is mandatory. This first adapter is NX-only, not restored
    one-shot SIGILL ingress. Both complete contexts and FP blobs remain retained.
    """
    need(type(actual)is list and len(actual)==len(ref['rows']),'all selected rows required')
    for row,got in zip(ref['rows'],actual):
        need(type(got)is dict and set(got)=={'index','entered','returned','committed','entry','before','after'},'exact actual row schema')
        need(all(type(got[k])is int for k in('index','entered','returned','committed')) and (got['index'],got['entered'],got['returned'],got['committed'])==(row['index'],1,1,1),'truthful completed callback prefix')
        entry,before,after=(snapshot(got[k],layout)for k in('entry','before','after'))
        go,fo=layout['greg'],layout['fp_pointer'];eg=struct.unpack_from('<23Q',entry['uc'],go)
        need(eg[20]==14 and eg[19]==21 and eg[22]==q(entry['si'],16)==row['before']['registers']['rip'],'genuine original NX trap14/execute error21/CR2/si_addr')
        need(entry['header'][2:8]==before['header'][2:8]==after['header'][2:8],'same actual frame/pointer/base/selector observations')
        need(entry['uc']==before['uc'] and entry['fp']==before['fp']==after['fp'] and entry['si']==before['si']==after['si'] and entry['header'][12:]==before['header'][12:]==after['header'][12:],'exact real NX/before/full FP/siginfo snapshots')
        for phase,state in(('before',before),('after',after)):
            expected=row[phase]
            architectural={k:v for k,v in expected['registers'].items()if k!='orig_rax'}
            if phase=='before':architectural['eflags']|=0x10000
            need(state['registers']==architectural,'all comparable architectural registers; exact hardware NX RF retained')
            need(state['mask']==expected['mask'] and state['data']==expected['data'] and state['source']==ref['source'],'full data/source/mask equality')
            fp_payload(expected['xstate'],state['fp'])
        expected_uc=bytearray(before['uc']);rg=row['after']['registers']
        for name,index in zip(GPRS,GREG):struct.pack_into('<Q',expected_uc,go+index*8,rg[name])
        struct.pack_into('<Q',expected_uc,go+16*8,rg['rip']);struct.pack_into('<Q',expected_uc,go+17*8,rg['eflags'])
        need(after['uc']==expected_uc,'full raw UC equality outside exact architectural effect')
    return dict(scope='finite_dynamic_selected_reference',selected=len(actual),reference_sha256=ref['sha256'],
                whole_program_completion=False,independent_selected_models=1,ptrace_only_field='orig_rax')

def final_entry(ref,data,layout):
    """Last commit returned via the kernel to a genuine next NX event. No exit credit."""
    s=snapshot(data,layout);last=ref['rows'][-1]['after'];g=struct.unpack_from('<23Q',s['uc'],layout['greg'])
    need(g[20]==14 and g[19]==21 and g[22]==q(s['si'],16)==last['registers']['rip'],'actual unexecuted next-instruction NX')
    expected={k:v for k,v in last['registers'].items()if k!='orig_rax'};expected['eflags']|=0x10000
    need(s['registers']==expected and s['data']==last['data'] and s['source']==ref['source'] and s['mask']==last['mask'],'exact final returned architectural state and original next source')
    fp_payload(last['xstate'],s['fp'])
    return dict(return_observed=True,next_instruction_executed=False,operation_exit_required=False)

def emit_script(ref,path):
    """Literal immutable rows for a separate fixture-only all-class policy binding."""
    def words(xs):return ','.join('UINT64_C('+str(x)+')'for x in xs)
    text='#define B2_SCRIPT_ROWS '+str(len(ref['rows']))+'\nstatic const struct b2_script_row b2_script[B2_SCRIPT_ROWS]={\n'
    for r in ref['rows']:
        a,b=r['before']['registers'],r['after']['registers']
        text+='{'+words([r['kind'],r['width'],r['destination'],len(r['encoding']),a['rip'],b['rip'],a['eflags'],b['eflags'],r['carry']])+', {'+words(r['values'])+'}, {'+','.join(str(x)for x in r['encoding'])+'}, {'+words(a[k]for k in GPRS)+'}, {'+words(b[k]for k in GPRS)+'}},\n'
    text+='};\n'
    with Path(path).open('x')as f:f.write(text)
    return hashlib.sha256(text.encode()).hexdigest()
