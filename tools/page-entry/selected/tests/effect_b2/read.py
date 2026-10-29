"""Strict additive reader for genuine new-controller B2 observations.

The enclosing evaluator owns source/build/ELF/DWARF/command/capture custody,
the original raw+model+explicit-trap references, and the same-CPU format probe.
This leaf grants finite selected-transition credit only, never app completion.
"""
import sys
sys.dont_write_bytecode=True
import hashlib,struct,types
from pathlib import Path

def _load(name,path):
    module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module

_base=Path(__file__).resolve().parent.parent/'b2_reference'
B=_load('effect_b2_boundary',Path(__file__).resolve().parent/'reference/boundary.py')
X=_load('effect_b2_xstate',_base/'xstate.py')
need=B.need
U64=(1<<64)-1
def words(xs,width=8):
    need(all(type(x)is int and 0<=x<1<<(8*width) for x in xs),'exact unsigned integer array')
    return b''.join(x.to_bytes(width,'little')for x in xs)
def qs(b):
    need(len(b)%8==0,'complete u64 array');return struct.unpack('<'+'Q'*(len(b)//8),b)

class Reader:
    """Every named member and every padding byte has an explicit expectation."""
    def __init__(self,layout):
        need(type(layout)is dict,'actual complete DWARF object')
        self.layout=layout
        for name,t in layout.items():
            if name in('layout','symbols'):continue
            need(type(t)is dict and set(t)=={'bytes','fields'} and type(t['bytes'])is int and
                 0<t['bytes']<2<<20 and type(t['fields'])is dict,'bounded actual type '+name)
            spans=[]
            for key,f in t['fields'].items():
                need(type(key)is str and type(f)is dict and set(f)=={'offset','bytes'} and
                     type(f['offset'])is int and type(f['bytes'])is int and
                     0<=f['offset']<t['bytes'] and 0<f['bytes']<=t['bytes']-f['offset'],
                     'complete member extent '+name)
                spans.append((f['offset'],f['offset']+f['bytes']))
            spans.sort();need(all(a[1]<=b[0]for a,b in zip(spans,spans[1:])),
                               'nonoverlapping members '+name)
    def size(self,name):return self.layout[name]['bytes']
    def field(self,raw,name,key):
        need(type(raw)is bytes and len(raw)==self.size(name),'whole retained '+name)
        f=self.layout[name]['fields'][key];return raw[f['offset']:f['offset']+f['bytes']]
    def uint(self,raw,name,key):
        v=self.field(raw,name,key);need(len(v)in(2,4,8),'scalar member '+key)
        return int.from_bytes(v,'little')
    def pack(self,name,fields):
        spec=self.layout[name];need(type(fields)is dict and set(fields)==set(spec['fields']),
                                   'every typed member classified '+name)
        data=bytearray(spec['bytes'])
        for key,value in fields.items():
            f=spec['fields'][key]
            if type(value)is int:
                need(0<=value<1<<(8*f['bytes']),'unsigned exact '+name+'.'+key)
                value=value.to_bytes(f['bytes'],'little')
            need(type(value)is bytes and len(value)==f['bytes'],'exact member bytes '+name+'.'+key)
            data[f['offset']:f['offset']+f['bytes']]=value
        return bytes(data)
    def exact(self,raw,name,**fields):
        need(raw==self.pack(name,fields),'all actual members/padding '+name)
        return raw

def _snapshot(raw,layout,held,signal,stack):
    need(type(raw)is bytes and len(raw)==B.SNAPSHOT_BYTES,'complete real snapshot')
    need(set(layout)=={'uc_bytes','greg','fp_pointer','sigmask'} and
         all(type(x)is int for x in layout.values()),'actual ucontext layout')
    h=qs(raw[:128]);n,fn,ua,fa,fsb,gsb,ds,es,go,fo,mo,reserved=h[:12]
    need((n,go,fo,mo)==tuple(layout[k]for k in('uc_bytes','greg','fp_pointer','sigmask')) and
         0<n<=2048 and go+184<=n and fo+8<=n and mo+8<=n and reserved==0,
         'exact actual context offsets')
    lo,extent=stack
    def inside(at,size):return type(at)is int and lo<=at<=U64-size and size<=extent and at-lo<=extent-size
    need(inside(ua,n)and inside(fa,fn)and inside(h[13],128)and fa%16==0 and
         580<=fn<=65536 and ds<=65535 and es<=65535 and h[12:]==(signal,h[13],128,int(held)),
         'actual signal/FP/si allocation and typed held-copy marker')
    if held:need(fsb==gsb==0,'held copy makes no base-query claim')
    si=raw[128:256];need(struct.unpack_from('<3i',si)==(signal,0,2),'genuine complete signal tuple')
    uc=raw[256:256+n];fp=raw[2304:2304+fn]
    need(not any(raw[256+n:2304])and not any(raw[2304+fn:67840]),'zero unused snapshot storage')
    views=((ua,uc),(fa,fp),(h[13],si))
    for a,left in views:
        for b,right in views:
            lo,hi=max(a,b),min(a+len(left),b+len(right))
            if lo<hi:
                need(left[lo-a:hi-a]==right[lo-b:hi-b],
                     'every actual kernel UC/FP/siginfo physical alias byte')
    need(B.q(uc,fo)==fa,'actual original fpregs pointer')
    g=struct.unpack_from('<23Q',uc,go)
    regs={name:g[index]for name,index in zip(B.GPRS,B.GREG)}
    regs.update(rip=g[16],eflags=g[17],cs=g[18]&65535,gs=g[18]>>16&65535,
        fs=g[18]>>32&65535,ss=g[18]>>48,ds=ds,es=es)
    if not held:regs.update(fs_base=fsb,gs_base=gsb)
    return dict(raw=raw,header=h,si=si,uc=uc,fp=fp,registers=regs,greg=g,
                source=raw[67840:88320],data=raw[88320:],mask=B.q(uc,mo))

def _architecture(s,state,ref,facts,*,held,ingress):
    expected={k:v for k,v in state['registers'].items()if k!='orig_rax'}
    if ingress:expected['eflags']|=0x10000
    if held:
        del expected['fs_base'];del expected['gs_base']
    need(s['registers']==expected,'all actual architectural registers and raw RF')
    need(s['source']==ref['source']and s['data']==state['data']and s['mask']==state['mask'],
         'full source/data/application-mask equality')
    X.pair(state['xstate'],s['fp'],facts,B)

def _state(r,state):
    a=state['registers']
    return r.pack('li2_effect_state',dict(pc=a['rip'],gpr=words([a[k]for k in B.GPRS]),
        logical_flags=a['eflags'],selectors=words([a['cs'],0,0,0,a['fs'],a['gs']],2),
        selectors_observed=49,reserved=0,xstate=r.pack('li2_effect_xstate',dict(bytes=0,length=0,reserved=0,format=0))))

def _result(r,kind,*,value=0,carry=0,aux=0,cpuid=(0,0,0,0)):
    return r.pack('li2_effect_result',dict(kind=kind,carry=carry,aux=aux,reserved=0,
                                        value=value,cpuid=words(cpuid,4)))

def _decode(r,row,ref,got):
    pc=row['before']['registers']['rip'];n=len(row['encoding']);available=min(15,4096-pc%4096)
    # The decoder classifies SYSCALL as a kernel transfer before selected effects.
    step=5 if row['kind']==7 else 8
    need(type(got)is dict and set(got)=={'pc','next_pc','abi','decode_status','code','kind',
         'destination','width','step_disposition','length'}and all(type(v)is int for v in got.values()),
         'actual independent decoder command result')
    need({k:v for k,v in got.items()if k!='code'}==dict(pc=pc,next_pc=pc+n,abi=1,decode_status=0,
         kind=row['kind'],destination=row['destination'],width=row['width'],step_disposition=step,length=n)and
         0<got['code']<1<<32,'complete exact selected decoder descriptor')
    source=ref['source'][pc-B.BASE:pc-B.BASE+available]
    need(len(source)==available and source[:n]==row['encoding'],'actual complete decoder input prefix')
    return r.pack('li2_decoded',dict(pc=pc,next_pc=pc+n,abi_version=1,decode_status=0,code=got['code'],
        kind=row['kind'],destination=row['destination'],width_bits=row['width'],step_disposition=step,
        available=available,length=n,reserved=0,bytes=source+bytes(16-available)))

def _publication(r,raw,plan,row,ordinal,source):
    p=qs(raw);need(len(p)==32,'complete publication prefix')
    pc=row['before']['registers']['rip'];page=pc&~4095
    get=lambda k:r.uint(plan,'li2_oneshot_plan',k)
    landing,allocation,generation=get('landing'),get('landing_allocation'),get('landing_generation')
    need(landing>=0x200000000 and landing%4096==0 and allocation>0 and generation>0 and
         -(1<<31)<=landing-(pc+5)<1<<31,'actual object-bound rel32 landing')
    pages=r.field(plan,'li2_oneshot_plan','pages');ps=r.size('li2_oneshot_page')
    first=pages[:ps];old=r.uint(first,'li2_oneshot_page','generation')
    need(old>0 and p[18]>old and p[18]==source['generation'],'restored current source generation')
    r.exact(first,'li2_oneshot_page',address=page,allocation=source['allocation'],generation=old,offset=page-B.BASE)
    need(len(pages)==2*ps and not any(pages[ps:]),'unused second source page zero')
    r.exact(plan,'li2_oneshot_plan',abi_version=1,kind={1:3,5:2,7:1}[row['kind']],sequence=ordinal,
        pc=pc,next_pc=pc+len(row['encoding']),landing=landing,landing_allocation=allocation,
        landing_generation=generation,pages=pages,page_count=1,reserved=0,
        original=row['_source'][pc-B.BASE:pc-B.BASE+5],
        redirect=b'\xe9'+struct.pack('<i',landing-pc-5),reserved_bytes=bytes(6))
    need(p==(8,1,1,1,1,1,1,31,31,1,31,31,1,1,1,0,0,ordinal,p[18],0,
             ordinal,ordinal,ordinal,ordinal,0,0,0,0,0,0,0,0),
         'actual completed/restored/released/retired publication, no inferred operation')
    return landing

def _native(r,row,owner,backend,random,builtin,hardware,pid,cpuid_ordinal):
    kind=row['kind'];actual=r.field(owner,'li2_effect_owner','native_result')
    value=r.uint(actual,'li2_effect_result','value');carry=r.uint(actual,'li2_effect_result','carry')
    aux=r.uint(actual,'li2_effect_result','aux');cp=struct.unpack('<4I',r.field(actual,'li2_effect_result','cpuid'))
    b=qs(backend);expected=[0]*32
    if kind==1:
        leaf=row['before']['registers']['rax']&0xffffffff;sub=row['before']['registers']['rcx']&0xffffffff
        need((leaf,sub)in((1,0),(7,0)),'unchanged two literal CPUID inputs')
        need(cp==tuple(hardware['leaf'+str(leaf)]),'genuine same-CPU native feature result')
        expected[:18]=[3,1,1,cpuid_ordinal,cpuid_ordinal,cpuid_ordinal,
            row['before']['registers']['rip'],row['after']['registers']['rip'],leaf,sub,*cp,*row['values']]
        expected_native=_result(r,kind,cpuid=cp)
        r.exact(builtin,'selected_builtin_prefix',kind=kind,phase=0,enable_result=0,restore_result=0,
                a=cp[0],b=cp[1],c=cp[2],d=cp[3])
    elif kind in(2,3,4):
        need(aux==0 and not any(cp)and carry in(0,1),'typed actual random result')
        maximum=(1<<row['width'])-1
        need(value<=maximum and(kind==4 and carry==0 and value<=0xffffffff or
             kind in(2,3)and(carry==1 or value==0)),'actual width/carry result domain')
        before=row['before']['registers'];input_value=before[B.GPRS[row['destination']]]
        output_value=(input_value&~65535)|value if row['width']==16 else value
        output_flags=before['eflags']if kind==4 else(before['eflags']&~0x8d5)|carry
        r.exact(random,'li2_selected_completion',abi_version=1,mechanism=1,phase=4,status=0,
            kind=kind,destination=row['destination'],width_bits=row['width'],carry=carry,native_attempts=1,
            reserved=0,pc=before['rip'],next_pc=row['after']['registers']['rip'],frame_flags=before['eflags']|0x10000,
            logical_flags=before['eflags'],input_destination=input_value,value=value,
            output_destination=output_value,output_flags=output_flags)
        need(not any(builtin),'random lane has no builtin sample claim')
        expected_native=_result(r,kind,value=value,carry=carry)
    elif kind in(5,6):
        need(carry==0 and not any(cp)and(kind==6 or aux==0),'typed actual clock result')
        r.exact(builtin,'selected_builtin_prefix',kind=kind,phase=7,enable_result=0,restore_result=0,
                a=value&0xffffffff,b=0,c=aux,d=value>>32)
        expected_native=_result(r,kind,value=value,aux=aux)
    else:
        need(kind==7 and row['before']['registers']['rax']==39,'literal real getpid syscall')
        expected[:4]=[1,1,39,pid];need(not any(builtin),'syscall has no builtin sample claim')
        expected_native=_result(r,kind,value=pid)
    if kind not in(2,3,4):need(not any(random),'no invented random backend receipt')
    need(b==tuple(expected)and actual==expected_native,'complete actual backend/native payload')
    return expected_native

def _scripted(r,row,backend,random,builtin):
    """Exact no-native backend state; initialization is not erased."""
    kind=row['kind'];b=[0]*32
    if kind==1:
        # selected_initialize observed hardware once; no selected CPUID was issued.
        b[1:3]=[1,1]
    elif kind==7:
        need(row['before']['registers']['rax']==39,'literal scripted scalar getpid only')
        b[2]=39
    need(qs(backend)==tuple(b),'no selected native issue, result or CPUID sample history')
    if kind in(2,3,4):
        before=row['before']['registers'];value=row['values'][0];carry=row['carry']if kind in(2,3)else 0
        input_value=before[B.GPRS[row['destination']]]
        output_value=(input_value&~65535)|value if row['width']==16 else value
        output_flags=before['eflags']if kind==4 else(before['eflags']&~0x8d5)|carry
        r.exact(random,'li2_selected_completion',abi_version=1,mechanism=2,phase=4,status=0,
            kind=kind,destination=row['destination'],width_bits=row['width'],carry=carry,native_attempts=0,
            reserved=0,pc=before['rip'],next_pc=row['after']['registers']['rip'],frame_flags=before['eflags']|0x10000,
            logical_flags=before['eflags'],input_destination=input_value,value=value,
            output_destination=output_value,output_flags=output_flags)
        need(not any(builtin),'scripted random lane has no builtin sample claim')
    else:
        need(not any(random),'no random backend receipt outside its exact class')
        if kind==7:need(not any(builtin),'scripted syscall has no builtin sample claim')
        else:r.exact(builtin,'selected_builtin_prefix',kind=kind,phase=0,enable_result=0,restore_result=0,a=0,b=0,c=0,d=0)
    return bytes(r.size('li2_effect_result'))


def record(raw,layout,reference_bytes,format_facts,pid,cpu,decodes,*,policy='native-post'):
    """All inputs are actual custody-bound artifacts; no callback predicates.

    decodes are the exact 17-per-corpus fixture_observe decode outputs, using
    each original source prefix and the identical release decoder archive.
    """
    need(type(policy)is str and policy in ('native-post','scripted'),'explicit exact finite policy')
    native_mode=policy=='native-post'
    need(type(pid)is int and pid>0 and type(cpu)is int and cpu>=0,'actual target PID/CPU')
    ref=B.reference(reference_bytes);n=len(ref['rows']);r=Reader(layout)
    expected_types={'be_record','be_row','b2_snapshot','b2_format_record','b2_format_sample',
        'li2_effect_owner','li2_effect_input','li2_effect_binding','li2_effect_decision','li2_effect_result',
        'li2_effect_fault','li2_effect_state','li2_effect_xstate','li2_effect_source','li2_decoded',
        'li2_selected_completion','li2_selected_hardware','selected_builtin_prefix','li2_oneshot_plan',
        'li2_oneshot_page','layout','symbols'}
    need(set(layout)==expected_types and type(raw)is bytes and len(raw)==r.size('be_record')+X.FORMAT_BYTES,
         'exact actual record types/stream extent with no suffix')
    need(type(decodes)is list and len(decodes)==n and format_facts['cpu']==cpu,
         'all fresh independent decodes and same-CPU format probe')
    X.trailer(raw[-X.FORMAT_BYTES:],{k:layout[k]for k in('b2_format_record','b2_format_sample')},format_facts)
    data=raw[:-X.FORMAT_BYTES];h=qs(r.field(data,'be_record','h'));need(len(h)==32,'complete record header')
    pubtotal=sum(row['kind']in(1,5,7)for row in ref['rows'])
    if native_mode:
        need(h[:26]==(0x3146454232494c,1,len(data),n,0,0,0,n,0,4*n+2,0,0,0,n,n,n,n,n,n,0,
                      pubtotal,pubtotal,pubtotal,pubtotal,0,0),'complete exact successful finite prefixes')
    else:
        need(h[:26]==(0x3146454232494c,1,len(data),n,0,0,0,n,0,4*n+2,0,0,0,n,0,n,n,n,0,n,
                      pubtotal,pubtotal,pubtotal,pubtotal,0,0),'complete exact scripted finite prefixes')
    lo,extent,bias=h[26:29];need(lo>0 and extent>0 and lo<=U64-extent and bias>0 and bias%4096==0,
                              'actual guarded stack and bridge load bias')
    symbols=layout['symbols']
    if native_mode:
        need(type(symbols)is dict and set(symbols)=={
            'be_record','b2_format_record','be_policy_callback','be_policy_post','be_policy_context'}and
            all(type(v)is int and 0<v<=U64-bias for v in symbols.values()),'actual emitted ELF symbols')
        need(h[29:]==tuple(bias+symbols[k]for k in('be_policy_callback','be_policy_post','be_policy_context')),
             'actual linked immutable callback/post/context binding')
    else:
        need(type(symbols)is dict and set(symbols)=={'be_record','b2_format_record','be_policy_callback','be_policy_context'}and
            all(type(v)is int and 0<v<=U64-bias for v in symbols.values()),'actual scripted ELF has no post callback symbol')
        need(h[29:]==(bias+symbols['be_policy_callback'],0,bias+symbols['be_policy_context']),
             'actual immutable scripted binding with null post-native callback')
    for name,size in(('be_record',len(data)),('b2_format_record',X.FORMAT_BYTES)):
        at=bias+symbols[name]
        need(at<=U64-size and not(at<lo+extent and lo<at+size)and
             not(at<B.BASE+20480 and B.BASE<at+size)and not(at<B.DATA+B.N and B.DATA<at+size),
             'actual private record storage disjoint from live frame and fixture')
    hardware_raw=r.field(data,'be_record','hardware');cp=format_facts['cpuid']
    hardware={name:tuple(cp[i][2:])for i,name in enumerate(('leaf0','leaf1','leaf7'))}
    r.exact(hardware_raw,'li2_selected_hardware',abi_version=1,reserved=0,
            **{k:words(v,4)for k,v in hardware.items()})
    need(hardware['leaf1'][2]>>30&1 and hardware['leaf7'][1]>>18&1 and hardware['leaf7'][2]>>22&1,
         'actual RDRAND/RDSEED/RDPID features required, no fallback or skip')
    # These fixed source types are wire authorities, not inferred from h[].
    need(layout['b2_snapshot']=={'bytes':B.SNAPSHOT_BYTES,'fields':{
        'h':{'offset':0,'bytes':128},'si':{'offset':128,'bytes':128},'uc':{'offset':256,'bytes':2048},
        'fp':{'offset':2304,'bytes':65536},'source':{'offset':67840,'bytes':20480},
        'data':{'offset':88320,'bytes':8192}}},'unchanged complete B2 snapshot layout')
    rows=r.field(data,'be_record','rows');rs=r.size('be_row')
    need(len(rows)==4*rs and not any(rows[n*rs:]),'all unused physical rows remain zero')
    bases=[];object_id=None;page_ids={};pubordinal=cpordinal=0;counts=[0]*7
    fault_zero=bytes(r.size('li2_effect_fault'));row_values=[]
    for index,row0 in enumerate(ref['rows']):
        row=dict(row0,_source=ref['source']);kind=row['kind'];counts[kind-1]+=1
        if kind==1:cpordinal+=1
        canonical=kind in(1,5,7)
        if canonical:pubordinal+=1
        rr=rows[index*rs:(index+1)*rs];get=lambda k:r.field(rr,'be_row',k)
        if native_mode:
            expected_h=[2,index,kind,int(canonical),1,1,int(canonical),0]+[index+1]*4+[0,301,0,0,1,8,0,1,int(kind in(2,3,4)),0]+[0]*10
        else:
            expected_h=[2,index,kind,int(canonical),1,1,int(canonical),0]+[index+1]*3+[0,index+1,301,0,0,1,8,0,0,0,0]+[0]*10
        need(qs(get('h'))==tuple(expected_h),'every real per-row prefix')
        owner=get('owner');inp=r.field(owner,'li2_effect_owner','input')
        sources=r.field(inp,'li2_effect_input','source');ss=r.size('li2_effect_source');first=sources[:ss]
        source={k:r.uint(first,'li2_effect_source',k)for k in('page','object_id','allocation','generation','offset','backing','reserved')}
        pc=row['before']['registers']['rip'];page=pc&~4095
        need(source['page']==page and source['offset']==page-B.BASE and source['backing']==1 and
             source['reserved']==0 and min(source['object_id'],source['allocation'],source['generation'])>0,
             'actual sealed original main source identity')
        if object_id is None:object_id=source['object_id']
        need(source['object_id']==object_id,'same actual immutable main object')
        if page in page_ids:
            allocation,generation=page_ids[page]
            need(source['allocation']==allocation and(source['generation']>generation if canonical else
                 source['generation']==generation),'same live page allocation and exact generation transition')
        page_ids[page]=(source['allocation'],source['generation'])
        r.exact(first,'li2_effect_source',**source)
        need(len(sources)==2*ss and not any(sources[ss:]),'zero unused source fragment')
        r.exact(inp,'li2_effect_input',abi_version=1,source_count=1,sequence=index+1,
                decoded=_decode(r,row,ref,decodes[index]),source=sources,before=_state(r,row['before']))
        landing=_publication(r,get('publication'),get('plan'),row,pubordinal,source)if canonical else pc
        if not canonical:need(not any(get('publication'))and not any(get('plan')),'direct NX makes no publication claim')
        entry=_snapshot(get('entry'),layout['layout'],False,11,(lo,extent))
        before=_snapshot(get('before'),layout['layout'],True,4 if canonical else 11,(lo,extent))
        after=_snapshot(get('after'),layout['layout'],False,4 if canonical else 11,(lo,extent))
        eg=entry['greg'];need(eg[20]==14 and eg[19]==21 and eg[22]==B.q(entry['si'],16)==pc,
                             'genuine first original NX/execute fault')
        _architecture(entry,row['before'],ref,format_facts,held=False,ingress=True)
        need(entry['header'][0:4]==before['header'][0:4]==after['header'][0:4]and
             entry['header'][6:12]==before['header'][6:12]==after['header'][6:12]and
             entry['header'][13:15]==before['header'][13:15]==after['header'][13:15],
             'same real frame/FP/si addresses and selectors')
        expected_uc=bytearray(entry['uc']);go=layout['layout']['greg']
        if canonical:
            for slot,value in((16,landing),(19,0),(20,6)):struct.pack_into('<Q',expected_uc,go+slot*8,value)
            need(before['greg'][22]==pc and B.q(before['si'],16)==landing,
                 'genuine restored UD2 keeps original CR2 and actual landing si_addr')
            expected_si=bytearray(entry['si'])
            struct.pack_into('<i',expected_si,0,4)
            struct.pack_into('<Q',expected_si,16,landing)
            need(before['si']==expected_si,'whole actual NX-to-UD2 siginfo origin transition')
            # libc's ucontext_t can extend into the kernel's adjacent siginfo.
            # Project only the independently checked signal-origin writes into
            # their actual overlapping addresses; retain both raw observations.
            ua,sa=entry['header'][2],entry['header'][13]
            first,end=max(ua,sa),min(ua+len(expected_uc),sa+len(expected_si))
            if first<end:expected_uc[first-ua:end-ua]=expected_si[first-sa:end-sa]
        else:need(entry['si']==before['si'],'direct NX same actual complete siginfo')
        need(before['uc']==expected_uc and before['fp']==entry['fp']==after['fp']and
             before['si']==after['si'],'whole actual ingress/FP/siginfo preserved, no normalized record')
        logical_before=dict(row['before'],registers=dict(row['before']['registers'],rip=landing))
        _architecture(before,logical_before,ref,format_facts,held=True,ingress=True)
        _architecture(after,row['after'],ref,format_facts,held=False,ingress=False)
        for name,slot in zip(B.GPRS,B.GREG):struct.pack_into('<Q',expected_uc,go+slot*8,row['after']['registers'][name])
        for slot,key in((16,'rip'),(17,'eflags')):struct.pack_into('<Q',expected_uc,go+slot*8,row['after']['registers'][key])
        need(after['uc']==expected_uc,'full real returned UC differs only by exact reference effect')
        for observed in(entry,after):
            bases.extend([(0x1003,1,1,0,observed['header'][4]),(0x1004,1,1,0,observed['header'][5])])
        need(entry['header'][4:6]==after['header'][4:6],'same actual bases before borrow and after retirement')
        if native_mode:
            native=_native(r,row,owner,get('backend'),get('random'),get('builtin'),hardware,pid,cpordinal)
        else:native=_scripted(r,row,get('backend'),get('random'),get('builtin'))
        logical=_result(r,kind,cpuid=row['values'])if kind==1 else _result(r,kind,value=row['values'][0],
            carry=row['carry']if kind in(2,3)else 0,aux=row['values'][1]if kind==6 else 0)
        if native_mode:
            r.exact(owner,'li2_effect_owner',phase=9,first_error=0,callback_entered=1,callback_returned=1,
                native_entered=1,native_returned=1,exit_entered=0,committed=1,post_guards_complete=1,
                post_callback_entered=1,post_callback_returned=1,callback_status=0,post_callback_status=0,input=inp,
                binding=r.pack('li2_effect_binding',dict(abi_version=1,reserved=0,callback=h[29],post_native=h[30],context=h[31])),
                decision=r.pack('li2_effect_decision',dict(action=1,reserved=0,result=bytes(r.size('li2_effect_result')),fault=fault_zero)),
                native_result=native,result=logical,fault=fault_zero)
        else:
            r.exact(owner,'li2_effect_owner',phase=9,first_error=0,callback_entered=1,callback_returned=1,
                native_entered=0,native_returned=0,exit_entered=0,committed=1,post_guards_complete=0,
                post_callback_entered=0,post_callback_returned=0,callback_status=0,post_callback_status=0,input=inp,
                binding=r.pack('li2_effect_binding',dict(abi_version=1,reserved=0,callback=h[29],post_native=0,context=h[31])),
                decision=r.pack('li2_effect_decision',dict(action=2,reserved=0,result=logical,fault=fault_zero)),
                native_result=native,result=logical,fault=fault_zero)
        need(get('applied')==_state(r,row['after']),'complete actual committed descriptive state')
        row_values.append(r.exact(rr,'be_row',**{k:get(k)for k in
            ('h','backend','publication','entry','before','after','owner','applied','random','builtin','plan')}))
    final_raw=r.field(data,'be_record','final');final=_snapshot(final_raw,layout['layout'],False,11,(lo,extent))
    final_result=B.final_entry(ref,final_raw,layout['layout'])
    X.pair(ref['rows'][-1]['after']['xstate'],final['fp'],format_facts,B)
    bases.extend([(0x1003,1,1,0,final['header'][4]),(0x1004,1,1,0,final['header'][5])])
    base_bytes=words([v for row in bases for v in row])+bytes((32-len(bases))*40)
    r.exact(data,'be_record',h=words(h),bases=base_bytes,hardware=hardware_raw,
            rows=b''.join(row_values)+bytes((4-n)*rs),final=final_raw)
    return dict(accepted=True,profile='effect-b2-native-post-v1'if native_mode else 'effect-b2-scripted-v1',case=ref['case'],selected=n,classes=counts,
        actual_native=n if native_mode else 0,post_native=n if native_mode else 0,scripted=0 if native_mode else n,
        original_nx=n,restored_ud2=pubtotal,direct_nx=n-pubtotal,
        published=pubtotal,restored=pubtotal,retired=pubtotal,pid=pid,cpu=cpu,
        reference_sha256=ref['sha256'],record_sha256=hashlib.sha256(raw).hexdigest(),
        full_state_equal=True,full_fp_equal=True,all_record_bytes_classified=True,
        terminal=final_result,whole_program_completion=False,registered_rseq_claim=False)

def cohort(results,*,policy='native-post'):
    need(type(policy)is str and policy in ('native-post','scripted'),'explicit exact cohort policy')
    native_mode=policy=='native-post'
    need(type(results)is list and len(results)==5 and all(type(r)is dict and r.get('accepted')is True for r in results),
         'all five accepted real finite records')
    need([r['case']for r in results]==[name for name,_ in B.LITERALS]and
         len({r['pid']for r in results})==5 and len({r['cpu']for r in results})==1,
         'fixed ordered independent actual subjects on one reserved CPU')
    expected_profile='effect-b2-native-post-v1'if native_mode else 'effect-b2-scripted-v1'
    need(all(r['profile']==expected_profile and r['actual_native']==(r['selected']if native_mode else 0)and
             r['post_native']==(r['selected']if native_mode else 0)and r['scripted']==(0 if native_mode else r['selected'])
             for r in results),'no mixed-policy or substituted effect cohort')
    need([sum(r['classes'][i]for r in results)for i in range(7)]==[2,2,4,3,4,1,1]and
         sum(r['selected']for r in results)==17 and sum(r['restored_ud2']for r in results)==7 and
         sum(r['direct_nx']for r in results)==10,'unchanged seventeen operations, all seven classes and exact ingress routes')
    return dict(accepted=True,subjects=5,selected=17,classes=[2,2,4,3,4,1,1],
        actual_native=17 if native_mode else 0,post_native=17 if native_mode else 0,scripted=0 if native_mode else 17,
        restored_ud2=7,direct_nx=10,
        whole_program_completion=False,registered_rseq_claim=False)
