"""Actual dedicated pre-edge v2 primitive capture.
Mode0 validates generated completion followed by a real ordinary data fault.
Mode1 validates failed physical revoke with no source release or permit.
Neither scope replaces primitive9, full26 or reuse65 qualification.
"""
import hashlib,struct,json
from pathlib import Path
import importlib.util
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

HERE=Path(__file__).resolve().parent
wire=load('preedge_failure_wire',HERE/'wire.py');plan=load('preedge_failure_plan',HERE/'plan.py')
span=load('preedge_trace_helpers',HERE.parent/'scalar_span_trace_owner/read.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=old.DATA,old.STACK,old.RSP
P,L,R=old.P,old.L,old.R
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
COUNTS='initialized used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks generation retirement_attempts retirements claims permits_issued pending retiring cursor first_error first_detail decoding closing resuming live_checks proof_checks proof_pending proof_arena proof_bytes proof_registry refaults graph_refaults cut_exits'.split()
def elf_symbols(data):
    registered=wire.REGISTERED
    h,loads=old.elf(data)
    need(h[11]==64 and h[12]>0 and h[6]+h[12]*64<=len(data),'whole actual bridge section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    symbols={}
    for s in sections:
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[6]<len(sections) and s[4]+s[5]<=len(data),'actual complete ELF symbol table')
        tab=sections[s[6]];need(tab[1]==3 and tab[4]+tab[5]<=len(data),'actual symbol string table');strings=data[tab[4]:tab[4]+tab[5]]
        for at in range(s[4],s[4]+s[5],24):
            name,info,other,section,address,size=struct.unpack_from('<IBBHQQ',data,at)
            if not section or not name:continue
            end=strings.find(b'\0',name);need(0<=name<end<len(strings),'bounded symbol name')
            name=strings[name:end].decode('ascii')
            if name in registered or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(registered)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols


class Check(span.Check):
    def __init__(self,reader,image,app,pid,cpu,control):
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'lpec_wire','h'));self.control_words=q(self.f(self.b,'lpec_wire','control'))
        self.bias=self.h[9]-reader.layout['symbols']['li2_raw6'];self.head=app['head'];self.page=self.head&-PAGE
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'actual explicit object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual original object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(reader.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(reader.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'actual same emitted bridge and DWARF symbols')
        self.storage=q(self.f(self.b,'lpec_wire','storage'));self.counts=dict(zip(COUNTS,q(self.f(self.b,'lpec_wire','counts')),strict=True))
        self.entries=self.r.items(self.b,'lpec_wire','entries','lpec_entry')
        self.entry=self.entries[0];self.record=self.f(self.entry,'lpec_entry','owner')

    def header(self,status):
        h=self.h;r=self.r;t='lpec_wire';mode=self.app['mode'];c=self.control
        need(status==125 and c==0 and mode in(0,1),'exact required cut-failure outcome');code,detail=(7,11)if mode==0 else(3103,9)
        need(h[:9]==(0x324f43454c49324c,2,r.types[t]['bytes'],r.types['lpec_entry']['bytes'],r.types['le_record']['bytes'],r.types['le_slot']['bytes'],r.types['le_frame']['bytes'],968,128),'whole actual linked capture version/type extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted bridge bias and gateway')
        need(canonical(h[12],h[13])and h[12]%PAGE==0 and h[13]==524288,'whole actual altstack')
        need(h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual exclusive regular0600 FD3 sink')
        count=1
        need(h[20]==self.head and h[22]==self.image['main_object']and h[23:26]==(1,mode,count)and h[26:30]==(1,status,code,detail),'exact source, invocation population and required failure')
        need(h[39:43]==(0,0,h[16],0)and h[45]<=h[44]<=h[43]and h[46]<=h[43]and h[47:50]==(0,0,0)and h[50:52]==(1,1)and h[57]==1 and h[63]==0,'complete diagnostics/sink closure')
        need(h[52:57]==tuple(self.symbol(k)for k in('selected_linked_epoch','span_progress','ler','selected_chain','lpec_wire')),'actual protected owner addresses')
        control=self.control_words
        need(control[:5]==((0,0,0,0,0)if mode==0 else(1,1,1,1,0))and control[6]>=control[5]and control[6]-control[5]==int(mode==0)and control[6]==self.counts['cut_exits']and not any(control[7:]),'actual mode-specific munmap and completed-cut counter delta')
        for key in('sink_initial','sink_terminal'):
            b=self.f(self.b,t,key);st=self.stat(b);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual empty0600 sink');self.eq(b,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x324643454c49324c,2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'whole actual record/footer/write completion')
        if footer[4]==1:need(footer[5]==len(self.b),'single complete actual write')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        spans=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+PAGE<=bias+p[3]+p[5]]
        need(len(spans)==1 and h[21]==spans[0][2]+self.page-bias-spans[0][3]and obj['data'][h[21]:h[21]+PAGE]==self.app['source']==self.f(self.b,t,'original_source'),'whole actual retained main source')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual initial CPU facts')
        return dict(status=status,failure_code=code,detail_abs=detail,detail_negative=0)

    def registry(self,b):
        t='spto_registry';self.eq(b,t,complete=1,table=self.symbol('protected'));count=self.i(b,t,'count');need(0<count<=128,'bounded actual registration table')
        rows=self.r.items(b,t,'ranges','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:count]]
        for row in rows[count:]:zero(row,'whole unused protected range')
        need(all(canonical(a,z-a)for a,z in ranges),'whole actual protected byte intervals')
        kinds=self.f(b,t,'initial_code');need(not any(kinds[count:])and all(x in(0,1)for x in kinds),'literal initial-code classification')
        im=self.f(b,t,'bridge');self.eq(im,'image',bias=self.bias,entry=self.bias+self.eh[4],n=len(self.ph),source=0,source_size=0,backing_fd=(1<<32)-1,kind=3)
        zero(self.f(im,'image','source_hash'),'no invented original bridge hash');need(canonical(self.i(im,'image','ph'),56*len(self.ph)),'actual program header pointer')
        need(self.f(b,t,'ph')==b''.join(struct.pack('<IIQQQQQQ',*p)for p in self.ph)+bytes((32-len(self.ph))*56),'all actual bridge program headers')
        objects=[];decl=self.r.layout['registrations'];need(set(decl)==set(self.r.registered),'all exact byte-registration source witnesses')
        headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
        for name,(source,tag)in self.r.registered.items():
            d=decl[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual symbol/DWARF/source-selected registration '+name)
            need(d['source']in headers and type(headers[d['source']])is dict and set(headers[d['source']])=={'bytes','sha256'},'every actual DWARF origin belongs to the complete compiler-M closure')
            if name not in self.r.lifetime:need(ranges.count((a,z))==1 and kinds[ranges.index((a,z))]==0,'whole strict registered object extent')
            loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
            need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole registered object in one RW/NX load')
            p=loads[0];rounded=((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE)
            need(ranges.count(rounded)==1 and kinds[ranges.index(rounded)]==0,'whole bridge load strict protection');objects.append((a,z))
        need(all(a%PAGE==z%PAGE==0 or(a,z)in objects for a,z in ranges),'every non-page interval is an exact source registration')
        for i,kind in enumerate(kinds[:count]):
            if not kind:continue
            a,z=ranges[i];matches=[]
            for key in ('main_object','interpreter_object'):
                obj,_,loads=self.objects[self.image[key]];bias=self.bases[self.image[key]]
                matches += [p for p in loads if p[1]&1 and ((bias+p[3])&-PAGE,(bias+p[3]+p[6]+PAGE-1)&-PAGE)==(a,z)]
            need(len(matches)==1,'initial protection exception names one original executable load')
        return ranges,kinds[:count]

    def arena(self,initial,terminal):
        high,low,n,proof,pn,registry,epoch,reuse=self.storage
        need(n==64*PAGE and pn==64*65536 and registry==self.symbol('lep')and epoch==self.symbol('preedge_epoch')and reuse==self.symbol('ler'),'actual immutable arena and owner identities')
        ranges=((high,n),(low,n),(proof,pn))
        need(all(canonical(a,n)and a%PAGE==0 for a,n in ranges)and low+n<=1<<31 and all(a+n<=b or b+m<=a for i,(a,n)in enumerate(ranges)for b,m in ranges[i+1:]),'whole disjoint nonwrapping code/proof arenas')
        for a,n in ranges:
            for actual,kinds in(initial,terminal):need(actual.count((a,a+n))==1 and kinds[actual.index((a,a+n))]==0,'whole strict actual anonymous arena registration')
        for i,query in enumerate(self.r.items(self.b,'lpec_wire','initial_code','li2_private_code_query')):self.query(query,(high,low)[i],3,pages=64)
        for i,query in enumerate(self.r.items(self.b,'lpec_wire','initial_proof','li2_private_code_query')):self.query(query,proof+i*64*PAGE,3,pages=64)

    def proof_permission(self,b,address,prot):
        self.eq(b,'le_permission',started=1,returned=1,sync_started=1,sync_returned=1,complete=1,prot=prot,result=0,sync_result=0)
        self.query(self.f(b,'le_permission','query'),address,prot,pages=16)

    def proof(self,e,source,record):
        slot=self.f(e,'lpec_entry','slot');index=self.i(record,'le_record','slot');generation=self.i(record,'le_record','publication_generation')
        need(0<=index<64 and 0<generation<=self.counts['generation'],'actual occupied slot and monotonic generation')
        generated=self.storage[1]+index*PAGE;address=self.storage[3]+index*65536
        self.eq(slot,'le_slot',installed=1,complete=1,identity=generation,filled=PAGE,verified=PAGE,generated=generated,proof=address)
        self.query(self.f(slot,'le_slot','writable'),generated,3);self.permission(self.f(slot,'le_slot','publication'),generated,1)
        p=self.f(e,'lpec_entry','proof');h=self.f(p,'li2_preedge_proof','header');pt='li2_preedge_proof_header'
        self.eq(h,pt,version=2,bytes=65536,registry=self.symbol('lep'),slot=index,generation=generation,generated=generated)
        zero(self.f(h,pt,'reserved'),'whole immutable proof reserved capacity')
        binding=self.image['binding'];need(type(binding)is dict and binding['version']==1,'actual source-pinned production binding')
        need(self.f(h,pt,'archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(h,pt,'policy')==bytes.fromhex(binding['policy_sha256']),'actual archive and universal NONE policy binding')
        cp,cn=self.v(h,pt,'plan_proof none_proof');need(0<cp<=self.counts['plan_checks']and 0<cn<=self.counts['rseq_checks'],'actual completed cold proof ordinals')
        key=self.f(p,'li2_preedge_proof','key');self.eq(key,'li2_span_source_key',entry=self.head)
        self.r.change(key,source['key'],'li2_span_source_key',observed=('backing',));self.backing(self.f(key,'li2_span_source_key','backing'))
        need(self.v(self.f(key,'li2_span_source_key','backing'),'li2_fetch_backing','retained_fd seals')==self.v(self.f(source['key'],'li2_span_source_key','backing'),'li2_fetch_backing','retained_fd seals'),'exact actual retained descriptor/seals')
        expected,image,heads=plan.plan(self.app['source'],self.page,self.head,generated,self.app['mode'])
        need(self.f(p,'li2_preedge_proof','plan')==expected,'whole independent reachable graph, descriptor effects, links and PC table')
        need(self.f(e,'lpec_entry','generated_page')==image and self.i(e,'lpec_entry','generated_bytes')==PAGE,'every emitted byte and untouched CC gap')
        need(self.i(e,'lpec_entry','proof_bytes')==65536 and self.i(e,'lpec_entry','ready_generation')==generation,'actual full primary proof and readiness generation')
        zero(self.f(e,'lpec_entry','proof_tail'),'entire actual immutable proof tail')
        publication=self.f(e,'lpec_entry','proof_publication');t='le_proof_publication'
        self.eq(publication,t,started=1,complete=1,zeroed=65536,copied=self.r.types['li2_preedge_proof']['bytes'],verified=65536)
        need(self.f(publication,t,'header')==h,'every actual immutable/publisher anchor byte')
        self.query(self.f(publication,t,'writable'),address,3,pages=16);self.proof_permission(self.f(publication,t,'sealed'),address,1)
        return dict(address=address,generated=generated,index=index,generation=generation,plan=expected,heads=heads,raw=p,cp=cp,cn=cn)

    def epoch(self,e,source,p,completed,entered):
        t='li2_preedge_epoch_progress';held=self.f(e,'lpec_entry','epoch_held');opened=self.f(e,'lpec_entry','epoch_opened');terminal=self.f(e,'lpec_entry','epoch_terminal')
        self.eq(held,t,phase=1,first_error=0,first_detail=0,release_started=0,release_complete=0,publication=p['generation'],borrow=source['borrow'],source=self.page,generated=p['generated'])
        serial,allocation,generation,transactions,records=self.v(held,t,'serial allocation_epoch generation_epoch transactions_epoch records_epoch')
        page=self.f(source['key'],'li2_span_source_key','page')
        need(serial==q(self.f(e,'lpec_entry','counts_before'))[0]+1 and allocation>=self.i(page,'li2_fetch_page','allocation')and generation>=self.i(page,'li2_fetch_page','generation')and transactions>0 and records>0,'actual source lifetime epochs and serial')
        for k in('opened','closed'):zero(self.f(held,t,k),'no physical RX or release before actual grant')
        if entered:
            self.r.change(held,opened,t,observed=('phase','opened'));self.eq(opened,t,phase=2);self.query(self.f(opened,t,'opened'),p['generated'],5)
        else:zero(opened,'no invented executable epoch')
        if completed:
            self.r.change(opened,terminal,t,observed=('phase','release_started','release_complete','closed'))
            self.eq(terminal,t,phase=4,release_started=1,release_complete=1);self.query(self.f(terminal,t,'closed'),p['generated'],1)
        elif self.control==2:
            self.r.change(held,terminal,t,observed=('first_error','first_detail'));self.eq(terminal,t,first_error=302,first_detail=401)
        else:need(terminal==(opened if entered else held),'failed prefix retains actual unreleased epoch; inactive is not release')
        return dict(serial=serial,generation=generation,allocation=allocation,transactions=transactions,records=records,raw=terminal)

    def live_rseq(self,b,state,frame):
        t='li2_link_rseq_live';self.eq(b,t,attempted=1,complete=1,result=0,session=self.symbol('selected_session'),epoch=self.i(state,'li2_rseq_state','epoch'),registered=self.i(state,'li2_rseq_state','registered'))
        regs=self.f(b,t,'registers');self.eq(regs,'li2_write_registers',fs_base=self.i(state,'li2_rseq_state','fs_base'),gs_base=self.i(state,'li2_rseq_state','gs_base'))
        need(q(self.f(regs,'li2_write_registers','gpr'))==tuple(frame['greg'][i]for i in GREG),'every actual live rseq GPR')
        if self.i(state,'li2_rseq_state','registered'):need(self.v(regs,'li2_write_registers','fs_base gs_base')==(frame['fs'],frame['gs']),'registered current TLS bound to actual frame')

    def rseq_transition(self,e,record,before,after,cold,entered,completed,attempt):
        st='li2_rseq_state';a=self.f(self.f(e,'lpec_entry','source_owners'),'lpec_owners','rseq')
        self.owners(self.f(e,'lpec_entry','source_owners'))
        endpoint=self.f(e,'lpec_entry','redirected_owners')if entered else self.f(self.b,'lpec_wire','terminal_owners')
        self.owners(endpoint,redirected=entered);b=self.f(endpoint,'lpec_owners','rseq')
        if cold:
            self.r.change(a,b,st,observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'))
            self.eq(b,st,last_first=0,last_end=0,last_pc=self.head+25,last_code=357,last_policy=1)
            self.eq(self.f(b,st,'last_footprint'),'li2_write_footprint',pc=self.head+25,next_pc=self.head+30,first=0,end=0,abi_version=1,policy=1,code=357,length=5)
        else:need(a==b,'whole hit rseq state unchanged; no fictitious cold footprint update')
        reg=0
        self.eq(b,st,registered=0,held=0,phase=0,calls=0,epoch=0,registrations=0,unregistrations=0,kernel_errors=0)
        if reg:self.eq(b,st,address=0x500000200000,page=0x500000200000,length=32,signature=0x53053053)
        if completed:
            out=self.f(e,'lpec_entry','completed_owners');self.owners(out)
            need(self.f(out,'lpec_owners','rseq')==b,'whole actual live-only exit rseq state conserved')
        else:zero(self.f(e,'lpec_entry','completed_owners'),'no failed completion owner bundle')
        observations=self.r.items(record,'le_record','live_rseq','li2_link_rseq_live')
        wanted=(not cold,True,entered,True)
        for i,(item,used)in enumerate(zip(observations,wanted,strict=True)):
            if not used:zero(item,'unexecuted live guard snapshot')
            else:self.live_rseq(item,b,after if i==3 else before)


    def invocation(self,e):
        self.entry=e;self.record=r=self.f(e,'lpec_entry','owner');t='le_record';et='lpec_entry';completed=self.app['mode']==0
        self.eq(e,et,present=1,closed=1,source_ready=1,redirected=1,completed=int(completed),terminal=1,source_bytes=PAGE,terminal_source_bytes=PAGE,frontier_closed=0)
        need(self.f(e,et,'source_page')==self.f(e,et,'terminal_source_page')==self.app['source'],'whole original source through released epoch')
        before=self.frame(self.f(r,t,'before'));ingress=self.normalized(self.f(r,t,'ingress'),before)
        self.trace(ingress,self.head,self.app['seed'][1]|TF);self.trace(before,self.head,self.app['seed'][1]);self.same_event(ingress,before,self.app['seed'][1])
        need((before['fs'],before['gs'])==tuple(self.app['machine'][1:3]),'actual per-lane TLS before entry')
        pi,closed_slot,oldref,predecessor=self.closed_transition(self.f(e,et,'predecessor'),self.f(e,et,'closed_chain'),self.head-2,ingress)
        source=self.source(self.f(r,t,'source'));self.transfer(self.f(r,t,'transfer'),source,closed_slot,pi,False)
        self.eq(self.f(r,t,'transfer'),'li2_span_transfer_progress',refault_attempted=0,refaulted=0)
        self.eq(r,t,refault_started=0,refault_complete=0,refault_result=0,hint_checked=0,hint_hit=0,hint_publication=0)
        self.eq(r,t,slot_present=1,redirected=1,completed=int(completed),release_started=int(completed),release_complete=int(completed),release_result=0,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,prepare_result=0,miss_release_started=0,miss_release_complete=0,miss_release_result=0,resume_started=0,resume_complete=0,resume_result=0,resumed_route=0,flags=self.app['seed'][1],gpr_written=1,flags_written=0)
        zero(self.f(r,t,'miss_fetch'),'accepted primitive has no descriptive fallback')
        p=self.proof(e,source,r);generated=p['generated'];cold=bool(self.i(r,t,'build_started'))
        self.eq(r,t,build_started=int(cold),build_returned=int(cold),build_result=0)
        if cold:self.eq(r,t,cold_plan_proof=p['cp'],cold_none_proof=p['cn']);zero(self.f(r,t,'proof_before'),'cold entry has no hit guard')
        else:self.eq(r,t,cold_plan_proof=0,cold_none_proof=0);self.query(self.f(r,t,'proof_before'),p['address'],1,pages=16)
        self.query(self.f(r,t,'proof_enter'),p['address'],1,pages=16);self.query(self.f(r,t,'idle'),generated,1);self.eq(r,t,idle_bytes=PAGE)
        self.eq(self.f(r,t,'epoch'),'li2_preedge_epoch_token',owner=self.symbol('preedge_epoch'),serial=self.i(self.f(e,et,'epoch_held'),'li2_preedge_epoch_progress','serial'))
        self.permission(self.f(r,t,'open'),generated,5);self.query(self.f(r,t,'live'),generated,5);self.eq(r,t,live_bytes=PAGE)
        need(self.i(e,et,'redirect_event')==self.i(e,et,'ingress_event')>0 and self.i(e,et,'terminal_event')==self.i(e,et,'redirect_event')+1,'one real original NX after redirect, zero interior events')
        after=self.frame(self.f(r,t,'after'));self.nx(after,self.app['cut_pc'])
        self.eq(r,t,exit_seen=1,exit_index=0,unexpected_seen=0,map_result=0)
        need(before['fp']==after['fp']and before['fp_bytes']==after['fp_bytes']and before['mask']==after['mask']and(before['fs'],before['gs'])==(after['fs'],after['gs']),'full FP/mask/TLS conservation at original cut')
        need(before['uc'][:40]==after['uc'][:40]and before['uc'][296:304]==after['uc'][296:304],'same actual UC envelope and full kernel mask')
        expected=list(before['greg']);expected[13]=7;expected[16]=self.app['cut_pc'];expected[17]|=RF;expected[19:21]=[21,14];expected[22]=self.app['cut_pc']
        need(after['greg']==tuple(expected),'six MOV effects only; whole cut has not executed at source NX')
        zero(self.f(r,t,'unexpected'),'original cut NX is expected');zero(self.f(r,t,'original'),'original cut has no generated fault association')
        self.query(self.f(r,t,'proof_exit'),p['address'],1,pages=16)
        self.permission(self.f(r,t,'close'),generated,1,error=0 if completed else -12)
        self.eq(r,t,closed_bytes=PAGE if completed else 0,cleanup_started=int(not completed),cleanup_complete=0)
        if completed:
            zero(self.f(r,t,'cleanup'),'successful generated close has no abort cleanup')
            self.progress(self.f(r,t,'final_fetch'),source['borrow'],False)
            self.eq(self.f(e,et,'permit'),'ler_permit',generation=p['generation'],completion=q(self.f(e,et,'counts_after'))[1],valid=1)
            need(self.f(e,et,'proof_final')==p['raw']and self.i(e,et,'proof_final_bytes')==65536,'entire immutable proof through completed release');zero(self.f(e,et,'proof_final_tail'),'whole immutable final tail')
        else:
            self.permission(self.f(r,t,'cleanup'),generated,1,error=-12)
            self.progress(self.f(r,t,'final_fetch'),source['borrow'],True)
            need(self.f(r,t,'final_fetch')==self.f(self.b,'lpec_wire','terminal_fetch'),'actual still-held generated source after failed cleanup')
            self.eq(self.f(e,et,'permit'),'ler_permit',valid=0)
            self.eq(e,et,proof_final_bytes=0);zero(self.f(e,et,'proof_final'),'no fabricated completed proof reread');zero(self.f(e,et,'proof_final_tail'),'no fabricated final proof tail')
        ep=self.epoch(e,source,p,completed,True)
        if completed:need(self.f(r,t,'epoch_final')==ep['raw'],'whole returned typed release')
        else:zero(self.f(r,t,'epoch_final'),'no return from epoch release on failed revoke')
        self.rseq_transition(e,r,before,after,cold,True,completed,0)
        a,z=(q(self.f(e,et,k))for k in('counts_before','counts_after'));need(all(y>=x for x,y in zip(a,z,strict=True)),'monotonic actual counters')
        delta=tuple(y-x for x,y in zip(a,z,strict=True));retirement=delta[8]
        need(retirement in(0,1)and delta==(1,int(completed),int(cold)+retirement,int(cold),3+int(not cold),2+int(not cold),int(cold),int(not cold),retirement,retirement),'exact cold/hit proof calls and actual retirement accounting; no replacement qualification claim')
        result=dict(ingress=ingress,before=before,predecessor_before=predecessor,after=after,source=self.app['source'],terminal_source=self.app['source'],proof=p,epoch=ep,disposition='ordinary_fault_after_release'if completed else'failed_epoch_revoke',frontier_kind=2,before_memory=self.memory(self.f(e,et,'before_memory')),after_memory=self.memory(self.f(e,et,'after_memory'),after_abort=not completed))
        return self.post_cut(result)if completed else self.no_post(result)

    def page_at(self,b,address):
        page,h=self.page,self.h
        try:
            self.page=address;words=list(h);words[21]+=address-page;self.h=tuple(words)
            return self.page_row(b)
        finally:self.page,self.h=page,h

    def post_cut(self,result):
        et='lpec_entry';w='lpec_wire';ct='li2_tf_chain';st='li2_tf_chain_slot';ot='li2_tf_owner';qt='li2_step_owner'
        h=q(self.f(self.b,w,'post'));event=self.i(self.entry,et,'terminal_event')+1
        need(h==(1,event,2,1,1,2,0,0),'actual next datafault before handler and terminal failed-chain snapshot; handler never returned')
        post=self.frame(self.f(self.b,w,'post_cut'),False);post.update(fs=result['after']['fs'],gs=result['after']['gs'])
        # The whole admitted original cut is a MOV load. It has no TLS, flags,
        # memory-write or committed destination effect when its data access faults.
        g=post['greg'];want=list(result['after']['greg']);want[17]|=TF;want[19]=4;want[22]=DATA+8192
        need(post['sig']==11 and struct.unpack_from('<iii',post['si'])==(11,0,2)and int.from_bytes(post['si'][16:24],'little')==DATA+8192 and g==tuple(want),'actual original-PC data fault before any load effect')
        need(post['fp']==result['after']['fp']and post['fp_bytes']==result['after']['fp_bytes']and post['mask']==result['after']['mask'],'whole fault FP/mask unchanged')
        need(post['uc'][:40]==result['after']['uc'][:40]and post['uc'][296:304]==result['after']['uc'][296:304],'whole fault UC envelope and application mask')
        a,b=(self.f(self.b,w,k)for k in('post_before','post_after'));index=self.i(a,ct,'active')
        need(index in(0,1),'actual original-cut slot')
        closed=self.f(self.entry,et,'closed_chain');previous=self.i(closed,ct,'active')
        need(index==previous^1,'actual new ordinary slot after closed generated predecessor')
        self.r.change(closed,a,ct,observed=('active','pending','event_id','attempts','nx_entries','slots','entry'))
        self.eq(a,ct,event_id=self.i(closed,ct,'event_id')+1,attempts=self.i(closed,ct,'attempts')+1,nx_entries=self.i(closed,ct,'nx_entries')+1)
        self.r.change(self.f(closed,ct,'entry'),self.f(a,ct,'entry'),'li2_tf_trace_entry',observed=('valid',))
        need(self.r.items(closed,ct,'slots',st)[previous]==self.r.items(a,ct,'slots',st)[previous],'whole closed predecessor retained through new ordinary cut admission')
        self.eq(a,ct,session=self.symbol('selected_session'),initialized=1,first_error=0,first_detail=0,pending=1,in_handler=0,unexpected_events=0)
        self.eq(b,ct,session=self.symbol('selected_session'),initialized=1,first_error=7,first_detail=11,pending=1,in_handler=0,unexpected_events=1,event_id=self.i(a,ct,'event_id')+1)
        self.r.change(a,b,ct,observed=('first_error','first_detail','event_id','unexpected_events','slots','entry'))
        self.r.change(self.f(a,ct,'entry'),self.f(b,ct,'entry'),'li2_tf_trace_entry',observed=('valid',));self.eq(self.f(b,ct,'entry'),'li2_tf_trace_entry',valid=0)
        need(self.r.items(a,ct,'slots',st)[index^1]==self.r.items(b,ct,'slots',st)[index^1],'failed cut never mutates the retained predecessor')
        x,y=(self.r.items(c,ct,'slots',st)[index]for c in(a,b));generation=self.i(x,st,'generation')
        need(generation==self.i(self.r.items(closed,ct,'slots',st)[index],st,'generation')+1 and self.f(x,st,'decoded')==self.f(y,st,'decoded'),'exact new ordinary generation and unchanged decoded cut')
        self.r.change(x,y,st,observed=('phase','owner','fetch','unexpected_frame_observed','unexpected_signal','unexpected_code','unexpected_errno','unexpected_address','unexpected'))
        decoded=result['proof']['plan'][29768:29840];window=self.app['source'][-3:]
        need(window==bytes.fromhex('448b07')and self.f(x,st,'decoded')==decoded,'whole actual three-byte ordinary cut, not truncated or generated execution')
        address=self.symbol('selected_chain')+self.r.types[ct]['fields']['slots']['offset']+index*self.r.types[st]['bytes']
        for slot,failed in((x,False),(y,True)):
            owner=self.f(slot,st,'owner');step=self.f(owner,ot,'step');fetch=self.f(slot,st,'fetch');ref=self.f(fetch,'li2_chain_fetch','ref');sequence=self.i(ref,'li2_fetch_ref','sequence')
            self.eq(slot,st,chain=self.symbol('selected_chain'),index=index,phase=7 if failed else 3,origin=1,fallback=0,generation=generation,prepare_attempted=0,prepare_complete=1,prepare_result=0,decode_attempted=1,decode_complete=1,decode_result=0,classify_result=0,retry=0,unexpected_frame_observed=int(failed),unexpected_signal=11 if failed else 0,unexpected_code=2 if failed else 0,unexpected_errno=0,unexpected_address=DATA+8192 if failed else 0)
            for key in('first_decoded','first_fetch','first_release','query','release'):zero(self.f(slot,st,key),'no invented retry, continuation or release for failed load')
            if failed:self.step_frame(self.f(slot,st,'unexpected'),post)
            else:zero(self.f(slot,st,'unexpected'),'no future data fault in running prefix')
            need(self.i(slot,st,'event_id')>0 and canonical(self.i(ref,'li2_fetch_ref','owner'))and sequence>self.i(self.f(self.f(self.record,'le_record','source'),'li2_span_source','borrow'),'li2_fetch_ref','sequence'),'actual newer ordinary borrow after generated release')
            self.eq(fetch,'li2_chain_fetch',pc=self.app['cut_pc'],length=3,page_count=1,pid=self.pid,tid=self.pid,identity_observed=1)
            need(self.f(fetch,'li2_chain_fetch','bytes')==window+bytes(12),'whole actual cut fetch and zero suffix')
            progress=self.f(fetch,'li2_chain_fetch','progress');self.eq(progress,'li2_fetch_progress',held=1,complete=1,first_error=0,first_detail=0,identity_observed=1,pages_copied=1,bytes_copied=3,sequence=sequence,last_backing_page=0,last_backing_observed=1)
            self.maps(self.f(progress,'li2_fetch_progress','preparation'));self.maps(self.f(progress,'li2_fetch_progress','validation'));need(self.i(progress,'li2_fetch_progress','validation_calls')>0,'actual whole-window source validation')
            sourcepages=self.r.items(fetch,'li2_chain_fetch','pages','li2_fetch_page');backs=self.r.items(fetch,'li2_chain_fetch','backing','li2_fetch_backing')
            self.page_at(sourcepages[0],self.page);self.backing(backs[0]);zero(sourcepages[1],'unused second source page');zero(backs[1],'unused second backing');self.backing(self.f(fetch,'li2_chain_fetch','last_backing'))
            self.eq(step,qt,phase=6 if failed else 3,first_error=7 if failed else 0,first_detail=11 if failed else 0,in_handler=0,self_test=0,trace_seen=0,revoke_sync_started=int(failed),open_sync=0,revoke_sync=0,session=self.symbol('selected_session'),destination=0,width=0,immediate=0,effect=0,source=0,signal_number=11,signal_code=2,signal_errno=0,signal_address=self.app['cut_pc'])
            hooks=self.f(step,qt,'hooks');self.eq(hooks,'li2_step_hooks',context=address)
            need(all(canonical(self.i(hooks,'li2_step_hooks',k))for k in('authenticate','failure'))and self.f(self.f(owner,ot,'hooks'),'li2_tf_hooks','step')==hooks and canonical(self.i(self.f(owner,ot,'hooks'),'li2_tf_hooks','continue_closed')),'actual ordinary cleanup callbacks')
            self.eq(owner,ot,continuation_started=0,continuation_complete=0,continuation_result=0,unexpected_frame_observed=0,actual_post_pc=0,actual_post_flags=0)
            for key in('rdssp_query_attempted','rdssp_query_complete','rdssp_query_result','rdssp_features','bnd_xcr0_attempted','bnd_xcr0_complete','bnd_xcr0'):self.eq(owner,ot,**{key:0})
            zero(self.f(owner,ot,'rdssp_observation'),'load has no special state observer')
            self.eq(self.f(owner,ot,'classification'),'li2_tf_classification',pc=self.app['cut_pc'],next_pc=self.page+PAGE,abi_version=1,policy=1,code=285,length=3,flow=1,family=1)
            request=self.f(step,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=self.app['seed'][1]);need(self.f(request,'li2_step_request','decoded')==decoded,'whole actual original MOV request')
            pages=self.r.items(request,'li2_step_request','pages','li2_step_page');sp=sourcepages[0]
            self.eq(pages[0],'li2_step_page',address=self.page,object=self.i(sp,'li2_fetch_page','allocation'),generation=self.i(sp,'li2_fetch_page','generation'),offset=self.h[21],closed_prot=1,open_prot=5);zero(pages[1],'unused permission page')
            for key in('open_started','opened'):need(struct.unpack('<2I',self.f(step,qt,key))==(1,0),'one actual original-page open')
            for key in('revoke_started','revoked'):need(struct.unpack('<2I',self.f(step,qt,key))==(int(failed),0),'failed ordinary load physically revokes exactly its source page')
            for key in('open_result','revoke_result'):zero(self.f(step,qt,key),'actual successful physical open/revoke results')
            self.step_frame(self.f(step,qt,'before'),result['after']);zero(self.f(step,qt,'after'),'foreign event is retained in slot.unexpected, not a completed TRACE')
        ox,oy=(self.f(slot,st,'owner')for slot in(x,y));self.r.change(ox,oy,ot,observed=('step',))
        self.r.change(self.f(ox,ot,'step'),self.f(oy,ot,'step'),qt,observed=('phase','first_error','first_detail','revoke_sync_started','revoke_started','revoked'))
        fx,fy=(self.f(slot,st,'fetch')for slot in(x,y));self.r.change(fx,fy,'li2_chain_fetch',observed=('progress',))
        need(self.f(self.b,w,'terminal_chain')==b and self.f(self.b,w,'terminal_fetch')==self.f(fy,'li2_chain_fetch','progress'),'actual final failed chain and held singleton; never a fabricated quiet release')
        need(self.f(self.b,w,'post_data')==self.app['data']and self.f(self.b,w,'post_stack')==self.app['stack'],'whole accessible memory after failed load')
        result.update(post_cut=post,post_memory=dict(data=self.f(self.b,w,'post_data'),stack=self.f(self.b,w,'post_stack')));return result

    def no_post(self,result):
        for key in('post','post_cut','post_before','post_after','post_data','post_stack'):zero(self.f(self.b,'lpec_wire',key),'failed revoke never reaches ordinary execution or data fault')
        return result

    def finish(self,status):
        outcome=self.header(status);c=self.counts;failed_epoch=int(self.app['mode']==1)
        terminal_transfer(self);terminal_state(self)
        session=self.f(self.b,'lpec_wire','session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')&96==96,'actual sync-core registration')
        initial,terminal=(self.registry(self.f(self.b,'lpec_wire',k))for k in('initial_registry','terminal_registry'));need(terminal[0][:len(initial[0])]==initial[0]and terminal[1][:len(initial[1])]==initial[1],'all original protected registrations retained');self.arena(initial,terminal)
        entries=[self.invocation(self.entries[0])];self.owners(self.f(self.b,'lpec_wire','terminal_owners'));self.physical_rows(outcome)
        final_rseq=self.f(self.f(self.b,'lpec_wire','terminal_owners'),'lpec_owners','rseq')
        at_exit=self.f(self.f(self.entry,'lpec_entry','redirected_owners'),'lpec_owners','rseq')
        need(final_rseq==at_exit,'whole unregistered rseq state survives the cut/fault; no registration or TLS effect')
        need(c['initialized']==1 and 1<=c['used']<=64 and c['offers']==c['closed']==c['candidates']==c['entries']+c['resumed']+c['refaults']+c['graph_refaults'],'complete actual offer partition')
        need(c['resumed']+c['refaults']+c['graph_refaults']==sum(c[k]for k in('hash_misses','source_misses','plan_misses','capacity_misses'))and c['entries']==c['publications']+c['hits']==c['claims'],'actual miss/claim partition')
        need(c['generation']==c['publications']==c['used']+c['retirements']and c['retirement_attempts']==c['retirements']and c['cursor']<64,'actual completed retirement accounting')
        need(c['completed']==c['permits_issued']==c['entries']-failed_epoch and c['pending']==failed_epoch and c['first_error']==3103*failed_epoch and c['first_detail']==9*failed_epoch and not any(c[k]for k in('unexpected','retiring','decoding','closing','resuming','proof_pending')),'exact generated completion or held failed-revoke prefix')
        need(c['plan_checks']==c['publications']+c['retirement_attempts']and c['rseq_checks']==c['publications']and c['live_checks']==3*c['publications']+4*c['hits']and c['proof_checks']==2*c['publications']+3*c['hits'],'all cold/live/proof guards precede both actual cut close attempts')
        need((c['proof_arena'],c['proof_bytes'],c['proof_registry'])==(self.storage[3],self.storage[4],self.storage[5])and 1-failed_epoch<=c['cut_exits']<=c['completed'],'actual v2 proof arena and completed cut population')
        events=q(self.f(self.b,'lpec_wire','events'));raw=q(self.f(self.b,'lpec_wire','raw_ingress'))
        need(events[0]==sum(events[1:6])and sum(events[6:10])==c['plan_misses']and sum(events[10:])==c['completed']and raw[0]==sum(raw[1:])and 0<raw[0]<=events[0]and all(x<=y for x,y in zip(raw[1:],events[1:6],strict=True)),'complete actual event/refusal/completion census')
        need(self.h[30:39]==((1,1,1,1,1,1,9,1,self.app['seed'][1])if failed_epoch else(1,0,0,0,0,1,2,1,self.app['seed'][1])),'source-derived terminal owner/handler/route/flags prefix')
        need(self.f(self.b,'lpec_wire','terminal_record')==self.record and self.f(self.b,'lpec_wire','terminal_epoch')==entries[0]['epoch']['raw'],'actual terminal is the retained focal generation')
        chain=self.f(self.b,'lpec_wire','terminal_chain');self.eq(chain,'li2_tf_chain',initialized=1,first_error=0 if failed_epoch else 7,first_detail=0 if failed_epoch else 11,pending=1-failed_epoch,in_handler=0,unexpected_events=1-failed_epoch)
        row=span.chain_report(self.r,chain,outcome)
        need(row['nx_entries']==row['fallbacks']+c['entries']+c['refaults']+c['graph_refaults']+1-failed_epoch,'actual ordinary initial segments include the one faulting unfinished cut')
        need(self.i(self.f(chain,'li2_tf_chain','entry'),'li2_tf_trace_entry','valid')==0 and not self.i(self.f(chain,'li2_tf_chain','lease'),'li2_tf_same_page','origin_active'),'no live ordinary one-use or same-page lease authority')
        if failed_epoch:
            # Only raw ingress advances the chain event; the epoch never hands
            # off to any new ordinary owner when physical close fails.
            closed=self.f(self.entry,'lpec_entry','closed_chain')
            self.r.change(closed,chain,'li2_tf_chain',observed=('event_id','entry'))
            self.eq(chain,'li2_tf_chain',event_id=self.i(closed,'li2_tf_chain','event_id')+1)
            self.r.change(self.f(closed,'li2_tf_chain','entry'),self.f(chain,'li2_tf_chain','entry'),'li2_tf_trace_entry',observed=('valid',))
        return dict(control=0,mode=self.app['mode'],entries=entries,outcome=outcome,summary=c,events=events,raw_ingress=raw,original_sha256=hashlib.sha256(self.r.data).hexdigest(),whole_profile_qualified=0,_check=self)

def read(data,layout,image,app,pid,cpu,exit_status,control=0):
    need(type(control)is int and control==0 and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0 and type(app['mode'])is int and app['mode']in(0,1)and type(exit_status)is int and exit_status==125,'two exact actual gated failure cases')
    return Check(wire.Reader(data,layout),image,app,pid,cpu,control).finish(exit_status)
def terminal(parsed,owner):
    """Full typed report-to-actual capture joins; these never synthesize frames."""
    check=owner['_check'];c=owner['summary'];h=check.h;outcome=owner['outcome'];events=owner['events']
    fields='initialized first_error used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks live_checks proof_checks refaults'.split()
    linked=dict(version=2,**outcome,**{k:c[k]for k in fields},events=events[0],active=h[31],busy=h[32],decoding=c['decoding'],closing=c['closing'],resuming=c['resuming'])
    f=old.Fields(check.r,check.f(check.b,'lpec_wire','terminal_transfer'),'li2_span_transfer_progress')
    linked['transfer']=f.values('phase serial event previous next successor_installed previous_generation previous_borrow fresh_borrow pc flags issued consume_attempted consumed resume_attempted resumed first_error')+[abs(f.signed('first_detail')),int(f.signed('first_detail')<0)]+f.values('refault_attempted refaulted')
    linked['signals']=list(events[1:6]);linked['refusals']=list(events[6:10]);linked['exit_indices']=list(events[10:])
    r=old.Fields(check.r,check.f(check.b,'lpec_wire','terminal_record'),'le_record')
    linked['current']=r.values('slot_present slot redirected exit_seen completed exit_index')+r.child('open','le_permission').values('started returned complete')+r.child('close','le_permission').values('started returned complete')+r.values('release_started release_complete cleanup_started cleanup_complete')+[r.child('before','le_frame').integer('complete'),r.child('after','le_frame').integer('complete'),r.integer('unexpected_seen'),r.child('unexpected','le_frame').integer('complete')]+r.child('original','li2_region_pc').values('ready kind head_index source_offset')+r.values('idle_bytes live_bytes closed_bytes')+r.child('final_fetch','li2_fetch_progress').values('held complete')+r.values('build_started build_returned build_result gpr_written flags_written refault_started refault_complete refault_result')
    reuse=dict(version=2,**outcome,**{k:c[k]for k in' generation retirement_attempts retirements claims permits_issued pending retiring cursor'.split()})
    current=old.Fields(check.r,check.f(check.b,'lpec_wire','terminal_current'),'li2_current_custody_stats')
    current_row=dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],**{k:current.integer(k)for k in'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels first_error'.split()},first_detail_abs=abs(current.signed('first_detail')),first_detail_negative=int(current.signed('first_detail')<0))
    chain=span.chain_report(check.r,check.f(check.b,'lpec_wire','terminal_chain'),outcome)
    expected=dict(linked_preedge=linked,linked_preedge_reuse=reuse,current_tf=current_row,chain=chain,lease={k:v for k,v in chain.items()if k.startswith('lease_')},**check.physical_rows(outcome))
    linked['graph_refaults']=c['graph_refaults'];linked['cut_exits']=c['cut_exits']
    expected['native_hint']=hint_row(check,outcome)
    import json
    def typed(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
    for key,value in expected.items():need(key in parsed and typed(parsed[key])==typed(value),'entire actual protected terminal row '+key)
    return dict(actual_terminal_rows=len(expected),native_operations=0)

def values(c,b):return {k:c.i(b,T,k)for k in ROW}

def hint_row(c,outcome):
    p=values(c,c.f(c.b,'lpec_wire','terminal_hint'));r=c.f(c.b,'lpec_wire','terminal_record')
    return dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],**p,
        current_checked=c.i(r,'le_record','hint_checked'),current_hit=c.i(r,'le_record','hint_hit'),current_publication=c.i(r,'le_record','hint_publication'))

T='li2_link_native_hint_progress'

COUNTERS='publications evictions lookups hits invalidations next_nx admitted refused errors'.split()

PROVENANCE='receipt_sequence receipt_publication selected_publication selected_serial selected_event selected_pc selected_seeds selected_published'.split()

ROW='ready pending outcome_complete'.split()+COUNTERS+PROVENANCE+['outcome_result']


def receipt(c,b):
    p=values(c,b);s=c.f(b,T,'receipt');S='li2_native_pair_slot';page=c.f(s,S,'page');P='li2_fetch_page'
    if not p['publications']:
        zero(b,'no native hint publication means whole hint is zero');return p
    need(p['receipt_sequence']>0 and p['receipt_publication']>0,'actual positive native publication identity')
    c.eq(s,S,prepared=1,published=1,policy=0)
    a,allocation,generation,offset,extent=c.v(page,P,'address allocation generation offset initial_extent')
    backing,obj,logical,closed=c.v(page,P,'backing object logical closed_prot')
    need(a%4096==0 and 0x200000000<=a<1<<47 and allocation>0 and generation>0 and backing==1 and logical==5 and closed==1 and obj in c.objects,'actual retained positive hint page identity')
    original,_,loads=c.objects[obj];data=original['data'];left,right,n,initialized=c.v(s,S,'window_before window_after window_bytes window_initialized')
    owners=[x for x in loads if x[1]==5 and (x[2]&-4096)<=offset and offset+4096<=((x[2]+x[5]+4095)&-4096)]
    need(len(owners)==1 and offset%4096==0,'hint page has one actual original executable load')
    seg=owners[0];bias=a-((seg[3]&-4096)+offset-(seg[2]&-4096))
    need(bias>=0 and bias%4096==0,'actual positive hint ELF load bias')
    if obj in c.bases:need(c.bases[obj]==bias,'positive hint retains actual object bias')
    else:c.bases[obj]=bias
    maximum=max((x[3]+x[6]+4095)&-4096 for x in loads)
    need(extent in((0,maximum)if offset==0 and obj not in(c.image['main_object'],c.image['interpreter_object'])else(0,)),'exact hint original extent annotation')
    neighbors=struct.unpack('<2I',c.f(b,T,'neighbors'))
    need(neighbors in((0,0),(0,1),(1,0),(1,1))and(left,right)==tuple(14*x for x in neighbors)and n==initialized==4096+left+right,'actual complete hint policy window and present halos')
    need(c.i(s,S,'pc')>=a and c.i(s,S,'pc')<a+4096,'actual historical policy candidate belongs to receipt page')
    ids=c.r.items(b,T,'identity','li2_link_native_hint_identity');I='li2_link_native_hint_identity'
    c.eq(ids[0],I,address=a,allocation=allocation,generation=generation,offset=offset,initial_extent=extent,backing=backing,object=obj,logical=logical)
    expected=[]
    for i,item in enumerate(ids):
        present=not i or neighbors[i-1]
        if not present:zero(item,'absent halo has whole zero identity');continue
        addr,alloc,gen,off,initial=c.v(item,I,'address allocation generation offset initial_extent');bo,ob,lo=c.v(item,I,'backing object logical')
        need(addr==(a if not i else a-4096 if i==1 else a+4096)and alloc>0 and gen>0 and bo==1 and lo==5 and ob in c.objects,'actual sealed present hint identity')
        blob=c.objects[ob][0]['data'];start=off if i!=1 else off+4096-14;length=4096 if not i else 14
        need(0<=start<=len(blob)-length,'whole actual hint object bytes')
        expected.append((i,blob[start:start+length]))
    chunks=dict(expected);window=chunks.get(1,b'')+chunks[0]+chunks.get(2,b'')
    need(c.f(s,S,'window')==window+bytes(4124-len(window)),'full immutable native hint page and halo bytes')
    back=c.f(s,S,'backing');c.eq(back,'li2_fetch_backing',seals_observed=1,stat_observed=1,seals=15,stat_result=0)
    fd=c.i(back,'li2_fetch_backing','retained_fd');st=c.stat(c.f(back,'li2_fetch_backing','stat'))
    need(200<=fd<1<<31 and st['size']==original['carrier_bytes']and st['mode']&0xf000==0x8000,'actual sealed positive hint backing descriptor')
    if obj==c.image['main_object']:need(st==c.stat(c.f(c.b,'lpec_wire','main_backing')),'positive hint original main backing identity')
    elif obj!=c.image['interpreter_object']:
        expected=original['backing'];need(all(st[k]==expected[k]for k in('dev','ino','size'))and expected['seals']==15,'positive hint exact dependency carrier identity')
    first,end,major,minor,inode,vmaoff=c.v(page,P,'vma_first vma_end vma_major vma_minor vma_inode vma_offset');dev=st['dev']
    need(first%4096==end%4096==vmaoff%4096==0 and first<=a<a+4096<=end and vmaoff+a-first==offset and(major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'complete positive hint VMA and sealed object identity')
    need(c.i(b,T,'allocation_epoch')>=allocation and c.i(b,T,'generation_epoch')>=generation and c.i(b,T,'records_epoch')>0,'actual hint publication lifetime epochs')
    return p


def terminal_state(c):
    b=c.f(c.b,'lpec_wire','terminal_hint');p=receipt(c,b);count=c.counts['graph_refaults']
    need(all(p[k]in(0,1)for k in('ready','pending','outcome_complete')),'literal actual hint state flags')
    need(p['ready']+p['evictions']+p['hits']+p['invalidations']==p['publications']and p['hits']<=p['lookups'],'one-use positive hint conservation')
    need(p['lookups']<=q(c.f(c.b,'lpec_wire','events'))[8],'every advisory lookup follows an actual GRAPH refusal')
    # All fixed failures occur outside a pending hint-selected native API. An
    # undeclared incomplete fatal prefix remains failed, never refused/admitted.
    need(p['pending']==p['errors']==p['refused']==0 and p['hits']==count==p['next_nx']==p['admitted'],'all declared finite hint selections reached actual native admission')
    need(count<=q(c.f(c.b,'lpec_wire','events'))[8],'every graph retry is an actual counted GRAPH refusal')
    owners=c.f(c.b,'lpec_wire','terminal_owners');life=c.f(owners,'lpec_owners','lifecycle');pair=c.f(owners,'lpec_owners','pair')
    need(p['publications']==p['receipt_publication']==c.i(life,'li2_native_pair_lifecycle','published')and 0<p['receipt_sequence']<=c.i(life,'li2_native_pair_lifecycle','sequence'),'all actual native publications feed the bounded advisory receipt')
    if not p['hits']:
        need(not any(p[k]for k in('outcome_complete','outcome_result')+tuple(PROVENANCE[2:])),'no selection means no invented native outcome')
    else:
        need(p['outcome_complete']==1 and p['outcome_result']==1 and 0<p['selected_publication']<p['receipt_publication']and p['selected_serial']>0 and p['selected_pc']>=0x200000000,'actual completed hint native outcome and older selected receipt')
        need(p['selected_publication']<=p['selected_published']<p['receipt_publication']and p['selected_serial']<=c.counts['offers']and p['selected_event']<c.i(pair,'li2_native_pair_progress','events')and p['selected_seeds']<c.i(pair,'li2_native_pair_progress','seeds'),'actual selected receipt precedes terminal native lifecycle')
    r=c.f(c.b,'lpec_wire','terminal_record');R='le_record';checked,hit,pub=c.v(r,R,'hint_checked hint_hit hint_publication')
    need(checked in(0,1)and hit in(0,1)and hit<=checked and bool(pub)==bool(hit),'exact actual current hint flags/publication')
    if checked:
        c.eq(r,R,build_started=1,build_returned=1,build_result=2403,miss_release_complete=1,miss_release_result=0)
        source=c.f(r,R,'source');key=c.f(source,'li2_span_source','key');need(c.i(key,'li2_span_source_key','entry')>=0x200000000,'actual high GRAPH lookup source')
    if hit:
        need(pub==p['selected_publication']and c.i(c.f(r,R,'transfer'),'li2_span_transfer_progress','serial')==p['selected_serial'],'current hit binds the actual one-use selection')
    return p


def terminal_transfer(c):
    t='li2_span_transfer_progress';b=c.f(c.b,'lpec_wire','terminal_transfer');r=c.f(c.b,'lpec_wire','terminal_record');R='le_record'
    need(c.counts['refaults']<=q(c.f(c.b,'lpec_wire','events'))[9],'actual retry count bounded by actual relocation refusals')
    phase=c.i(b,t,'phase');done=phase==6
    need(c.v(b,t,'refault_attempted refaulted')==((1,1)if done else(0,0))and c.v(r,R,'refault_started refault_complete refault_result')==((1,1,0)if done else(0,0,0)),'actual terminal retry phase and completion fields')
    if done:
        result=c.i(r,R,'build_result');need(result in(2403,2404),'actual distinct GRAPH or relocation retry result')
        c.eq(r,R,slot_present=0,redirected=0,completed=0,build_started=1,build_returned=1,close_complete=1,prepare_complete=1,miss_release_complete=1,miss_release_result=0,resume_started=0,resume_complete=0)
        need(c.counts['graph_refaults'if result==2403 else'refaults']>0 and c.i(b,t,'serial')==c.counts['offers']and c.i(b,t,'pc')>=0x200000000 and 0<c.i(b,t,'previous_borrow')<c.i(b,t,'fresh_borrow'),'terminal retry is actual high miss and newer released borrow')
        c.eq(b,t,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0)
        c.progress(c.f(r,R,'miss_fetch'),c.i(b,t,'fresh_borrow'),False)
        fresh=c.f(b,t,'fresh');F='li2_span_fetch_observation'
        c.eq(fresh,F,complete=1,pc=c.i(b,t,'pc'),length=15,page_count=1,pid=c.pid,tid=c.pid)
        c.eq(c.f(fresh,F,'ref'),'li2_fetch_ref',sequence=c.i(b,t,'fresh_borrow'))
        need(c.f(fresh,F,'progress')==c.f(r,R,'miss_fetch'),'whole actual terminal released fresh observation')
        if result==2403:c.eq(r,R,hint_checked=1,hint_hit=1);need(c.i(r,R,'hint_publication')>0,'positive receipt selected GRAPH retry')
        else:c.eq(r,R,hint_checked=0,hint_hit=0,hint_publication=0)



CONTROL_COUNTS={(0,0):57,(1,0):52}
def controls(data,layout,image,app,pid,cpu,exit_status,control=0):
    base=read(data,layout,image,app,pid,cpu,exit_status,control);c=base['_check'];r=c.r
    def where(path):
        t='lpec_wire';at=0
        for key in path.split('.'):
            if key.isdigit():at+=int(key)*r.types[t]['bytes'];continue
            field=r.types[t]['fields'][key];at+=field['offset'];t=r.layout['edges'][t].get(key,t)
        return at
    tests=[]
    def add(name,path,delta=0,mask=1):tests.append((name,[(where(path)+delta,mask)],None))
    for name,delta in(('magic',0),('version',8),('extent',16),('actual_head',160),('actual_mode',192),('focal_count',200),('terminal_status',216),('owner_address',416)):add(name,'h',delta)
    for name,path in(
        ('source_ready','entries.0.owner.source.ready'),('source_generation','entries.0.owner.source.key.page.generation'),
        ('source_allbytes','entries.0.source_page'),('source_final','entries.0.terminal_source_page'),
        ('proof_version','entries.0.proof.header.version'),('proof_generation','entries.0.proof.header.generation'),
        ('proof_bytes','entries.0.proof.plan.bytes'),('frontier_kind','entries.0.proof.plan.frontier_kind'),
        ('head_image','entries.0.generated_page'),('proof_tail','entries.0.proof_tail'),
        ('epoch_token','entries.0.owner.epoch.serial'),('epoch_held','entries.0.epoch_held.phase'),('epoch_release','entries.0.epoch_terminal.release_complete'),
        ('cold_ordinal','entries.0.proof.header.none_proof'),('ready_generation','entries.0.ready_generation'),
        ('completion_permit','entries.0.permit.valid'),('same_event','entries.0.redirect_event'),('interior_event','entries.0.terminal_event'),
        ('source_NX','entries.0.owner.after.si'),('full_FP','entries.0.owner.after.frame.fp'),
        ('actual_TLS','entries.0.owner.after.fs'),('mask','entries.0.owner.after.frame.mask'),
        ('generated_revoke','entries.0.owner.close.complete'),('fetch_release','entries.0.owner.final_fetch.held'),
        ('memory_before','entries.0.before_memory.data'),('memory_after','entries.0.after_memory.stack'),
        ('final_fetch','terminal_fetch.held'),('terminal_native','terminal_native_counts.closed'),('actual_registry','terminal_registry.complete')):add(name,path)
    add('global_error','counts',25*8);add('cut_completed_delta','control',6*8)
    for name,index in(('cut_before_RAX',13),('cut_before_AF',17)):
        mask=0x10 if index==17 else 1
        tests.append((name,[(where('entries.0.owner.after.frame.greg')+index*8,mask),(where('entries.0.owner.after.uc')+40+index*8,mask)],'six MOV effects only; whole cut has not executed at source NX'))
    if app['mode']==0:
        index=c.i(c.f(c.b,'lpec_wire','post_before'),'li2_tf_chain','active');slot='post_after.slots.'+str(index)
        for name,path in(('post_marker','post'),('post_FP','post_cut.frame.fp'),('post_stack','post_stack'),('post_data','post_data'),('ordinary_revoke',slot+'.owner.step.revoked'),('ordinary_held',slot+'.fetch.progress.held'),('ordinary_unexpected',slot+'.unexpected'),('ordinary_false_release',slot+'.release.complete'),('ordinary_false_TRACE',slot+'.owner.step.trace_seen'),('ordinary_first_error',slot+'.owner.step.first_error'),('handler_returned','post'),('ordinary_cut_descriptor',slot+'.decoded')):
            add(name,path,48 if name=='handler_returned'else 0)
        for name,index in(('fault_R8',0),('fault_CR2',22),('fault_AF',17)):
            mask=0x10 if index==17 else 1
            tests.append((name,[(where('post_cut.frame.greg')+index*8,mask),(where('post_cut.uc')+40+index*8,mask)],'actual original-PC data fault before any load effect'))
    else:
        for name,path,delta in(('real_munmap','control',16),('real_munmap_result','control',32),('cleanup_result','entries.0.owner.cleanup.result',0),('failed_query','entries.0.owner.close.query.complete',0),('false_post','post',0),('false_final_proof','entries.0.proof_final',0),('false_release_result','entries.0.owner.release_result',0),('cleanup_complete','entries.0.owner.cleanup_complete',0),('false_completed','entries.0.completed',0),('false_closed_bytes','entries.0.owner.closed_bytes',0)):
            add(name,path,delta)
    tests.append(('footer',[(len(data)-8,1)],None))
    need(len(tests)==CONTROL_COUNTS[app['mode'],0],'fixed separate cut-failure owner refusals')
    refused=[]
    for name,edits,error in tests:
        changed=bytearray(data)
        for at,mask in edits:changed[at]^=mask
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control)
        except ValueError as failure:
            if error is not None:need(str(failure)==error,'coherent supplied control reaches its exact source-state guard')
            refused.append(name)
        else:raise ValueError('supplied cut-failure owner accepted '+name)
    return dict(refusals=refused,native_operations=0,original_sha256=hashlib.sha256(data).hexdigest())
