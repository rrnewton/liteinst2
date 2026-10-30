"""Distinct finite linked epoch observations; no old-wire or decoder substitution.
Actual source/build/ELF/header/process closure and native pair comparison are
mandatory caller obligations. A returned observation is not qualification.
"""
import hashlib,struct
from pathlib import Path
import importlib.util

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('linked_epoch_wire',HERE/'wire.py');plan=load('linked_epoch_plan',HERE/'plan.py')
refault=load('linked_epoch_refault',HERE/'refault.py')
span=load('linked_epoch_trace_helpers',HERE.parent/'scalar_span_trace_owner/read.py')
old=wire.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=old.DATA,old.STACK,old.RSP
P,L,R=old.P,old.L,old.R
COUNTS='initialized used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks generation retirement_attempts retirements claims permits_issued pending retiring cursor first_error first_detail decoding closing resuming live_checks proof_checks proof_pending proof_arena proof_bytes proof_registry refaults'.split()
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)

def elf_symbols(data):
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
            if name in wire.REGISTERED or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(wire.REGISTERED)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols


class Check(span.Check):
    def __init__(self,reader,image,app,pid,cpu,control,refault_control=0):
        self.refault_control=refault_control
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'leto_wire','h'));self.control_words=q(self.f(self.b,'leto_wire','control'))
        self.bias=self.h[9]-reader.layout['symbols']['li2_raw6'];self.head=app['head'];self.page=self.head&-PAGE
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'actual explicit object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual original object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(reader.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(reader.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'actual same emitted bridge and DWARF symbols')
        self.storage=q(self.f(self.b,'leto_wire','storage'));self.counts=dict(zip(COUNTS,q(self.f(self.b,'leto_wire','counts')),strict=True))
        self.entries=self.r.items(self.b,'leto_wire','entries','leto_entry')
        self.entry=self.entries[0];self.record=self.f(self.entry,'leto_entry','owner')

    def header(self,status):
        h=self.h;r=self.r;t='leto_wire';mode=self.app['mode'];c=self.control
        expected=(3104,{1:3002,2:3002,3:3001,4:3003}[self.refault_control])if self.refault_control else (0,0)if not status else (3104,11)if not c else {1:(3104,5),2:(3102,302),3:(301,440),4:(3103,9)}[c]
        code,detail=expected
        need(h[:9]==(0x314f54454c49324c,2,r.types[t]['bytes'],r.types['leto_entry']['bytes'],r.types['le_record']['bytes'],r.types['le_slot']['bytes'],r.types['le_frame']['bytes'],968,128),'whole actual linked capture version/type extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted bridge bias and gateway')
        need(canonical(h[12],h[13])and h[12]%PAGE==0 and h[13]==524288,'whole actual altstack')
        need(h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual exclusive regular0600 FD3 sink')
        count=2 if c==2 else 6 if mode==5 else 1
        need(h[20]==self.head and h[22]==self.image['main_object']and h[23:26]==(1,mode,count)and h[26:30]==(1,status,code,detail),'exact source, invocation population and required failure')
        need(h[39:43]==(0,0,h[16],0)and h[45]<=h[44]<=h[43]and h[46]<=h[43]and h[47:50]==(0,0,0)and h[50:52]==(1,1)and h[57]==1 and h[63]==0,'complete diagnostics/sink closure')
        need(h[52:57]==tuple(self.symbol(k)for k in('selected_linked_epoch','span_progress','ler','selected_chain','leto_wire')),'actual protected owner addresses')
        control=self.control_words;need(control[0]==c,'exact supplied control identity')
        if not c:need(not any(control),'whole unused failure stimulus');zero(self.f(self.b,t,'nested_fp'),'no fabricated nested observation')
        elif c==1:
            need(control[1:3]==(1,1)and not any(control[3:6])and control[6:9]==(self.pid,self.pid,5)and not any(control[9:12])and control[12]==1 and not any(control[13:18]),'actual nonreturning tgkill stimulus')
        else:
            need(control[:5]==(c,1,1,int(c!=3),302 if c==2 else 0)and not any(control[5:]),'actual selected failure call and exact returned prefix')
            zero(self.f(self.b,t,'nested_fp'),'no fabricated nested observation')
        for key in('sink_initial','sink_terminal'):
            b=self.f(self.b,t,key);st=self.stat(b);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual empty0600 sink');self.eq(b,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x314654454c49324c,2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'whole actual record/footer/write completion')
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
        objects=[];decl=self.r.layout['registrations'];need(set(decl)==set(wire.REGISTERED),'all exact byte-registration source witnesses')
        headers=self.image['headers'];need(type(headers)is dict and headers,'actual complete compiler-M header closure')
        for name,(source,tag)in wire.REGISTERED.items():
            d=decl[name];at,n=self.symbols[name];a,z=self.bias+at,self.bias+at+n
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,n,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'actual symbol/DWARF/source-selected registration '+name)
            need(d['source']in headers and type(headers[d['source']])is dict and set(headers[d['source']])=={'bytes','sha256'},'every actual DWARF origin belongs to the complete compiler-M closure')
            if name not in wire.LIFETIME:need(ranges.count((a,z))==1 and kinds[ranges.index((a,z))]==0,'whole strict registered object extent')
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
        need(n==64*PAGE and pn==64*65536 and registry==self.symbol('lep')and epoch==self.symbol('linked_epoch')and reuse==self.symbol('ler'),'actual immutable arena and owner identities')
        ranges=((high,n),(low,n),(proof,pn))
        need(all(canonical(a,n)and a%PAGE==0 for a,n in ranges)and low+n<=1<<31 and all(a+n<=b or b+m<=a for i,(a,n)in enumerate(ranges)for b,m in ranges[i+1:]),'whole disjoint nonwrapping code/proof arenas')
        for a,n in ranges:
            for actual,kinds in(initial,terminal):need(actual.count((a,a+n))==1 and kinds[actual.index((a,a+n))]==0,'whole strict actual anonymous arena registration')
        for i,query in enumerate(self.r.items(self.b,'leto_wire','initial_code','li2_private_code_query')):self.query(query,(high,low)[i],3,pages=64)
        for i,query in enumerate(self.r.items(self.b,'leto_wire','initial_proof','li2_private_code_query')):self.query(query,proof+i*64*PAGE,3,pages=64)

    def proof_permission(self,b,address,prot):
        self.eq(b,'le_permission',started=1,returned=1,sync_started=1,sync_returned=1,complete=1,prot=prot,result=0,sync_result=0)
        self.query(self.f(b,'le_permission','query'),address,prot,pages=16)

    def proof(self,e,source,record):
        slot=self.f(e,'leto_entry','slot');index=self.i(record,'le_record','slot');generation=self.i(record,'le_record','publication_generation')
        need(0<=index<64 and 0<generation<=self.counts['generation'],'actual occupied slot and monotonic generation')
        generated=self.storage[1]+index*PAGE;address=self.storage[3]+index*65536
        self.eq(slot,'le_slot',installed=1,complete=1,identity=generation,filled=PAGE,verified=PAGE,generated=generated,proof=address)
        self.query(self.f(slot,'le_slot','writable'),generated,3);self.permission(self.f(slot,'le_slot','publication'),generated,1)
        p=self.f(e,'leto_entry','proof');h=self.f(p,'li2_link_proof','header');pt='li2_link_proof_header'
        self.eq(h,pt,version=1,bytes=65536,registry=self.symbol('lep'),slot=index,generation=generation,generated=generated)
        zero(self.f(h,pt,'reserved'),'whole immutable proof reserved capacity')
        binding=self.image['binding'];need(type(binding)is dict and binding['version']==1,'actual source-pinned production binding')
        need(self.f(h,pt,'archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(h,pt,'policy')==bytes.fromhex(binding['policy_sha256']),'actual archive and universal NONE policy binding')
        cp,cn=self.v(h,pt,'plan_proof none_proof');need(0<cp<=self.counts['plan_checks']and 0<cn<=self.counts['rseq_checks'],'actual completed cold proof ordinals')
        key=self.f(p,'li2_link_proof','key');self.eq(key,'li2_span_source_key',entry=self.head)
        self.r.change(key,source['key'],'li2_span_source_key',observed=('backing',));self.backing(self.f(key,'li2_span_source_key','backing'))
        need(self.v(self.f(key,'li2_span_source_key','backing'),'li2_fetch_backing','retained_fd seals')==self.v(self.f(source['key'],'li2_span_source_key','backing'),'li2_fetch_backing','retained_fd seals'),'exact actual retained descriptor/seals')
        expected,image,heads=plan.plan(self.app['source'],self.page,self.head,generated)
        need(self.f(p,'li2_link_proof','plan')==expected,'whole independent reachable graph, descriptor effects, links and PC table')
        need(self.f(e,'leto_entry','generated_page')==image and self.i(e,'leto_entry','generated_bytes')==PAGE,'every emitted byte and untouched CC gap')
        need(self.i(e,'leto_entry','proof_bytes')==65536 and self.i(e,'leto_entry','ready_generation')==generation,'actual full primary proof and readiness generation')
        zero(self.f(e,'leto_entry','proof_tail'),'entire actual immutable proof tail')
        publication=self.f(e,'leto_entry','proof_publication');t='le_proof_publication'
        self.eq(publication,t,started=1,complete=1,zeroed=65536,copied=self.r.types['li2_link_proof']['bytes'],verified=65536)
        need(self.f(publication,t,'header')==h,'every actual immutable/publisher anchor byte')
        self.query(self.f(publication,t,'writable'),address,3,pages=16);self.proof_permission(self.f(publication,t,'sealed'),address,1)
        return dict(address=address,generated=generated,index=index,generation=generation,plan=expected,heads=heads,raw=p,cp=cp,cn=cn)

    def epoch(self,e,source,p,completed,entered):
        t='li2_link_epoch_progress';held=self.f(e,'leto_entry','epoch_held');opened=self.f(e,'leto_entry','epoch_opened');terminal=self.f(e,'leto_entry','epoch_terminal')
        self.eq(held,t,phase=1,first_error=0,first_detail=0,release_started=0,release_complete=0,publication=p['generation'],borrow=source['borrow'],source=self.page,generated=p['generated'])
        serial,allocation,generation,transactions,records=self.v(held,t,'serial allocation_epoch generation_epoch transactions_epoch records_epoch')
        page=self.f(source['key'],'li2_span_source_key','page')
        need(serial==q(self.f(e,'leto_entry','counts_before'))[0]+1 and allocation>=self.i(page,'li2_fetch_page','allocation')and generation>=self.i(page,'li2_fetch_page','generation')and transactions>0 and records>0,'actual source lifetime epochs and serial')
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
        st='li2_rseq_state';a=self.f(self.f(e,'leto_entry','source_owners'),'leto_owners','rseq')
        self.owners(self.f(e,'leto_entry','source_owners'))
        endpoint=self.f(e,'leto_entry','redirected_owners')if entered else self.f(self.b,'leto_wire','terminal_owners')
        self.owners(endpoint,redirected=entered);b=self.f(endpoint,'leto_owners','rseq')
        if cold:
            self.r.change(a,b,st,observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'))
            self.eq(b,st,last_first=0,last_end=0,last_pc=self.page+0x513,last_code=696,last_policy=1)
            self.eq(self.f(b,st,'last_footprint'),'li2_write_footprint',pc=self.page+0x513,next_pc=self.page+0x518,first=0,end=0,abi_version=1,policy=1,code=696,length=5)
        else:need(a==b,'whole hit rseq state unchanged; no fictitious cold footprint update')
        reg=int(self.app['mode']==5 and attempt==4)
        self.eq(b,st,registered=reg,registrations=int(self.app['mode']==5 and attempt>=4),unregistrations=int(self.app['mode']==5 and attempt>=5),kernel_errors=0)
        if reg:self.eq(b,st,address=0x500000200000,page=0x500000200000,length=32,signature=0x53053053)
        if completed:
            out=self.f(e,'leto_entry','completed_owners');self.owners(out)
            need(self.f(out,'leto_owners','rseq')==b,'whole actual live-only exit rseq state conserved')
        else:zero(self.f(e,'leto_entry','completed_owners'),'no failed completion owner bundle')
        observations=self.r.items(record,'le_record','live_rseq','li2_link_rseq_live')
        wanted=(not cold,True,entered,completed or self.control==4)
        for i,(item,used)in enumerate(zip(observations,wanted,strict=True)):
            if not used:zero(item,'unexecuted live guard snapshot')
            else:self.live_rseq(item,b,after if i==3 else before)

    def invocation(self,e,index,failed):
        self.entry=e;self.record=r=self.f(e,'leto_entry','owner');t='le_record';et='leto_entry'
        preheld=failed and self.control in(2,3);entered=not preheld;completed=not failed
        self.eq(e,et,present=1,closed=1,source_ready=1,redirected=int(entered),completed=int(completed),terminal=1,source_bytes=PAGE,terminal_source_bytes=PAGE)
        need(self.f(e,et,'source_page')==self.f(e,et,'terminal_source_page')==self.app['source'],'whole original source before and after actual lifetime')
        machine=list(self.app['machine']);machine[2]=0x500000200080 if self.app['mode']==5 and index==2 else machine[2]
        previous_app=self.app;self.app=dict(self.app,machine=tuple(machine))
        before=self.frame(self.f(r,t,'before'));ingress=self.normalized(self.f(r,t,'ingress'),before)
        self.trace(ingress,self.head,self.app['seed'][1]|TF);self.trace(before,self.head,self.app['seed'][1]);self.same_event(ingress,before,self.app['seed'][1])
        need((before['fs'],before['gs'])==tuple(machine[1:3]),'actual expected lifecycle TLS at entry')
        pi,closed_slot,oldref,predecessor=self.closed_transition(self.f(e,et,'predecessor'),self.f(e,et,'closed_chain'),self.head-2,ingress)
        source=self.source(self.f(r,t,'source'));self.transfer(self.f(r,t,'transfer'),source,closed_slot,pi,False)
        self.eq(self.f(r,t,'transfer'),'li2_span_transfer_progress',refault_attempted=0,refaulted=0)
        self.eq(r,t,refault_started=0,refault_complete=0,refault_result=0)
        self.eq(r,t,slot_present=1,redirected=int(entered),completed=int(completed),release_started=int(completed),release_complete=int(completed),release_result=0,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,prepare_result=0,miss_release_started=0,miss_release_complete=0,miss_release_result=0,resume_started=0,resume_complete=0,resume_result=0,resumed_route=0,flags=self.app['seed'][1])
        zero(self.f(r,t,'miss_fetch'),'no fictional descriptive fallback for this accepted graph')
        p=self.proof(e,source,r);generated=p['generated'];cold=bool(self.i(r,t,'build_started'))
        self.eq(r,t,build_started=int(cold),build_returned=int(cold),build_result=0)
        if cold:self.eq(r,t,cold_plan_proof=p['cp'],cold_none_proof=p['cn']);zero(self.f(r,t,'proof_before'),'cold entry has no cached proof check')
        else:self.eq(r,t,cold_plan_proof=0,cold_none_proof=0);self.query(self.f(r,t,'proof_before'),p['address'],1,pages=16)
        self.query(self.f(r,t,'proof_enter'),p['address'],1,pages=16);self.query(self.f(r,t,'idle'),generated,1);self.eq(r,t,idle_bytes=PAGE)
        token=self.f(r,t,'epoch');self.eq(token,'li2_link_epoch_token',owner=self.symbol('linked_epoch'),serial=self.i(self.f(e,et,'epoch_held'),'li2_link_epoch_progress','serial'))
        descriptors=[p['plan'][8256+i*336:8256+(i+1)*336]for i in range(16)]
        gpr=flags=0
        for d in descriptors:
            gpr|=struct.unpack_from('<I',d,316)[0]
            for offset in(296,300,304,308):flags|=struct.unpack_from('<I',d,offset)[0]
        self.eq(r,t,gpr_written=gpr,flags_written=flags)
        if entered:
            self.permission(self.f(r,t,'open'),generated,5);self.query(self.f(r,t,'live'),generated,5);self.eq(r,t,live_bytes=PAGE)
            need(self.i(e,et,'redirect_event')==self.i(e,et,'ingress_event')>0 and self.i(e,et,'terminal_event')==self.i(e,et,'redirect_event')+1,'exact one real ingress after redirect; no internal generated signal')
        else:
            for k in('open','live'):zero(self.f(r,t,k),'no invented execution before held failure')
            self.eq(r,t,live_bytes=0);self.eq(e,et,redirect_event=0,terminal_event=0)
        result=dict(ingress=ingress,before=before,predecessor_before=predecessor,after=None,unexpected=None,mapped=None,source=self.app['source'],terminal_source=self.app['source'],proof=p,disposition='completed'if completed else 'failure')
        after=None
        if completed or self.control==4:
            after=self.frame(self.f(r,t,'after'));self.nx(after,self.page+(0x620 if self.app['mode']==1 else 0x600))
            self.eq(r,t,exit_seen=1,exit_index=int(self.app['mode']!=1),unexpected_seen=0,map_result=0)
            need(before['fp']==after['fp']and before['fp_bytes']==after['fp_bytes']and before['mask']==after['mask']and(before['fs'],before['gs'])==(after['fs'],after['gs']),'whole actual FP/mask/TLS conservation')
            need(before['uc'][:40]==after['uc'][:40]and before['uc'][296:304]==after['uc'][296:304],'same UC flags/link/altstack and full kernel mask')
            for k in range(16):
                if not(gpr>>k&1):need(before['greg'][GREG[k]]==after['greg'][GREG[k]],'all definitely unchanged GPRs')
            need(after['greg'][17]&~(flags|RF)==before['greg'][17]&~flags and after['greg'][17]&(TF|RF)==RF,'all unaffected flags; defined and undefined outputs remain hardware')
            zero(self.f(r,t,'unexpected'),'ordinary external NX is not unexpected');zero(self.f(r,t,'original'),'external frontier has no generated fault association')
            self.query(self.f(r,t,'proof_exit'),p['address'],1,pages=16)
            self.permission(self.f(r,t,'close'),generated,1,error=-12 if self.control==4 else 0)
            self.eq(r,t,closed_bytes=PAGE if completed else 0);result['after']=after
        else:
            self.eq(r,t,exit_seen=0,exit_index=0,closed_bytes=0)
            for k in('after','close','proof_exit'):zero(self.f(r,t,k),'no fabricated successful external exit')
        if completed:
            self.eq(r,t,cleanup_started=0,cleanup_complete=0,unexpected_seen=0,map_result=0);zero(self.f(r,t,'cleanup'),'successful epoch has no abort cleanup')
            self.progress(self.f(r,t,'final_fetch'),source['borrow'],False)
            self.eq(self.f(e,et,'permit'),'ler_permit',generation=p['generation'],completion=q(self.f(e,et,'counts_after'))[1],valid=1)
            need(self.f(e,et,'proof_final')==p['raw']and self.i(e,et,'proof_final_bytes')==65536,'entire primary proof unchanged through completed epoch');zero(self.f(e,et,'proof_final_tail'),'entire final immutable tail')
        else:
            self.eq(r,t,cleanup_started=1,cleanup_complete=int(self.control!=4));self.permission(self.f(r,t,'cleanup'),generated,1,error=-12 if self.control==4 else 0)
            self.progress(self.f(r,t,'final_fetch'),source['borrow'],True)
            need(self.f(r,t,'final_fetch')==self.f(self.b,'leto_wire','terminal_fetch'),'actual failed held source prefix')
            self.eq(self.f(e,et,'permit'),'ler_permit',valid=0)
            self.eq(e,et,proof_final_bytes=0);zero(self.f(e,et,'proof_final'),'no invented completed proof reread');zero(self.f(e,et,'proof_final_tail'),'no invented final proof tail')
            if preheld or self.control==4:
                self.eq(r,t,unexpected_seen=0,map_result=0);zero(self.f(r,t,'unexpected'),'direct terminal failure has no fabricated signal');zero(self.f(r,t,'original'),'no fabricated generated PC')
            else:
                self.eq(r,t,unexpected_seen=1,map_result=1 if self.control==1 else 0)
                f=self.frame(self.f(r,t,'unexpected'));result['unexpected']=f
                if self.control==1:
                    g=f['greg'];need(f['sig']==5 and struct.unpack_from('<iii',f['si'])==(5,0,-6)and struct.unpack_from('<II',f['si'],16)==(self.pid,self.image['uid']),'actual SI_TKILL sender')
                    need(g[16]==g[14]==self.h[9]+25 and g[13]==0 and(g[8],g[9],g[12],g[2],g[0],g[1])==(self.pid,self.pid,5,0,0,0)and self.h[12]<=g[15]<self.h[12]+self.h[13]and g[17]&0x10500==0 and g[21]==MASK and(f['fs'],f['gs'])==(before['fs'],before['gs']),'actual nested gateway and full handler state')
                    self.nested_fp(before,f);zero(self.f(r,t,'original'),'nested runtime PC is never a generated association');result['disposition']='nested'
                else:
                    off=0x300 if self.app['mode']==2 else 0x500;head=p['heads'][off];rows=[p['plan'][34560+i*48:34560+(i+1)*48]for i in range(28)]
                    matched=[x for x in rows if struct.unpack_from('<Q',x,32)[0]==self.page+off and struct.unpack_from('<I',x,12)[0]!=3]
                    need(len(matched)==1 and self.f(r,t,'original')==matched[0],'exact previously validated generated instruction head')
                    g=f['greg'];need(f['sig']==11 and struct.unpack_from('<iii',f['si'])==(11,0,2)and g[16]==generated+head['offset']and g[19:22]==(4,14,MASK)and g[22]==DATA+8192 and int.from_bytes(f['si'][16:24],'little')==DATA+8192 and g[17]&(TF|RF)==RF,'actual data fault at exact relocated original load')
                    need(f['fp']==before['fp']and(f['fs'],f['gs'])==(before['fs'],before['gs']),'whole fault FP/TLS conservation')
                    result.update(disposition='fault',mapped=dict(original_pc=self.page+off,generated_pc=g[16],head_index=head['head']))
        ep=self.epoch(e,source,p,completed,entered);result['epoch']=ep
        if completed:need(self.f(r,t,'epoch_final')==ep['raw'],'whole actual returned release proof')
        else:zero(self.f(r,t,'epoch_final'),'no return from epoch release on failed prefix')
        self.rseq_transition(e,r,before,after,cold,entered,completed,index)
        result['before_memory']=self.memory(self.f(e,et,'before_memory'));result['after_memory']=self.memory(self.f(e,et,'after_memory'),after_abort=failed)
        a,z=(q(self.f(e,et,k))for k in('counts_before','counts_after'));need(all(y>=x for x,y in zip(a,z,strict=True)),'monotonic actual invocation counters')
        delta=tuple(y-x for x,y in zip(a,z,strict=True));retirement=delta[8]
        need(retirement in(0,1)and delta[9]==retirement and delta==(int(entered),int(completed),int(cold)+retirement,int(cold),sum((not cold,True,entered,completed or self.control==4)),int(not cold)+1+int(completed or self.control==4),int(cold),int(not cold),retirement,retirement),'exact cold/warm proof calls and actual retirement partition')
        if self.app['mode']==4:
            need(self.i(e,et,'frontier_closed')==1 and completed,'actual unsupported frontier ordinary completion')
            f=self.frame(self.f(self.b,'leto_wire','frontier_exit'),False);f.update(fs=after['fs'],gs=after['gs']);self.trace(f,self.page+0x602,(after['greg'][17]&~RF)|TF)
            temp=self.app;seed=list(self.app['seed']);seed[1]=after['greg'][17]&~RF;self.app=dict(self.app,seed=tuple(seed))
            self.closed_transition(self.f(self.b,'leto_wire','frontier_before'),self.f(self.b,'leto_wire','frontier_after'),self.page+0x600,f)
            self.app=temp;result.update(frontier_closed=1,frontier_exit=f)
        else:self.eq(e,et,frontier_closed=0)
        self.app=previous_app;return result
    def finish(self,status):
        outcome=self.header(status);failed=bool(status)and not self.refault_control;c=self.counts
        refault.terminal_state(self)
        session=self.f(self.b,'leto_wire','session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        sync=self.i(session,'li2_step_session','sync_query');need(sync<1<<63 and sync&96==96,'actual sync-core registration')
        initial,terminal=(self.registry(self.f(self.b,'leto_wire',k))for k in('initial_registry','terminal_registry'))
        need(terminal[0][:len(initial[0])]==initial[0]and terminal[1][:len(initial[1])]==initial[1],'all original actual protected rows retained')
        self.arena(initial,terminal)
        result=[]
        for i,e in enumerate(self.entries):
            if i>=self.h[25]:zero(e,'entire unused focal record capacity');continue
            result.append(self.invocation(e,i,failed and i==self.h[25]-1))
        if self.app['mode']!=4:
            for key in('frontier_exit','frontier_before','frontier_after'):zero(self.f(self.b,'leto_wire',key),'no invented ordinary frontier transition')
        if self.app['mode']==5:
            need(len(result)==(2 if self.control==2 else 6),'all actual lifecycle attempts retained')
            a,b=result[:2];need(b['epoch']['generation']>a['epoch']['generation']and b['epoch']['serial']>a['epoch']['serial']and a['proof']['generation']<b['proof']['generation'],'real mapping generation invalidates prior graph authority')
            need(a['disposition']=='completed'and self.i(self.entries[0],'leto_entry','completed')==1,'first generation fully released before actual source R/RX')
            if not self.control:
                need(all(x['epoch']['serial']<y['epoch']['serial']for x,y in zip(result,result[1:])),'each live excursion gets a fresh epoch serial')
                for i in range(2,6):need(result[i]['proof']['generation']==result[1]['proof']['generation']and result[i]['proof']['raw']==result[1]['proof']['raw'],'same immutable cold proof survives GS/rseq boundary changes with fresh live guards')
                need([self.i(self.f(e,'leto_entry','owner'),'le_record','build_started')for e in self.entries]==[1,1,0,0,0,0],'actual cold source replacement then four warm live-checked entries')
        self.owners(self.f(self.b,'leto_wire','terminal_owners'));self.physical_rows(outcome)
        held=int(self.control in(2,3));unexpected=int(failed and(self.control==1 or not self.control))
        need(c['initialized']==1 and 1<=c['used']<=64 and c['offers']==c['closed']==c['candidates']==c['entries']+c['resumed']+c['refaults']+held+int(bool(self.refault_control)and self.refault_control!=2),'actual chosen offers/closed predecessor/entry partition')
        need(c['resumed']+c['refaults']+int(bool(self.refault_control)and self.refault_control!=2)==sum(c[k]for k in('hash_misses','source_misses','plan_misses','capacity_misses'))and c['entries']+held==c['publications']+c['hits']==c['claims'],'all actual misses and claimed generations')
        need(c['generation']==c['publications']==c['used']+c['retirements']and c['retirement_attempts']==c['retirements']and c['cursor']<64,'monotonic publications and completed generation retirement')
        need(c['completed']==c['permits_issued']==c['entries']-int(failed and not held)and c['unexpected']==unexpected and c['pending']==int(failed)and not c['retiring'],'actual completion permits; no failed completion')
        need(c['plan_checks']==c['publications']+c['retirement_attempts']and c['rseq_checks']==c['publications'],'every cold and retirement full proof, no warm decoder reconstruction')
        missing_live=2 if held else unexpected;missing_proof=1 if held or unexpected else 0
        need(c['live_checks']==3*c['publications']+4*c['hits']-missing_live and c['proof_checks']==2*c['publications']+3*c['hits']-missing_proof,'exact all live and immutable authority checks by actual prefix')
        need(c['first_error']==outcome['failure_code']and c['first_detail']==outcome['detail_abs']and not any(c[k]for k in('decoding','closing','resuming','proof_pending'))and(c['proof_arena'],c['proof_bytes'],c['proof_registry'])==(self.storage[3],self.storage[4],self.storage[5]),'actual error/static readiness/storage terminal facts')
        events=q(self.f(self.b,'leto_wire','events'));raw=q(self.f(self.b,'leto_wire','raw_ingress'))
        need(events[0]==sum(events[1:6])and sum(events[6:10])==c['plan_misses']and sum(events[10:])==c['completed']and raw[0]==sum(raw[1:])and 0<raw[0]<=events[0]and all(x<=y for x,y in zip(raw[1:],events[1:6],strict=True)),'all actual ingress/event/refusal/exit census')
        if failed:
            need(self.h[31:34]==(int(not held),1,1)and self.h[35:37]==(1,9),'actual terminal active/busy/route prefix')
            need(self.f(self.b,'leto_wire','terminal_record')==self.f(self.entries[self.h[25]-1],'leto_entry','owner'),'whole retained failed current is actual focal prefix')
            need(self.f(self.b,'leto_wire','terminal_epoch')==result[-1]['epoch']['raw'],'whole actual unreleased failure epoch')
        elif self.refault_control:
            need(self.h[31:37]==(0,1,1,1,0,0),'actual retry refusal has no generated or ordinary execution owner')
            self.eq(self.f(self.b,'leto_wire','terminal_fetch'),'li2_fetch_progress',held=int(self.refault_control==3),complete=1,first_error=0,first_detail=0)
            self.eq(self.f(self.b,'leto_wire','terminal_epoch'),'li2_link_epoch_progress',phase=4,first_error=0,first_detail=0,release_started=1,release_complete=1)
        else:
            need(self.h[31:37]==(0,0,0,1,0,0),'all executable owners and pending routes closed before exit')
            self.eq(self.f(self.b,'leto_wire','terminal_fetch'),'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0)
            self.eq(self.f(self.b,'leto_wire','terminal_epoch'),'li2_link_epoch_progress',phase=4,first_error=0,first_detail=0,release_started=1,release_complete=1)
        chain=self.f(self.b,'leto_wire','terminal_chain');self.eq(chain,'li2_tf_chain',initialized=1,first_error=0,first_detail=0,pending=0,in_handler=0)
        row=span.chain_report(self.r,chain,outcome)
        need(row['nx_entries']==row['fallbacks']+c['entries']+c['refaults']+held+int(bool(self.refault_control)and self.refault_control!=2),'all actual closed segments partition into fallback, graph, retry and required terminal prefix')
        need(self.i(self.f(chain,'li2_tf_chain','entry'),'li2_tf_trace_entry','valid')==0 and not self.i(self.f(chain,'li2_tf_chain','lease'),'li2_tf_same_page','origin_active'),'no ordinary executable or one-use authority survives terminal state')
        # This finite original-image exit is explicitly two fully closed owners;
        # no unrelated whole-program cache saturation assumption is imposed.
        for slot in self.r.items(chain,'li2_tf_chain','slots','li2_tf_chain_slot'):
            self.eq(slot,'li2_tf_chain_slot',phase=5,fallback=0,unexpected_frame_observed=0)
            owner=self.f(slot,'li2_tf_chain_slot','owner');step=self.f(owner,'li2_tf_owner','step')
            self.eq(step,'li2_step_owner',phase=5,first_error=0,first_detail=0,in_handler=0,trace_seen=1,revoke_sync_started=1,open_sync=0,revoke_sync=0)
            self.eq(owner,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0,unexpected_frame_observed=0)
            n=self.i(self.f(step,'li2_step_owner','request'),'li2_step_request','page_count');need(n in(1,2),'real bounded ordinary page bundle')
            for key in('open_started','opened','revoke_started','revoked'):need(struct.unpack('<2I',self.f(step,'li2_step_owner',key))==tuple(int(i<n)for i in range(2)),'all actual ordinary permission actions complete')
            for key in('open_result','revoke_result'):zero(self.f(step,'li2_step_owner',key),'all actual ordinary permission results')
            self.eq(self.f(slot,'li2_tf_chain_slot','query'),'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0,pc=self.i(owner,'li2_tf_owner','actual_post_pc'))
            self.eq(self.f(slot,'li2_tf_chain_slot','release'),'li2_chain_release',started=1,complete=1,result=0)
            fetch=self.f(slot,'li2_tf_chain_slot','fetch');ref=self.f(fetch,'li2_chain_fetch','ref');sequence=self.i(ref,'li2_fetch_ref','sequence');need(sequence>0,'actual old released borrow')
            self.eq(self.f(fetch,'li2_chain_fetch','progress'),'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0,sequence=sequence)
        retry=refault.check(self)
        return dict(refault_control=self.refault_control,refault=retry,control=self.control,mode=self.app['mode'],entries=result,outcome=outcome,summary=c,events=events,raw_ingress=raw,original_sha256=hashlib.sha256(self.r.data).hexdigest(),_check=self)


def read(data,layout,image,app,pid,cpu,exit_status,control=0,*,refault_control=0):
    need(type(refault_control)is int and refault_control in range(5)and(not refault_control or(control==0 and app['mode']==0)),'exact additional retry control selector')
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0 and type(control)is int and control in range(5),'actual process, CPU and fixed control')
    need(type(app['mode'])is int and app['mode']in range(6)and(not control or app['mode']==(5 if control==2 else 0)),'six modes and exact source-causal control application')
    need(type(exit_status)is int and exit_status==(125 if app['mode']in(2,3)or control or refault_control else 0),'fixed actual outcome; no failure relabel')
    return Check(wire.Reader(data,layout),image,app,pid,cpu,control,refault_control).finish(exit_status)


def terminal(parsed,owner):
    """Full typed report-to-actual capture joins; these never synthesize frames."""
    check=owner['_check'];c=owner['summary'];h=check.h;outcome=owner['outcome'];events=owner['events']
    fields='initialized first_error used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks live_checks proof_checks refaults'.split()
    linked=dict(version=1,**outcome,**{k:c[k]for k in fields},events=events[0],active=h[31],busy=h[32],decoding=c['decoding'],closing=c['closing'],resuming=c['resuming'])
    f=old.Fields(check.r,check.f(check.b,'leto_wire','terminal_transfer'),'li2_span_transfer_progress')
    linked['transfer']=f.values('phase serial event previous next successor_installed previous_generation previous_borrow fresh_borrow pc flags issued consume_attempted consumed resume_attempted resumed first_error')+[abs(f.signed('first_detail')),int(f.signed('first_detail')<0)]+f.values('refault_attempted refaulted')
    linked['signals']=list(events[1:6]);linked['refusals']=list(events[6:10]);linked['exit_indices']=list(events[10:])
    r=old.Fields(check.r,check.f(check.b,'leto_wire','terminal_record'),'le_record')
    linked['current']=r.values('slot_present slot redirected exit_seen completed exit_index')+r.child('open','le_permission').values('started returned complete')+r.child('close','le_permission').values('started returned complete')+r.values('release_started release_complete cleanup_started cleanup_complete')+[r.child('before','le_frame').integer('complete'),r.child('after','le_frame').integer('complete'),r.integer('unexpected_seen'),r.child('unexpected','le_frame').integer('complete')]+r.child('original','li2_region_pc').values('ready kind head_index source_offset')+r.values('idle_bytes live_bytes closed_bytes')+r.child('final_fetch','li2_fetch_progress').values('held complete')+r.values('build_started build_returned build_result gpr_written flags_written refault_started refault_complete refault_result')
    reuse=dict(version=1,**outcome,**{k:c[k]for k in' generation retirement_attempts retirements claims permits_issued pending retiring cursor'.split()})
    current=old.Fields(check.r,check.f(check.b,'leto_wire','terminal_current'),'li2_current_custody_stats')
    current_row=dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],**{k:current.integer(k)for k in'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels first_error'.split()},first_detail_abs=abs(current.signed('first_detail')),first_detail_negative=int(current.signed('first_detail')<0))
    chain=span.chain_report(check.r,check.f(check.b,'leto_wire','terminal_chain'),outcome)
    expected=dict(linked_epoch=linked,linked_epoch_reuse=reuse,current_tf=current_row,chain=chain,lease={k:v for k,v in chain.items()if k.startswith('lease_')},**check.physical_rows(outcome))
    import json
    def typed(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
    for key,value in expected.items():need(key in parsed and typed(parsed[key])==typed(value),'entire actual protected terminal row '+key)
    return dict(actual_terminal_rows=len(expected),native_operations=0)

# Every mutation targets a checked actual field; none changes execution policy.
# Counts remain a separate supplied-copy population from the16 native subjects.
CONTROL_BASE=41
CONTROL_COUNTS={(m,0):41+(2 if m in(2,3,4)else 4 if m==5 else 0)for m in range(6)}
CONTROL_COUNTS.update({(0,1):43,(5,2):45,(0,3):43,(0,4):43})

def controls(data,layout,image,app,pid,cpu,exit_status,control=0):
    baseline=read(data,layout,image,app,pid,cpu,exit_status,control);types=layout['types'];tests=[]
    def where(path):
        at=0;t='leto_wire'
        for key,index,child in path:
            field=types[t]['fields'][key];at+=field['offset']
            if index is not None:at+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return at
    def add(name,path):tests.append((name,[(where(path),1)],None))
    def coherent(name,paths,error):tests.append((name,[(where(p),1)for p in paths],error))
    for i in(0,1,2,20,25,27,28,39,48,52):add('header_'+str(i),[('h',i,None)])
    add('strict_main_protection',[('initial_registry',None,'leto_registry'),('initial_code',None,None)])
    add('readonly_arena_identity',[('storage',3,None)])
    add('actual_global_close',[('terminal_global_close',None,'li2_native_close'),('complete',None,None)])
    add('actual_rseq_status',[('terminal_owners',None,'leto_owners'),('rseq',None,'li2_rseq_state'),('first_error',None,None)])
    add('actual_raw_ingress_total',[('raw_ingress',0,None)])
    e=[('entries',0,'leto_entry')];r=e+[('owner',None,'le_record')]
    for name,tail in(
        ('entry_presence',[('present',None,None)]),('source_bytes',[('source_page',None,None)]),
        ('terminal_source',[('terminal_source_page',None,None)]),('generated_image',[('generated_page',None,None)]),
        ('epoch_serial',[('epoch_held',None,'li2_link_epoch_progress'),('serial',None,None)]),
        ('epoch_release',[('epoch_terminal',None,'li2_link_epoch_progress'),('release_complete',None,None)]),
        ('readonly_proof_header',[('proof',None,'li2_link_proof'),('header',None,'li2_link_proof_header'),('generation',None,None)]),
        ('archive_binding',[('proof',None,'li2_link_proof'),('header',None,'li2_link_proof_header'),('archive',None,None)]),
        ('policy_binding',[('proof',None,'li2_link_proof'),('header',None,'li2_link_proof_header'),('policy',None,None)]),
        ('whole_graph',[('proof',None,'li2_link_proof'),('plan',None,'li2_link_plan'),('image',None,None)]),
        ('none_effects',[('proof',None,'li2_link_proof'),('plan',None,'li2_link_plan'),('original',0,'li2_span_decoded'),('gpr_write',None,None)]),
        ('immutable_tail',[('proof_tail',None,None)]),('ready_generation',[('ready_generation',None,None)]),
        ('actual_R_permission',[('proof_publication',None,'le_proof_publication'),('sealed',None,'le_permission'),('prot',None,None)]),
        ('data_memory',[('before_memory',None,'li2_leto_memory'),('data',None,None)]),
        ('stack_memory',[('after_memory',None,'li2_leto_memory'),('stack',None,None)]),
        ('interior_signal',[('terminal_event',None,None)]),
        ('cold_ordinal',[('counts_after',2,None)])):
        add(name,e+tail)
    for name,tail in(
        ('fresh_borrow',[('source',None,'li2_span_source'),('borrow',None,'li2_fetch_ref'),('sequence',None,None)]),
        ('token_serial',[('epoch',None,'li2_link_epoch_token'),('serial',None,None)]),
        ('full_before_GPR',[('before',None,'le_frame'),('frame',None,'li2_step_frame'),('greg',13,None)]),
        ('full_before_FP',[('before',None,'le_frame'),('frame',None,'li2_step_frame'),('fp',None,None)]),
        ('actual_live_session',[('live_rseq',1,'li2_link_rseq_live'),('session',None,None)]),
        ('source_effect_union',[('gpr_written',None,None)]),
        ('before_mask',[('before',None,'le_frame'),('frame',None,'li2_step_frame'),('mask',None,None)])):
        add(name,r+tail)
    # Preserve every serial alias within this focal record. The independent
    # actual pre-entry count must still reject this forged later epoch.
    serials=[e+[(key,None,'li2_link_epoch_progress'),('serial',None,None)]
             for key in ('epoch_held','epoch_terminal')]
    serials.append(r+[('epoch',None,'li2_link_epoch_token'),('serial',None,None)])
    first=wire.Reader(data,layout).items(data[:-64],'leto_wire','entries','leto_entry')[0]
    fields=old.Fields(wire.Reader(data,layout),first,'leto_entry')
    if fields.integer('redirected'):serials.append(e+[('epoch_opened',None,'li2_link_epoch_progress'),('serial',None,None)])
    if fields.integer('completed'):serials.append(r+[('epoch_final',None,'li2_link_epoch_progress'),('serial',None,None)])
    coherent('stale_serial_all_focal_aliases',serials,'actual source lifetime epochs and serial')
    need(len(tests)==CONTROL_BASE,'fixed41 independently enumerated base refusal population')
    mode=app['mode']
    if mode in(2,3)and not control:
        add('fault_source_pc',r+[('original',None,'li2_region_pc'),('original_pc',None,None)])
        add('fault_full_FP',r+[('unexpected',None,'le_frame'),('frame',None,'li2_step_frame'),('fp',None,None)])
    elif mode==4:
        add('frontier_complete',e+[('frontier_closed',None,None)])
        add('real_successor_release',[('frontier_after',None,'li2_tf_chain'),('releases',None,None)])
    elif mode==5:
        second=[('entries',1,'leto_entry')]
        add('new_source_generation',second+[('owner',None,'le_record'),('source',None,'li2_span_source'),('key',None,'li2_span_source_key'),('page',None,'li2_fetch_page'),('generation',None,None)])
        add('old_epoch_completion',e+[('completed',None,None)])
        add('actual_later_epoch',second+[('epoch_held',None,'li2_link_epoch_progress'),('serial',None,None)])
        add('second_current_token',second+[('owner',None,'le_record'),('epoch',None,'li2_link_epoch_token'),('serial',None,None)])
    if control and control!=2:
        add('actual_control_return',[('control',3,None)])
        add('actual_control_operation',[('control',2,None)])
    need(len(tests)==CONTROL_COUNTS[(mode,control)],'complete fixed declared supplied population')
    refused=[]
    for name,changes,error in tests:
        changed=bytearray(data)
        for at,mask in changes:changed[at]^=mask
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control)
        except ValueError as exc:
            if error is not None:need(str(exc)==error,'mutation reached exact intended semantic gate')
            refused.append(name)
        else:raise ValueError('supplied linked record accepted '+name)
    return dict(refusals=refused,native_operations=0,original_sha256=baseline['original_sha256'])

# New wire-v2 observations are separately required on each exact actual case.
# The historical controls() above remains unchanged and is never run under a
# new selector or credited for a new native failure.
REFAULT_CONTROL_COUNTS={(0,0,0):9,(1,0,0):9,(2,0,0):9,(3,0,0):9,(4,0,0):9,(5,0,0):29,
                        (0,1,0):9,(5,2,0):9,(0,3,0):9,(0,4,0):9,
                        (0,0,1):17,(0,0,2):17,(0,0,3):17,(0,0,4):17}

def refault_controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,refault_control=0):
    """Exact additional copy-only refusals; every mutation runs the full reader."""
    baseline=read(data,layout,image,app,pid,cpu,exit_status,control,refault_control=refault_control)
    types=layout['types'];check=baseline['_check'];tests=[]
    def at(path):
        offset=0;t='leto_wire'
        for field,index,child in path:
            offset+=types[t]['fields'][field]['offset']
            if index is not None:offset+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return offset
    def add(name,path,error):tests.append((name,[(at(path),None)],error))
    def set_value(path,value,width=8):return at(path),value.to_bytes(width,'little')
    tr=[('terminal_transfer',None,'li2_span_transfer_progress')];r=[('terminal_record',None,'le_record')]
    flags='actual terminal retry phase and completion fields'
    for k in('refault_attempted','refaulted'):add('terminal_'+k,tr+[(k,None,None)],flags)
    for k in('refault_started','refault_complete','refault_result'):add('terminal_'+k,r+[(k,None,None)],flags)
    tests.append(('refault_above_actual_relocation',[set_value([('counts',36,None)],baseline['events'][9]+1)],'actual retry count bounded by actual relocation refusals'))
    phase=check.i(check.f(check.b,'leto_wire','terminal_transfer'),'li2_span_transfer_progress','phase')
    tests.append(('terminal_phase_flags',[set_value(tr+[('phase',None,None)],5 if phase==6 else 6,4)],flags))
    # A coherent added completed retry preserves offers/miss/refusal arithmetic;
    # the independent actual ordinary segment count must still refuse it.
    changes=[set_value([('counts',i,None)],baseline['summary'][COUNTS[i]]+1)for i in(2,3,6,8,36)]
    changes.append(set_value([('events',9,None)],baseline['events'][9]+1))
    if phase==6:changes.append(set_value(tr+[('serial',None,None)],baseline['summary']['offers']+1))
    tests.append(('coherent_retry_without_ordinary_segment',changes,'all actual closed segments partition into fallback, graph, retry and required terminal prefix'))
    add('consumed_focal_false_refault',[('entries',0,'leto_entry'),('owner',None,'le_record'),('transfer',None,'li2_span_transfer_progress'),('refault_attempted',None,None)],'exact li2_span_transfer_progress.refault_attempted')
    need(len(tests)==9,'nine separate common retry observations')
    w=[('refault',None,'leto_refault')];wr=w+[('record',None,'le_record')]
    def frame_changes(name,field,index,error):
        p=w+[(field,None,'le_frame')]
        tests.append((name,[(at(p+[('uc',None,None)])+40+8*index,None),(at(p+[('frame',None,'li2_step_frame'),('greg',index,None)]),None)],error))
    if app['mode']==5 and not control and not refault_control:
        add('mandatory_actual_retry',w+[('h',1,None)],'mandatory genuine helper retry witness')
        chronology='immediate actual NX followed by exactly one native boundary and complete close'
        for i in(2,3,4,6):add('actual_boundary_ordinal_'+str(i),w+[('h',i,None)],chronology)
        add('actual_retained_serial',w+[('h',11,None)],'current retained serial and strictly newer real source borrow')
        add('actual_released_borrow',w+[('before_fetch',None,'li2_fetch_progress'),('held',None,None)],'exact li2_fetch_progress.held')
        add('actual_fresh_release_complete',wr+[('miss_release_complete',None,None)],'exact le_record.miss_release_complete')
        add('actual_token_consumed',wr+[('transfer',None,'li2_span_transfer_progress'),('refaulted',None,None)],'exact li2_span_transfer_progress.refaulted')
        frame_changes('returned_full_RAX','returned',13,'entire same-event captured frame except actual TF edit and observed TLS fields')
        full='all23 actual retry-to-NX GREG including AF and whole FP/mask'
        frame_changes('next_NX_full_flags','nx',17,full)
        add('next_NX_full_FP',w+[('nx',None,'le_frame'),('frame',None,'li2_step_frame'),('fp',None,None)],full)
        a=w+[('native_admitted',None,'leto_owners')];z=w+[('native_closed',None,'leto_owners')]
        add('actual_native_owner_phase',a+[('pair',None,'li2_native_pair_progress'),('phase',None,None)],'exact li2_native_pair_progress.phase')
        add('actual_whole_page_policy',a+[('lifecycle',None,'li2_native_pair_lifecycle'),('slots',0,'li2_native_pair_slot'),('policy',None,None)],'exact li2_native_pair_slot.policy')
        add('actual_whole_policy_window',a+[('lifecycle',None,'li2_native_pair_lifecycle'),('slots',0,'li2_native_pair_slot'),('window',None,None)],'complete actual native policy bytes including halo and padding')
        add('actual_native_TLS_seed',a+[('rseq_pair',None,'li2_rseq_pair_progress'),('fs_before',None,None)],'native actual TLS seed equals closed TRACE observation')
        add('actual_native_close_verified',z+[('lifecycle',None,'li2_native_pair_lifecycle'),('close',None,'li2_native_close'),('verified',None,None)],'exact li2_native_close.verified')
        add('actual_native_close_rseq',z+[('rseq',None,'li2_rseq_state'),('first_error',None,None)],'exact li2_rseq_state.first_error')
        add('actual_native_close_epoch',z+[('pair',None,'li2_native_pair_progress'),('epochs_closed',None,None)],'all actual pair epochs closed')
        add('actual_full_helper_source',wr+[('source',None,'li2_span_source'),('key',None,'li2_span_source_key'),('bytes',None,None)],'whole4096 source ticket bytes')
    elif refault_control:
        for i in(12,15,16,17):add('actual_negative_call_'+str(i),w+[('h',i,None)],'real negative call, exact error, and terminal observation')
        add('actual_negative_borrow',w+[('before_fetch',None,'li2_fetch_progress'),('held',None,None)],'exact li2_fetch_progress.held')
        add('actual_negative_argument',w+[('h',13,None)],'real negative call, exact error, and terminal observation')
        add('actual_negative_error',wr+[('transfer',None,'li2_span_transfer_progress'),('first_error',None,None)],'exact li2_span_transfer_progress.first_error')
        if refault_control==1:add('actual_stale_prior_serial',w+[('prior',None,'li2_span_transfer_progress'),('serial',None,None)],'exact li2_span_transfer_progress.serial')
        elif refault_control==2:add('actual_double_consume_phase',wr+[('transfer',None,'li2_span_transfer_progress'),('phase',None,None)],'exact li2_span_transfer_progress.phase')
        elif refault_control==3:add('actual_before_release_stimulus',wr+[('miss_release_started',None,None)],'exact le_record.miss_release_started')
        else:frame_changes('actual_changed_RAX_stimulus','changed',13,'actual changed-frame stimulus is exactly RAX xor1 in UC and full frame')
    need(len(tests)==REFAULT_CONTROL_COUNTS[(app['mode'],control,refault_control)],'complete exact separate retry mutation population')
    refused=[]
    for name,changes,error in tests:
        changed=bytearray(data)
        for offset,value in changes:
            if value is None:changed[offset]^=1
            else:changed[offset:offset+len(value)]=value
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,refault_control=refault_control)
        except ValueError as exc:need(str(exc)==error,'exact retry mutation causal refusal '+name);refused.append(name)
        else:raise ValueError('supplied retry witness accepted '+name)
    return dict(refault_refusals=refused,native_operations=0,original_sha256=baseline['original_sha256'])
