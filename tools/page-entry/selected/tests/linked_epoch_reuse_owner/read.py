"""Separate65-entry replacement observation. Original16 qualification remains mandatory.
Full actual closed frames/native comparison and actual old-generation retirement
are required; unrelated replacement graph semantics gain no native credit.
"""
import hashlib,struct,json,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
base=load('reuse65_common_finite',HERE.parent/'linked_epoch_owner/read.py')
wire=load('reuse65_wire',HERE/'wire.py');plan=load('reuse65_plan',HERE/'plan.py')
old,span=base.old,base.span
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,FP,TF,RF,MASK=old.U64,old.PAGE,old.FP,old.TF,old.RF,old.MASK
DATA,STACK,RSP=old.DATA,old.STACK,old.RSP
COUNTS='initialized used offers closed resumed hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks generation retirement_attempts retirements claims permits_issued pending retiring cursor first_error first_detail decoding closing resuming live_checks proof_checks proof_pending proof_arena proof_bytes proof_registry refaults'.split()
GREG=base.GREG
def elf_symbols(data,native_hint=False):
    _,registered,_=wire.profile(native_hint)
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


class Check(base.Check):
    def __init__(self,reader,image,app,pid,cpu,control,native_hint=False):
        self.native_hint=native_hint
        if native_hint:base.hint_module()
        self.r,self.image,self.app,self.pid,self.cpu,self.control=reader,image,app,pid,cpu,control
        self.b=reader.data[:-64];self.h=q(self.f(self.b,'lero_wire','h'));self.control_words=q(self.f(self.b,'lero_wire','control'))
        self.bias=self.h[9]-reader.layout['symbols']['li2_raw6'];self.head=app['head'];self.page=self.head&-PAGE
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and key>=0 and type(obj)is dict,'actual explicit object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual original object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'],native_hint)
        need(set(reader.layout['symbols'])==set(self.symbols)|{'span_progress'}and all(reader.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'actual same emitted bridge and DWARF symbols')
        self.storage=q(self.f(self.b,'lero_wire','storage'));self.counts=dict(zip(COUNTS+(['graph_refaults']if native_hint else[]),q(self.f(self.b,'lero_wire','counts')),strict=True))
        self.entries=self.r.items(self.b,'lero_wire','entries','lero_entry')
        self.entry=self.entries[0];self.record=self.f(self.entry,'lero_entry','owner')

    def header(self,status):
        h=self.h;r=self.r;t='lero_wire';mode=self.app['mode'];c=self.control
        expected=(0,0)if not status else (3104,11)if not c else {1:(3104,5),2:(3102,302),3:(301,440),4:(3103,9)}[c]
        code,detail=expected
        need(h[:9]==(0x3152554c4549324c,3 if self.native_hint else 2,r.types[t]['bytes'],r.types['lero_entry']['bytes'],r.types['lero_record']['bytes'],r.types['le_slot']['bytes'],r.types['le_frame']['bytes'],968,128),'whole actual linked capture version/type extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted bridge bias and gateway')
        need(canonical(h[12],h[13])and h[12]%PAGE==0 and h[13]==524288,'whole actual altstack')
        need(h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual exclusive regular0600 FD3 sink')
        count=65
        need(h[20]==self.head and h[22]==self.image['main_object']and h[23:26]==(1,mode,count)and h[26:30]==(1,status,code,detail),'exact source, invocation population and required failure')
        need(h[39:43]==(0,0,h[16],0)and h[45]<=h[44]<=h[43]and h[46]<=h[43]and h[47:50]==(0,0,0)and h[50:52]==(1,1)and h[57]==1 and h[63]==0,'complete diagnostics/sink closure')
        need(h[52:57]==tuple(self.symbol(k)for k in('selected_linked_epoch','span_progress','ler','selected_chain','lero_wire')),'actual protected owner addresses')
        need(c==0 and mode==6 and status==0 and not any(self.control_words),'only actual completed65-entry profile')
        for key in('sink_initial','sink_terminal'):
            b=self.f(self.b,t,key);st=self.stat(b);need(st['mode']&0xffff==0x8180 and st['size']==0,'actual empty0600 sink');self.eq(b,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        footer=q(r.data[-64:]);need(footer[:4]==(0x3146554c4549324c,3 if self.native_hint else 2,len(self.b),len(self.b))and 1<=footer[4]<=64 and 0<footer[5]<=len(self.b)and footer[6:]==(status,code),'whole actual record/footer/write completion')
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
        need(n==64*PAGE and pn==64*65536 and registry==self.symbol('lep')and epoch==self.symbol('linked_epoch')and reuse==self.symbol('ler'),'actual immutable arena and owner identities')
        ranges=((high,n),(low,n),(proof,pn))
        need(all(canonical(a,n)and a%PAGE==0 for a,n in ranges)and low+n<=1<<31 and all(a+n<=b or b+m<=a for i,(a,n)in enumerate(ranges)for b,m in ranges[i+1:]),'whole disjoint nonwrapping code/proof arenas')
        for a,n in ranges:
            for actual,kinds in(initial,terminal):need(actual.count((a,a+n))==1 and kinds[actual.index((a,a+n))]==0,'whole strict actual anonymous arena registration')
        for i,query in enumerate(self.r.items(self.b,'lero_wire','initial_code','li2_private_code_query')):self.query(query,(high,low)[i],3,pages=64)
        for i,query in enumerate(self.r.items(self.b,'lero_wire','initial_proof','li2_private_code_query')):self.query(query,proof+i*64*PAGE,3,pages=64)

    def proof_permission(self,b,address,prot):
        self.eq(b,'le_permission',started=1,returned=1,sync_started=1,sync_returned=1,complete=1,prot=prot,result=0,sync_result=0)
        self.query(self.f(b,'le_permission','query'),address,prot,pages=16)

    def proof(self,e,source,record):
        slot=self.f(e,'lero_entry','slot');index=self.i(record,'lero_record','slot');generation=self.i(record,'lero_record','publication_generation')
        need(0<=index<64 and 0<generation<=self.counts['generation'],'actual occupied slot and monotonic generation')
        generated=self.storage[1]+index*PAGE;address=self.storage[3]+index*65536
        self.eq(slot,'le_slot',installed=1,complete=1,identity=generation,filled=PAGE,verified=PAGE,generated=generated,proof=address)
        self.query(self.f(slot,'le_slot','writable'),generated,3);self.permission(self.f(slot,'le_slot','publication'),generated,1)
        p=self.f(e,'lero_entry','proof');h=self.f(p,'li2_link_proof','header');pt='li2_link_proof_header'
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
        need(self.f(e,'lero_entry','generated_page')==image and self.i(e,'lero_entry','generated_bytes')==PAGE,'every emitted byte and untouched CC gap')
        need(self.i(e,'lero_entry','proof_bytes')==65536 and self.i(e,'lero_entry','ready_generation')==generation,'actual full primary proof and readiness generation')
        zero(self.f(e,'lero_entry','proof_tail'),'entire actual immutable proof tail')
        publication=self.f(e,'lero_entry','proof_publication');t='le_proof_publication'
        self.eq(publication,t,started=1,complete=1,zeroed=65536,copied=self.r.types['li2_link_proof']['bytes'],verified=65536)
        need(self.f(publication,t,'header')==h,'every actual immutable/publisher anchor byte')
        self.query(self.f(publication,t,'writable'),address,3,pages=16);self.proof_permission(self.f(publication,t,'sealed'),address,1)
        return dict(address=address,generated=generated,index=index,generation=generation,plan=expected,heads=heads,raw=p,cp=cp,cn=cn)

    def live_rseq(self,b,state,frame):
        t='li2_link_rseq_live';self.eq(b,t,attempted=1,complete=1,result=0,session=self.symbol('selected_session'),epoch=self.i(state,'li2_rseq_state','epoch'),registered=self.i(state,'li2_rseq_state','registered'))
        regs=self.f(b,t,'registers');self.eq(regs,'li2_write_registers',fs_base=self.i(state,'li2_rseq_state','fs_base'),gs_base=self.i(state,'li2_rseq_state','gs_base'))
        need(q(self.f(regs,'li2_write_registers','gpr'))==tuple(frame['greg'][i]for i in GREG),'every actual live rseq GPR')
        if self.i(state,'li2_rseq_state','registered'):need(self.v(regs,'li2_write_registers','fs_base gs_base')==(frame['fs'],frame['gs']),'registered current TLS bound to actual frame')

    def transfer65(self,b,source,e):
        t='li2_span_transfer_progress';p=q(self.f(e,'lero_entry','closed_owner'))
        index,generation,event,phase,prepared,step_phase,trace,revoke,cont_start,cont_done,rel_start,rel_done,queried,pc,borrow,rel_result,query_result,chain_event=p
        need(index in(0,1)and generation>0 and 0<event<=chain_event and p[3:13]==(5,1,5,1,1,1,1,1,1,1)and pc==self.head and borrow>0 and rel_result==query_result==0,'actual completed predecessor scalar permission/query/release witness')
        self.eq(b,t,phase=3,issued=1,consume_attempted=1,consumed=1,resume_attempted=0,resumed=0,refault_attempted=0,refaulted=0,
                previous=index,next=0,successor_installed=0,first_error=0,first_detail=0,pc=self.head,
                flags=self.app['seed'][1],previous_generation=generation,previous_borrow=borrow,
                fresh_borrow=source['borrow'],event=chain_event)
        need(self.i(b,t,'serial')>0,'actual issued single-use serial')
        a,n=self.observation(self.f(b,t,'released'),self.head-2,False)
        x,m=self.observation(self.f(b,t,'fresh'),self.head,True,source['ref'])
        need(a==x and n==borrow and m>n,'actual released old borrow and newer consumed ref')
        return index

    def epoch65(self,e,source,p):
        t='li2_link_epoch_progress';held=self.f(e,'lero_entry','epoch_held');opened=self.f(e,'lero_entry','epoch_opened')
        terminal=self.f(self.record,'lero_record','epoch_final')
        self.eq(held,t,phase=1,first_error=0,first_detail=0,release_started=0,release_complete=0,
                publication=p['generation'],borrow=source['borrow'],source=self.page,generated=p['generated'])
        serial,allocation,generation,transactions,records=self.v(held,t,'serial allocation_epoch generation_epoch transactions_epoch records_epoch')
        page=self.f(source['key'],'li2_span_source_key','page')
        need(serial==q(self.f(e,'lero_entry','counts_before'))[0]+1 and allocation>=self.i(page,'li2_fetch_page','allocation')and generation>=self.i(page,'li2_fetch_page','generation')and transactions>0 and records>0,'actual source lifetime epochs and serial')
        for k in('opened','closed'):zero(self.f(held,t,k),'held epoch has no future permission result')
        self.r.change(held,opened,t,observed=('phase','opened'));self.eq(opened,t,phase=2);self.query(self.f(opened,t,'opened'),p['generated'],5)
        self.r.change(opened,terminal,t,observed=('phase','release_started','release_complete','closed'))
        self.eq(terminal,t,phase=4,release_started=1,release_complete=1);self.query(self.f(terminal,t,'closed'),p['generated'],1)
        token=self.f(self.record,'lero_record','epoch');self.eq(token,'li2_link_epoch_token',owner=self.symbol('linked_epoch'),serial=serial)
        return dict(serial=serial,generation=generation,raw=terminal)

    def rseq65(self,e,before,after):
        st='li2_rseq_state';a,b,c=(self.f(e,'lero_entry',k)for k in('source_rseq','redirected_rseq','completed_rseq'))
        for v in(a,b,c):
            self.eq(v,st,initialized=1,registered=0,held=1,first_error=0,first_detail=0,pid=self.pid,tid=self.pid,
                    registrations=0,unregistrations=0,kernel_errors=0,address=0,page=0,length=0,signature=0)
        self.r.change(a,b,st,observed=('last_first','last_end','last_pc','last_code','last_policy','last_footprint'))
        self.eq(b,st,last_first=0,last_end=0,last_pc=self.head+5,last_code=696,last_policy=1)
        self.eq(self.f(b,st,'last_footprint'),'li2_write_footprint',pc=self.head+5,next_pc=self.head+10,
                first=0,end=0,abi_version=1,policy=1,code=696,length=5)
        need(b==c,'whole cold state retained through live-only exit')
        rows=self.r.items(self.record,'lero_record','live_rseq','li2_link_rseq_live');zero(rows[0],'no invented warm hit check')
        for i in(1,2,3):self.live_rseq(rows[i],b,after if i==3 else before)

    def invocation65(self,e,index):
        self.head=self.app['head']+index*32;self.entry=e;self.record=r=self.f(e,'lero_entry','owner');t='lero_record';et='lero_entry'
        self.eq(e,et,present=1,closed=1,source_ready=1,redirected=1,completed=1,terminal=1,generated_bytes=PAGE,terminal_source_bytes=PAGE,proof_bytes=65536)
        if self.native_hint:self.eq(r,t,hint_checked=0,hint_hit=0,hint_publication=0)
        need(self.f(e,et,'terminal_source_page')==self.app['source'],'whole actual source after every epoch')
        before=self.frame(self.f(r,t,'before'));self.trace(before,self.head,self.app['seed'][1])
        need((before['fs'],before['gs'])==self.app['machine'][1:3],'actual per-lane entry TLS')
        source=self.source(self.f(r,t,'source'));index_old=self.transfer65(self.f(r,t,'transfer'),source,e)
        self.eq(r,t,slot_present=1,redirected=1,exit_seen=1,completed=1,release_started=1,release_complete=1,
                release_result=0,cleanup_started=0,cleanup_complete=0,unexpected_seen=0,map_result=0,
                build_started=1,build_returned=1,build_result=0,flags=self.app['seed'][1],gpr_written=1,flags_written=0,
                exit_index=0,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,prepare_result=0,
                miss_release_started=0,miss_release_complete=0,miss_release_result=0,resume_started=0,resume_complete=0,resume_result=0,resumed_route=0)
        for k in('miss_fetch','cleanup','original','proof_before'):zero(self.f(r,t,k),'no fabricated miss/cleanup/fault/warm authority '+k)
        p=self.proof(e,source,r);generated=p['generated'];self.eq(r,t,cold_plan_proof=p['cp'],cold_none_proof=p['cn'])
        self.query(self.f(r,t,'proof_enter'),p['address'],1,pages=16);self.query(self.f(r,t,'proof_exit'),p['address'],1,pages=16)
        self.query(self.f(r,t,'idle'),generated,1);self.permission(self.f(r,t,'open'),generated,5);self.query(self.f(r,t,'live'),generated,5);self.permission(self.f(r,t,'close'),generated,1)
        self.eq(r,t,idle_bytes=PAGE,live_bytes=PAGE,closed_bytes=PAGE)
        after=self.frame(self.f(r,t,'after'));self.nx(after,self.page+0xc00)
        need(before['fp']==after['fp']and before['fp_bytes']==after['fp_bytes']and before['mask']==after['mask']and(before['fs'],before['gs'])==(after['fs'],after['gs']),'whole actual FP/mask/TLS through replacement epoch')
        need(before['uc'][:40]==after['uc'][:40]and before['uc'][296:304]==after['uc'][296:304],'whole UC flags/link/altstack/mask')
        want=list(before['greg']);want[13]=index+1;want[16]=self.page+0xc00;want[17]|=RF;want[19],want[20],want[22]=21,14,self.page+0xc00
        need(after['greg']==tuple(want),'all23 actual GREG and exact MOV result/AF with only real NX fields')
        need(self.i(e,et,'redirect_event')==self.i(e,et,'ingress_event')>0 and self.i(e,et,'terminal_event')==self.i(e,et,'redirect_event')+1,'exact one external ingress; no internal generated signal')
        self.progress(self.f(r,t,'final_fetch'),source['borrow'],False)
        ep=self.epoch65(e,source,p);self.rseq65(e,before,after)
        a,z=(q(self.f(e,et,k))for k in('counts_before','counts_after'));delta=tuple(y-x for x,y in zip(a,z,strict=True));retired=delta[8]
        need(retired in(0,1)and delta==(1,1,1+retired,1,3,2,1,0,retired,retired),'exact cold publication/live/static/retirement accounting per actual root')
        need(p['cp']==a[2]+1 and p['cn']==a[3]+1,'cold proof ordinals precede any old-generation reconstruction')
        self.eq(self.f(e,et,'permit'),'ler_permit',generation=p['generation'],completion=z[1],valid=1)
        return dict(before=before,after=after,source=self.app['source'],terminal_source=self.app['source'],
                    before_memory=self.memory(self.f(e,et,'before_memory')),after_memory=self.memory(self.f(e,et,'after_memory')),
                    proof=p,epoch=ep,source_key=source['key'],disposition='completed',old_index=index_old)

    def closed_first(self,first):
        self.head=self.app['head'];pc=self.head-2;index=first['old_index'];closed=True
        flags=first['before']['greg'][17]|TF;g=list(first['before']['greg']);g[17]=flags
        after=dict(first['before'],greg=tuple(g))
        s=self.f(self.b,'lero_wire','first_closed');t='li2_tf_chain_slot'
        address=self.symbol('selected_chain')+self.r.types['li2_tf_chain']['fields']['slots']['offset']+index*self.r.types[t]['bytes']
        self.eq(s,t,chain=self.symbol('selected_chain'),index=index,phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(s,t,'generation')>0 and q(self.f(self.entries[0],'lero_entry','closed_owner'))[17]>=self.i(s,t,'event_id')>0,'actual owner generation and event chronology')
        zero(self.f(s,t,'unexpected'),'no fabricated ordinary unexpected frame');self.nop(self.f(s,t,'decoded'),pc)
        need(self.i(s,t,'origin')in(1,2)and self.i(s,t,'prepare_attempted')==int(self.i(s,t,'origin')==2),'actual NX or TRACE-created owner preparation')
        zero(self.f(s,t,'first_decoded'),'no fabricated boundary retry');zero(self.f(s,t,'first_fetch'),'no fabricated boundary fetch');zero(self.f(s,t,'first_release'),'no fabricated boundary release')
        ref=self.chain_fetch(self.f(s,t,'fetch'),pc,not closed)
        o=self.f(s,t,'owner');ot='li2_tf_owner';st=self.f(o,ot,'step');qtype='li2_step_owner'
        self.eq(st,qtype,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        hooks=self.f(st,qtype,'hooks');self.eq(hooks,'li2_step_hooks',context=address)
        for key in ('authenticate','failure'):need(canonical(self.i(hooks,'li2_step_hooks',key)),'actual nonnull ordinary callback')
        need(self.f(self.f(o,ot,'hooks'),'li2_tf_hooks','step')==hooks and canonical(self.i(self.f(o,ot,'hooks'),'li2_tf_hooks','continue_closed')),'actual matching typed TF hooks')
        request=self.f(st,qtype,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=self.app['seed'][1]);self.nop(self.f(request,'li2_step_request','decoded'),pc)
        pages=self.r.items(request,'li2_step_request','pages','li2_step_page');sourcepage=self.r.items(self.f(s,t,'fetch'),'li2_chain_fetch','pages','li2_fetch_page')[0]
        self.eq(pages[0],'li2_step_page',address=self.page,object=self.i(sourcepage,'li2_fetch_page','allocation'),generation=self.i(sourcepage,'li2_fetch_page','generation'),offset=self.h[21],closed_prot=1,open_prot=5);zero(pages[1],'whole unused permission page')
        for key in ('open_started','opened'):need(struct.unpack('<2I',self.f(st,qtype,key))==(1,0),'one actual permission open')
        for key in ('revoke_started','revoked'):need(struct.unpack('<2I',self.f(st,qtype,key))==(int(closed),0),'one actual completed or not-yet-started revoke')
        for key in ('open_result','revoke_result'):zero(self.f(st,qtype,key),'all actual permission results')
        for key in ('rdssp_query_attempted','rdssp_query_complete','rdssp_query_result','rdssp_features','bnd_xcr0_attempted','bnd_xcr0_complete','bnd_xcr0'):self.eq(o,ot,**{key:0})
        zero(self.f(o,ot,'rdssp_observation'),'NOP has no shadow-stack observer');self.eq(o,ot,unexpected_frame_observed=0,continuation_started=int(closed),continuation_complete=int(closed),continuation_result=0)
        cl=self.f(o,ot,'classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+2,abi_version=1,policy=1,code=299,length=2,flow=1,family=1)
        before=self.f(st,qtype,'before');g=q(self.f(before,'li2_step_frame','greg'));n=self.i(before,'li2_step_frame','fp_bytes')
        need(self.i(before,'li2_step_frame','mask')==MASK and self.i(before,'li2_step_frame','initialized')==n and 580<=n<=FP,'actual complete predecessor original frame')
        result=dict(greg=g,mask=MASK,fp=self.f(before,'li2_step_frame','fp'),fp_bytes=n,fs=self.app['machine'][1],gs=self.app['machine'][2])
        if closed:
            need(after is not None,'actual TRACE witness required for close');self.step_frame(self.f(st,qtype,'after'),after)
            self.eq(st,qtype,signal_number=5,signal_code=2,signal_errno=0,signal_address=pc+2)
            self.eq(o,ot,actual_post_pc=pc+2,actual_post_flags=after['greg'][17])
            query=self.f(s,t,'query');self.eq(query,'li2_tf_continuation',pc=pc+2,attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.page_row(self.f(query,'li2_tf_continuation','page'));self.backing(self.f(query,'li2_tf_continuation','backing'))
            self.eq(self.f(s,t,'release'),'li2_chain_release',started=1,complete=1,result=0)
        else:
            for key in ('query','release'):zero(self.f(s,t,key),'ordinary owner not prematurely closed/released')
            self.eq(st,qtype,signal_number=11 if self.i(s,t,'origin')==1 else 5,signal_code=2,signal_errno=0,signal_address=pc)
            zero(self.f(st,qtype,'after'),'ordinary owner has no future TRACE frame');self.eq(o,ot,actual_post_pc=0,actual_post_flags=0)
        transfer=self.f(self.f(self.entries[0],'lero_entry','owner'),'lero_record','transfer')
        self.eq(transfer,'li2_span_transfer_progress',previous=index,previous_generation=self.i(s,t,'generation'),previous_borrow=self.i(ref,'li2_fetch_ref','sequence'))
        return result

    def replacement(self,entries):
        w=self.f(self.b,'lero_wire','retirement');wt='lero_retirement';self.eq(w,wt,present=1,held=1,opened=1,completed=1)
        i=self.i(w,wt,'old_focal');need(0<=i<65,'actual previously completed focal retirement index');old_entry=entries[i]
        old_e=self.entries[i];old_p=old_entry['proof'];t=self.f(w,wt,'retirement');tt='ler_retirement'
        old_generation,new_generation,ordinal,completion=self.v(t,tt,'old_generation new_generation ordinal completion')
        need(old_generation==old_p['generation']and old_generation<new_generation<=self.counts['generation']and 0<ordinal<=self.counts['retirements'],'strict replacement of an actual older completed generation')
        self.eq(t,tt,started=1,consumed=1,old_verified=1,target_ready=1,replaced=1,slot=old_p['index'],verified_bytes=PAGE,old_entry=old_p['generated'])
        need(self.f(t,tt,'old_slot')==self.f(old_e,'lero_entry','slot'),'entire actual old resident metadata retained before overwrite')
        need(self.f(t,tt,'old_payload')==old_p['raw']+self.f(old_e,'lero_entry','proof_tail'),'whole actual old immutable65536 proof before reuse')
        need(completion==q(self.f(old_e,'lero_entry','counts_after'))[1],'consumed permit is the actual focal completion endpoint')
        self.eq(self.f(w,wt,'claimed'),'ler_permit',generation=old_generation,completion=completion,valid=1)
        self.query(self.f(t,tt,'old_idle'),old_p['generated'],1);self.permission(self.f(t,tt,'revoked'),old_p['generated'],1)
        newslot=self.f(w,wt,'new_slot');generated,address=self.v(newslot,'le_slot','generated proof');index=old_p['index']
        need(generated in(self.storage[0]+index*PAGE,self.storage[1]+index*PAGE)and address==old_p['address'],'actual fixed logical slot and one original code arena')
        self.eq(t,tt,new_entry=generated);self.permission(self.f(t,tt,'target_closed'),generated,1);self.permission(self.f(t,tt,'writable'),generated,3);zero(self.f(t,tt,'cleanup'),'no invented retirement cleanup')
        self.proof_permission(self.f(w,wt,'proof_close'),address,1);self.proof_permission(self.f(w,wt,'proof_writable'),address,3)
        self.eq(newslot,'le_slot',installed=1,complete=1,identity=new_generation,filled=PAGE,verified=PAGE,proof=address)
        self.query(self.f(newslot,'le_slot','writable'),generated,3);self.permission(self.f(newslot,'le_slot','publication'),generated,1)
        payload=self.f(w,wt,'new_payload');n=self.r.types['li2_link_proof']['bytes'];p=payload[:n];zero(payload[n:],'whole new immutable tail')
        header=self.f(p,'li2_link_proof','header');ht='li2_link_proof_header';self.eq(header,ht,version=1,bytes=65536,registry=self.symbol('lep'),slot=index,generation=new_generation,generated=generated)
        zero(self.f(header,ht,'reserved'),'new immutable header reserved')
        binding=self.image['binding'];need(self.f(header,ht,'archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(header,ht,'policy')==bytes.fromhex(binding['policy_sha256']),'same actual production archive/static NONE policy')
        planbytes=self.f(p,'li2_link_proof','plan');key=self.f(p,'li2_link_proof','key');pt='li2_link_plan'
        self.eq(planbytes,pt,version=1,ready=1,generated=generated,entry=self.i(key,'li2_span_source_key','entry'),page=self.i(self.f(key,'li2_span_source_key','page'),'li2_fetch_page','address'),decoder_result=0)
        need(self.f(planbytes,pt,'image')==self.f(w,wt,'generated_page')and self.f(planbytes,pt,'source')==self.f(key,'li2_span_source_key','bytes'),'entire actual new payload/source/generated publication; no arbitrary graph native credit')
        cp,cn=self.v(header,ht,'plan_proof none_proof');need(old_p['cp']<cp<=self.counts['plan_checks']and old_p['cn']<cn<=self.counts['rseq_checks'],'new cold authority strictly follows old completed proof')
        pub=self.f(w,wt,'publication');self.eq(pub,'le_proof_publication',started=1,complete=1,zeroed=65536,copied=n,verified=65536)
        need(self.f(pub,'le_proof_publication','header')==header,'whole new actual publication anchor');self.query(self.f(pub,'le_proof_publication','writable'),address,3,pages=16);self.proof_permission(self.f(pub,'le_proof_publication','sealed'),address,1)
        held,opened,terminal=(self.f(w,wt,k)for k in('held_epoch','opened_epoch','terminal_epoch'));et='li2_link_epoch_progress'
        self.eq(held,et,phase=1,first_error=0,first_detail=0,release_started=0,release_complete=0,publication=new_generation,generated=generated,source=self.i(planbytes,pt,'page'))
        need(self.i(held,et,'serial')>old_entry['epoch']['serial'],'genuine later epoch for replacement')
        for k in('opened','closed'):zero(self.f(held,et,k),'no future new epoch permission')
        self.r.change(held,opened,et,observed=('phase','opened'));self.eq(opened,et,phase=2);self.query(self.f(opened,et,'opened'),generated,5)
        self.r.change(opened,terminal,et,observed=('phase','release_started','release_complete','closed'));self.eq(terminal,et,phase=4,release_started=1,release_complete=1);self.query(self.f(terminal,et,'closed'),generated,1)
        self.permission(self.f(w,wt,'close'),generated,1);permit=self.f(w,wt,'permit');self.eq(permit,'ler_permit',generation=new_generation,valid=1)
        need(completion<self.i(permit,'ler_permit','completion')<=self.counts['completed'],'new permit exists only after genuine later completion')
        return dict(matched_prior_entry=1,old_focal=i,old_generation=old_generation,new_generation=new_generation,ordinal=ordinal,slot=index,completed=1)
    def refault_state(self):
        if self.native_hint:return self.hint_refault_state()
        c=self.counts;events=q(self.f(self.b,'lero_wire','events'))
        need(c['refaults']<=events[9],'actual reuse refault count is bounded by relocation refusals')
        b=self.f(self.b,'lero_wire','terminal_transfer');t='li2_span_transfer_progress'
        refault=self.i(b,t,'phase')==6;current=q(self.f(self.b,'lero_wire','terminal_current_fields'))
        need(self.v(b,t,'refault_attempted refaulted')==((1,1)if refault else(0,0))and
             current[34:]==((1,1,0)if refault else(0,0,0)),
             'actual reuse terminal refault phase and completion fields')
        if not refault:return
        self.eq(b,t,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,
                next=0,successor_installed=0,first_error=0,first_detail=0,serial=c['offers'])
        pc=self.i(b,t,'pc');oldborrow,fresh=self.v(b,t,'previous_borrow fresh_borrow')
        need(c['refaults']>0 and self.i(b,t,'previous')<2 and self.i(b,t,'event')>0 and
             self.i(b,t,'previous_generation')>0 and 0<oldborrow<fresh and
             canonical(pc)and pc>=0x200000000 and pc%PAGE<=PAGE-15 and not self.i(b,t,'flags')&0x30100,
             'actual reuse closed retry has high PC and a newer released borrow without successor')
        expected=[0]*37;expected[16]=1;expected[29:32]=[1,1,2404];expected[34:36]=[1,1]
        need(current==tuple(expected),'actual reuse retry current is a returned relocation miss without execution')
        fresh_b=self.f(b,t,'fresh');self.eq(fresh_b,'li2_span_fetch_observation',complete=1,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid)
        self.eq(self.f(fresh_b,'li2_span_fetch_observation','ref'),'li2_fetch_ref',sequence=fresh)
        self.progress(self.f(fresh_b,'li2_span_fetch_observation','progress'),fresh,False)

    def hint_refault_state(self):
        c=self.counts;events=q(self.f(self.b,'lero_wire','events'))
        need(c['refaults']<=events[9],'actual reuse refault count is bounded by relocation refusals')
        need(c['graph_refaults']<=events[8],'every graph retry is an actual counted GRAPH refusal')
        b=self.f(self.b,'lero_wire','terminal_transfer');t='li2_span_transfer_progress';refault=self.i(b,t,'phase')==6
        current=q(self.f(self.b,'lero_wire','terminal_current_fields'));advisory=q(self.f(self.b,'lero_wire','terminal_hint_fields'))
        need(self.v(b,t,'refault_attempted refaulted')==((1,1)if refault else(0,0))and current[34:]==((1,1,0)if refault else(0,0,0)),
             'actual reuse terminal refault phase and completion fields')
        if not refault:return
        self.eq(b,t,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,next=0,successor_installed=0,first_error=0,first_detail=0,serial=c['offers'])
        pc=self.i(b,t,'pc');oldborrow,fresh=self.v(b,t,'previous_borrow fresh_borrow');result=current[31]
        need(result in(2403,2404),'distinct actual reuse GRAPH or relocation retry')
        need(c['graph_refaults'if result==2403 else'refaults']>0 and self.i(b,t,'previous')<2 and self.i(b,t,'event')>0 and self.i(b,t,'previous_generation')>0 and 0<oldborrow<fresh and canonical(pc)and pc>=0x200000000 and pc%PAGE<=PAGE-15 and not self.i(b,t,'flags')&0x30100,
             'actual reuse closed retry has high PC and a newer released borrow without successor')
        expected=[0]*37;expected[16]=1;expected[29:32]=[1,1,result];expected[34:36]=[1,1]
        need(current==tuple(expected),'actual reuse retry current has exactly its returned refusal without execution')
        need(advisory[:2]==(1,1)and advisory[2]>0 if result==2403 else advisory==(0,0,0),'actual reuse retry class has exact advisory provenance')
        fresh_b=self.f(b,t,'fresh');self.eq(fresh_b,'li2_span_fetch_observation',complete=1,pc=pc,length=15,page_count=1,pid=self.pid,tid=self.pid)
        self.eq(self.f(fresh_b,'li2_span_fetch_observation','ref'),'li2_fetch_ref',sequence=fresh)
        self.progress(self.f(fresh_b,'li2_span_fetch_observation','progress'),fresh,False)

    def hint_state(self):
        hint=base.hint;T=hint.T;b=self.f(self.b,'lero_wire','terminal_hint');p=hint.receipt(self,b)
        need(all(p[k]in(0,1)for k in('ready','pending','outcome_complete')),'literal actual hint state flags')
        need(p['ready']+p['evictions']+p['hits']+p['invalidations']==p['publications']and p['hits']+p['invalidations']<=p['lookups'],'one-use positive hint conservation')
        need(p['lookups']<=q(self.f(self.b,'lero_wire','events'))[8],'every advisory lookup follows an actual GRAPH refusal')
        need(p['pending']==p['errors']==p['refused']==0 and p['hits']==self.counts['graph_refaults']==p['next_nx']==p['admitted']and p['hits']>0,'all65 complete with actual admitted graph retries and no fabricated native refusal')
        owners=self.f(self.b,'lero_wire','terminal_owners');life=self.f(owners,'leto_owners','lifecycle');pair=self.f(owners,'leto_owners','pair')
        need(p['publications']==p['receipt_publication']==self.i(life,'li2_native_pair_lifecycle','published')and 0<p['receipt_sequence']<=self.i(life,'li2_native_pair_lifecycle','sequence'),'all actual native publications feed the bounded advisory receipt')
        need(p['outcome_complete']==1 and p['outcome_result']==1 and 0<p['selected_publication']<=p['selected_published']<p['receipt_publication']and 0<p['selected_serial']<=self.counts['offers']and p['selected_event']<self.i(pair,'li2_native_pair_progress','events')and p['selected_seeds']<self.i(pair,'li2_native_pair_progress','seeds')and canonical(p['selected_pc'])and p['selected_pc']>=0x200000000 and p['selected_pc']%PAGE<=PAGE-15,'actual completed reuse hint outcome and older selected receipt')
        checked,hit,pub=q(self.f(self.b,'lero_wire','terminal_hint_fields'));current=q(self.f(self.b,'lero_wire','terminal_current_fields'));transfer=self.f(self.b,'lero_wire','terminal_transfer');t='li2_span_transfer_progress'
        need(checked in(0,1)and hit in(0,1)and hit<=checked and bool(pub)==bool(hit),'exact actual reuse current hint flags/publication')
        if checked:need(current[29:32]==(1,1,2403)and self.i(transfer,t,'pc')>=0x200000000,'actual high reuse GRAPH advisory source')
        if hit:need(pub==p['selected_publication']and self.i(transfer,t,'serial')==p['selected_serial']and self.i(transfer,t,'pc')==p['selected_pc'],'reuse current hit binds actual publication serial and PC')
        return p

    def hint_row(self,outcome):
        p=base.hint.values(self,self.f(self.b,'lero_wire','terminal_hint'));checked,hit,pub=q(self.f(self.b,'lero_wire','terminal_hint_fields'))
        return dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],**p,current_checked=checked,current_hit=hit,current_publication=pub)

    def finish(self,status):
        outcome=self.header(status);c=self.counts;self.refault_state();extra=c['graph_refaults']if self.native_hint else 0
        session=self.f(self.b,'lero_wire','session');self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        sync=self.i(session,'li2_step_session','sync_query');need(sync<1<<63 and sync&96==96,'actual sync-core registration')
        initial,terminal=(self.registry(self.f(self.b,'lero_wire',k))for k in('initial_registry','terminal_registry'))
        need(terminal[0][:len(initial[0])]==initial[0]and terminal[1][:len(initial[1])]==initial[1],'all original protected rows retained')
        self.arena(initial,terminal)
        entries=[self.invocation65(e,i)for i,e in enumerate(self.entries)]
        need(len(entries)==65 and len({x['proof']['generation']for x in entries})==65,'all65 actual distinct newly published generations')
        for a,b in zip(entries,entries[1:]):
            need(a['proof']['generation']<b['proof']['generation']and a['epoch']['serial']<b['epoch']['serial'],'actual ordered distinct root publication/epoch identities')
        self.head=self.app['head'];first=self.closed_first(entries[0]);replacement=self.replacement(entries)
        self.owners(self.f(self.b,'lero_wire','terminal_owners'));self.physical_rows(outcome)
        need(c['initialized']==1 and c['used']==64 and c['publications']>=65 and c['retirements']>0 and c['offers']==c['closed']==c['candidates']==c['entries']+c['resumed']+c['refaults']+extra,'actual64-slot saturation and all accepted/chosen offer accounting')
        need(c['resumed']+c['refaults']+extra==sum(c[k]for k in('hash_misses','source_misses','plan_misses','capacity_misses'))and c['entries']==c['publications']+c['hits']==c['claims'],'all actual misses/claims, no omitted runtime activity')
        need(c['generation']==c['publications']==64+c['retirements']and c['retirement_attempts']==c['retirements']and c['cursor']<64,'exact actual64-slot replacement population')
        need(c['completed']==c['permits_issued']==c['entries']and not any(c[k]for k in('unexpected','pending','retiring','first_error','first_detail','decoding','closing','resuming','proof_pending')),'all real completions/permits and no live or failed owner')
        need(c['plan_checks']==c['publications']+c['retirement_attempts']and c['rseq_checks']==c['publications']and c['live_checks']==3*c['publications']+4*c['hits']and c['proof_checks']==2*c['publications']+3*c['hits'],'whole actual cold/retirement/live/immutable proof accounting')
        need((c['proof_arena'],c['proof_bytes'],c['proof_registry'])==(self.storage[3],self.storage[4],self.storage[5]),'whole actual proof storage identity')
        events=q(self.f(self.b,'lero_wire','events'));raw=q(self.f(self.b,'lero_wire','raw_ingress'))
        need(events[0]==sum(events[1:6])and sum(events[6:10])==c['plan_misses']and sum(events[10:])==c['completed']and raw[0]==sum(raw[1:])and 0<raw[0]<=events[0]and all(x<=y for x,y in zip(raw[1:],events[1:6],strict=True)),'all actual event/refusal/exit rows')
        need(self.h[31:37]==(0,0,0,1,0,0),'no executable owner or pending route at final exit')
        self.eq(self.f(self.b,'lero_wire','terminal_fetch'),'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0)
        self.eq(self.f(self.b,'lero_wire','terminal_epoch'),'li2_link_epoch_progress',phase=4,first_error=0,first_detail=0,release_started=1,release_complete=1)
        chain=self.f(self.b,'lero_wire','terminal_chain');self.eq(chain,'li2_tf_chain',initialized=1,first_error=0,first_detail=0,pending=0,in_handler=0)
        chain_counts=span.chain_report(self.r,chain,outcome)
        need(chain_counts['nx_entries']==chain_counts['fallbacks']+c['entries']+c['refaults']+extra,
             'every actual reuse refault requires its own real NX chain segment')
        need(self.i(self.f(chain,'li2_tf_chain','entry'),'li2_tf_trace_entry','valid')==0 and not self.i(self.f(chain,'li2_tf_chain','lease'),'li2_tf_same_page','origin_active'),'no retained ordinary executable authority')
        for slot in self.r.items(chain,'li2_tf_chain','slots','li2_tf_chain_slot'):
            self.eq(slot,'li2_tf_chain_slot',phase=5,fallback=0,unexpected_frame_observed=0)
            owner=self.f(slot,'li2_tf_chain_slot','owner');step=self.f(owner,'li2_tf_owner','step')
            self.eq(step,'li2_step_owner',phase=5,first_error=0,first_detail=0,in_handler=0,trace_seen=1,revoke_sync_started=1,open_sync=0,revoke_sync=0)
            self.eq(owner,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0,unexpected_frame_observed=0)
            n=self.i(self.f(step,'li2_step_owner','request'),'li2_step_request','page_count');need(n in(1,2),'real bounded ordinary page bundle')
            for key in('open_started','opened','revoke_started','revoked'):need(struct.unpack('<2I',self.f(step,'li2_step_owner',key))==tuple(int(i<n)for i in range(2)),'all terminal ordinary permissions complete')
            for key in('open_result','revoke_result'):zero(self.f(step,'li2_step_owner',key),'all actual ordinary results')
            self.eq(self.f(slot,'li2_tf_chain_slot','query'),'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0,pc=self.i(owner,'li2_tf_owner','actual_post_pc'))
            self.eq(self.f(slot,'li2_tf_chain_slot','release'),'li2_chain_release',started=1,complete=1,result=0)
            fetch=self.f(slot,'li2_tf_chain_slot','fetch');ref=self.f(fetch,'li2_chain_fetch','ref');sequence=self.i(ref,'li2_fetch_ref','sequence');need(sequence>0,'actual terminal old released borrow')
            self.eq(self.f(fetch,'li2_chain_fetch','progress'),'li2_fetch_progress',held=0,complete=1,first_error=0,first_detail=0,sequence=sequence)
        if self.native_hint:self.hint_state()
        return dict(control=0,mode=6,entries=entries,first_predecessor_before=first,replacement=replacement,outcome=outcome,summary=c,events=events,raw_ingress=raw,original_sha256=hashlib.sha256(self.r.data).hexdigest(),_check=self)


def read(data,layout,image,app,pid,cpu,exit_status,control=0,*,native_hint=False):
    need(type(native_hint)is bool,'literal distinct reuse hint profile')
    need(type(control)is int and control==0 and type(app['mode'])is int and app['mode']==6 and type(exit_status)is int and exit_status==0,'actual65-entry pair only; failure cannot earn replacement credit')
    return Check(wire.Reader(data,layout,native_hint=native_hint),image,app,pid,cpu,control,native_hint).finish(exit_status)


def terminal(parsed,owner,*,native_hint=False):
    check=owner['_check'];c=owner['summary'];h=check.h;outcome=owner['outcome'];events=owner['events']
    need(type(native_hint)is bool and native_hint==check.native_hint,'exact reuse protected hint profile')
    fields='initialized first_error used offers closed resumed refaults hash_misses candidates source_misses plan_misses capacity_misses publications hits entries completed unexpected plan_checks rseq_checks live_checks proof_checks'.split()
    linked=dict(version=1,**outcome,**{k:c[k]for k in fields},events=events[0],active=h[31],busy=h[32],decoding=c['decoding'],closing=c['closing'],resuming=c['resuming'])
    f=old.Fields(check.r,check.f(check.b,'lero_wire','terminal_transfer'),'li2_span_transfer_progress')
    linked['transfer']=f.values('phase serial event previous next successor_installed previous_generation previous_borrow fresh_borrow pc flags issued consume_attempted consumed resume_attempted resumed first_error')+[abs(f.signed('first_detail')),int(f.signed('first_detail')<0)]+f.values('refault_attempted refaulted')
    linked['signals']=list(events[1:6]);linked['refusals']=list(events[6:10]);linked['exit_indices']=list(events[10:]);linked['current']=list(q(check.f(check.b,'lero_wire','terminal_current_fields')))
    reuse=dict(version=1,**outcome,**{k:c[k]for k in'generation retirement_attempts retirements claims permits_issued pending retiring cursor'.split()})
    current=old.Fields(check.r,check.f(check.b,'lero_wire','terminal_current'),'li2_current_custody_stats')
    current_row=dict(version=1,status=0,failure_code=0,**{k:current.integer(k)for k in'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels first_error'.split()},first_detail_abs=abs(current.signed('first_detail')),first_detail_negative=int(current.signed('first_detail')<0))
    chain=span.chain_report(check.r,check.f(check.b,'lero_wire','terminal_chain'),outcome)
    expected=dict(linked_epoch=linked,linked_epoch_reuse=reuse,current_tf=current_row,chain=chain,lease={k:v for k,v in chain.items()if k.startswith('lease_')},**check.physical_rows(outcome))
    if native_hint:
        linked['graph_refaults']=c['graph_refaults'];expected['native_hint']=check.hint_row(outcome)
    typed=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'))
    for key,value in expected.items():need(key in parsed and typed(parsed[key])==typed(value),'entire actual protected reuse terminal row '+key)
    return dict(actual_terminal_rows=len(expected),native_operations=0)


CONTROL_COUNTS={(6,0):47}
def controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,native_hint=False):
    baseline=read(data,layout,image,app,pid,cpu,exit_status,control,native_hint=native_hint);types=layout['types'];tests=[]
    def at(path):
        t='lero_wire';offset=0
        for field,index,child in path:
            offset+=types[t]['fields'][field]['offset']
            if index is not None:offset+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return offset
    def add(name,path):tests.append((name,[(at(path),1)],None))
    for i in(0,1,2,20,25,27,28,39,48,52):add('header_'+str(i),[('h',i,None)])
    e=[('entries',0,'lero_entry')];r=e+[('owner',None,'lero_record')]
    for name,path in(
      ('last_ready_generation',[('entries',64,'lero_entry'),('ready_generation',None,None)]),('actual_generation',[('counts',17,None)]),('actual_retirements',[('counts',19,None)]),
      ('capacity',[('counts',1,None)]),('proof_arena',[('storage',3,None)]),('strict_registry',[('initial_registry',None,'leto_registry'),('initial_code',None,None)]),
      ('entry_source',r+[('source',None,'li2_span_source'),('key',None,'li2_span_source_key'),('bytes',None,None)]),
      ('before_GPR',r+[('before',None,'le_frame'),('frame',None,'li2_step_frame'),('greg',13,None)]),
      ('after_FP',r+[('after',None,'le_frame'),('frame',None,'li2_step_frame'),('fp',None,None)]),
      ('before_mask',r+[('before',None,'le_frame'),('frame',None,'li2_step_frame'),('mask',None,None)]),
      ('actual_token',r+[('epoch',None,'li2_link_epoch_token'),('serial',None,None)]),
      ('source_borrow',r+[('source',None,'li2_span_source'),('borrow',None,'li2_fetch_ref'),('sequence',None,None)]),
      ('exit_release',r+[('release_complete',None,None)]),('live_guard',r+[('live_rseq',1,'li2_link_rseq_live'),('session',None,None)]),
      ('old_closed',e+[('closed_owner',3,None)]),('rseq_full_state',e+[('completed_rseq',None,'li2_rseq_state'),('last_code',None,None)]),
      ('proof_tail',e+[('proof_tail',None,None)]),('graph_image',e+[('proof',None,'li2_link_proof'),('plan',None,'li2_link_plan'),('image',None,None)]),
      ('archive',e+[('proof',None,'li2_link_proof'),('header',None,'li2_link_proof_header'),('archive',None,None)]),
      ('policy',e+[('proof',None,'li2_link_proof'),('header',None,'li2_link_proof_header'),('policy',None,None)]),
      ('generated',e+[('generated_page',None,None)]),('terminal_source',e+[('terminal_source_page',None,None)]),
      ('data',e+[('before_memory',None,'li2_leto_memory'),('data',None,None)]),('stack',e+[('after_memory',None,'li2_leto_memory'),('stack',None,None)]),
      ('interior_event',e+[('terminal_event',None,None)]),('last_cold',[('entries',64,'lero_entry'),('owner',None,'lero_record'),('build_started',None,None)]),
      ('last_FP',[('entries',64,'lero_entry'),('owner',None,'lero_record'),('after',None,'le_frame'),('frame',None,'li2_step_frame'),('fp',None,None)]),
      ('old_retired_payload',[('retirement',None,'lero_retirement'),('retirement',None,'ler_retirement'),('old_payload',None,None)]),
      ('consumed_permit',[('retirement',None,'lero_retirement'),('claimed',None,'ler_permit'),('completion',None,None)]),
      ('proof_reopen',[('retirement',None,'lero_retirement'),('proof_writable',None,'le_permission'),('prot',None,None)]),
      ('replacement_ro',[('retirement',None,'lero_retirement'),('publication',None,'le_proof_publication'),('sealed',None,'le_permission'),('prot',None,None)]),
      ('replacement_complete',[('retirement',None,'lero_retirement'),('completed',None,None)]),
      ('new_completion',[('retirement',None,'lero_retirement'),('permit',None,'ler_permit'),('valid',None,None)]),
      ('actual_terminal_rseq',[('terminal_owners',None,'leto_owners'),('rseq',None,'li2_rseq_state'),('first_error',None,None)]),
      ('actual_terminal_close',[('terminal_global_close',None,'li2_native_close'),('complete',None,None)]),
      ('first_predecessor',[('first_closed',None,'li2_tf_chain_slot'),('release',None,'li2_chain_release'),('complete',None,None)])):
        add(name,path)
    # A coherent supplied stale-generation claim: every new-generation alias in
    # the retained retirement witness is changed to its actual retired generation.
    w=[('retirement',None,'lero_retirement')];check=baseline['_check'];wb=check.f(check.b,'lero_wire','retirement')
    oldgen=check.i(check.f(wb,'lero_retirement','retirement'),'ler_retirement','old_generation')
    paths=[w+[('retirement',None,'ler_retirement'),('new_generation',None,None)],w+[('new_slot',None,'le_slot'),('identity',None,None)],
           w+[('publication',None,'le_proof_publication'),('header',None,'li2_link_proof_header'),('generation',None,None)],
           w+[('permit',None,'ler_permit'),('generation',None,None)]]
    paths += [w+[(k,None,'li2_link_epoch_progress'),('publication',None,None)]for k in('held_epoch','opened_epoch','terminal_epoch')]
    changes=[(at(p),struct.pack('<Q',oldgen))for p in paths]
    changes.append((at(w+[('new_payload',None,None)])+types['li2_link_proof']['fields']['header']['offset']+types['li2_link_proof_header']['fields']['generation']['offset'],struct.pack('<Q',oldgen)))
    tests.append(('coherent_retired_generation',changes,'strict replacement of an actual older completed generation'))
    need(len(tests)==47==CONTROL_COUNTS[(6,0)],'complete literal reuse47 supplied refusal population')
    refused=[]
    for name,changes,error in tests:
        changed=bytearray(data)
        for offset,value in changes:
            if type(value)is int:changed[offset]^=value
            else:changed[offset:offset+len(value)]=value
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,native_hint=native_hint)
        except ValueError as exc:
            if error is not None:need(str(exc)==error,'coherent stale generation reaches exact causal refusal')
            refused.append(name)
        else:raise ValueError('supplied reuse observation accepted '+name)
    return dict(refusals=refused,native_operations=0,original_sha256=baseline['original_sha256'])


REFAULT_CONTROL_COUNTS={(6,0):9}
def refault_controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,native_hint=False):
    """Nine new supplied refusals; the original47 controls remain separate."""
    baseline=read(data,layout,image,app,pid,cpu,exit_status,control,native_hint=native_hint);types=layout['types'];check=baseline['_check']
    def at(field):return types['lero_wire']['fields'][field]['offset']
    transfer=at('terminal_transfer');tf=types['li2_span_transfer_progress']['fields'];tests=[]
    flags='actual reuse terminal refault phase and completion fields'
    for key in('refault_attempted','refaulted'):
        tests.append(('terminal_'+key,[(transfer+tf[key]['offset'],None)],flags))
    for i in range(34,37):tests.append(('terminal_current_'+str(i),[(at('terminal_current_fields')+8*i,None)],flags))
    tests.append(('refault_above_relocation',[(at('counts')+36*8,baseline['events'][9]+1)],
                  'actual reuse refault count is bounded by relocation refusals'))
    phase=check.i(check.f(check.b,'lero_wire','terminal_transfer'),'li2_span_transfer_progress','phase')
    tests.append(('refault_phase_flags',[(transfer+tf['phase']['offset'],5 if phase==6 else 6)],flags))
    # One extra completed relocation retry, coherent across every count alias,
    # still lacks its mandatory actual ordinary NX segment.
    changes=[(at('counts')+8*i,baseline['summary'][COUNTS[i]]+1)for i in(2,3,6,8,36)]
    changes.append((at('events')+9*8,baseline['events'][9]+1))
    if phase==6:changes.append((transfer+tf['serial']['offset'],baseline['summary']['offers']+1))
    tests.append(('refault_missing_NX',changes,'every actual reuse refault requires its own real NX chain segment'))
    eo=at('entries')+types['lero_entry']['fields']['owner']['offset']+types['lero_record']['fields']['transfer']['offset']
    tests.append(('consumed_focal_false_refault',[(eo+tf['refault_attempted']['offset'],None)],
                  'exact li2_span_transfer_progress.refault_attempted'))
    refused=[]
    for name,changes,error in tests:
        changed=bytearray(data)
        for offset,value in changes:
            if value is None:changed[offset]^=1
            else:
                width=4 if offset==transfer+tf['phase']['offset']else 8
                changed[offset:offset+width]=value.to_bytes(width,'little')
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,native_hint=native_hint)
        except ValueError as exc:need(str(exc)==error,'exact new refault refusal '+name);refused.append(name)
        else:raise ValueError('supplied reuse refault accepted '+name)
    need(len(refused)==REFAULT_CONTROL_COUNTS[(6,0)],'all nine additive reuse refault refusals')
    return dict(refault_refusals=refused,native_operations=0,original_sha256=baseline['original_sha256'])

HINT_CONTROL_COUNTS={(6,0):20}
def hint_controls(data,layout,image,app,pid,cpu,exit_status,control=0,*,native_hint=False):
    need(native_hint is True,'reuse advisory controls require explicit v3')
    baseline=read(data,layout,image,app,pid,cpu,exit_status,control,native_hint=True);c=baseline['_check'];types=layout['types'];tests=[]
    def at(path):
        offset=0;t='lero_wire'
        for key,index,child in path:
            offset+=types[t]['fields'][key]['offset']
            if index is not None:offset+=index*(types[child]['bytes']if child else 8)
            if child:t=child
        return offset
    def value(path,n,width=8):return at(path),n.to_bytes(width,'little')
    terminal=[('terminal_hint',None,base.hint.T)];p=base.hint.values(c,c.f(c.b,'lero_wire','terminal_hint'))
    for key,n,width in(('ready',2,4),('pending',1,4),('outcome_complete',0,4),('publications',p['publications']+1,8),
        ('evictions',p['evictions']+1,8),('invalidations',p['invalidations']+1,8),('hits',p['hits']+1,8),
        ('lookups',baseline['events'][8]+1,8),('next_nx',p['next_nx']+1,8),('admitted',p['admitted']+1,8),
        ('refused',1,8),('errors',1,8),('receipt_sequence',0,8),('receipt_publication',0,8),('selected_serial',0,8),('selected_pc',0,8)):
        tests.append(('reuse_hint_terminal_'+key,[value(terminal+[(key,None,None)],n,width)],None))
    entry=[('entries',0,'lero_entry'),('owner',None,'lero_record')]
    for key in('hint_checked','hint_hit','hint_publication'):
        tests.append(('reuse_focal_'+key,[(at(entry+[(key,None,None)]),None)],'exact lero_record.'+key))
    changes=[value([('counts',i,None)],baseline['summary'][COUNTS[i]]+1)for i in(2,3,6,8)]
    changes += [value([('counts',37,None)],baseline['summary']['graph_refaults']+1),value([('events',8,None)],baseline['events'][8]+1)]
    phase=c.i(c.f(c.b,'lero_wire','terminal_transfer'),'li2_span_transfer_progress','phase')
    if phase==6:changes.append(value([('terminal_transfer',None,'li2_span_transfer_progress'),('serial',None,None)],baseline['summary']['offers']+1))
    tests.append(('reuse_graph_retry_without_actual_segment',changes,'every actual reuse refault requires its own real NX chain segment'))
    need(len(tests)==HINT_CONTROL_COUNTS[(6,0)]and len({x[0]for x in tests})==len(tests),'exact20 separate reuse hint refusals')
    refused=[]
    for name,changes,error in tests:
        changed=bytearray(data)
        for offset,payload in changes:
            if payload is None:changed[offset]^=1
            else:changed[offset:offset+len(payload)]=payload
        need(bytes(changed)!=data,'actual reuse supplied mutation')
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status,control,native_hint=True)
        except ValueError as exc:
            if error is not None:need(str(exc)==error,'reuse advisory mutation reaches exact semantic gate '+name)
            refused.append(name)
        else:raise ValueError('supplied reuse advisory accepted '+name)
    return dict(hint_refusals=refused,native_operations=0,original_sha256=baseline['original_sha256'])
