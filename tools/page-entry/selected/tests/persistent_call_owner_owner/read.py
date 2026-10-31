"""One actual cold CALL hit/miss, full frames and original-stack authority.

This reader observes the real protected owner. It does not execute a model or
supply owner authority. Whole-profile, warm, RET and performance gates remain
separate. All predecessor readers and their control populations are unchanged.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
wire=load('call_owner_wire',HERE/'wire.py')
plan=load('call_owner_plan',HERE/'plan.py')
donor=load('call_owner_existing_checks',HERE.parent/'persistent_direct_frontier_owner/read.py')
old=wire.base.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,TF,RF,MASK=old.U64,old.PAGE,old.TF,old.RF,old.MASK
T='pclo_wire'
COUNTERS='offers publications hits cold_attempts cancelled retirements permit_claims entries completed unexpected'.split()
TERMINAL_NAMES='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
SUBENTRY_NAMES='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split()

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
            if name in registered or name in ('li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected','maps_current','rows'):
                need(name not in symbols,'unique actual bridge symbol');symbols[name]=(address,size)
    need(set(symbols)==set(registered)|{'li2_raw6','li2_gateway_start','li2_gateway_end','span_transfer','selected_chain','protected','maps_current','rows'},'whole required compiled object inventory')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    return h,ph,symbols

class Check(donor.Check):
    """Reuse the complete existing source/query/frame primitives unchanged.

    No older cohort's storage, graph, peer-selection or terminal predicate is
    used as authority for this different witness. Those methods are replaced
    below with the exact singleton shape and actual saved values.
    """
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data;self.h=q(self.f(self.b,T,'h'));h=self.h
        self.bias=h[9]-r.layout['symbols']['pe'];self.page=app['source_page_address'];self.head=app['head']
        self.mode=app['mode'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for k,obj in image['objects'].items():
            need(type(k)is int and type(obj)is dict,'actual complete original-object inventory')
            eh,loads=old.elf(obj['data']);self.objects[k]=(obj,eh,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual main/interpreter identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'whole actual ELF/DWARF object-address join')
        b=image['persistent_binding'];need(b['version']==1 and b['unregistered']is True and b['subentry']is True and b['cross_pair']is True and b['direct_frontier']is True and b['call_dispatch']is True and b['call_owner_capture']is True and b['typed_capture']is True and b['capture_schema']==1 and b['mode']in('capture','differential')and b['profile']=='persistent-call-owner-'+b['mode']+'-v1','distinct actual CALL owner build')
        self.differential=b['mode']=='differential'
        self.payload=self.f(self.b,T,'payload');self.key=self.f(self.payload,'pe_payload','source');self.header=self.f(self.payload,'pe_payload','header');self.compacted=self.f(self.payload,'pe_payload','plan')
        row=r.items(self.key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        identity=self.f(row,'li2_pg_source_page','identity');self.main_backing=self.f(row,'li2_pg_source_page','backing')
        self.source_offset=self.i(identity,'li2_fetch_page','offset');self.main_vma_identity=self.v(identity,'li2_fetch_page','vma_major vma_minor vma_inode')
        self.geometry=self.layout(self.f(self.header,'pe_header','layout'));self.generated=self.geometry[0];self.spill=self.geometry[4];self.proof=h[67];self.table=h[68]
        self.serial,self.generation=h[63:65]

    def layout(self,b,base=None):
        v=q(b);need(len(v)==7,'whole actual CALL layout including sealed window')
        a,c,stubs,slots,spill,directory,window=v
        need(a%PAGE==0 and canonical(a,77824)and v[:5]==(a,a+32768,a+65536,a+69632,a+73728),'exact contiguous complete two-bank image geometry')
        need((directory,window)==(self.h[66],self.h[65])and directory%PAGE==window%PAGE==0 and canonical(directory,12288)and canonical(window,PAGE),'actual shared directory and window coordinates')
        ranges=[(a,a+77824),(directory,directory+12288),(window,window+PAGE)]
        need(all(x1<=y0 or y1<=x0 for i,(x0,x1)in enumerate(ranges)for y0,y1 in ranges[i+1:]),'whole bank/directory/window allocations disjoint')
        if base is not None:need(a==base,'actual selected bank base')
        return v

    def frame(self,b,tls=True):
        f=super().frame(b,tls)
        need(f['uc'][304:432]==f['si'],'whole actual adjacent kernel siginfo in copied context')
        return f

    def source_window(self,pc):
        off=pc-self.page;source=self.app['source']+self.app['continuation']
        need(0<=off<=len(source)-15 and off%PAGE<=PAGE-15,'whole ordinary one-page source window')
        return source[off:off+15],1

    def decoded(self,b,pc,kind=None):
        forms={self.page+0x1fe:(765,2),self.page+0x20a:(759,3),self.page+0x304:(765,3)}
        need(pc in forms,'exact original predecessor/CALL/memory-JMP source')
        code,length=forms[pc];window,_=self.source_window(pc)
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=0,available=15,length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==window+b'\0','whole actual ordinary decoded bytes')
        return code,length

    def page_row(self,b,index=0):
        need(index in(0,1,2),'only complete source pair or actual U page')
        super().page_row(b,index)
        if index in self.source_ids:need(self.source_ids[index]==bytes(b),'whole source page/allocation/generation/backing/VMA identity unchanged')
        else:self.source_ids[index]=bytes(b)

    def source_key(self,key,entry):
        self.eq(key,'li2_pg_source_key',entry=entry);need(entry==self.head,'exact focal compiled root')
        for i,row in enumerate(self.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')):
            self.page_row(self.f(row,'li2_pg_source_page','identity'),i);self.backing(self.f(row,'li2_pg_source_page','backing'))
            need(self.f(row,'li2_pg_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],'complete original source pair')

    def counts(self,b):
        return {k:self.i(b,'pclo_counts',k)for k in COUNTERS}

    def source_registry(self):
        s=self.f(self.b,T,'window_seed');self.eq(s,'pcw_seed',rsp=self.h[30],pc=self.head,first=self.h[30]-256,end=self.h[30]+256)
        need(q(self.f(s,'pcw_seed','page'))==(self.page,self.page+PAGE),'prospective window authenticated source pair')
        n=self.i(s,'pcw_seed','registry_count');need(0<n<=128,'whole bounded protected registry')
        rows=self.r.items(s,'pcw_seed','registry','li2_fork_range');ranges=[self.v(x,'li2_fork_range','first end')for x in rows[:n]]
        for x in rows[n:]:zero(x,'all unused protected registry rows')
        need(len(set(ranges))==n and all(canonical(a,z-a)for a,z in ranges),'complete distinct protected byte extents')
        headers=self.image['headers'];declarations=self.r.layout['registrations'];need(set(declarations)==set(wire.REGISTERED),'every actual registered object declaration')
        objects=[]
        for name,(source,tag)in wire.REGISTERED.items():
            d=declarations[name];at,size=self.symbols[name];a,z=self.bias+at,self.bias+at+size
            need(set(d)=={'address','bytes','alignment','tag','source'}and(d['address'],d['bytes'],d['tag'])==(at,size,tag)and type(d['alignment'])is int and 0<d['alignment']<=PAGE and not d['alignment']&(d['alignment']-1)and a%d['alignment']==0 and d['source'].endswith('/tools/page-entry/selected/'+source),'whole actual registered symbol/type/source '+name)
            need(d['source']in headers and set(headers[d['source']])=={'bytes','sha256'},'actual compiler-M source closure '+name)
            if name not in wire.LIFETIME:need(ranges.count((a,z))==1,'whole strict protected object '+name)
            loads=[p for p in self.ph if p[0]==1 and p[6]and self.bias+p[3]<z and a<self.bias+p[3]+p[6]]
            need(len(loads)==1 and loads[0][1]==6 and self.bias+loads[0][3]<=a<z<=self.bias+loads[0][3]+loads[0][6],'whole registered object in actual RW/NX load')
            p=loads[0];need(ranges.count(((self.bias+p[3])&-PAGE,(self.bias+p[3]+p[6]+PAGE-1)&-PAGE))==1,'whole actual bridge load is protected');objects.append((a,z))
        need(all(a%PAGE==z%PAGE==0 or(a,z)in objects for a,z in ranges),'all non-page ranges are exact registered objects')
        for a,z in((self.generated,self.generated+77824),(self.proof,self.proof+364544),(self.h[65],self.h[65]+PAGE),(self.h[66],self.h[66]+12288)):
            need(ranges.count((a,z))==1,'complete current generated/proof/window/directory protection')
        first,end=self.h[30]-256,self.h[30]+264
        need(all(end<=a or z<=first for a,z in ranges+[(self.page,self.page+8192)]),'whole original stack envelope excludes all protected storage and both source pages')
        self.ranges=ranges

    def stack_origin(self,b):
        t='li2_maps_call_stack';anchor,a,z,first,end,origin=self.v(b,t,'anchor origin_first origin_end first end origin_acquisition')
        need(a%PAGE==z%PAGE==0 and canonical(a,z-a)and a<=anchor<z and a<=first<end<=z and(first,end)==(self.h[30]-256,self.h[30]+264)and origin>0,'actual bootstrap original-stack anchor and whole CALL envelope')
        o=self.f(b,t,'observation');acq,handler,epoch,kind,io=self.v(o,'li2_maps_observation','acquisition_id handler_id mutation_epoch kind io_performed')
        need(acq>=origin and epoch>0 and kind in((0,1,3)if self.differential else(0,1,4))and io==int(kind!=4)and(handler==0 if kind==0 else handler>0),'actual original-stack query acquisition')
        return anchor,a,z,first,end,origin

    def window(self):
        prepared,bound=(self.f(self.b,T,k)for k in('prepared_stack','bound_stack'))
        self.stack_identity=self.stack_origin(prepared);need(self.stack_origin(bound)==self.stack_identity,'same original bootstrap stack lineage at preparation and bind')
        w=self.f(self.b,T,'expected_window');self.eq(w,'li2_cd_window',version=1,owner=self.symbol('pe'),serial=self.serial,first=self.h[30]-256,end=self.h[30]+256)
        zero(self.f(w,'li2_cd_window','reserved'),'whole reserved window words')
        need(self.f(self.b,T,'window')==w+bytes(PAGE-len(w)),'whole actual sealed window page including zero tail')
        self.permission(self.f(self.b,T,'window_write'),self.h[65],3,1);self.permission(self.f(self.b,T,'window_seal'),self.h[65],1,1)

    def memory(self,b,site):
        t='li2_pclo_memory';self.eq(b,t,attempted=1,complete=1,rows_checked=6,pages_checked=3,site=site,reserved=0,source_copied=8192,continuation_copied=4096,data_copied=8192,stack_copied=520,result=0,detail=0,rsp=self.h[30])
        need(self.stack_origin(self.f(b,t,'stack_origin'))==self.stack_identity,'same complete bootstrap stack lineage at every frame')
        m=self.maps(self.f(b,t,'maps'),1 if site==2 else 0);a,z=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats';phase=int(site==2)
        self.eq(a,mt,active=phase,poisoned=0,reserved=0);self.eq(z,mt,active=phase,poisoned=0,reserved=0,valid=1)
        self.r.change(a,z,mt,values=dict(fresh_calls=self.i(a,mt,'fresh_calls')+1,acquisitions=self.i(a,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        inc=self.i(z,mt,'invalidations')-self.i(a,mt,'invalidations')
        need(inc>=1 and self.i(z,mt,'mutation_epoch')-self.i(a,mt,'mutation_epoch')==inc and m[:3]==(self.i(z,mt,'acquisitions'),self.i(a,mt,'handler_id')if phase else 0,self.i(z,mt,'mutation_epoch')),'actual fresh maps read and complete mutation/phase accounting')
        rows=self.r.items(b,t,'rows','li2_pclo_map_row');anchor,first,end,*_=self.stack_identity
        for i,row in enumerate(rows):
            self.eq(row,'li2_pclo_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pclo_map_row','first end prot');need(a%PAGE==z%PAGE==0 and canonical(a,z-a),'whole actual memory mapping')
            if i<2:need((a,z,prot)==(old.DATA,old.DATA+8192,3),'complete writable data mapping')
            elif i==2:need(a<=old.DATA+8192 and old.DATA+12288<=z and prot==0,'actual inaccessible data guard')
            else:need(a<=first<end<=z and prot==3,'complete writable original stack mapping')
        for i,(p,back)in enumerate(zip(self.r.items(b,t,'pages','li2_fetch_page'),self.r.items(b,t,'backing','li2_fetch_backing'),strict=True)):
            self.page_row(p,i);self.backing(back)
        need(self.f(b,t,'source')==self.app['source']and self.f(b,t,'continuation')==self.app['continuation']and self.f(b,t,'data')==self.app['data'],'every original source/U/data byte at each frame')
        expected=bytearray(self.app['stack'])
        if site==2 or(site==1 and not self.mode):struct.pack_into('<Q',expected,248,self.h[23])
        need(self.f(b,t,'stack')==bytes(expected),'all520 original stack bytes and exact one return-word store')
        return self.f(b,t,'stack')

    def entry(self,e,source):
        t='li2_pgs_entry';self.eq(e,t,complete=1,reserved=0,transfer_serial=self.i(self.f(self.b,T,'entered_progress'),'li2_pg_progress','transfer_serial'),generation=self.generation,build_serial=self.serial,slot=self.h[61],bank=self.h[62])
        self.eq(self.f(e,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=self.serial)
        need(self.f(e,t,'anchor')==self.f(source,'li2_pg_sources','anchor'),'entry owns the actual held original-source anchor')
        v=self.f(e,t,'target');self.eq(v,'li2_pgs_target',version=1,heads=4,head=0,member=0,local=0,source_page=0,root=self.head,pc=self.head,generated=self.generated)
        need(q(self.f(v,'li2_pgs_target','page'))==(self.page,self.page+PAGE),'exact root-entry source pages')
        for field,typ in(('row','li2_pe_head'),('original','li2_span_decoded')):
            cf='head'if field=='row'else'original';need(self.f(e,t,field)==self.r.items(self.compacted,'li2_pg_compact',cf,typ)[0],'whole actual root '+field)

    def compact(self):
        c=self.compacted;t='li2_pg_compact'
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+8192)],self.table)
        need(self.f(c,t,'table')==table,'whole canonical exclusion tree covers every protected range and both complete source pages')
        expected=plan.graph(self.app['source'],self.page,self.head,self.geometry,table)
        self.eq(c,t,version=6,bytes=self.r.types[t]['bytes'],ready=1,result=0,heads=4,exits=2,stores=1,source_bytes=17,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=self.head)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(4,0)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole actual compact source, layout and membership')
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent CALL graph '+k)
        need(self.f(c,t,'exit_pc')==expected['exit_pc_bytes'],'all exact ordered CALL and memory-JMP exits')
        plan_at=self.proof+self.r.types['pe_payload']['fields']['plan']['offset']
        need(self.table==plan_at+self.r.types[t]['fields']['table']['offset']and self.table-64576==plan_at+self.r.types[t]['fields']['original']['offset'],'actual immutable row/table relocation relation')
        code=expected['image']+expected['stub_image'];need(len(code)==69632 and self.f(self.b,T,'code')==code,'all17 actual emitted code pages equal independent model')
        ph=self.header;gt='pe_header'
        self.eq(ph,gt,version=1,serial=self.serial,generation=self.generation,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=0,rseq_address=0,rseq_length=0,rseq_signature=0,lifetime_version=1,lifetime_mode=2)
        need(self.f(ph,gt,'layout')==self.f(c,t,'layout')and q(self.f(ph,gt,'member_generation'))==(2*self.generation,2*self.generation+1),'whole publication generation/layout')
        b=self.image['persistent_binding'];need(self.f(ph,gt,'archive')==bytes.fromhex(b['archive']['sha256'])and self.f(ph,gt,'policy')==bytes.fromhex(b['policy_sha256']),'whole actual archive and source policy')
        zero(self.f(ph,gt,'reserved'),'whole immutable header reserved words');zero(self.f(self.b,T,'proof_tail'),'whole89-page proof zero tail')
        self.source_key(self.key,self.head)
        for key,n in(('proof_scan',364544),('code_scan',69632),('window_scan',4096),('unexpected_scan',self.r.types['li2_step_frame']['bytes'])):
            self.eq(self.f(self.b,T,key),'pclo_scan',compared=n,differences=0,first_offset=0,expected=0,actual=0)
        return expected

    def reference(self,b):
        self.eq(b,'li2_pgd_ref',generation=self.generation,slot=self.h[61],bank=self.h[62],proof=self.proof,root=self.head)
        need(self.layout(self.f(b,'li2_pgd_ref','layout'))==self.geometry,'whole singleton member layout')

    def work(self,w,terminal):
        t='pda_work';self.eq(w,t,bound=1,peer=2,primary=self.h[61],primary_bank=self.h[62],exit_member=0 if terminal else 2,receipt=self.h[69],recovery_member=2,completion=int(terminal),aborting=0)
        v=self.f(w,t,'view');self.eq(v,'li2_pgd_view',count=1,reserved=0,directory=self.h[66]);self.eq(self.f(v,'li2_pgd_view','token'),'li2_pg_token',owner=self.symbol('pe'),serial=self.serial)
        members=self.r.items(v,'li2_pgd_view','member','li2_pgd_member');m=members[0];zero(members[1],'no fabricated second active member')
        ref=self.f(m,'li2_pgd_member','identity');self.reference(ref)
        self.eq(m,'li2_pgd_member',plan=self.proof+self.r.types['pe_payload']['fields']['plan']['offset'],key=self.proof+self.r.types['pe_payload']['fields']['source']['offset'])
        self.entry(self.f(v,'li2_pgd_view','entry'),self.f(self.f(self.b,T,'entered_source'),'li2_pg_source_progress','source'))
        zero(self.f(w,t,'peer_claim'),'cold singleton has no peer claim')
        self.permission(self.f(w,t,'directory_write'),self.h[66],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[66],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[66],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory close')
        for i,x in enumerate(self.r.items(w,t,'proof_exit','pg_proof_query')):
            if terminal and i==0:self.proof_query(x,self.proof,1)
            else:zero(x,'no unused or premature proof exit')
        d=self.f(w,t,'directory');self.eq(d,'li2_jd_domain_directory',version=1,count=4,serial=self.serial,reserved=0)
        rows=b''.join(struct.pack('<3Q2I',self.page+off,self.generated+i*512,self.generation,self.h[61],i)for i,off in enumerate((0x200,0x204,0x300,0x20a)))
        need(self.f(d,'li2_jd_domain_directory','row')==rows+bytes((256-4)*32),'all actual directory rows and unused tail; U is absent')
        need(self.f(self.b,T,'terminal_directory'if terminal else'initial_directory')==d+bytes(12288-len(d)),'whole actual sealed directory pages')
        return ref

    def generation_transition(self,g,z):
        t='li2_pg_generation';gen=self.generation;serial=self.serial
        self.eq(g,t,installed=1,complete=1,proof_complete=1,generation=gen,ready_generation=gen,build_serial=serial,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362672,proof_verified=364544)
        need(self.layout(self.f(g,t,'layout'))==self.geometry and q(self.f(g,t,'member_generation'))==(2*gen,2*gen+1)and q(self.f(g,t,'member_refs'))==(1,1),'exact actual bank generations and active references')
        zero(self.f(g,t,'incoming'),'zero static links have no incoming references')
        self.query3(self.f(g,t,'code_writable'),3);self.proof_query(self.f(g,t,'proof_writable'),self.proof,3);self.query(self.f(g,t,'spill_query'),self.spill,3);zero(self.f(g,t,'slot_query'),'unused aggregate slot query')
        self.permission3(self.f(g,t,'code_sealed'),1);self.proof_permission(self.f(g,t,'proof_sealed'),self.proof,1);self.permission3(self.f(g,t,'open'),5)
        zero(self.f(g,t,'close'),'no premature code revoke');zero(self.f(g,t,'cleanup'),'no failed code cleanup')
        a=self.r.items(g,t,'slots','pg_slot_transition');b=self.r.items(z,t,'slots','pg_slot_transition')
        self.slots_transition(a[0],False);self.slots_transition(a[1],True);zero(a[2],'no premature slot drain')
        self.r.change(g,z,t,values=dict(active_refs=0,linked=0,domain_refs=0),observed=('member_refs','incoming','close','slots','cell'))
        for k in('incoming','member_refs'):zero(self.f(z,t,k),'all original and generated references drained')
        self.permission3(self.f(z,t,'close'),1);need(b[:2]==a[:2],'whole initial/link observations retained');self.slots_transition(b[2],False)
        ca=self.r.items(g,t,'cell','pg_dispatch_cell_transition');cz=self.r.items(z,t,'cell','pg_dispatch_cell_transition')
        self.cell(ca[0],gen,serial,0);self.cell(ca[1],gen,serial,0);zero(ca[2],'no premature CALL target-cell drain')
        need(cz[:2]==ca[:2],'whole initial/entry target-cell resets retained')
        self.cell(cz[2],gen,serial,0 if self.mode else self.generated+2*512)

    def lifetime(self,b,ref,terminal):
        self.unregistered_pin(b,self.serial,terminal)
        self.eq(b,'li2_pg_rseq_progress',cold_heads=4,cold_stores=1,cold_stubs=0,domain_count=1)
        need(self.f(b,'li2_pg_rseq_progress','domain_ref')==ref+bytes(self.r.types['li2_pgd_ref']['bytes']),'whole singleton unregistered lifetime member')

    def domain_source(self,b,ref,source):
        t='li2_pgd_source_progress';self.eq(b,t,count=1,bound=1,opened=1,closed=1,released=1,first_error=0,first_detail=0)
        self.eq(self.f(b,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=self.serial)
        need(self.f(b,t,'ref')==ref+bytes(self.r.types['li2_pgd_ref']['bytes']),'exact released singleton member set')
        zero(self.f(b,t,'peer'),'singleton has no invented cross-pair lease')
        n=3*self.r.types['li2_private_code_query']['bytes']
        for field,prot,key in(('open',5,'opened'),('close',1,'closed')):
            x=self.f(b,t,field);self.query3(x[:n],prot);zero(x[n:],'unused second-member queries')
            need(x[:n]==self.f(source,'li2_pg_source_progress',key),'actual source/domain share complete query receipts')
        self.entry(self.f(b,t,'entry'),self.f(source,'li2_pg_source_progress','source'))

    def activation(self):
        h=self.h;prior,entered,ended,final=(self.counts(self.f(self.b,T,k))for k in('prior_counts','entered_counts','terminal_counts','final_counts'))
        need(prior['entries']==prior['completed']and prior['unexpected']==0,'preceding unrelated entries actually completed')
        replacement=entered['retirements']-prior['retirements'];need(replacement in(0,1),'at most one actual replaced idle generation')
        increments=dict(offers=1,publications=1,cold_attempts=1,retirements=replacement,permit_claims=replacement,entries=1)
        need(all(entered[k]==prior[k]+increments.get(k,0)for k in COUNTERS),'exact cold focal publication, entry, no hit/cancel')
        need(all(ended[k]==entered[k]+int(k=='completed')for k in COUNTERS),'one complete focal owner activation')
        need(all(final[k]>=ended[k]for k in COUNTERS),'final descriptive counters retain every focal event')
        ew,zw=(self.f(self.b,T,k)for k in('entered_work','terminal_work'));ref=self.work(ew,False);need(self.work(zw,True)==ref,'whole member stable through close')
        self.r.change(ew,zw,'pda_work',values=dict(exit_member=0,completion=1),observed=('proof_exit','directory_closed'))
        c=self.f(self.b,T,'completion');ct='pda_completion';cid=self.i(c,ct,'id');need(0<cid<U64,'actual immutable completion identity')
        self.eq(c,ct,serial=self.serial,count=1,complete=1)
        m,unused=self.r.items(c,ct,'member','pda_member_completion');zero(unused,'whole unused completion member')
        need(self.f(m,'pda_member_completion','identity')==ref and self.f(m,'pda_member_completion','header')==self.header and self.f(m,'pda_member_completion','source')==self.key,'whole by-value completed member certificate')
        self.generation_transition(self.f(self.b,T,'entered_generation'),self.f(m,'pda_member_completion','generation'))
        self.proof_query(self.f(m,'pda_member_completion','proof'),self.proof,1)
        need(self.f(m,'pda_member_completion','proof')==self.r.items(zw,'pda_work','proof_exit','pg_proof_query')[0],'actual final proof query copied into completion')
        self.eq(self.f(self.b,T,'claim'),'li2_pgd_claim',id=cid,cell=h[69],member=0,valid=1,reserved=0)
        es=self.f(self.b,T,'entered_source');zs=self.f(c,ct,'source');actual=self.f(es,'li2_pg_source_progress','source');anchor=self.f(actual,'li2_pg_sources','anchor')
        self.source(es,self.serial,self.head,self.key,anchor);self.source(zs,self.serial,self.head,self.key,anchor,terminal=True)
        need(self.f(zs,'li2_pg_source_progress','source')==actual,'entire held source value preserved through release')
        self.domain_source(self.f(c,ct,'domain_source'),ref,zs)
        need(self.f(self.f(c,ct,'domain_source'),'li2_pgd_source_progress','entry')==self.f(self.f(ew,'pda_work','view'),'li2_pgd_view','entry'),'whole actual entry copied into completion')
        er=self.f(self.b,T,'entered_rseq');zr=self.f(c,ct,'rseq');self.lifetime(er,ref,False);self.lifetime(zr,ref,True)
        need(self.i(zr,'li2_pg_rseq_progress','raw_checks')>self.i(er,'li2_pg_rseq_progress','raw_checks'),'actual close rechecks the unregistered lifetime')
        self.progress(self.f(c,ct,'fetch'),self.i(anchor,'li2_fetch_ref','sequence'),False)
        self.query(self.f(c,ct,'directory_closed'),h[66],1,pages=3)
        need(self.f(c,ct,'directory_closed')==self.f(zw,'pda_work','directory_closed'),'whole actual directory-close receipt')
        zero(self.f(c,ct,'direct_exit'),'CALL and unsupported memory-JMP are not typed external direct arms')
        p,z=(self.f(self.b,T,k)for k in('entered_progress','terminal_progress'));pt='li2_pg_progress'
        self.eq(p,pt,serial=self.serial,registration_epoch=0,publication=1,generation=self.generation,phase=9,first_error=0,source_count=2,opened_pages=17,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual primary source/progress layout')
        self.r.change(p,z,pt,values=dict(phase=13,closed_pages=17,anchor_released=1,registration_rechecked=1,completion_permit=1))
        tr=self.f(self.b,T,'predecessor');tt='li2_span_transfer_progress';seq=self.i(anchor,'li2_fetch_ref','sequence')
        self.eq(tr,tt,phase=3,issued=1,consume_attempted=1,consumed=1,resume_attempted=0,resumed=0,previous=h[59],next=0,successor_installed=0,first_error=0,first_detail=0,fresh_borrow=seq,pc=self.head,flags=self.before['greg'][17],refault_attempted=0,refaulted=0,event=h[60])
        need(self.i(tr,tt,'serial')==self.i(p,pt,'transfer_serial')>0 and 0<self.i(tr,tt,'previous_borrow')<seq and self.i(tr,tt,'previous_generation')>0,'real consumed older predecessor then fresh root source')
        self.observation(self.f(tr,tt,'released'),self.page+0x1fe,False)
        need(self.i(self.f(self.f(tr,tt,'released'),'li2_span_fetch_observation','ref'),'li2_fetch_ref','sequence')==self.i(tr,tt,'previous_borrow'),'whole released predecessor borrow identity')
        self.observation(self.f(tr,tt,'fresh'),self.head,True,anchor)
        zero(self.f(self.b,T,'recovered'),'ordinary frontier required no generated-boundary recovery')
        return final,replacement

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='call'if pc==self.page+0x20a else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2,family=4 if kind=='call'else 3)
        desc=self.f(slot,t,'descriptive_classification')
        if origin==2:need(desc==cl,'actual TRACE descriptive classification')
        else:zero(desc,'NX origin has no separate descriptive classification')
        address=self.symbol('selected_chain')+self.r.types['li2_tf_chain']['fields']['slots']['offset']+index*self.r.types[t]['bytes']
        hooks=self.f(st,qt,'hooks');self.eq(hooks,'li2_step_hooks',context=address)
        for k in('authenticate','failure'):need(canonical(self.i(hooks,'li2_step_hooks',k)),'actual predecessor callback')
        oh=self.f(o,'li2_tf_owner','hooks');need(self.f(oh,'li2_tf_hooks','step')==hooks and canonical(self.i(oh,'li2_tf_hooks','continue_closed')),'actual typed continuation hook')
        pages=self.r.items(request,'li2_step_request','pages','li2_step_page');src=self.r.items(self.f(slot,t,'fetch'),'li2_chain_fetch','pages','li2_fetch_page')[0]
        self.eq(pages[0],'li2_step_page',address=pc&-PAGE,object=self.i(src,'li2_fetch_page','allocation'),generation=self.i(src,'li2_fetch_page','generation'),offset=self.source_offset+(pc&-PAGE)-self.page,closed_prot=1,open_prot=5);zero(pages[1],'unused predecessor permission page')
        for k in('open_started','opened'):need(struct.unpack('<2I',self.f(st,qt,k))==(1,0),'actual original page open')
        for k in('revoke_started','revoked'):need(struct.unpack('<2I',self.f(st,qt,k))==(int(closed),0),'actual original page revoke')
        for k in('open_result','revoke_result'):zero(self.f(st,qt,k),'actual successful page operations')
        self.eq(o,'li2_tf_owner',unexpected_frame_observed=0,continuation_started=int(closed),continuation_complete=int(closed),continuation_result=0,rdssp_query_attempted=0,rdssp_query_complete=0,rdssp_query_result=0,rdssp_features=0,bnd_xcr0_attempted=0,bnd_xcr0_complete=0,bnd_xcr0=0)
        zero(self.f(o,'li2_tf_owner','rdssp_observation'),'no unrelated SHSTK observation')
        before=self.f(st,qt,'before');g=q(self.f(before,'li2_step_frame','greg'));n=self.i(before,'li2_step_frame','fp_bytes')
        need(self.i(before,'li2_step_frame','mask')==MASK and self.i(before,'li2_step_frame','initialized')==n and n==ingress['fp_bytes']and self.f(before,'li2_step_frame','fp')==ingress['fp'],'whole real predecessor FP and mask')
        need(g[16]==pc and g[18]==0x2b000000000033 and g[21]==MASK and g[17]==flags|(RF if origin==1 else 0),'original real NX/TRACE predecessor frame')
        need(g[19:21]==((21,14)if origin==1 else(0,1)),'actual predecessor event class')
        if origin==1:need(g[22]==pc,'original predecessor NX CR2')
        if closed:
            self.step_frame(self.f(st,qt,'after'),ingress);self.eq(st,qt,signal_number=5,signal_code=2,signal_errno=0,signal_address=ingress['greg'][16])
            self.eq(o,'li2_tf_owner',actual_post_pc=ingress['greg'][16],actual_post_flags=ingress['greg'][17])
            query=self.f(slot,t,'query');self.eq(query,'li2_tf_continuation',pc=ingress['greg'][16],attempted=1,page_observed=1,complete=1,result=0);self.maps(self.f(query,'li2_tf_continuation','maps'));self.continuation_page(self.f(query,'li2_tf_continuation','page'),ingress['greg'][16]);self.backing(self.f(query,'li2_tf_continuation','backing'))
            self.eq(self.f(slot,t,'release'),'li2_chain_release',started=1,complete=1,result=0)
        else:
            for k in('query','release'):zero(self.f(slot,t,k),'no premature predecessor '+k)
            zero(self.f(st,qt,'after'),'no future predecessor frame');self.eq(o,'li2_tf_owner',actual_post_pc=0,actual_post_flags=0)
            self.eq(st,qt,signal_number=11 if origin==1 else 5,signal_code=2,signal_errno=0,signal_address=pc)
        return dict(greg=g,mask=MASK,fp=self.f(before,'li2_step_frame','fp'),fp_bytes=n,fs=ingress['fs'],gs=ingress['gs']),ref

    def next_trace(self):
        prefix=self.f(self.b,T,'next_closed');need(len(prefix)==wire.CLOSED_BYTES==self.r.types['li2_tf_chain_slot']['fields']['unexpected']['offset'],'whole actual closed ordinary-slot prefix')
        slot=prefix+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        self.eq(slot,'li2_tf_chain_slot',index=self.h[40],origin=1)
        need(self.h[42]==self.h[60]+2 and self.i(slot,'li2_tf_chain_slot','event_id')==self.h[60]+1,'one real chain event per frontier and next TRACE')
        self.trace(self.next,self.h[31],(self.terminal['greg'][17]&~RF)|TF)
        need(self.next['greg'][22]==self.h[29],'actual next TRACE retains the final original frontier CR2')
        before,ref=self.predecessor(slot,self.h[29],self.next)
        step=self.f(self.f(slot,'li2_tf_chain_slot','owner'),'li2_tf_owner','step')
        self.step_frame(self.f(step,'li2_step_owner','before'),self.terminal)
        need(before['greg']==self.terminal['greg']and before['fp']==self.terminal['fp'],'ordinary CALL or memory-JMP starts at the exact retained terminal frame')
        fetch=self.f(self.f(self.b,T,'completion'),'pda_completion','fetch')
        need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary source borrow follows actual group anchor release')

    def finish(self,status):
        h=self.h;r=self.r
        need(type(status)is int and status==0 and self.mode in(0,1)and self.app['header'][5]==0,'actual successful gated process and exact case')
        need(h[:9]==(0x314f4c435049324c,1,990144,r.layout['registrations']['pe']['bytes'],362672,364544,69632,968,128),'whole distinct CALL witness/schema extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in('pe','pclo_wire','selected_chain')),'actual protected owner/wire/ordinary-chain addresses')
        need(h[12]%PAGE==0 and canonical(h[12],h[13])and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,self.mode),'actual alternate stack, private writable sink and selected case')
        sym=self.app['symbols'];s=self.app['rsp'];terminal=self.page+(0x20a if self.mode else 0x304);nxt=self.page+0x2100 if self.mode else sym['region_app_capture_high']
        need(self.page==0x410000 and self.head==self.page+0x200 and s==self.app['stack_base']+2056 and h[20:32]==(self.page,self.head,self.page+0x20a,self.page+0x20d,self.page+0x300,self.page+0x304,self.page+0x2100,sym['region_app_capture_high'],self.page+(0x2100 if self.mode else 0x300),terminal,s,nxt),'actual original source/return/target and per-process stack coordinate')
        need(h[32]==h[34]==h[36]==h[41]==h[43]==1 and 0<h[33]==h[35]<U64-2 and h[37]==h[35]+1 and h[38]==h[39]==h[37]+1 and h[40]in(0,1)and h[42]>0,'exact cold entry, one frontier ingress and immediately following closed TRACE')
        need(h[44:54]==(0,0,0,1,0,0,0,h[16],0,1)and h[54:58]==(2,2,3,wire.CLOSED_BYTES)and h[58]==h[61]and h[58]in(0,1)and h[59]in(0,1)and h[60]>0 and h[62]in(0,1)and 0<h[63]<U64 and 0<h[64]<U64//2 and h[69]<3 and h[70:78]==(0 if self.mode else 1,1,17,17,1,1,17,0x8d5)and not any(h[78:]),'no declined/cancelled focal offer and complete exact cold closure')
        raw=q(self.f(self.b,T,'raw_ingress'));need(sum(raw[1:])==raw[0]>=h[39]>0,'whole actual ingress population and focal chronology')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,T,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,T,'sink_initial'),self.f(self.b,T,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        hardware=self.f(self.b,T,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual app/owner CPUID equality')
        for k,obj in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,T,k),obj)
        need(self.bases[self.image['main_object']]==0,'actual original ET_EXEC zero bias')
        self.eq(self.f(self.b,T,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,T,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];owners=[p for p in loads if p[1]==5 and p[3]<=self.page and self.page+12288<=p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-owners[0][3]and obj['data'][self.source_offset:self.source_offset+12288]==self.app['source']+self.app['continuation'],'complete original ELF source pair and independent U continuation')
        need(self.proof%PAGE==0 and canonical(self.proof,364544),'whole actual aligned proof allocation')
        self.source_registry();self.window();self.compact()
        self.before,self.terminal,self.next=(self.frame(self.f(self.b,T,k))for k in('before','terminal','next'))
        self.trace(self.before,self.head,self.app['seed'][1]);self.nx(self.terminal,terminal)
        need(self.before['greg'][22]==self.page+0x1fe and self.before['greg'][15]==s and self.terminal['greg'][15]==s-(0 if self.mode else 8)and self.next['greg'][15]==s-8,'actual original RSP before/after one PUSH and predecessor NX')
        for frame in(self.before,self.terminal,self.next):
            need(frame['fp']==self.before['fp']and frame['fp_bytes']==self.before['fp_bytes']and frame['mask']==MASK and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'every full65536 FP byte and original mask/FS/GS preserved')
        app_model=load('call_owner_actual_app_model',HERE.parent/'persistent_call_owner_app/read.py')
        states=app_model.trace_model(self.app)
        for frame,index in((self.before,1),(self.terminal,3 if self.mode else 5),(self.next,4 if self.mode else 6)):
            pc,g,flags,_,_=states[index];need(frame['greg'][16]==pc and tuple(frame['greg'][i]for i in donor.GREG)==g and(frame['greg'][17]&~(TF|RF))==flags,'every actual original architectural GPR/flag effect')
        stacks=[self.memory(x,i)for i,x in enumerate(r.items(self.b,T,'memory','li2_pclo_memory'))]
        final,replacement=self.activation();self.next_trace()
        values=q(self.f(self.b,T,'final_row'));row=dict(zip(TERMINAL_NAMES,values,strict=True));misses=q(self.f(self.b,T,'final_misses'))
        need(len(misses)==18 and misses[0]==0,'whole protected classified miss population');row['misses']=list(misses)
        need(values[:5]==(1,0,0,0,0),'actual protected final outcome')
        for k in COUNTERS:need(row[k]==final[k],'whole final protected counter join '+k)
        sv=q(self.f(self.b,T,'final_subentry'));sub=dict(zip(SUBENTRY_NAMES,sv,strict=True))
        need(sv[:3]==(1,0,0)and sub['selections']>=sub['hits']==sub['entries']==sub['completed'],'complete protected subentry counter partition')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+sub['hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(misses)==final['cancelled'],'whole actual completed/cancelled outcome partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['publications']>=2 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits']+sub['hits']+row['dual_entries'],'whole final two-slot claim/publication accounting')
        need(row['serial']==final['offers']and row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial']and row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed or cancelled owner, never a partial pass')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<x<=final['publications']for x in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<x<=row['serial']for x in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==1,'actual final retained generations and completion permits')
        need(row['dual_entries']==row['dual_completed']and row['dual_entries']<=final['hits']+sub['hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and(row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'complete final actual active-domain extent and recovery')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),'actual final entry names its retained generation')
        else:need(not any(sv[7:]),'cancelled final attempt creates no entry receipt')
        anchor,first,end,*_=self.stack_identity
        return dict(mode=self.mode,rsp=s,window_first=s-256,window_end=s+256,original_stack_first=first,original_stack_end=end,original_stack_anchor=anchor,before=self.before,terminal_frame=self.terminal,terminal=self.terminal,next=self.next,source=self.app['source'],continuation=self.app['continuation'],source_page_address=self.page,entry_pc=self.head,call_pc=h[22],target=h[28],return_pc=h[23],terminal_pc=h[29],next_pc=h[31],before_stack=stacks[0],terminal_stack=stacks[1],next_stack=stacks[2],cold_publications=1,completed=1,domain_members=1,anchor_released=1,closed_pages=17,interior_signals=0,lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,word_available=False,tls_complete=1,replacements=replacement,terminal_row=row,subentry_terminal=sub,status=0,code=0,detail=0,qualification_credit=False,performance_credit=False)


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'whole actual record and process/CPU identity')
    need(len(data)==990144+64 and len(data)<4<<20,'strict complete raw witness plus actual footer')
    footer=q(data[-64:]);need(footer[:4]==(0x31464c435049324c,1,990144,990144)and 1<=footer[4]<=64 and 0<footer[5]<=990144 and footer[6:]==(0,0),'actual bounded complete body write and successful footer')
    r=wire.Reader(memoryview(data)[:-64],layout)
    out=Check(r,image,app,pid,cpu).finish(exit_status);out['transport']=dict(raw_bytes=990144,body_bytes=footer[3],body_calls=footer[4],last_body_result=footer[5],status=footer[6],code=footer[7]);return out


def terminal(parsed,owner):
    expected=owner['terminal_row'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected CALL terminal row including every miss bucket')
    return dict(fields=len(expected),protected_call_owner_row=1,inherited_row_protection=0)


def subentry_terminal(parsed,owner):
    need(type(parsed)is dict and all(type(v)is int for v in parsed.values())and parsed==owner['subentry_terminal'],'whole protected CALL subentry terminal row')
    return dict(fields=15,protected_subentry_row=1)

# These are new causal controls for this narrow witness. Older owner/capture
# populations are unchanged and remain separate mandatory qualification gates.
CONTROL_FIELDS=(
 ('source_image',('payload','source','page',0,'bytes'),0x201),
 ('source_generation',('payload','source','page',0,'identity','generation'),0),
 ('source_seals',('payload','source','page',0,'backing','seals'),0),
 ('payload_policy',('payload','header','policy'),0),
 ('payload_archive',('payload','header','archive'),0),
 ('compiled_root',('payload','plan','entry'),0),
 ('compiled_call_image',('payload','plan','image'),3*512+236),
 ('compiled_return_literal',('payload','plan','image'),3*512+504),
 ('compiled_guard',('payload','plan','guard'),3*1584),
 ('compiled_frontier',('payload','plan','exit_pc'),0),
 ('compiled_exclusion',('payload','plan','table','node',0,'first'),0),
 ('actual_emitted_image',('code',),3*512+242),
 ('proof_zero_tail',('proof_tail',),0),
 ('before_rsp',('before','frame','greg'),15*8),
 ('before_flags',('before','frame','greg'),17*8),
 ('before_fp',('before','frame','fp'),32),
 ('terminal_fp',('terminal','frame','fp'),32),
 ('next_fp',('next','frame','fp'),32),
 ('terminal_fs',('terminal','fs'),0),
 ('next_gs',('next','gs'),0),
 ('before_embedded_siginfo',('before','uc'),304),
 ('terminal_mask',('terminal','frame','mask'),0),
 ('next_siginfo_address',('next','si'),16),
 ('memory_source',('memory',0,'source'),0x201),
 ('memory_u',('memory',1,'continuation'),0x100),
 ('memory_data',('memory',2,'data'),8183),
 ('before_stack',('memory',0,'stack'),248),
 ('terminal_stack',('memory',1,'stack'),248),
 ('next_stack',('memory',2,'stack'),248),
 ('stack_anchor',('memory',1,'stack_origin','anchor'),0),
 ('stack_origin_acquisition',('memory',2,'stack_origin','origin_acquisition'),0),
 ('stack_fresh_count',('memory',2,'after','fresh_calls'),0),
 ('stack_direct_phase',('memory',0,'before','active'),0),
 ('stack_next_phase',('memory',2,'before','active'),0),
 ('source_page_identity',('memory',1,'pages',0,'generation'),0),
 ('source_read_permission',('memory',0,'pages',0,'closed_prot'),0),
 ('data_writable_mapping',('memory',0,'rows',0,'prot'),0),
 ('data_guard_mapping',('memory',1,'rows',2,'prot'),0),
 ('window_origin',('bound_stack','origin_first'),0),
 ('window_source_pair',('window_seed','page'),0),
 ('window_registry',('window_seed','registry',0,'first'),0),
 ('window_rsp',('window_seed','rsp'),0),
 ('window_serial',('expected_window','serial'),0),
 ('window_full_page',('window',),128),
 ('window_write',('window_write','prot'),0),
 ('window_seal',('window_seal','query','actual_prot'),0),
 ('entered_generation',('entered_generation','generation'),0),
 ('entered_refs',('entered_generation','member_refs'),0),
 ('entered_proof_bytes',('entered_generation','proof_verified'),0),
 ('entered_open_page',('entered_generation','open',0,'query','pages_checked'),0),
 ('entered_publication',('entered_progress','publication'),0),
 ('source_validations',('entered_source','validations'),0),
 ('source_anchor',('entered_source','source','anchor','sequence'),0),
 ('unregistered_lifetime',('entered_rseq','lifetime_mode'),0),
 ('unavailable_word',('entered_rseq','word_observed'),0),
 ('unregistered_count',('entered_rseq','cold_heads'),0),
 ('entered_peer_sentinel',('entered_work','peer'),0),
 ('actual_directory_target',('initial_directory',),32+2*32+8),
 ('actual_directory_tail',('terminal_directory',),12287),
 ('typed_directory_rows',('entered_work','directory','row',2,'generated'),0),
 ('completion_identity',('completion','id'),0),
 ('completion_member',('completion','member',0,'identity','generation'),0),
 ('completion_source',('completion','source','release_complete'),0),
 ('completion_source_checks',('completion','source','validations'),0),
 ('completion_word',('completion','rseq','word_after'),0),
 ('completion_fetch_released',('completion','fetch','held'),0),
 ('completion_peer_lease',('completion','domain_source','peer','started'),0),
 ('completion_code_closed',('completion','member',0,'generation','close',0,'prot'),0),
 ('completion_target_cell',('completion','member',0,'generation','cell',2,'before'),0),
 ('completion_claim',('claim','id'),0),
 ('ticket_consumed_phase',('predecessor','phase'),0),
 ('ticket_consumed',('predecessor','consumed'),0),
 ('ticket_previous_borrow',('predecessor','previous_borrow'),0),
 ('terminal_anchor_released',('terminal_progress','anchor_released'),0),
 ('terminal_closed_pages',('terminal_progress','closed_pages'),0),
 ('proof_scan_count',('proof_scan','compared'),0),
 ('code_scan_difference',('code_scan','differences'),0),
 ('window_scan_difference',('window_scan','differences'),0),
 ('unexpected_full_extent',('unexpected_scan','compared'),0),
 ('raw_next_closed',('next_closed',),0),
 ('no_generated_recovery',('recovered','complete'),0),
 ('protected_terminal_status',('final_row',),8),
 ('protected_miss_partition',('final_misses',),0),
 ('protected_subentry_status',('final_subentry',),8),
)
HEADER_CONTROLS=(0,1,2,3,4,5,6,7,8,9,10,11,14,15,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78)
OWNER_CONTROL_COUNT=164
OWNER_CONTROL_COUNTS={0:OWNER_CONTROL_COUNT,1:OWNER_CONTROL_COUNT}

def controls(data,layout,image,app,pid,cpu,exit_status):
    read(data,layout,image,app,pid,cpu,exit_status)
    def where(path,byte):
        t=T;at=0;span=layout['types'][t]['bytes']
        for part in path:
            if type(part)is int:
                need(t is not None and part>=0 and(part+1)*layout['types'][t]['bytes']<=span,'bounded typed control array')
                at+=part*layout['types'][t]['bytes'];span=layout['types'][t]['bytes']
            else:
                need(t is not None and part in layout['types'][t]['fields'],'actual named control field')
                f=layout['types'][t]['fields'][part];at+=f['offset'];span=f['bytes'];t=layout['edges'][t].get(part)
        need(type(byte)is int and 0<=byte<span,'whole bounded causal mutation byte');return at+byte
    tests=[(name,where(path,byte))for name,path,byte in CONTROL_FIELDS]
    tests += [('header_'+str(i),where(('h',),i*8))for i in HEADER_CONTROLS]
    tests += [('footer_status',len(data)-16),('footer_extent',len(data)-48)]
    need(len(tests)==OWNER_CONTROL_COUNT-2 and len({name for name,_ in tests})==len(tests),'exact complete new owner-control population')
    refused=[]
    for name,at in tests:
        changed=bytearray(data);changed[at]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted actual CALL owner mutation '+name)
    for name,mutant in(('truncated_footer',data[:-1]),('extra_byte',data+b'\0')):
        try:read(mutant,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted complete-record extent mutation '+name)
    need(len(refused)==OWNER_CONTROL_COUNT,'all owner semantic and complete-record controls refused')
    return dict(refusals=refused,native_operations=0,mode=app['mode'],source_sha256=hashlib.sha256(data).hexdigest())
