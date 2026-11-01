"""Additional version-8 cached return-head hit, with complete actual owner state.

This reader observes the real protected owner. It does not execute a model or
supply owner authority. Whole-profile, warm, fault and performance gates remain
separate. All predecessor readers and their control populations are unchanged.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
baseline=load('return_heads_version7_owner',HERE.parent/'persistent_ret_owner_owner/read.py')
wire=baseline.wire
plan=load('return_heads_owner_plan',HERE/'plan.py')
donor=baseline.donor
old=donor.old
need,zero,q,canonical=old.need,old.zero,old.q,old.canonical
U64,PAGE,TF,RF,MASK=old.U64,old.PAGE,old.TF,old.RF,old.MASK
T='prto_wire'
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

class Check(baseline.Check):
    """Reuse the complete existing source/query/frame primitives unchanged.

    No older cohort's storage, graph, peer-selection or terminal predicate is
    used as authority for this different witness. Those methods are replaced
    below with the exact singleton shape and actual saved values.
    """
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data;self.h=q(self.f(self.b,T,'h'));h=self.h
        self.bias=h[9]-r.layout['symbols']['pe'];self.page=app['source_page_address'];self.head=app['head']
        self.mode=app['mode'];self.loaded_route=False
        need(type(self.mode)is int and self.mode==1,'only the additional byte-exact mode1 return-head positive')
        self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for k,obj in image['objects'].items():
            need(type(k)is int and type(obj)is dict,'actual complete original-object inventory')
            eh,loads=old.elf(obj['data']);self.objects[k]=(obj,eh,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual main/interpreter identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'whole actual ELF/DWARF object-address join')
        b=image['persistent_binding'];need(b['version']==1 and b['unregistered']is True and b['subentry']is True and b['cross_pair']is True and b['direct_frontier']is True and b['call_dispatch']is True and b['ret_dispatch']is True and b['ret_owner_capture']is True and b['typed_capture']is True and b['capture_schema']==1 and b['mode']in('capture','differential')and b['profile']=='persistent-call-return-heads-owner-'+b['mode']+'-v1'and b.get('call_return_heads')is True and b.get('plan_version')==8,'distinct actual RET owner build')
        self.differential=b['mode']=='differential'
        self.payload=self.f(self.b,T,'payload');self.key=self.f(self.payload,'pe_payload','source');self.header=self.f(self.payload,'pe_payload','header');self.compacted=self.f(self.payload,'pe_payload','plan')
        row=r.items(self.key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        identity=self.f(row,'li2_pg_source_page','identity');self.main_backing=self.f(row,'li2_pg_source_page','backing')
        self.source_offset=self.i(identity,'li2_fetch_page','offset');self.main_vma_identity=self.v(identity,'li2_fetch_page','vma_major vma_minor vma_inode')
        self.geometry=self.layout(self.f(self.header,'pe_header','layout'));self.generated=self.geometry[0];self.spill=self.geometry[4];self.proof=h[67];self.table=h[68]
        self.serial,self.generation=h[63:65]












    def entry(self,e,source):
        t='li2_pgs_entry';self.eq(e,t,complete=1,reserved=0,transfer_serial=self.i(self.f(self.b,T,'entered_progress'),'li2_pg_progress','transfer_serial'),generation=self.generation,build_serial=self.serial,slot=self.h[61],bank=self.h[62])
        self.eq(self.f(e,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=self.serial)
        need(self.f(e,t,'anchor')==self.f(source,'li2_pg_sources','anchor'),'entry owns the actual held original-source anchor')
        v=self.f(e,t,'target');self.eq(v,'li2_pgs_target',version=1,heads=8,head=0,member=0,local=0,source_page=0,root=self.head,pc=self.head,generated=self.generated)
        need(q(self.f(v,'li2_pgs_target','page'))==(self.page,self.page+PAGE),'exact root-entry source pages')
        for field,typ in(('row','li2_pe_head'),('original','li2_span_decoded')):
            cf='head'if field=='row'else'original';need(self.f(e,t,field)==self.r.items(self.compacted,'li2_pg_compact',cf,typ)[0],'whole actual root '+field)

    def compact(self):
        c=self.compacted;t='li2_pg_compact'
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+8192)],self.table)
        need(self.f(c,t,'table')==table,'whole canonical exclusion tree covers every protected range and both complete source pages')
        expected=plan.graph(self.app['source'],self.page,self.head,self.geometry,table)
        self.eq(c,t,version=8,bytes=self.r.types[t]['bytes'],ready=1,result=0,heads=8,exits=4,stores=1,source_bytes=32,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=self.head)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(8,0)and q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],'whole actual compact source, layout and membership')
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent CALL/RET graph '+k)
        need(self.f(c,t,'exit_pc')==expected['exit_pc_bytes'],'all exact ordered CALL/RET-before and memory-JMP exits')
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
            self.eq(self.f(self.b,T,key),'prto_scan',compared=n,differences=0,first_offset=0,expected=0,actual=0)
        return expected


    def work(self,w,terminal):
        t='pda_work';self.eq(w,t,bound=1,peer=2,primary=self.h[61],primary_bank=self.h[62],exit_member=0 if terminal and not self.loaded_route else 2,receipt=self.h[69],recovery_member=2,completion=int(terminal),aborting=0)
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
        d=self.f(w,t,'directory');self.eq(d,'li2_jd_domain_directory',version=1,count=8,serial=self.serial,reserved=0)
        rows=b''.join(struct.pack('<3Q2I',self.page+off,self.generated+i*512,self.generation,self.h[61],i)for i,off in enumerate((0x600,0x604,0x300,0x60a,0x304,0x60d,0x20d,0x30a)))
        need(self.f(d,'li2_jd_domain_directory','row')==rows+bytes((256-8)*32),'all actual directory rows and unused tail; validated A-prime return is row5')
        need(self.f(self.b,T,'terminal_directory'if terminal else'initial_directory')==d+bytes(12288-len(d)),'whole actual sealed directory pages')
        return ref

    def generation_transition(self,g,z):
        t='li2_pg_generation';gen=self.generation;serial=self.serial
        self.eq(g,t,installed=1,complete=1,proof_complete=1,generation=gen,ready_generation=gen,build_serial=serial,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362688,proof_verified=364544)
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
        self.cell(cz[2],gen,serial,self.generated+(2 if self.loaded_route else 5)*512)

    def lifetime(self,b,ref,terminal):
        self.unregistered_pin(b,self.serial,terminal)
        self.eq(b,'li2_pg_rseq_progress',cold_heads=8,cold_stores=1,cold_stubs=0,domain_count=1)
        need(self.f(b,'li2_pg_rseq_progress','domain_ref')==ref+bytes(self.r.types['li2_pgd_ref']['bytes']),'whole singleton unregistered lifetime member')


    def activation(self):
        h=self.h;prior,entered,ended,final=(self.counts(self.f(self.b,T,k))for k in('prior_counts','entered_counts','terminal_counts','final_counts'))
        need(prior['entries']==prior['completed']and prior['unexpected']==0,'preceding unrelated entries actually completed')
        replacement=entered['retirements']-prior['retirements'];need(replacement in(0,1),'at most one actual replaced idle generation')
        increments=dict(offers=1,publications=1,cold_attempts=1,retirements=replacement,permit_claims=replacement,entries=1)
        need(all(entered[k]==prior[k]+increments.get(k,0)for k in COUNTERS),'exact cold focal publication, entry, no hit/cancel')
        need(all(ended[k]==entered[k]+int(k=='completed')for k in COUNTERS),'one complete focal owner activation')
        need(all(final[k]>=ended[k]for k in COUNTERS),'final descriptive counters retain every focal event')
        ew,zw=(self.f(self.b,T,k)for k in('entered_work','terminal_work'));ref=self.work(ew,False);need(self.work(zw,True)==ref,'whole member stable through close')
        self.r.change(ew,zw,'pda_work',values=dict(exit_member=2 if self.loaded_route else 0,completion=1),observed=('proof_exit','directory_closed'))
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
        self.observation(self.f(tr,tt,'released'),self.head-2,False)
        need(self.i(self.f(self.f(tr,tt,'released'),'li2_span_fetch_observation','ref'),'li2_fetch_ref','sequence')==self.i(tr,tt,'previous_borrow'),'whole released predecessor borrow identity')
        self.observation(self.f(tr,tt,'fresh'),self.head,True,anchor)
        zero(self.f(self.b,T,'recovered'),'ordinary frontier required no generated-boundary recovery')
        return final,replacement


    def next_trace(self):
        prefix=self.f(self.b,T,'next_closed');need(len(prefix)==wire.CLOSED_BYTES==self.r.types['li2_tf_chain_slot']['fields']['unexpected']['offset'],'whole actual closed ordinary-slot prefix')
        slot=prefix+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        following=self.following if self.loaded_route else self.next;before_frame=self.next if self.loaded_route else self.terminal
        pc=self.h[23]if self.loaded_route else self.h[29];index=self.h[85]if self.loaded_route else self.h[40]
        self.eq(slot,'li2_tf_chain_slot',index=index,origin=1)
        need(index==(self.h[59]^1)and self.h[42]==self.h[60]+(4 if self.loaded_route else 2)and
             self.i(slot,'li2_tf_chain_slot','event_id')==self.h[42]-1,'one actual chain boundary for every retained ingress')
        self.trace(following,self.h[80]if self.loaded_route else self.h[31],
                   (self.states[8][2]if self.loaded_route else self.states[9][2])|TF)
        need(following['greg'][22]==pc,'ordinary ADD or memory-JMP TRACE retains its actual source NX CR2')
        before,ref=self.predecessor(slot,pc,following)
        step=self.f(self.f(slot,'li2_tf_chain_slot','owner'),'li2_tf_owner','step')
        self.step_frame(self.f(step,'li2_step_owner','before'),before_frame)
        need(before['greg']==before_frame['greg']and before['fp']==before_frame['fp'],'ordinary instruction starts at its exact actual retained NX frame')
        fetch=self.f(self.f(self.b,T,'completion'),'pda_completion','fetch')
        need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary source borrow follows actual group anchor release')


    def private_storage(self):
        p=self.f(self.b,T,'private_state');t='prto_private'
        owner,a,code,cell=self.v(p,t,'owner allocation code cell')
        need(owner==self.symbol('prr')and canonical(a,2*PAGE)and a%PAGE==0 and
             (code,cell)==(a+256,a+PAGE+256),'actual separately allocated immutable C3 and operand pages')
        self.eq(p,t,initialized=1,registered=1)
        prior,value,cell_serial=self.v(p,t,'prior_consumed prior_cell_value prior_cell_serial')
        need(0<=prior<self.serial and cell_serial==prior and (prior>0 or value==0),'complete previous private-operand lifetime before this distinct serial')
        self.query(self.f(p,t,'initial'),a,3,pages=2)
        self.permission(self.f(p,t,'initial_code'),a,5,1);self.permission(self.f(p,t,'initial_cell'),a+PAGE,1,1)
        need(self.f(p,t,'code_page')==b'\xcc'*256+b'\xc3'+b'\xcc'*(PAGE-257),'entire immutable private C3 code page')
        expected=bytes(256)+struct.pack('<Q',value)+bytes(PAGE-264)
        need(self.f(p,t,'initial_operand_page')==expected,'complete previous sealed operand page including all zero bytes')
        need(all(a+2*PAGE<=first or end<=a for first,end in
             ((self.generated,self.generated+77824),(self.proof,self.proof+364544),
              (self.h[65],self.h[65]+PAGE),(self.h[66],self.h[66]+12288),
              (self.page,self.page+12288),(self.h[30]-256,self.h[30]+264))),
             'whole private-C3 storage excludes generated/proof/source/window/directory and original stack')
        self.private=(a,code,cell,prior,value,cell_serial)
        if not self.loaded_route:
            need(self.f(p,t,'operand_page')==expected,'hit never arms a private operand')
            zero(self.f(self.b,T,'private_scan'),'hit has no private arm scan')
        else:
            need(self.f(p,t,'operand_page')==bytes(256)+struct.pack('<Q',self.h[23])+bytes(PAGE-264),
                 'whole sealed operand is the saved target, including all unused bytes')
            self.eq(self.f(self.b,T,'private_scan'),'prto_scan',compared=PAGE,differences=0,first_offset=0,expected=0,actual=0)


    def loaded_resume(self):
        if not self.loaded_route:
            for key in('phase','loaded','resume','poison','committed','loaded_ingress','following'):
                zero(self.f(self.b,T,key),'cached hit creates no private loaded continuation '+key)
            zero(self.r.items(self.b,T,'memory','li2_prto_memory')[3],'hit has no pre-poison observation')
            zero(self.r.items(self.b,T,'memory','li2_prto_memory')[4],'hit has no post-poison observation')
            zero(self.f(self.f(self.b,T,'completion'),'pda_completion','ret_exit'),'cached hit has no loaded-miss completion')
            return None
        h=self.h;loaded=self.f(self.b,T,'loaded');t='pda_ret_exit';resume=self.f(self.b,T,'resume');rt='prr_attempt'
        model=self.expected['ret_models'][7]
        self.eq(loaded,t,complete=1,member=0,heads=8,head=7,landing=h[81])
        need(self.f(loaded,t,'row')==self.expected['head'][7*32:8*32]and
             self.f(loaded,t,'original')==self.expected['original_rows'][7]and
             self.f(loaded,t,'plan')==model['whole'][:2328],'complete actual loaded exit joins every independent RET descriptor/record/image byte')
        need(self.f(loaded,t,'window')==self.f(self.b,T,'expected_window')and
             self.f(loaded,t,'stack')==self.f(self.b,T,'bound_stack'),'whole loaded window and original stack lineage copied by value')
        recovered=self.f(loaded,t,'recovered');rr='li2_rd_recovered'
        g=tuple(self.terminal['greg'][i]for i in donor.GREG)
        self.eq(recovered,rr,flags=self.terminal['greg'][17],original_pc=h[25],original_rsp=h[30]-8,target=h[23],phase=7,complete=1,target_valid=1,reserved=0)
        need(q(self.f(recovered,rr,'gpr'))==g and g[4]==h[30]-8,'all16 restored GPRs, saved flags and single loaded target')
        need(all(self.page+off!=h[23]for off in self.expected['offsets']),'loaded target absent from every independently compiled head')
        completion=self.f(self.b,T,'completion');cid=self.i(completion,'pda_completion','id')
        need(self.f(completion,'pda_completion','ret_exit')==loaded==self.f(resume,rt,'loaded'),'entire loaded capability preserved through drain and consume')
        self.eq(resume,rt,phase=5,event=1,terminal=0,consumed=1,serial=self.serial,completion_id=cid,interior_result=0)
        zero(self.f(resume,rt,'interior'),'selected landing requires no invented interior recovery')
        logical=self.f(resume,rt,'logical');want=bytearray(recovered)
        struct.pack_into('<Q',want,4*8,h[30]);struct.pack_into('<Q',want,128,self.terminal['greg'][17]&~RF)
        struct.pack_into('<I',want,160,6)
        need(logical==bytes(want),'whole committed mapping changes only logical RSP, removed fault RF, and committed phase')
        raw=self.frame(self.f(resume,rt,'after'));a,code,cell,prior,prior_value,prior_serial=self.private
        self.trace(raw,h[23],(self.terminal['greg'][17]&~RF)|TF)
        want_g=list(self.terminal['greg']);want_g[15]=cell+8;want_g[16]=h[23];want_g[17]=(want_g[17]&~RF)|TF
        want_g[19:21]=(0,1);want_g[22]=raw['greg'][22]
        need(raw['greg']==tuple(want_g),'actual private C3 TRACE commits its private operand RSP before any target instruction; CR2 is retained literal')
        self.preserved_context(self.terminal,raw)
        need(self.stack_origin(self.f(resume,rt,'stack'))==self.stack_identity,'actual post-C3 query retains original entry.S stack lineage')
        for field in('before','observed'):
            queries=self.r.items(resume,rt,field,'li2_private_code_query')
            self.query(queries[0],a,5);self.query(queries[1],a+PAGE,1)
        self.permission(self.f(resume,rt,'write'),a+PAGE,3,1);self.permission(self.f(resume,rt,'seal'),a+PAGE,1,1)
        phases=self.r.items(self.b,T,'phase','prto_phase')
        expected=((0,1,1,1,0,0,4,1),(0,1,1,1,0,1,4,1),(1,1,1,1,1,1,5,1),(1,1,0,0,1,0,5,1),(0,0,0,0,0,1,0,0))
        for i,(phase,values)in enumerate(zip(phases,expected,strict=True)):
            pending,busy,active,pe_busy,resuming,handling,route,step=values
            self.eq(phase,'prto_phase',complete=1,ordinal=h[35]+(1 if i<3 else 2),phase=i+1,
                pending=pending,busy=busy,pe_active=active,pe_busy=pe_busy,resuming=resuming,handling=handling,
                route=route,step_pending=step,serial=self.serial,completion_id=0 if i==0 else cid,
                last_consumed=self.serial if i==4 else prior,cell_value=h[23]if i>=2 else prior_value,
                cell_serial=self.serial if i>=2 else prior_serial)
        committed=self.f(self.b,T,'committed');want=bytearray(raw['uc'])
        struct.pack_into('<Q',want,40+15*8,h[30]);struct.pack_into('<Q',want,40+17*8,self.terminal['greg'][17]&~RF)
        need(committed==bytes(want),'whole explicit owner ucontext commit; it is not presented as a kernel capture')
        poison=self.f(self.b,T,'poison');mutated=self.mode==2
        self.eq(poison,'prto_poison',complete=1,applied=int(mutated),original_rsp=h[30]-8,word_address=h[30]-8,
             target=h[23],before=h[23],after=0xa5a55a5af0f00f0f if mutated else h[23],changed_bytes=8 if mutated else 0)
        memories=self.r.items(self.b,T,'memory','li2_prto_memory');before=self.memory(memories[3],3);after=self.memory(memories[4],4)
        changed=tuple(i for i,(a,b)in enumerate(zip(before,after,strict=True))if a!=b)
        need(changed==(tuple(range(248,256))if mutated else()),'all520 poison-envelope bytes; exactly the consumed qword changes')
        self.loaded_ingress=self.frame(self.f(self.b,T,'loaded_ingress'),False)
        self.nx(self.loaded_ingress,h[81]);self.same_event(self.loaded_ingress,self.terminal,self.terminal['greg'][17])
        self.private_after=raw
        return dict(loaded=loaded,recovered=recovered,logical=logical,committed=committed,private_after=raw,
                    poison_before=before,poison_after=after,poison=poison)

    def finish(self,status):
        h=self.h;r=self.r
        need(type(status)is int and status==0 and self.mode==1 and self.app['header'][5]==0,'actual successful gated process and exact RET case')
        need(h[:9]==(0x314f54525049324c,1,1261760,r.layout['registrations']['pe']['bytes'],362688,364544,69632,968,128),'whole distinct RET witness/schema extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(k)for k in('pe','prto_wire','selected_chain')),'actual protected owner/wire/ordinary-chain addresses')
        need(h[12]%PAGE==0 and canonical(h[12],h[13])and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,self.mode),'actual alternate stack, private writable sink and selected case')
        sym=self.app['symbols'];s=self.app['rsp'];ret=self.page+0x30a
        terminal=h[81]if self.loaded_route else self.head+17;nxt=self.head+13 if self.loaded_route else sym['region_app_capture_high']
        need(self.page==0x410000 and self.head==self.page+0x600 and s==self.app['stack_base']+2056 and
             h[20:32]==(self.page,self.head,self.head+10,self.head+13,self.page+0x300,ret,self.page+0x2100,
                        sym['region_app_capture_high'],self.page+0x300,terminal,s,nxt),'actual original source/return and per-process original stack coordinate')
        need(h[32]==h[34]==h[36]==h[41]==h[43]==1 and 0<h[33]==h[35]<U64-4 and h[37]==h[35]+1 and
             h[38]==h[39]==h[35]+(3 if self.loaded_route else 2)and h[40]in(0,1)and h[42]>0,
             'exact cold entry, terminal and genuine subsequent ordinary ingress chronology')
        need(h[44:54]==(0,0,0,1,0,0,0,h[16],0,1)and h[54:58]==(2,2,3,wire.CLOSED_BYTES)and
             h[58]==h[61]and h[58]in(0,1)and h[59]in(0,1)and h[60]>0 and h[62]in(0,1)and
             0<h[63]<U64 and 0<h[64]<U64//2 and h[69]<3 and
             h[70:78]==(0 if self.loaded_route else 2,1,17,17,1,1,17,0x8d5)and
             h[78:82]==(self.page+0x200,self.page+0x600,self.head+17,self.geometry[7]+7*8)and not any(h[86:]),
             'no declined/cancelled focal offer and complete exact cold closure')
        if self.loaded_route:
            need(h[40]==h[59]and h[82]==h[35]+2 and h[83]==h[84]==h[35]+4 and h[85]==(h[59]^1),
                 'private TRACE/consume then real target NX and first ADD TRACE, with exact old/new ordinary slots')
        else:need(h[40]==(h[59]^1)and not any(h[82:86]),'cached hit uses only its ordinary memory-JMP frontier')
        raw=q(self.f(self.b,T,'raw_ingress'));need(sum(raw[1:])==raw[0]>=max(h[39],h[84])>0,'whole actual ingress population and focal chronology')
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
        self.source_registry();self.window();self.expected=self.compact();self.private_storage()
        self.before,self.terminal,self.next=(self.frame(self.f(self.b,T,k))for k in('before','terminal','next'))
        self.following=self.frame(self.f(self.b,T,'following'))if self.loaded_route else None
        app_model=load('ret_owner_actual_app_model',HERE.parent/'persistent_ret_owner_app/read.py');self.states=app_model.trace_model(self.app)
        self.trace(self.before,self.head,self.app['seed'][1]);self.nx(self.terminal,terminal)
        need(self.before['greg'][22]==self.head-2 and self.before['greg'][15]==s and
             self.terminal['greg'][15]==s-(8 if self.loaded_route else 0)and self.next['greg'][15]==s,
             'actual original RSP before CALL, at RET terminal and after exactly one pop')
        frames=[(self.before,1,self.head),(self.terminal,6 if self.loaded_route else 8,terminal),
                (self.next,7 if self.loaded_route else 9,nxt)]
        if self.loaded_route:
            self.nx(self.next,nxt);frames.append((self.following,8,self.head+17))
        for frame,index,pc in frames:
            _,g,flags,_,_=self.states[index]
            need(frame['greg'][16]==pc and tuple(frame['greg'][i]for i in donor.GREG)==g and
                 (frame['greg'][17]&~(TF|RF))==flags,'every actual original architectural GPR/flag effect')
            need(frame['fp']==self.before['fp']and frame['fp_bytes']==self.before['fp_bytes']and frame['mask']==MASK and
                 (frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'every full65536 FP byte and original mask/FS/GS preserved')
        memories=r.items(self.b,T,'memory','li2_prto_memory');stacks=[self.memory(x,i)for i,x in enumerate(memories[:3])]
        final,replacement=self.activation();resume=self.loaded_resume();self.next_trace()
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
        return dict(mode=self.mode,rsp=s,window_first=s-256,window_end=s+256,original_stack_first=first,original_stack_end=end,
            original_stack_anchor=anchor,before=self.before,terminal_frame=self.terminal,terminal=self.terminal,next=self.next,
            following=self.following,resume=resume,source=self.app['source'],continuation=self.app['continuation'],
            source_page_address=self.page,entry_pc=self.head,call_pc=h[22],ret_pc=h[25],target=h[28],return_pc=h[23],
            terminal_pc=h[29],next_pc=h[31],ret_landing=h[81],private_cell=self.private[2],before_stack=stacks[0],terminal_stack=stacks[1],next_stack=stacks[2],
            cold_publications=1,completed=1,domain_members=1,anchor_released=1,closed_pages=17,
            interior_signals=int(bool(self.loaded_route)),cached_ret_hits=int(not self.loaded_route),loaded_misses=int(bool(self.loaded_route)),
            consumed_word_poisoned=int(self.mode==2),lifetime_mode=2,registration_epoch=0,registration_calls=0,
            word_observed=0,word_available=False,tls_complete=1,replacements=replacement,terminal_row=row,
            subentry_terminal=sub,status=0,code=0,detail=0,
            generated_base=self.generated,return_head_index=5,return_head_pc=self.head+13,
            return_head_generated=self.generated+5*512,return_head_kind=1,directory_heads=8,plan_version=8,
            qualification_credit=False,performance_credit=False)



def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(data)is bytes and type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'whole actual record and process/CPU identity')
    need(len(data)==1261760+64 and len(data)<4<<20,'strict complete raw witness plus actual footer')
    footer=q(data[-64:]);need(footer[:4]==(0x314654525049324c,1,1261760,1261760)and 1<=footer[4]<=64 and 0<footer[5]<=1261760 and footer[6:]==(0,0),'actual bounded complete body write and successful footer')
    r=wire.Reader(memoryview(data)[:-64],layout)
    out=Check(r,image,app,pid,cpu).finish(exit_status);out['transport']=dict(raw_bytes=1261760,body_bytes=footer[3],body_calls=footer[4],last_body_result=footer[5],status=footer[6],code=footer[7]);return out


def terminal(parsed,owner):
    expected=owner['terminal_row'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected RET terminal row including every miss bucket')
    return dict(fields=len(expected),protected_ret_owner_row=1,inherited_row_protection=0)


def subentry_terminal(parsed,owner):
    need(type(parsed)is dict and all(type(v)is int for v in parsed.values())and parsed==owner['subentry_terminal'],'whole protected RET subentry terminal row')
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
RET_CONTROL_FIELDS=(('ret_descriptor', ('payload', 'plan', 'instruction'), 1008),
 ('ret_guard_load', ('payload', 'plan', 'guard'), 11096),
 ('ret_generated_load', ('code',), 3652),
 ('ret_generated_miss', ('code',), 3774),
 ('ret_generated_commit', ('code',), 3858),
 ('ret_block', ('payload', 'plan', 'layout', 'ret_miss'), 0),
 ('loaded_complete', ('loaded', 'complete'), 0),
 ('loaded_head', ('loaded', 'head'), 0),
 ('loaded_landing', ('loaded', 'landing'), 0),
 ('loaded_original', ('loaded', 'original', 'decoded', 'pc'), 0),
 ('loaded_full_plan', ('loaded', 'plan', 'image'), 190),
 ('loaded_target', ('loaded', 'recovered', 'target'), 0),
 ('loaded_rsp', ('loaded', 'recovered', 'original_rsp'), 0),
 ('loaded_phase', ('loaded', 'recovered', 'phase'), 0),
 ('loaded_flags', ('loaded', 'recovered', 'flags'), 0),
 ('loaded_stack', ('loaded', 'stack', 'anchor'), 0),
 ('completion_loaded_target', ('completion', 'ret_exit', 'recovered', 'target'), 0),
 ('resume_phase', ('resume', 'phase'), 0),
 ('resume_event', ('resume', 'event'), 0),
 ('resume_consumed', ('resume', 'consumed'), 0),
 ('resume_completion_id', ('resume', 'completion_id'), 0),
 ('resume_logical_rsp', ('resume', 'logical', 'gpr'), 32),
 ('resume_logical_target', ('resume', 'logical', 'target'), 0),
 ('resume_interior', ('resume', 'interior', 'complete'), 0),
 ('private_trace_fp', ('resume', 'after', 'frame', 'fp'), 160),
 ('private_trace_rsp', ('resume', 'after', 'frame', 'greg'), 120),
 ('private_trace_siginfo', ('resume', 'after', 'si'), 16),
 ('private_code_query', ('resume', 'before', 0, 'actual_prot'), 0),
 ('private_cell_query', ('resume', 'observed', 1, 'pages_checked'), 0),
 ('private_write', ('resume', 'write', 'prot'), 0),
 ('private_seal', ('resume', 'seal', 'prot'), 0),
 ('private_original_stack', ('resume', 'stack', 'origin_acquisition'), 0),
 ('phase_0_ordinal', ('phase', 0, 'ordinal'), 0),
 ('phase_0_route', ('phase', 0, 'route'), 0),
 ('phase_0_cell_serial', ('phase', 0, 'cell_serial'), 0),
 ('phase_1_ordinal', ('phase', 1, 'ordinal'), 0),
 ('phase_1_route', ('phase', 1, 'route'), 0),
 ('phase_1_cell_serial', ('phase', 1, 'cell_serial'), 0),
 ('phase_2_ordinal', ('phase', 2, 'ordinal'), 0),
 ('phase_2_route', ('phase', 2, 'route'), 0),
 ('phase_2_cell_serial', ('phase', 2, 'cell_serial'), 0),
 ('phase_3_ordinal', ('phase', 3, 'ordinal'), 0),
 ('phase_3_route', ('phase', 3, 'route'), 0),
 ('phase_3_cell_serial', ('phase', 3, 'cell_serial'), 0),
 ('phase_4_ordinal', ('phase', 4, 'ordinal'), 0),
 ('phase_4_route', ('phase', 4, 'route'), 0),
 ('phase_4_cell_serial', ('phase', 4, 'cell_serial'), 0),
 ('private_owner', ('private_state', 'owner'), 0),
 ('private_allocation', ('private_state', 'allocation'), 0),
 ('private_code', ('private_state', 'code'), 0),
 ('private_cell', ('private_state', 'cell'), 0),
 ('private_C3_byte', ('private_state', 'code_page'), 256),
 ('private_initial_operand', ('private_state', 'initial_operand_page'), 256),
 ('private_current_operand', ('private_state', 'operand_page'), 256),
 ('private_initial_query', ('private_state', 'initial', 'expected_prot'), 0),
 ('private_prior_serial', ('private_state', 'prior_cell_serial'), 0),
 ('private_scan', ('private_scan', 'compared'), 0),
 ('poison_complete', ('poison', 'complete'), 0),
 ('poison_applied', ('poison', 'applied'), 0),
 ('poison_original_rsp', ('poison', 'original_rsp'), 0),
 ('poison_word_address', ('poison', 'word_address'), 0),
 ('poison_target', ('poison', 'target'), 0),
 ('poison_before', ('poison', 'before'), 0),
 ('poison_after', ('poison', 'after'), 0),
 ('poison_changed_bytes', ('poison', 'changed_bytes'), 0),
 ('poison_before_stack', ('memory', 3, 'stack'), 248),
 ('poison_after_stack', ('memory', 4, 'stack'), 248),
 ('poison_before_mapping', ('memory', 3, 'rows', 5, 'prot'), 0),
 ('poison_after_fresh', ('memory', 4, 'after', 'fresh_calls'), 0),
 ('loaded_ingress_FP', ('loaded_ingress', 'frame', 'fp'), 160),
 ('loaded_ingress_TLS', ('loaded_ingress', 'tls_complete'), 0),
 ('committed_rsp', ('committed',), 160),
 ('committed_flags', ('committed',), 176),
 ('committed_context_tail', ('committed',), 967),
 ('following_FP', ('following', 'frame', 'fp'), 160),
 ('following_RAX', ('following', 'frame', 'greg'), 104),
 ('following_embedded_event', ('following', 'uc'), 304))
HEADER_CONTROLS=(0,1,2,3,4,5,6,7,8,9,10,11,14,15,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78)
OWNER_CONTROL_COUNT=248
OWNER_CONTROL_COUNTS={1:OWNER_CONTROL_COUNT}

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
    tests=[(name,where(path,byte))for name,path,byte in CONTROL_FIELDS+RET_CONTROL_FIELDS]
    tests += [('header_'+str(i),where(('h',),i*8))for i in HEADER_CONTROLS+tuple(range(79,86))]
    tests += [('footer_status',len(data)-16),('footer_extent',len(data)-48)]
    need(len(tests)==OWNER_CONTROL_COUNT-2 and len({name for name,_ in tests})==len(tests),'exact complete new owner-control population')
    refused=[]
    for name,at in tests:
        changed=bytearray(data);changed[at]^=1
        try:read(bytes(changed),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted actual RET owner mutation '+name)
    for name,mutant in(('truncated_footer',data[:-1]),('extra_byte',data+b'\0')):
        try:read(mutant,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted complete-record extent mutation '+name)
    need(len(refused)==OWNER_CONTROL_COUNT,'all owner semantic and complete-record controls refused')
    return dict(refusals=refused,native_operations=0,mode=app['mode'],source_sha256=hashlib.sha256(data).hexdigest())


def pair(native,gated,owner):
    """Full native equality with explicitly separate load, private TRACE and commit."""
    mode=native['mode'];route=False;app_model=load('ret_pair_app_model',HERE.parent/'persistent_ret_owner_app/read.py')
    need(type(mode)is int and mode==1 and gated['mode']==owner['mode']==mode and
         native['header'][5]==1 and gated['header'][5]==0,'exact RET native/generated case pair')
    need(native['header'][8:13]==gated['header'][8:13]and native['header'][14:19]==gated['header'][14:19]and
         native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in
         ('source','continuation','stack','data','predecessor')),'whole same-source/CPU pair inputs')
    rsp=gated['rsp'];page=gated['source_page_address'];head=page+0x600
    def translated_live(value):
        g,flags,selectors=value;g=list(g);g[4]+=rsp-native['rsp'];return tuple(g),flags,selectors
    need(translated_live(native['seed'])==gated['seed']and native['rsp']==native['stack_base']+2056 and
         rsp==gated['stack_base']+2056,'all seeded GPRs with only authenticated per-process RSP translation')
    need(len(native['observations'])==len(gated['observations'])==1,'actual complete application observations')
    reference=native['observations'][0];actual=gated['observations'][0];frames=reference['frames']
    need(len(frames)==10,'all ten complete original native frames')
    need(owner['rsp']==rsp and owner['window_first']==rsp-256 and owner['window_end']==rsp+256 and
         PAGE<=owner['original_stack_first']<=rsp-256 and rsp+264<=owner['original_stack_end']<(1<<47)and
         owner['original_stack_first']<=owner['original_stack_anchor']<owner['original_stack_end'],
         'actual owner stack/window lineage and whole prospective envelope')
    def compare(value,ref,event,pc=None,private_rsp=None,cr2=None):
        need(type(value['greg'])is tuple and len(value['greg'])==23 and type(value['fp'])is bytes and
             len(value['fp'])==65536 and value['fp_bytes']==ref['header'][9]and value['mask']==MASK,
             'complete actual protected pair frame')
        want=list(ref['greg']);want[donor.GREG[4]]+=rsp-native['rsp']
        if event=='closed':want[17]&=~TF
        elif event=='nx':
            if pc is not None:want[16]=pc
            want[17]=(want[17]&~TF)|RF;want[19],want[20],want[22]=21,14,want[16]
        else:need(event=='original','exact genuine event transforms')
        if private_rsp is not None:want[15]=private_rsp
        if cr2 is not None:want[22]=cr2
        need(value['greg']==tuple(want)and value['fp']==ref['fp'],
             'all23 GREG/65536 FP with only authenticated RSP and causal event transforms')
        need((value['fs'],value['gs'])==tuple(gated['machine'][1:3]),'actual protected pair TLS')
        need(q(value['uc'][40:224])==value['greg']and value['uc'][304:432]==value['si']and
             int.from_bytes(value['uc'][296:304],'little')==MASK,'whole per-frame GREG/mask/siginfo aliases retained')
    terminal_pc=owner['ret_landing']if route else head+17;next_pc=head+13 if route else gated['expected_exit_pc']
    compare(owner['before'],frames[1],'closed')
    compare(owner['terminal'],frames[6 if route else 8],'nx',terminal_pc)
    if route:
        compare(owner['next'],frames[7],'nx')
        need(owner['following']is not None and type(owner['resume'])is dict,'actual complete loaded-continuation phases')
        compare(owner['following'],frames[8],'original',cr2=head+13)
        resume=owner['resume'];raw=resume['private_after']
        need(canonical(owner['private_cell'],8)and owner['private_cell']!=rsp-8,'actual distinct protected private operand')
        # TRACE does not define CR2. Keep its actual full value and per-frame UC join;
        # it cannot be equated to the native run's different preceding page fault.
        compare(raw,frames[7],'original',private_rsp=owner['private_cell']+8,cr2=raw['greg'][22])
        original_rsp,target=struct.unpack_from('<2Q',resume['recovered'],144)
        need((original_rsp,target)==(rsp-8,head+13),'exact loaded original RSP and saved return target')
        mutation=reference['mutation'];need(type(mutation)is dict and
             resume['poison_before']==mutation['before_stack']and resume['poison_after']==mutation['after_stack'],
             'whole native/owner520-byte before/after consumed-word poison bracket')
        need(struct.unpack_from('<8Q',resume['poison'])==(1,int(mode==2),rsp-8,rsp-8,head+13,head+13,
             0xa5a55a5af0f00f0f if mode==2 else head+13,8 if mode==2 else 0),
             'same initial saved target and exact eight-byte observer-only poison')
    else:
        compare(owner['next'],frames[9],'original',cr2=terminal_pc)
        need(owner['following']is None and owner['resume']is None,'cached hit has no private loaded continuation')
    need(owner['source']==native['source']and owner['continuation']==native['continuation']and
         owner['source_page_address']==page,'whole actual source pair and outside U page')
    need((owner['entry_pc'],owner['call_pc'],owner['ret_pc'],owner['target'],owner['return_pc'],owner['terminal_pc'],owner['next_pc'])==
         (head,head+10,page+0x30a,page+0x300,head+13,terminal_pc,next_pc),
         'exact owner CALL/RET target/return/frontier/next identity')
    native_model=app_model.trace_model(native)
    stack_terminal=7 if mode==2 else 6 if route else 8
    need(owner['before_stack']==native_model[1][4]and owner['terminal_stack']==native_model[stack_terminal][4]and
         owner['next_stack']==native_model[8 if route else 9][4],
         'whole520 stack bytes and exact CALL/load/poison/pop observation timing')
    need(owner['cold_publications']==owner['completed']==owner['domain_members']==owner['anchor_released']==1 and
         owner['closed_pages']==17 and owner['interior_signals']==int(bool(route))and
         (owner['cached_ret_hits'],owner['loaded_misses'],owner['consumed_word_poisoned'])==
         (int(not route),int(bool(route)),int(mode==2)),
         'one cold member and exact17-page completion with explicitly typed RET route')
    need(owner['lifetime_mode']==2 and owner['registration_epoch']==owner['registration_calls']==owner['word_observed']==0,
         'actual unregistered epoch0 no-call no-word lifetime')
    need(translated_live(reference['before'])==actual['before']and translated_live(reference['after'])==actual['after']and
         all(reference[k]==actual[k]for k in('live','data','stack'))and gated['effects']==native['effects']and gated['suffix']is not None,
         'whole application state/stack and later registration lifecycle')
    need((frames[3]['greg'][15],frames[4]['greg'][15],frames[6]['greg'][15],frames[7]['greg'][15])==
         (native['rsp'],native['rsp']-8,native['rsp']-8,native['rsp'])and
         struct.unpack_from('<Q',owner['terminal_stack'],248)[0]==head+13 and
         struct.unpack_from('<Q',owner['next_stack'],248)[0]==head+13 and owner['terminal']['greg'][15]==rsp,
         'actual original CALL push and exactly one RET pop preserve the full original return word')
    need((owner['return_head_index'],owner['return_head_pc'],owner['return_head_generated'],
          owner['return_head_kind'],owner['directory_heads'],owner['plan_version'])==
         (5,head+13,owner['generated_base']+5*512,1,8,8),
         'exact newly admitted source-owned return-head directory capability')
    return dict(observed_ret_owner=1,mode=mode,return_head_observation=True,plan_version=8,directory_heads=8,return_head_index=5,invocations=1,native_instructions=9,native_full_frames=10,
        generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
        modeled_completed_in_generated=5 if route else 7,generated_ret_load=1,cached_call=1,cached_ret_hit=int(not route),
        loaded_miss=int(bool(route)),private_C3=int(bool(route)),consumed_word_poisoned=int(mode==2),
        original_return_pc=head+13,stack_bytes=520,measured_interior_signals=int(bool(route)),
        lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,
        qualification_credit=False,performance_credit=False)


PAIR_CONTROL_COUNTS={1:52}
def pair_controls(native,gated,owner):
    import copy
    pair(native,gated,owner);refused=[];route=False
    names=('before_RAX','before_RSP','before_AF','before_FP','terminal_RAX','terminal_RSP',
        'terminal_AF','terminal_PC','terminal_FP','next_RSP','next_PC','next_AF','next_FP',
        'before_stack','terminal_stack','next_stack','source','continuation','owner_rsp',
        'window_first','window_end','stack_origin_anchor','call_target','return_pc','entry_pc',
        'call_pc','terminal_pc','next_pc','closed_pages','domain_members','completed','anchor_released',
        'interior_signals','lifetime_mode','registration_epoch','registration_calls','word_observed',
        'terminal_stack_first','terminal_stack_return_high','terminal_stack_last',
        'ret_pc','cached_ret_hits','loaded_misses','consumed_word_poisoned')
    names += ('following_RAX','following_RSP','following_PC','following_FP',
        'resume_FP','resume_loaded_target','resume_poison_before','resume_poison_after')if route else(
        'following_absent','resume_absent')
    names += ('return_head_index','return_head_pc','return_head_generated','return_head_kind',
              'directory_heads','plan_version')
    for name in names:
        mutant=copy.deepcopy(owner)
        expected='all23 GREG/65536 FP with only authenticated RSP and causal event transforms'
        if name.startswith('following_')or name.startswith('resume_'):
            if not route:
                mutant['following'if name.startswith('following_')else'resume']={}
                expected='cached hit has no private loaded continuation'
            elif name.startswith('following_')or name=='resume_FP':
                row=mutant['following']if name.startswith('following_')else mutant['resume']['private_after']
                field=name.split('_')[-1]
                if field=='FP':value=bytearray(row['fp']);value[160]^=1;row['fp']=bytes(value)
                else:
                    value=list(row['greg']);value[{'RAX':donor.GREG[0],'RSP':donor.GREG[4],'PC':16}[field]]^=1;row['greg']=tuple(value)
            elif name=='resume_loaded_target':
                value=bytearray(mutant['resume']['recovered']);value[152]^=1;mutant['resume']['recovered']=bytes(value)
                expected='exact loaded original RSP and saved return target'
            else:
                field='poison_before'if name=='resume_poison_before'else'poison_after'
                value=bytearray(mutant['resume'][field]);value[248]^=1;mutant['resume'][field]=bytes(value)
                expected='whole native/owner520-byte before/after consumed-word poison bracket'
        elif name in ('return_head_index','return_head_pc','return_head_generated','return_head_kind','directory_heads','plan_version'):
            mutant[name]^=1;expected='exact newly admitted source-owned return-head directory capability'
        elif name.split('_')[0]in ('before','terminal','next') and name.split('_')[-1]in ('RAX','RSP','AF','PC','FP'):
            label,field=name.split('_');row=mutant[label]
            if field=='FP':value=bytearray(row['fp']);value[160]^=1;row['fp']=bytes(value)
            else:
                value=list(row['greg']);index={'RAX':donor.GREG[0],'RSP':donor.GREG[4],'AF':17,'PC':16}[field]
                value[index]^=16 if field=='AF'else 1;row['greg']=tuple(value)
        elif name.endswith('_stack')or name.startswith('terminal_stack_'):
            field=name if name.endswith('_stack')else'terminal_stack'
            offset=0 if name=='terminal_stack_first'else 255 if name=='terminal_stack_return_high'else 519 if name=='terminal_stack_last'else 248
            value=bytearray(mutant[field]);value[offset]^=1;mutant[field]=bytes(value)
            expected='whole520 stack bytes and exact CALL/load/poison/pop observation timing'
        elif name in ('source','continuation'):
            value=bytearray(mutant[name]);value[-1]^=1;mutant[name]=bytes(value);expected='whole actual source pair and outside U page'
        elif name in ('owner_rsp','window_first','window_end','stack_origin_anchor'):
            if name=='stack_origin_anchor':mutant['original_stack_anchor']=mutant['original_stack_end']
            else:mutant['rsp'if name=='owner_rsp'else name]^=1
            expected='actual owner stack/window lineage and whole prospective envelope'
        elif name in ('call_target','return_pc','entry_pc','call_pc','terminal_pc','next_pc','ret_pc'):
            mutant['target'if name=='call_target'else name]^=1;expected='exact owner CALL/RET target/return/frontier/next identity'
        elif name in ('closed_pages','domain_members','completed','anchor_released','interior_signals','cached_ret_hits','loaded_misses','consumed_word_poisoned'):
            mutant[name]^=1;expected='one cold member and exact17-page completion with explicitly typed RET route'
        else:
            mutant[name]^=1;expected='actual unregistered epoch0 no-call no-word lifetime'
        try:pair(native,gated,mutant)
        except ValueError as error:need(str(error)==expected,'exact causal pair refusal '+name);refused.append(name)
        else:raise ValueError('supplied pair corruption accepted '+name)
    need(len(refused)==len(set(refused))==PAIR_CONTROL_COUNTS[native['mode']],'all exact case-specific RET owner pair controls')
    return dict(refusals=refused,native_operations=0,mode=native['mode'])
