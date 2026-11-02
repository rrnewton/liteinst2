"""Schema16 shared strict owner checks, with explicit mixed-policy history.

Unchanged inherited checks keep actual ownership, full frames, mappings,
registration, rseq, source leases and completion claims. Overrides below are
source-required schema/anonymous-fixture/immutable-policy changes; no captured
mask or current slot substitutes for historical reconstruction.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
prior=load('loop_prior_pf',HERE.parent/'persistent_fused_owner/read.py')
wire=load('loop_actual_wire',HERE/'wire.py');plan=load('loop_focal_plan',HERE.parent/'persistent_loop_owner/plan.py')
history=load('loop_saved_history',HERE/'history.py');chooser=history.chooser
old=prior.old;need,zero,q,canonical=prior.need,prior.zero,prior.q,prior.canonical
U64,PAGE,FP,TF,RF,MASK=prior.U64,prior.PAGE,prior.FP,prior.TF,prior.RF,prior.MASK
DATA,STACK,RSP,RSEQ,GREG=prior.DATA,prior.STACK,prior.RSP,prior.RSEQ,prior.GREG
LOOP_COUNTS=('chooser_attempts','chooser_selected','chooser_no_envelope','publications12',
 'hits12','entries_with12','completed_with12','historical_reconstructions','actual_entries12')
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

class Check(prior.Check):
    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data;self.h=q(self.f(self.b,'pdo_wire','h'))
        self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page,self.base,self.head=app['page'],app['base'],app['entry']
        self.source_offset=PAGE;self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory')
            h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,
             'actual main/interpreter object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and
             all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),
             'same actual bridge ELF and complete source-derived DWARF symbols')
        epoch=r.items(self.b,'pdo_wire','epochs','pdo_epoch')[0]
        slots=r.items(self.f(epoch,'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.bank_layouts=[[self.f(bank,'ped_bank','layout')for bank in r.items(slot,'pdo_slot','banks','ped_bank')]for slot in slots]
        self.certificates=r.items(self.b,'pdo_wire','certificates','pdo_certificate')
        need(len(self.certificates)==2,'fixed two certificate storage, one focal use')
        zero(self.certificates[1],'unused second focal certificate remains wholly zero')
        self.binding(image['persistent_binding'])
        payload=self.f(self.certificates[0],'pdo_certificate','payload')
        self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))

    def binding(self,b):
        need(type(b)is dict and b['version']==1 and b['mode']in('capture','differential')and
             b['profile']=='persistent-loop-effects-'+b['mode']+'-v1'and
             all(b[k]is True for k in('unregistered','subentry','cross_pair','direct_frontier','bounded_fused','bounded_loop'))and
             (b['policy_version'],b['fallback_policy'],b['header_version'],b['chooser_version'],
              b['decoder_read_version'],b['capture_version'])==(12,11,2,12,2,16)and
             b['pf_refusals']==dict(version=1,reason=256,shared_reasons=18,abi2=False),
             'exact distinct effects13 source binding and schema16 capture profile')
        domain=b.get('encoding_domain')
        need(type(domain)is dict and all(type(domain.get(k))is int for k in
             ('version','near_record','far_record','literal_bytes','literal_boundaries'))and
             type(domain.get('policies'))is list and all(type(x)is int for x in domain['policies'])and
             domain.get('old_pf_api')is False and domain==dict(version=2, policies=[11,12,13], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False),
             'exact LOOP-bound encoding domain2, canonical LD1/LD2 and no old PF API broadening')
        need(b.get('effects')==dict(binding_version=1,policy_version=13,scalar_version=3,mov_version=2,selection_order=[12,13,11]),
             'separate exact effects binding and old-first selector')
        self.differential=b['mode']=='differential'

    def counts(self,b):
        result=super().counts(b);raw=self.f(b,'pdo_counts','loop')
        values=self.loop_counts(raw)
        result.update({'loop_'+k:v for k,v in values.items()});return result

    def loop_counts(self,b):
        need(len(b)==72,'all nine literal loop counters')
        values=dict(zip(LOOP_COUNTS,q(b),strict=True))
        need(all(0<=x<U64 for x in values.values()),'overflow-checked literal loop counters')
        need(values['chooser_selected']+values['chooser_no_envelope']<=values['chooser_attempts']and
             values['publications12']<=values['chooser_selected']and
             values['actual_entries12']<=values['entries_with12']and
             values['completed_with12']<=values['entries_with12'],
             'actual independent loop observation counters, never a derived cancellation residual')
        return values

    def source_window(self,pc):
        off=pc-self.page
        need(0<=off<8192 and off%PAGE<=PAGE-15,'unchanged complete one-page ordinary source window')
        value=self.app['source'][off:off+15]
        need(len(value)==15,'complete actual ordinary original bytes');return value,1

    def decoded(self,b,pc,kind=None):
        window,_=self.source_window(pc);d=chooser.decoder.decode(pc,window)
        need(b==d['bridge'][:72],'whole independent actual ordinary decoder description')
        return d['code'],d['length']

    def page_row(self,b,index=0):
        need(index in(0,1),'one actual mapped source pair')
        t='li2_fetch_page';page=self.page+index*PAGE
        self.eq(b,t,address=page,backing=2,object=34,logical=5,closed_prot=1,
                offset=(index+1)*PAGE,initial_extent=0,vma_major=0,vma_minor=0,vma_inode=0,vma_offset=0)
        allocation,generation=self.v(b,t,'allocation generation')
        need(0<allocation<U64 and 0<generation<U64,'actual positive source allocation/generation')
        first,end=self.v(b,t,'vma_first vma_end')
        need(first==self.page and end==self.page+8192,'whole exact private anonymous source pair mapping')
        known=self.source_ids.setdefault(page,(allocation,generation))
        need(known==(allocation,generation),'unchanged actual mapped source identity throughout focal lifetime')

    def backing_identity(self,b):
        if self.i(b,'li2_fetch_backing','retained_fd')==(1<<32)-1:
            expected=bytearray(len(b));field=self.r.types['li2_fetch_backing']['fields']['retained_fd']
            need(field['bytes']==4,'actual signed fd ABI');expected[field['offset']:field['offset']+4]=b'\xff'*4
            need(b==bytes(expected),'anonymous source has exact fd-minus-one and no invented backing observations')
            return(-1,)
        return super().backing_identity(b)

    def backing(self,b):
        identity=self.backing_identity(b)
        need(identity==(-1,),'focal anonymous mapping does not invent sealed file authority');return identity

    def source_key(self,key,entry):
        need(entry==self.head,'exact genuine focal original root')
        self.eq(key,'li2_pg_source_key',entry=entry)
        for i,row in enumerate(self.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')):
            self.page_row(self.f(row,'li2_pg_source_page','identity'),i)
            self.backing(self.f(row,'li2_pg_source_page','backing'))
            need(self.f(row,'li2_pg_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],
                 'whole actual mapped original source page')

    def continuation_page(self,b,pc):
        need(self.page<=pc<self.page+8192,'focal predecessor/branch continuation remains in source pair')
        self.page_row(b,(pc-self.page)//PAGE)

    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+8192)],self.table)
        need(self.f(c,t,'table')==table,'complete independently rebuilt exclusion table and all actual protected source bytes')
        expected=plan.graph(self.app['source'],self.page,self.base,entry,
            self.app['endpoint'],self.geometry,table)
        self.eq(c,t,version=12,bytes=353608,ready=1,result=0,heads=28,exits=2,stores=0,
                source_bytes=88,source_mask=expected['source_mask'],decoder_result=0,guard_result=0,
                reserved=0,links=0,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(28,0)and
             q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and
             self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==self.app['source'],
             'whole independent policy12 source, layout and member partition')
        for name in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,name)==expected[name],'whole independent policy12 '+name)
        need(self.f(c,t,'exit_pc')==expected['exit_pc_bytes'],'all exact independently ordered typed cut tokens')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+
             self.r.types[t]['fields']['original']['offset'],'actual immutable source descriptor address')
        self.graph=expected;return expected

    def certificate(self,index,slot,entry,serial,gen):
        need(index==0,'one actual focal certificate; companion lifetimes remain separate')
        c=self.certificates[index];t='pdo_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=0,slot=self.i(self.f(slot,'pdo_slot','identity'),'li2_ptr_slot_ref','index'),
                generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362664)
        zero(self.f(c,t,'tail'),'whole immutable publication proof tail')
        payload=self.f(c,t,'payload');h=self.f(payload,'pe_payload','header')
        self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=2,version=2,plan_policy=12,
                serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,
                spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,
                registered_epoch=0,rseq_address=0,rseq_length=0,rseq_signature=0)
        need(self.layout(self.f(h,'pe_header','layout'))==self.geometry and
             q(self.f(h,'pe_header','member_generation'))==(2*gen,2*gen+1),'actual immutable member generations/layout')
        zero(self.f(h,'pe_header','reserved'),'whole immutable header reserved')
        binding=self.image['persistent_binding']
        need(self.f(h,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and
             self.f(h,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),
             'whole actual immutable archive and explicit policy binding')
        self.source_key(self.f(payload,'pe_payload','source'),entry)
        expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual immutable generated code pages')
        return payload
    def completion(self,c,next_id,next_serial):
        t='pda_completion';cid,serial=self.v(c,t,'id serial');count=self.i(c,t,'count')
        need(0<cid<=next_id and 0<serial<=next_serial and count in(1,2),'bounded actual immutable completion identity')
        self.eq(c,t,complete=1);members=self.r.items(c,t,'member','pda_member_completion');refs=[];seen=[]
        pin=self.f(c,t,'rseq');self.eq(pin,'li2_pg_rseq_progress',active=0,checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=1,close_complete=1,first_detail=0,cancel_started=0,cancel_complete=0,word_before=0,word_entry=0,word_after=0,domain_bound=1,domain_count=count)
        self.eq(self.f(pin,'li2_pg_rseq_progress','token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        lifetime=self.i(pin,'li2_pg_rseq_progress','lifetime_mode')
        # All captured completions precede this fixture's first registration.
        # A saved TLS value is historical; a future registration epoch is not.
        self.unregistered_pin(pin,serial,terminal=True,focal=False)
        source=self.f(c,t,'source');self.eq(source,'li2_pg_source_progress',phase=6,serial=serial,first_error=0,first_detail=0,aborted=0,release_started=1,release_complete=1,opened_extents=3,opened_pages=17,closed_extents=3,closed_pages=17,cancel_started=0,cancel_complete=0)
        saved_source=self.f(source,'li2_pg_source_progress','source');self.eq(saved_source,'li2_pg_sources',complete=1,reserved=0,serial=serial)
        self.maps(self.f(source,'li2_pg_source_progress','preparation'));self.maps(self.f(source,'li2_pg_source_progress','validation'))
        anchor=self.f(saved_source,'li2_pg_sources','anchor');self.progress(self.f(c,t,'fetch'),self.i(anchor,'li2_fetch_ref','sequence'),False)
        source_key=self.f(self.f(source,'li2_pg_source_progress','source'),'li2_pg_sources','key')
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused completion member');continue
            mt='pda_member_completion';g=self.f(m,mt,'generation');v=self.f(m,mt,'identity');h=self.f(m,mt,'header');key=self.f(m,mt,'source');saved=self.geometry;self.geometry=self.layout(self.f(g,'li2_pg_generation','layout'))
            slot,bank=self.v(v,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1)and slot not in seen,'distinct actual joint completion member');seen.append(slot)
            root=self.ref(v,g,slot,bank);need(root==self.i(key,'li2_pg_source_key','entry'),'completion retains original member root');refs.append(v)
            if i==0:
                # A historical activation may start at a certified internal head;
                # its compiled root remains immutable in this saved member.
                actual_entry=self.f(self.f(c,t,'domain_source'),'li2_pgd_source_progress','entry')
                self.entry_value(actual_entry,key,saved_source,self.f(v,'li2_pgd_ref','layout'))
                self.eq(actual_entry,'li2_pgs_entry',generation=self.i(g,'li2_pg_generation','generation'),build_serial=self.i(g,'li2_pg_generation','build_serial'),slot=slot,bank=bank)
                if self.i(source_key,'li2_pg_source_key','entry')==root:self.key_identity(source_key,key)
            # Pair identity excludes only separately authenticated root, never source bytes or stable backing identity.
            peer=self.f(self.f(c,t,'domain_source'),'li2_pgd_source_progress','peer')
            if i==1 and self.i(peer,'li2_pgx_source','started'):
                self.key_identity(self.f(peer,'li2_pgx_source','key'),key)
                tables=self.r.items(peer,'li2_pgx_source','table','li2_mg_table')
                need(self.i(tables[0],'li2_mg_table','address')==self.i(self.f(members[0],mt,'header'),'pe_header','table')and self.i(tables[1],'li2_mg_table','address')==self.i(h,'pe_header','table'),'historical peer tables bind both saved immutable header addresses')
            else:self.pair_key(source_key,key)
            gen=self.i(g,'li2_pg_generation','generation');self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen,linked=0,active_refs=0,domain_refs=0)
            for k in('member_refs','incoming','cleanup'):zero(self.f(g,'li2_pg_generation',k),'completed member has no live reference or failed cleanup')
            self.permission3(self.f(g,'li2_pg_generation','open'),5);self.permission3(self.f(g,'li2_pg_generation','close'),1)
            self.proof_query(self.f(m,mt,'proof'),self.i(g,'li2_pg_generation','proof'),1)
            self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=lifetime,version=2,serial=self.i(g,'li2_pg_generation','build_serial'),generation=gen,registry=self.symbol('pe'),generated=self.geometry[0],spill=self.geometry[4],registered_epoch=self.i(pin,'li2_pg_rseq_progress','registration_epoch'),rseq_address=self.i(pin,'li2_pg_rseq_progress','address'),rseq_length=self.i(pin,'li2_pg_rseq_progress','length'),rseq_signature=self.i(pin,'li2_pg_rseq_progress','signature'))
            need(self.f(h,'pe_header','layout')==self.f(v,'li2_pgd_ref','layout'),'immutable header and completion layout')
            binding=self.image['persistent_binding'];need(self.f(h,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(h,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'completed member actual archive/policy')
            transitions=self.r.items(g,'li2_pg_generation','slots','pg_slot_transition');self.slots_transition(transitions[2],False)
            cell=self.r.items(g,'li2_pg_generation','cell','pg_dispatch_cell_transition')[2];self.cell(cell,gen,serial,self.i(cell,'pg_dispatch_cell_transition','before'))
            self.geometry=saved
        self.domain_source(self.f(c,t,'domain_source'),refs,serial,True,source)
        need(self.f(pin,'li2_pg_rseq_progress','domain_ref')==b''.join(refs)+bytes((2-count)*80),'completion rseq retains exact shared member set')
        need(self.f(source,'li2_pg_source_progress','layout')==self.f(refs[0],'li2_pgd_ref','layout'),'completion primary source layout')
        self.query(self.f(c,t,'directory_closed'),self.h[40],1,pages=3)
        history.direct_history(self,c)
        return count,serial

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        need(pc==self.app['predecessor']or pc in(self.base+12,self.base+86),'only genuine E9 predecessor or observed final conditional branch')
        kind='jmp'if pc==self.app['predecessor']else'jcc';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2,family=3)
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
        need(self.i(before,'li2_step_frame','fp_address')==ingress['fp_address'],'saved predecessor FP pointer matches the same fixed-stack signal position')
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

    def member_transition(self,entry,end,serial,cold):
        t='pdo_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');z=self.f(end,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362664,proof_verified=364544)
        need(q(self.f(g,gt,'member_generation'))==(2*gen,2*gen+1)and q(self.f(g,gt,'member_refs'))==(1,1),'exact typed internal member refs');zero(self.f(g,gt,'incoming'),'zero graph links have no incoming refs')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'unused aggregate slot query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5)
        zero(self.f(g,gt,'close'),'no premature member close');zero(self.f(g,gt,'cleanup'),'no failed member cleanup')
        ts=self.r.items(g,gt,'slots','pg_slot_transition');zs=self.r.items(z,gt,'slots','pg_slot_transition');self.slots_transition(ts[0],False);self.slots_transition(ts[1],True);zero(ts[2],'no premature member slot reset')
        self.r.change(g,z,gt,values=dict(active_refs=0,linked=0,domain_refs=0),observed=('member_refs','incoming','close','slots','cell'))
        for k in('incoming','member_refs'):zero(self.f(z,gt,k),'all internal generation references drained')
        self.permission3(self.f(z,gt,'close'),1);need(zs[:2]==ts[:2],'whole initial and link receipts retained');self.slots_transition(zs[2],False)
        cs=self.r.items(g,gt,'cell','pg_dispatch_cell_transition');cz=self.r.items(z,gt,'cell','pg_dispatch_cell_transition')
        self.cell(cs[0],gen,build,0);self.cell(cs[1],gen,serial,0);zero(cs[2],'no premature dispatch-cell reset');need(cz[:2]==cs[:2],'whole initial and entry cell resets retained');self.cell(cz[2],gen,serial,self.i(cz[2],'pg_dispatch_cell_transition','before'))
        self.r.change(entry,end,t,values=dict(last_completed=serial),observed=('generation','claim','banks'))
        eb=self.r.items(entry,t,'banks','ped_bank');zb=self.r.items(end,t,'banks','ped_bank');idx=[i for i,x in enumerate(eb)if self.f(x,'ped_bank','layout')==self.f(g,gt,'layout')];need(len(idx)==1,'actual selected member bank');i=idx[0]
        self.eq(eb[i],'ped_bank',virgin=0,prot=5);self.r.change(eb[i],zb[i],'ped_bank',values=dict(prot=1));need(eb[1-i]==zb[1-i],'unused member bank remains byte-exact')
        return i

    def pin(self,b,state,serial,heads,refs,terminal=False):
        t='li2_pg_rseq_progress';checks=self.unregistered_pin(b,serial,terminal)
        self.eq(b,t,cold_heads=heads,cold_stores=0,cold_stubs=0,domain_count=len(refs))
        need(self.f(b,t,'domain_ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole actual unregistered source member references')
        rt='li2_rseq_state'
        self.eq(state,rt,initialized=1,registered=0,held=0,first_error=0,phase=0,first_detail=0,pid=self.pid,tid=self.pid,
                address=0,page=0,length=0,signature=0,epoch=0,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],
                fs_result=0,gs_result=0,tls_attempted=1,tls_complete=1,calls=0,registrations=0,unregistrations=0,
                kernel_errors=0,instruction_checks=0,range_checks=0,repeat_checks=0,run_checks=0,syscall_checks=0)
        zero(self.f(state,rt,'data'),'no registered-data receipt before first registration')
        zero(self.f(state,rt,'transaction'),'no attempted registration transaction during focal execution')
        return checks

    def memory(self,b,failed):
        t='li2_pdo_memory';self.eq(b,t,attempted=1,complete=1,after_abort=int(failed),rows_checked=6,data_copied=8192,stack_copied=224,result=0,detail=0,rsp=RSP,data_first=DATA,stack_first=RSP-128)
        m=self.maps(self.f(b,t,'maps'),0)
        before,after=(self.f(b,t,k)for k in('before','after'));mt='li2_maps_stats'
        self.eq(before,mt,active=0,poisoned=0,reserved=0);self.eq(after,mt,active=0,poisoned=0,reserved=0,valid=1)
        self.r.change(before,after,mt,values=dict(fresh_calls=self.i(before,mt,'fresh_calls')+1,acquisitions=self.i(before,mt,'acquisitions')+1),observed=('valid','invalidations','mutation_epoch'))
        invalidations=self.i(after,mt,'invalidations')-self.i(before,mt,'invalidations')
        need(invalidations>=1 and self.i(after,mt,'mutation_epoch')-self.i(before,mt,'mutation_epoch')==invalidations,'actual explicit fresh invalidation and every gateway invalidation')
        need(m[:3]==(self.i(after,mt,'acquisitions'),0,self.i(after,mt,'mutation_epoch')),'memory acquisition actual stats join')
        rows=self.r.items(b,t,'rows','li2_pdo_map_row')
        for i,row in enumerate(rows):
            self.eq(row,'li2_pdo_map_row',offset=0,major=0,minor=0,inode=0,private=1)
            a,z,prot=self.v(row,'li2_pdo_map_row','first end prot');need(a%PAGE==z%PAGE==0 and a<z,'actual page-aligned memory extent')
            if i<2:need((a,z,prot)==(DATA,DATA+8192,1),'actual two-page readonly data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))

    def checkpoint(self,slot,index,known):
        t='pdo_slot';g=self.f(slot,t,'generation');ref=self.f(slot,t,'identity');gen=self.i(ref,'li2_ptr_slot_ref','generation')
        self.eq(ref,'li2_ptr_slot_ref',owner=self.symbol('pe'),index=index,reserved=0)
        self.eq(g,'li2_pg_generation',generation=gen,proof=self.i(slot,t,'proof'))
        check=self.f(slot,t,'check');self.eq(check,'pdo_check',slot=index,generation=gen)
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'pdo_certificate','complete')==1 and self.i(c,'pdo_certificate','slot')==index and self.i(c,'pdo_certificate','generation')==gen]
        expected=next((i for i in matches if i in known),None)
        if expected is None:
            self.eq(check,'pdo_check',certificate=0)
            for k in('proof','code','publication'):zero(self.f(check,'pdo_check',k),'explicit unavailable unrelated-startup immutable comparison')
            need(not matches,'known focal generation cannot claim unavailable certificate')
            if self.i(g,'li2_pg_generation','installed'):
                _,member,_,_=self.claim(slot,self.current_domain);key=self.f(member,'pda_member_completion','source')
                need(self.i(key,'li2_pg_source_key','entry')!=self.head,'unrelated startup identity is not an unobserved focal root')
        else:
            c=self.certificates[expected];self.eq(check,'pdo_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'pdo_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362664)):self.scan(self.f(check,'pdo_check',k),n)
        return gen


    def prior_completed(self,slot,counts):
        t='pdo_slot';g=self.f(slot,t,'generation');c,m,_,_=self.claim(slot,self.current_domain);gt='li2_pg_generation'
        generation=self.i(g,gt,'generation');serial=self.i(c,'pda_completion','serial');self.setup(slot)
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=generation,plan_proofs=2,none_proofs=1,active_refs=0,linked=0,domain_refs=0,proof=self.proof,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362664,proof_verified=364544)
        need(0<generation<=counts['next_generation']and generation<U64//2 and 0<self.i(g,gt,'build_serial')<=serial<=counts['next_serial'],'actual completed retained publication serial/generation')
        self.eq(slot,t,last_completed=serial)
        need(q(self.f(g,gt,'member_generation'))==(2*generation,2*generation+1),'prior exact member generations')
        for k in('incoming','member_refs','cleanup'):zero(self.f(g,gt,k),'prior completed group has no active refs or failure cleanup')
        banks=self.r.items(slot,t,'banks','ped_bank')
        need(sum(self.f(x,'ped_bank','layout')==self.f(g,gt,'layout')for x in banks)==1 and self.i(g,gt,'generated')==self.geometry[0]and self.i(g,gt,'spill')==self.geometry[4],'prior actual registered bank identity')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'prior unused aggregate slots query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5);self.permission3(self.f(g,gt,'close'),1)
        for row,linked in zip(self.r.items(g,gt,'slots','pg_slot_transition'),(False,True,False),strict=True):self.slots_transition(row,linked)
        for i,row in enumerate(self.r.items(g,gt,'cell','pg_dispatch_cell_transition')):
            actual_serial=self.i(g,gt,'build_serial')if i==0 else serial
            self.cell(row,generation,actual_serial,0 if i<2 else self.i(row,'pg_dispatch_cell_transition','before'))
        h=self.f(m,'pda_member_completion','header');need(self.f(h,'pe_header','layout')==self.f(g,gt,'layout'),'whole saved completed header layout')
