"""Schema15 companion owner primitives; no isolated snapshot grants coverage.

Shared ownership, full-frame, registration, permissions and historical closure
predicates are inherited unchanged. This distinct profile independently binds
three immutable graphs on one source pair and every actual native memory frame.
"""
import hashlib,struct,importlib.util
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
focal=load('lifecycle_focal_state',HERE.parent/'persistent_loop_owner/state.py')
wire=load('lifecycle_actual_wire',HERE/'wire.py')
plan=load('lifecycle_companion_plan',HERE/'plan.py')
application=load('lifecycle_actual_native',HERE.parent/'tunables_lifecycle_app/read.py')
history,chooser=focal.history,focal.chooser
old=focal.base.old
need,zero,q,canonical=focal.need,focal.zero,focal.q,focal.canonical
PAGE,TF,RF,MASK,U64,GREG=focal.PAGE,focal.TF,focal.RF,focal.MASK,focal.U64,focal.GREG
DATA,STACK,RSP=focal.base.DATA,focal.base.STACK,focal.base.RSP
LOOP_COUNTS=focal.LOOP_COUNTS
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

class Check(focal.Check):
    def __init__(self,r,image,app,native,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data;self.h=q(self.f(self.b,'pdo_wire','h'))
        self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page,self.base,self.head=app['page'],app['base'],app['base']
        self.native=native;self.roots=(self.page+512,self.page+256,self.page+535);self.graphs={}
        need(native['lane']==0 and app['lane']==1 and native['native_reference_complete']is True and
             native['application_complete']is True and native['actual_fault']is False and
             app['application_complete']is True and not app['frames']and
             native['mode']==app['mode']and native['placement']==app['placement']and
             len(native['frames'])==(51,43)[app['mode']]and
             all(native[k]==app[k]for k in('hardware','facts','seed','machine','source','data','stack','base','page','entry','predecessor','endpoint','before','after','live','final_data')),
             'complete actual independent native reference and maintained application at same case/placement')
        self.native_frames=native['frames']
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
        need(len(self.certificates)==3,'three distinct immutable companion certificates')
        self.binding(image['persistent_binding'])
        payload=self.f(self.certificates[0],'pdo_certificate','payload')
        self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))
    def binding(self,b):
        need(type(b)is dict and b['version']==1 and b['mode']in('capture','differential')and
             b['profile']=='persistent-loop-lifecycle-'+b['mode']+'-v1'and
             all(b[k]is True for k in('unregistered','subentry','cross_pair','direct_frontier','bounded_fused','bounded_loop'))and
             (b['policy_version'],b['fallback_policy'],b['header_version'],b['chooser_version'],
              b['decoder_read_version'],b['capture_version'])==(12,11,2,12,2,15)and
             b['pf_refusals']==dict(version=1,reason=256,shared_reasons=18,abi2=False),
             'exact distinct mixed11/12 source binding and schema15 capture profile')
        self.differential=b['mode']=='differential'
    def source_key(self,key,entry):
        need(entry in self.roots+(self.base+19,),'one actual source-bound compiled or cancelled root')
        self.eq(key,'li2_pg_source_key',entry=entry)
        for i,row in enumerate(self.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')):
            self.page_row(self.f(row,'li2_pg_source_page','identity'),i)
            self.backing(self.f(row,'li2_pg_source_page','backing'))
            need(self.f(row,'li2_pg_source_page','bytes')==self.app['source'][i*PAGE:(i+1)*PAGE],
                 'whole actual mapped original source page')
    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        table=plan.table(self.ranges+[(self.page,self.page+PAGE),(self.page+PAGE,self.page+8192)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion tree for protected fields and exact common source pair')
        policy=11 if entry==self.roots[1]else 12
        expected=plan.graph(self.app['source'],self.page,entry,self.geometry,table,policy=policy,endpoint=self.app['endpoint'])
        self.eq(c,t,version=policy,bytes=353608,ready=1,result=0,heads=expected['heads'],exits=expected['exits'],
                stores=expected['stores'],source_bytes=expected['source_bytes'],source_mask=1,decoder_result=0,
                guard_result=0,reserved=0,links=0,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==expected['member_heads']and
             q(self.f(c,t,'page'))==(self.page,self.page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and
             self.f(c,t,'source')==self.app['source'],'whole source-bound member partition and actual geometry')
        for name in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,name)==expected[name],'whole independent companion '+name)
        need(self.f(c,t,'exit_pc')==expected['exit_pc_bytes'],'all independently ordered external branch tokens')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+
             self.r.types[t]['fields']['original']['offset'],'actual immutable original-descriptor binding')
        self.graph=expected;return expected
    def certificate(self,index,slot,entry,serial,gen):
        need(type(index)is int and index in(0,1,2)and entry==self.roots[(index^self.app['mode'])if index<2 else 2],
             'three chronological immutable A/B/C publications')
        c=self.certificates[index];t='pdo_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'pdo_slot','identity'),'li2_ptr_slot_ref','index'),
                generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362664)
        zero(self.f(c,t,'tail'),'whole immutable publication proof tail')
        payload=self.f(c,t,'payload');h=self.f(payload,'pe_payload','header')
        self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=2,version=2,plan_policy=11 if entry==self.roots[1]else 12,
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
        self.graphs[index]=expected
        return payload
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
                need(self.i(key,'li2_pg_source_key','entry')not in self.roots,'unrelated startup identity is not an unobserved companion root')
        else:
            c=self.certificates[expected];self.eq(check,'pdo_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'pdo_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362664)):self.scan(self.f(check,'pdo_check',k),n)
        return gen
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
            if i<2:need((a,z,prot)==(DATA,DATA+8192,3),'actual two-page writable companion data')
            elif i==4:need((a,z,prot)==(STACK+4096,STACK+4096+131072,3),'actual fixed writable guest stack')
            else:
                point=(DATA+8192,STACK,STACK+4096+131072)[(2,3,5).index(i)]
                need(a<=point and point+PAGE<=z and prot==0,'actual inaccessible data/stack guard')
        return dict(data=self.f(b,t,'data'),stack=self.f(b,t,'stack'))
    def pin(self,b,state,serial,heads,refs,terminal=False):
        t='li2_pg_rseq_progress';checks=self.unregistered_pin(b,serial,terminal)
        self.eq(b,t,cold_heads=heads,cold_stores=int(heads>0 and self.graph['stores']==1),cold_stubs=0,domain_count=len(refs))
        need(self.f(b,t,'domain_ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole actual unregistered source member references')
        rt='li2_rseq_state'
        self.eq(state,rt,initialized=1,registered=0,held=0,first_error=0,phase=0,first_detail=0,pid=self.pid,tid=self.pid,
                address=0,page=0,length=0,signature=0,epoch=0,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],
                fs_result=0,gs_result=0,tls_attempted=1,tls_complete=1,calls=0,registrations=0,unregistrations=0,
                kernel_errors=0,instruction_checks=0,range_checks=0,repeat_checks=0,run_checks=0,syscall_checks=0)
        zero(self.f(state,rt,'data'),'no registered-data receipt before first registration')
        zero(self.f(state,rt,'transaction'),'no attempted registration transaction during focal execution')
        return checks
    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        need(pc in(self.app['predecessor'],self.base+8,self.base+17,self.base+19,self.base+27,self.roots[1]+10),
             'only genuine E9, actual completed DIRECT, or one resumed unsupported store')
        kind='jmp'if pc in(self.app['predecessor'],self.roots[1]+10)else'store'if pc==self.base+19 else'jcc'
        code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2 if kind in('jmp','jcc')else 1,family=3 if kind in('jmp','jcc')else 1)
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
    def work(self,w,rows,count,serial,terminal=False):
        t='pda_work';v=self.f(w,t,'view');vt='li2_pgd_view';self.eq(w,t,bound=1,completion=int(terminal),aborting=0,recovery_member=2)
        self.eq(v,vt,count=count,reserved=0,directory=self.h[40]);self.eq(self.f(v,vt,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        members=self.r.items(v,vt,'member','li2_pgd_member');refs=[];pairs=[]
        for i,m in enumerate(members):
            if i>=count:zero(m,'whole unused active-domain member');continue
            mt='li2_pgd_member';ref=self.f(m,mt,'identity');slot,bank=self.v(ref,'li2_pgd_ref','slot bank');need(slot in(0,1)and bank in(0,1),'actual member slot/bank')
            s=rows[slot];g=self.f(s,'pdo_slot','generation');root=self.ref(ref,g,slot,bank);refs.append(ref)
            proof=self.i(s,'pdo_slot','proof');self.eq(m,mt,plan=proof+self.r.types['pe_payload']['fields']['plan']['offset'],key=proof+self.r.types['pe_payload']['fields']['source']['offset'])
            ci=next((j for j,c in enumerate(self.certificates)if self.i(c,'pdo_certificate','slot')==slot and self.i(c,'pdo_certificate','generation')==self.i(g,'li2_pg_generation','generation')),None)
            need(ci is not None and root==self.i(self.certificates[ci],'pdo_certificate','entry'),'actual active member joins its complete literal certificate')
            pairs.append((slot,self.i(g,'li2_pg_generation','generation'),self.i(g,'li2_pg_generation','build_serial')))
        need(len({x[0]for x in pairs})==count and len({x[1]for x in pairs})==count,'distinct actual domain generations')
        self.eq(w,t,primary=pairs[0][0],primary_bank=self.i(refs[0],'li2_pgd_ref','bank'),peer=2 if count==1 else pairs[1][0],exit_member=self.exit_member if terminal else 2)
        receipt=self.i(w,t,'receipt');need(receipt<3,'bounded selected immutable completion cell')
        self.permission(self.f(w,t,'directory_write'),self.h[40],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[40],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[40],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory terminal query')
        d=self.f(w,t,'directory');dt='li2_jd_domain_directory'
        selected=[]
        for ref in refs:
            root=self.i(ref,'li2_pgd_ref','root');ci=next(i for i,c in enumerate(self.certificates)if
                self.i(c,'pdo_certificate','entry')==root and self.i(c,'pdo_certificate','slot')==self.i(ref,'li2_pgd_ref','slot')and
                self.i(c,'pdo_certificate','generation')==self.i(ref,'li2_pgd_ref','generation'))
            need(ci in self.graphs,'every directory member was independently reconstructed before entry')
            selected.append(self.graphs[ci])
        total=sum(x['heads']for x in selected);need(0<total<=128,'unchanged complete bounded directory union')
        self.eq(d,dt,version=1,count=total,serial=serial,reserved=0);expected=[]
        for r,graph in zip(refs,selected,strict=True):
            base=self.layout(self.f(r,'li2_pgd_ref','layout'))[0]
            for j,off in enumerate(graph['offsets']):expected.append(struct.pack('<3Q2I',self.page+off,base+512*j,self.i(r,'li2_pgd_ref','generation'),self.i(r,'li2_pgd_ref','slot'),j))
        need(self.f(d,dt,'row')==b''.join(expected)+bytes((256-total)*32),'whole exact directory rows and unused tail')
        proofrows=self.r.items(w,t,'proof_exit','pg_proof_query')
        for i,p in enumerate(proofrows):
            if i<count and terminal:self.proof_query(p,self.i(refs[i],'li2_pgd_ref','proof'),1)
            else:zero(p,'no unused or premature member proof exit')
        peer=self.f(w,t,'peer_claim');pt='pda_claim_observation'
        if count==1:zero(peer,'cold activation has no peer claim')
        else:
            saved=self.geometry;self.geometry=self.layout(self.f(refs[1],'li2_pgd_ref','layout'));self.query3(self.f(peer,pt,'code'),1);self.query(self.f(peer,pt,'spill'),self.geometry[4],3);self.query(self.f(peer,pt,'slots'),self.geometry[3],1);self.proof_query(self.f(peer,pt,'proof'),self.i(refs[1],'li2_pgd_ref','proof'),1);self.geometry=saved
        return refs,pairs,receipt
    def offer(self,index):
        need(index in(0,1,2,3,4),'five actual chronological offers')
        return self.base+19 if index==3 else self.roots[2]if index==4 else self.roots[(int(index==1))^self.app['mode']]

    def predecessor_pc(self,index):
        if index==0:return self.app['predecessor']
        if index==1:return self.roots[1]+10 if self.app['mode']else self.base+8
        if index==2:return self.base+8 if self.app['mode']else self.roots[1]+10
        return self.base+17 if index==3 else self.base+19

    def native_positions(self,index):
        a=application.EPOCH_STEPS[self.app['mode']]
        need(index in(0,1,2,4),'four completed companion lifetimes')
        return (a[0:2],a[2:4],a[4:6],a[7:9])[(0,1,2,4).index(index)]

    def graph_for(self,ref):
        root=self.i(ref,'li2_pgd_ref','root');gen=self.i(ref,'li2_pgd_ref','generation')
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'pdo_certificate','entry')==root and
                 self.i(c,'pdo_certificate','generation')==gen and self.i(c,'pdo_certificate','slot')==self.i(ref,'li2_pgd_ref','slot')]
        need(len(matches)==1 and matches[0]in self.graphs,'one whole current or historical immutable graph identity')
        return matches[0],self.graphs[matches[0]]

    def companion_loop(self,raw,counts,index,warm=False):
        value=self.loop_state(raw,counts)
        policy=11 if index in(3,)or self.offer(index)==self.roots[1]else 12
        need(value['route']==policy and value['choice_complete']==int(not warm),
             'actual cold complete choice or exact warm policy route')
        chosen=value['witnesses']['choice']
        if warm:need(chosen is None,'warm entry invents no cold choice')
        else:
            need(chosen is not None and chosen['entry']==self.offer(index)and
                 chosen['pages']==(self.page,self.page+PAGE)and chosen['source']==self.app['source']and
                 chosen['result']==int(policy==11),'whole actual chooser witness bound to this exact attempt')
        return value
