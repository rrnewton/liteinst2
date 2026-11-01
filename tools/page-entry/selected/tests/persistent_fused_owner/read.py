"""Separate PF11 owner semantics with exact directional/MOV full-state proof.
Old native41 and PB10 remain mandatory separate predecessors; original bounds
and each full context/source/permission/cancellation gate remain strict.
"""
import hashlib,struct,importlib.util
from pathlib import Path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
HERE=Path(__file__).resolve().parent
prior=load('pb_prior_owner',HERE.parent/'persistent_direct_frontier_owner/read.py')
wire=load('pb_wire',HERE/'wire.py');plan=load('pb_plan',HERE/'plan.py')
app_model=load('pb_application',HERE.parent/'persistent_fused_app/read.py')
history=load('pb_saved_direct_history',HERE/'direct_history.py')
codec=prior.codec;old=prior.old
need,zero,q,canonical=prior.need,prior.zero,prior.q,prior.canonical
U64,PAGE,FP,TF,RF,MASK=prior.U64,prior.PAGE,prior.FP,prior.TF,prior.RF,prior.MASK
DATA,STACK,RSP,RSEQ,GREG=prior.DATA,prior.STACK,prior.RSP,prior.RSEQ,prior.GREG

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
    def counts(self,b):
        values=super().counts(b)
        for key in ('pf_backward_refused','pf_backward_cancelled'):
            value=self.i(b,'pdo_counts',key)
            need(type(value)is int and 0<=value<U64,'literal protected PF counter '+key)
            values[key]=value
        need(values['pf_backward_cancelled']<=values['pf_backward_refused'],'PF cancellation never precedes refusal')
        return values

    def pf_partition(self,b,pending_old=0):
        values=self.counts(b)
        need(pending_old in (0,1) and values['pf_backward_refused']==values['pf_backward_cancelled'] and
             sum(values['misses'])+values['pf_backward_cancelled']==values['cancelled']+pending_old,
             'literal PF cancellation plus all18 old reasons exactly partition this captured stage')
        return values

    def pf_stages(self,epochs,cancellation):
        rows=[]
        def take(name,b):
            c=self.counts(b);rows.append(dict(stage=name,refused=c['pf_backward_refused'],cancelled=c['pf_backward_cancelled']))
        for index,e in enumerate(self.r.items(self.b,'pdo_wire','epochs','pdo_epoch')[:epochs]):
            take('epoch'+str(index)+'_prior',self.f(e,'pdo_epoch','prior_counts'))
            for name in ('entered','terminal'):
                take('epoch'+str(index)+'_'+name,self.f(self.f(e,'pdo_epoch',name),'pdo_stage','counts'))
        if cancellation:
            c=self.f(self.b,'pdo_wire','cancellation')
            for name in ('held','resumed'):take('cancel_'+name,self.f(self.f(c,'pbo_cancel',name),'pdo_stage','counts'))
        take('final',self.f(self.b,'pdo_wire','final_counts'))
        need(len(rows)==(12 if cancellation else 4),'all literal PF refusal snapshot stages')
        return rows

    def frame(self,b,tls=True):
        f=super().frame(b,tls)
        need(f['uc'][304:432]==f['si'],'whole actual adjacent kernel siginfo in copied context')
        f.update(altstack=self.h[12:14],fp_address=self.i(self.f(b,'le_frame','frame'),'li2_step_frame','fp_address'))
        return f

    def preserved_context(self,a,b):
        # Each frame independently authenticates these event-dependent fields.
        # Every other byte, including uc_flags, uc_link and padding, is retained.
        need(a['fp']==b['fp']and a['fp_bytes']==b['fp_bytes']and a['mask']==b['mask']==MASK and
             (a['fs'],a['gs'])==(b['fs'],b['gs']),'entire65536 FP storage, kernel mask and actual TLS preserved')
        expected=bytearray(a['uc']);expected[40:224]=b['uc'][40:224]
        expected[224:232]=b['uc'][224:232];expected[304:432]=b['si']
        need(bytes(expected)==b['uc'],'every non-event ucontext byte retained across PB execution')

    def source_key(self,key,entry):
        self.eq(key,'li2_pg_source_key',entry=entry)
        for i,row in enumerate(self.r.items(key,'li2_pg_source_key','page','li2_pg_source_page')):
            pair=0 if entry in(self.head,self.page+0x223)else 2;need(entry in(self.head,self.page+0x2400,self.page+0x223),'one exact focal or cancelled source pair');self.page_row(self.f(row,'li2_pg_source_page','identity'),pair+i);self.backing(self.f(row,'li2_pg_source_page','backing'))
            need(self.f(row,'li2_pg_source_page','bytes')==self.app['source'][(pair+i)*PAGE:(pair+i+1)*PAGE],'whole immutable two-source bytes')

    def checkpoint(self,slot,index,known):
        t='pdo_slot';g=self.f(slot,t,'generation');ref=self.f(slot,t,'identity');gen=self.i(ref,'li2_ptr_slot_ref','generation')
        self.eq(ref,'li2_ptr_slot_ref',owner=self.symbol('pe'),index=index,reserved=0)
        self.eq(g,'li2_pg_generation',generation=gen,proof=self.i(slot,t,'proof'))
        check=self.f(slot,t,'check');self.eq(check,'pdo_check',slot=index,generation=gen)
        matches=[i for i,c in enumerate(self.certificates)if self.i(c,'pdo_certificate','slot')==index and self.i(c,'pdo_certificate','generation')==gen]
        expected=next((i for i in matches if i in known),None)
        if expected is None:
            self.eq(check,'pdo_check',certificate=0)
            for k in('proof','code','publication'):zero(self.f(check,'pdo_check',k),'explicit unavailable unrelated-startup immutable comparison')
            need(not matches,'known focal generation cannot claim unavailable certificate')
            if self.i(g,'li2_pg_generation','installed'):
                _,member,_,_=self.claim(slot,self.current_domain);key=self.f(member,'pda_member_completion','source')
                need(self.i(key,'li2_pg_source_key','entry')not in(self.page+0x206,self.page+0x2400),'unrelated startup identity is not an unobserved focal root')
        else:
            c=self.certificates[expected];self.eq(check,'pdo_check',certificate=expected+1)
            self.eq(g,'li2_pg_generation',installed=1,complete=1,proof_complete=1,ready_generation=gen)
            payload=self.f(c,'pdo_certificate','payload');header=self.f(payload,'pe_payload','header')
            need(self.f(g,'li2_pg_generation','layout')==self.f(header,'pe_header','layout')and self.i(g,'li2_pg_generation','build_serial')==self.i(header,'pe_header','serial'),'certificate binds actual immutable generation layout/build')
            for k,n in(('proof',364544),('code',69632),('publication',362656)):self.scan(self.f(check,'pdo_check',k),n)
        return gen


    def certificate(self,index,slot,entry,serial,gen):
        c=self.certificates[index];t='pdo_certificate';self.setup(slot)
        self.eq(c,t,complete=1,index=index,slot=self.i(self.f(slot,'pdo_slot','identity'),'li2_ptr_slot_ref','index'),generation=gen,entry=entry,proof_bytes=364544,code_bytes=69632,publication_bytes=362656)
        zero(self.f(c,t,'tail'),'whole literal immutable proof tail zero')
        payload=self.f(c,t,'payload');ph=self.f(payload,'pe_payload','header')
        self.eq(ph,'pe_header',lifetime_version=1,lifetime_mode=2,version=1,serial=serial,generation=gen,registry=self.symbol('pe'),generated=self.generated,spill=self.spill,table=self.table,plan_proof=2,none_proof=1,source_validations=1,registered_epoch=0,rseq_address=0,rseq_length=0,rseq_signature=0)
        need(self.layout(self.f(ph,'pe_header','layout'))==self.geometry and q(self.f(ph,'pe_header','member_generation'))==(2*gen,2*gen+1),'immutable actual retained member identities/layout');zero(self.f(ph,'pe_header','reserved'),'whole header reserved')
        binding=self.image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['subentry']is True and binding['cross_pair']is True and binding['direct_frontier']is True and binding['profile']=='persistent-fused-'+binding['mode']+'-v1'and binding['bounded_fused']is True and binding['policy_version']==11 and binding['pf_refusals']==dict(version=1,reason=256,shared_reasons=18,abi2=False),'explicit retained-two source binding')
        need(self.f(ph,'pe_header','archive')==bytes.fromhex(binding['archive']['sha256'])and self.f(ph,'pe_header','policy')==bytes.fromhex(binding['policy_sha256']),'whole actual retained archive/policy authority')
        key=self.f(payload,'pe_payload','source');self.source_key(key,entry);expected=self.compact(payload,entry)
        need(self.f(c,t,'code')==expected['image']+expected['stub_image'],'all17 actual code pages in shared literal certificate')
        return payload

    def source_window(self,pc):
            off=pc-self.page
            need(0<=off<4*PAGE and off%PAGE<=PAGE-15,'exact one-page window or final six-byte Jcc window')
            # selected_prepare first clips to the current page, and extends
            # only on TRUNCATED. The final six-byte Jcc decodes VALID there.
            length=15
            value=self.app['source'][off:off+length]
            need(len(value)==length,'whole actual page-clipped ordinary decoder window')
            return value,1

    def predecessor(self,slot,pc,ingress,closed=True):
        t='li2_tf_chain_slot';index=self.i(slot,t,'index');need(index in(0,1),'actual predecessor slot index')
        self.eq(slot,t,chain=self.symbol('selected_chain'),phase=5 if closed else 3,fallback=0,prepare_complete=1,decode_attempted=1,decode_complete=1,retry=0,unexpected_frame_observed=0,unexpected_signal=0,unexpected_code=0,unexpected_errno=0,unexpected_address=0,prepare_result=0,decode_result=0,classify_result=0)
        need(self.i(slot,t,'generation')>0 and self.i(slot,t,'event_id')>0,'actual predecessor generation/event')
        origin=self.i(slot,t,'origin');need(origin in(1,2)and self.i(slot,t,'prepare_attempted')==int(origin==2),'actual predecessor NX/TRACE preparation')
        for k in('first_decoded','first_fetch','first_release','unexpected'):zero(self.f(slot,t,k),'no unused predecessor '+k)
        kind='add'if pc==self.page+0x203 else'store'if pc==self.page+0x223 else'jmp';code,length=self.decoded(self.f(slot,t,'decoded'),pc,kind)
        ref=self.chain_fetch(self.f(slot,t,'fetch'),pc,not closed);o=self.f(slot,t,'owner');st=self.f(o,'li2_tf_owner','step');qt='li2_step_owner'
        flags=self.app['seed'][1]if pc==self.page+0x203 else ingress['greg'][17]&~TF
        self.eq(st,qt,phase=5 if closed else 3,first_error=0,in_handler=0,self_test=0,trace_seen=int(closed),revoke_sync_started=int(closed),first_detail=0,session=self.symbol('selected_session'),open_sync=0,revoke_sync=0,destination=0,width=0,immediate=0,effect=0,source=0)
        request=self.f(st,qt,'request');self.eq(request,'li2_step_request',page_count=1,original_flags=flags);self.decoded(self.f(request,'li2_step_request','decoded'),pc,kind)
        cl=self.f(o,'li2_tf_owner','classification');self.eq(cl,'li2_tf_classification',pc=pc,next_pc=pc+length,abi_version=1,policy=1,code=code,length=length,flow=2 if kind=='jmp'else 1,family=3 if kind=='jmp'else 1)
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

    def __init__(self,r,image,app,pid,cpu):
        self.r,self.image,self.app,self.pid,self.cpu=r,image,app,pid,cpu
        self.b=r.data;self.h=q(self.f(self.b,'pdo_wire','h'));self.bias=self.h[9]-r.layout['symbols']['li2_raw6']
        self.page=app['head']&-PAGE;self.head=app['head'];self.objects={};self.bases={};self.backings={};self.maps_seen={};self.source_ids={}
        for key,obj in image['objects'].items():
            need(type(key)is int and type(obj)is dict,'actual complete object inventory');h,loads=old.elf(obj['data']);self.objects[key]=(obj,h,loads)
        need(image['main_object']in self.objects and image['interpreter_object']in self.objects,'actual source object identities')
        self.eh,self.ph,self.symbols=elf_symbols(image['bridge'])
        need(set(r.layout['symbols'])==set(self.symbols)|{'span_progress','pg_domain_source'}and all(r.layout['symbols'][k]==v[0]for k,v in self.symbols.items()),'same actual bridge/DWARF symbols')
        initial_epoch=r.items(self.b,'pdo_wire','epochs','pdo_epoch')[0]
        initial_slots=r.items(self.f(initial_epoch,'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.bank_layouts=[[self.f(bank,'ped_bank','layout')for bank in r.items(slot,'pdo_slot','banks','ped_bank')]for slot in initial_slots]
        self.certificates=r.items(self.b,'pdo_wire','certificates','pdo_certificate')
        payload=self.f(self.certificates[0],'pdo_certificate','payload');key=self.f(payload,'pe_payload','source')
        row=r.items(key,'li2_pg_source_key','page','li2_pg_source_page')[0]
        self.main_backing=self.f(row,'li2_pg_source_page','backing');self.source_offset=self.i(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','offset')
        self.main_vma_identity=self.v(self.f(row,'li2_pg_source_page','identity'),'li2_fetch_page','vma_major vma_minor vma_inode')
        binding=image['persistent_binding'];need(binding['version']==1 and binding['unregistered']is True and binding['subentry']is True and binding['cross_pair']is True and binding['direct_frontier']is True and binding['mode']in('capture','differential')and binding['profile']=='persistent-fused-'+binding['mode']+'-v1'and binding['bounded_fused']is True and binding['policy_version']==11 and binding['pf_refusals']==dict(version=1,reason=256,shared_reasons=18,abi2=False),'actual distinct active-domain build mode')
        self.differential=binding['mode']=='differential';self.geometry=self.layout(self.f(self.f(payload,'pe_payload','header'),'pe_header','layout'))

    def decoded(self,b,pc,kind=None):
        off=pc-self.page;forms={0x203:(8,3,0),0x20a:(1871,6,0),0x2409:(696,5,0),0x221:(167,2,0),0x223:(280,3,0)}
        need(off in forms,'one actual retained-two ordinary boundary');code,length,step=forms[off]
        window,_=self.source_window(pc)
        self.eq(b,'li2_decoded',pc=pc,next_pc=pc+length,abi_version=1,decode_status=0,code=code,kind=0,destination=16,width_bits=0,step_disposition=step,available=len(window),length=length,reserved=0)
        need(self.f(b,'li2_decoded','bytes')==window+bytes(16-len(window)),'whole actual ordinary retained-two decoder window')
        return code,length

    def compact(self,payload,entry):
        c=self.f(payload,'pe_payload','plan');t='li2_pg_compact'
        need(entry in(self.head,self.page+0x2400),'one exact immutable cross-pair root')
        pair=0 if entry==self.head else 2;page=self.page+pair*PAGE;source=self.app['source'][pair*PAGE:(pair+2)*PAGE]
        table=plan.table(self.ranges+[(self.page+i*PAGE,self.page+(i+1)*PAGE)for i in range(4)],self.table)
        need(self.f(c,t,'table')==table,'whole independent exclusion tree including every source page and no unobserved rseq word')
        expected=plan.graph(source,page,entry,self.geometry,table);heads=expected['heads']
        self.eq(c,t,version=11,bytes=353608,ready=1,result=0,heads=heads,exits=expected['exits'],stores=expected['stores'],source_bytes=expected['source_bytes'],source_mask=expected['source_mask'],decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=entry)
        need(struct.unpack('<2I',self.f(c,t,'member_heads'))==(heads,0)and q(self.f(c,t,'page'))==(page,page+PAGE)and self.layout(self.f(c,t,'layout'))==self.geometry and self.f(c,t,'source')==source,'whole independent cross-pair source and head partition')
        for k in('image','stub_image','head','original','frontier','edge','instruction','guard'):
            need(self.f(c,t,k)==expected[k],'whole independent cross-pair '+k)
        need(self.f(c,t,'exit_pc')==expected['exit_pc_bytes'],'all distinct ordered register and direct frontier tokens')
        need(self.table-64576==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types[t]['fields']['original']['offset'],'actual immutable row address and common full/compact table relation')
        return expected

    def pin(self,b,state,serial,heads,refs,terminal=False):
        t='li2_pg_rseq_progress';checks=self.unregistered_pin(b,serial,terminal)
        self.eq(b,t,cold_heads=heads,cold_stores=int(heads>0),cold_stubs=0,domain_count=len(refs))
        need(self.f(b,t,'domain_ref')==b''.join(refs)+bytes((2-len(refs))*80),'whole actual unregistered source member references')
        rt='li2_rseq_state'
        self.eq(state,rt,initialized=1,registered=0,held=0,first_error=0,phase=0,first_detail=0,pid=self.pid,tid=self.pid,
                address=0,page=0,length=0,signature=0,epoch=0,fs_base=self.app['machine'][1],gs_base=self.app['machine'][2],
                fs_result=0,gs_result=0,tls_attempted=1,tls_complete=1,calls=0,registrations=0,unregistrations=0,
                kernel_errors=0,instruction_checks=0,range_checks=0,repeat_checks=0,run_checks=0,syscall_checks=0)
        zero(self.f(state,rt,'data'),'no registered-data receipt before first registration')
        zero(self.f(state,rt,'transaction'),'no attempted registration transaction during focal execution')
        return checks

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
            self.eq(h,'pe_header',lifetime_version=1,lifetime_mode=lifetime,version=1,serial=self.i(g,'li2_pg_generation','build_serial'),generation=gen,registry=self.symbol('pe'),generated=self.geometry[0],spill=self.geometry[4],registered_epoch=self.i(pin,'li2_pg_rseq_progress','registration_epoch'),rseq_address=self.i(pin,'li2_pg_rseq_progress','address'),rseq_length=self.i(pin,'li2_pg_rseq_progress','length'),rseq_signature=self.i(pin,'li2_pg_rseq_progress','signature'))
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
        self.eq(w,t,primary=pairs[0][0],primary_bank=self.i(refs[0],'li2_pgd_ref','bank'),peer=2 if count==1 else pairs[1][0],exit_member=0 if terminal else 2)
        receipt=self.i(w,t,'receipt');need(receipt<3,'bounded selected immutable completion cell')
        self.permission(self.f(w,t,'directory_write'),self.h[40],3,3);self.permission(self.f(w,t,'directory_seal'),self.h[40],1,3)
        if terminal:self.query(self.f(w,t,'directory_closed'),self.h[40],1,pages=3)
        else:zero(self.f(w,t,'directory_closed'),'no premature directory terminal query')
        d=self.f(w,t,'directory');dt='li2_jd_domain_directory';total=sum(10 if self.i(ref,'li2_pgd_ref','root')==self.head else 4 for ref in refs)
        self.eq(d,dt,version=1,count=total,serial=serial,reserved=0);expected=[]
        for r in refs:
            root=self.i(r,'li2_pgd_ref','root');offsets=(0x206,0x20a,0x210,0x214,0x218,0x21b,0x21e,0x221,0x200,0x203)if root==self.head else(0x2400,0x2403,0x2406,0x2409);base=q(self.f(r,'li2_pgd_ref','layout'))[0]
            for j,off in enumerate(offsets):expected.append(struct.pack('<3Q2I',self.page+off,base+512*j,self.i(r,'li2_pgd_ref','generation'),self.i(r,'li2_pgd_ref','slot'),j))
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

    def epoch(self,b,index,baseline,previous=None):
        t='pdo_epoch';st='pdo_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pdo_epoch_info';warm=index==2;count=2 if warm else 1
        entry=self.page+(0x2400 if index==1 else 0x206);ci=int(index==1);heads=4 if index==1 else 10;exitpc=self.page+(0x20a if index==0 else 0x2409 if index==1 else 0x221)
        h=q(self.f(b,t,'h'));need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,0,1,0)and h[11]==h[3]+1 and h[12:15]==(0,0,1)and h[24]in(0,1)and not any(h[25:]),'actual accepted domain entry/exit with zero interior signal')
        need(h[15]in(0,1)and h[16]==self.symbol('selected_session')and h[17]>0 and h[18]<U64 and h[19:24]==(h[15],1,0,0,1),'actual selected preclose domain predecessor')
        initial=self.f(b,t,'initial_registry');need(initial==self.f(b,t,'terminal_registry'),'whole domain registry unchanged during epoch');self.ranges,_=self.registry_prefix(self.f(self.b,'pdo_wire','startup_registry'),initial)
        prior=self.f(b,t,'prior_counts');pc=self.pf_partition(prior);prior_slots=self.f(b,t,'prior');prior_domain=self.domain_checkpoint(self.f(b,t,'prior_domain'),baseline)
        need(prior_domain==baseline,'complete prior domain unchanged between focal activations');self.domain_state(prior_domain,pc['next_serial'])
        need(pc['entries']==pc['completed']and pc['publications']==pc['next_generation']and pc['unexpected']==0,'all preceding domain epochs completed before focal entry')
        prior_rows,_=self.storage(prior_slots,pc,set(range(min(index,2))),prior_domain);chosen=self.choose(prior_rows,entry,prior_domain);need(chosen==h[24],'actual root/empty/oldest-completed selection')
        resident=prior_rows[chosen];rg=self.f(resident,'pdo_slot','generation');installed=self.i(rg,gt,'installed')
        entered=self.f(b,t,'entered');end=self.f(b,t,'terminal');p=self.f(entered,st,'progress');ep=self.f(end,st,'progress');serial=self.i(p,pt,'serial');gen=self.i(p,pt,'generation')
        need(serial==pc['next_serial']+1 and 0<gen<U64//2,'actual monotonic domain attempt/member generation')
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=2 if warm else installed)
        if warm:inc.update(hits=1)
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed)
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1)
        self.pf_partition(self.f(entered,st,'counts'));self.pf_partition(self.f(end,st,'counts'))
        ed=self.domain_checkpoint(self.f(entered,st,'domain'),baseline);zd=self.f(b,t,'terminal_domain');need(self.domain_checkpoint(self.f(end,st,'domain'),zd)==zd,'whole terminal domain checkpoint and literal state equality')
        self.domain_state(ed,serial);self.domain_state(zd,serial)
        self.r.change(prior_domain,ed,'pda_state',values=dict(dual_entries=self.i(prior_domain,'pda_state','dual_entries')+int(warm)),observed=('work','claimed'))
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots');active=(chosen,1-chosen)if warm else(chosen,)
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),set(range(2 if index else 1)),ed,active)
        zrows,zselected=self.storage(zslots,self.counts(self.f(end,st,'counts')),set(range(2 if index else 1)),zd)
        need(selected==zselected==chosen and self.f(eslots,'pdo_slots','previous_selection')==self.f(prior_slots,'pdo_slots','selection')and self.f(zslots,'pdo_slots','previous_selection')==self.f(eslots,'pdo_slots','previous_selection'),'actual previous and selected typed slot identities')
        if not warm:need(prior_rows[1-chosen]==erows[1-chosen]==zrows[1-chosen],'inactive retained slot unchanged through cold publication')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'pdo_slot','generation');eg=self.f(terminal,'pdo_slot','generation');buildserial=self.i(g,gt,'build_serial')
        payload=self.certificate(ci,actual,entry,buildserial,gen);key=self.f(payload,'pe_payload','source');ph=self.f(payload,'pe_payload','header')
        need(gen==(self.i(rg,gt,'generation')if warm else pc['next_generation']+1)and buildserial==(self.i(rg,gt,'build_serial')if warm else serial),'exact cold publication or retained primary generation')
        need(not warm or installed==1,'shared entry requires actual prior completed A')
        ew=self.f(ed,'pda_state','work');zw=self.f(zd,'pda_state','work');refs,members,cell=self.work(ew,erows,count,serial);zrefs,zmem,zcell=self.work(zw,zrows,count,serial,True)
        need(refs==zrefs and members==zmem and cell==zcell,'whole stable shared member set through closure')
        self.r.change(ew,zw,'pda_work',values=dict(exit_member=0,completion=1),observed=('proof_exit','directory_closed'))
        # Claim consumption precedes choosing the first fully reusable completion cell.
        masks=list(struct.unpack('<3I',self.f(prior_domain,'pda_state','claimed')))
        for slot in active:
            if warm or(slot==chosen and installed):
                _,_,prior_cell,member=self.claim(prior_rows[slot],prior_domain);masks[prior_cell]|=1<<member
        need(struct.unpack('<3I',self.f(ed,'pda_state','claimed'))==tuple(masks),'exact member claim bits consumed before domain entry')
        cells=self.state_cells(ed);available=[i for i,c in enumerate(cells)if not any(c)or masks[i]==(1<<self.i(c,'pda_completion','count'))-1]
        need(available and cell==available[0],'first complete unclaimed cell is the only reused receipt')
        nextid=self.i(prior_domain,'pda_state','next_id');need(nextid<U64,'nonwrapping immutable completion ID');masks[cell]=0
        self.r.change(ed,zd,'pda_state',values=dict(next_id=nextid+1,dual_completed=self.i(ed,'pda_state','dual_completed')+int(warm)),observed=('work','completion','claimed'))
        need(struct.unpack('<3I',self.f(zd,'pda_state','claimed'))==tuple(masks),'one new completion resets only its own claim mask')
        zcells=self.state_cells(zd)
        for i in range(3):
            if i!=cell:need(zcells[i]==cells[i],'every still-live completion cell remains byte-exact')
        c=zcells[cell];self.eq(c,'pda_completion',id=nextid+1,serial=serial,count=count,complete=1)
        self.eq(p,pt,serial=serial,registration_epoch=0,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17*count,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==((entry&-PAGE),(entry&-PAGE)+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual shared progress retains primary source/layout')
        self.r.change(p,ep,pt,values=dict(phase=13,closed_pages=17*count,anchor_released=1,registration_rechecked=1,completion_permit=1))
        for stage in(entered,end):self.eq(stage,st,busy=1,active=1,failing=0,resuming=0,pending=1);need(0<self.i(stage,st,'route')<32,'actual generated domain route')
        need(self.f(entered,st,'route')==self.f(end,st,'route'),'unchanged active route through shared close')
        for i,slot in enumerate(active):
            self.member_transition(erows[slot],zrows[slot],serial,not warm)
            claim,cm,claim_cell,claim_member=self.claim(zrows[slot],zd)
            need(claim==c and claim_cell==cell and claim_member==i and self.f(cm,'pda_member_completion','identity')==refs[i],'each member receives its exact joint completion claim')
            if warm:
                before=self.f(prior_rows[slot],'pdo_slot','generation');current=self.f(erows[slot],'pdo_slot','generation')
                self.r.change(before,current,gt,values=dict(active_refs=1,linked=1,domain_refs=1),observed=('member_refs','open','close','slots','cell'))
                self.r.change(prior_rows[slot],erows[slot],'pdo_slot',observed=('generation','claim','banks'))
        self.setup(actual)
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=1,exit_index=1 if warm else 0,recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=(7,5,7)[index],flags_written=0 if index==1 else 0x8d5,ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
        self.eq(self.f(info,it,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        need(self.f(info,it,'session')==self.f(self.b,'pdo_wire','session')and self.f(info,it,'registry')==self.f(initial,'pdo_registry','ranges')and self.f(info,it,'banks')==self.f(terminal,'pdo_slot','banks'),'whole actual domain session/registry/banks')
        if installed:
            save=self.geometry;self.geometry=self.layout(self.f(rg,gt,'layout'));self.query3(self.f(info,it,'claim_code'),1);self.proof_query(self.f(info,it,'claim_proof'),self.proof,1);self.query(self.f(info,it,'claim_spill'),self.geometry[4],3);self.query(self.f(info,it,'claim_slots'),self.geometry[3],1);self.geometry=save
        else:
            for k in('claim_code','claim_proof','claim_spill','claim_slots'):zero(self.f(info,it,k),'no invented virgin claim')
        if warm:
            for k in('bank_before','proof_before','reopen_code','reopen_proof'):zero(self.f(info,it,k),'warm never rebuilds immutable proof/code')
        else:
            rows=self.r.items(info,it,'bank_before','li2_private_code_query');prot=self.i(rows[0],'li2_private_code_query','actual_prot');need(prot in(1,3),'cold target bank is closed or virgin');self.query3(self.f(info,it,'bank_before'),prot);self.proof_query(self.f(info,it,'proof_before'),self.proof,1 if installed else 3);self.permission3(self.f(info,it,'reopen_code'),3);self.proof_permission(self.f(info,it,'reopen_proof'),self.proof,3)
            for actual_query,permission in zip(self.r.items(g,gt,'code_writable','li2_private_code_query'),self.r.items(info,it,'reopen_code','le_permission'),strict=True):need(actual_query==self.f(permission,'le_permission','query'),'whole code reopen publication join')
            need(self.f(g,gt,'proof_writable')==self.f(self.f(info,it,'reopen_proof'),'pg_proof_permission','query'),'whole proof reopen publication join')
        before=self.frame(self.f(b,t,'before'));ingress=self.normalized(self.f(b,t,'ingress'),before);returned=self.frame(self.f(b,t,'returned'));after=self.frame(self.f(b,t,'after'));flags=before['greg'][17]
        self.eq(info,it,flags=flags);self.trace(ingress,entry,flags|TF);self.trace(before,entry,flags);self.same_event(ingress,before,flags)
        want=list(before['greg']);want[16]=self.generated;need(returned['greg']==tuple(want)and returned['fp']==before['fp']and returned['si']==before['si']and(returned['fs'],returned['gs'])==tuple(self.app['machine'][1:3]),'whole domain redirect changes only original RIP')
        uc=bytearray(before['uc']);struct.pack_into('<Q',uc,40+16*8,self.generated);need(returned['uc']==bytes(uc),'whole returned UC except actual redirect')
        self.nx(after,exitpc);need(after['fp']==before['fp']and after['fp_bytes']==before['fp_bytes']and after['mask']==MASK and(after['fs'],after['gs'])==tuple(self.app['machine'][1:3]),'all domain FP/AF/mask/TLS preserved')
        self.preserved_context(before,after)
        projection=self.f(b,t,'predecessor');self.eq(projection,'pdo_predecessor',complete=1,unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        slot=self.f(projection,'pdo_predecessor','closed')+bytes(self.r.types['li2_step_frame']['bytes']);self.r.walk(slot,'li2_tf_chain_slot')
        prefix=self.f(projection,'pdo_predecessor','before_prefix');wanted=bytearray(prefix);sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields'];struct.pack_into('<I',wanted,sf['phase']['offset'],5);at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==slot[:len(prefix)],'whole actual predecessor prefix close transition')
        need(self.i(slot,'li2_tf_chain_slot','index')==h[15]and self.i(slot,'li2_tf_chain_slot','event_id')<h[17],'actual predecessor older generation/event')
        predecessor_pc=self.page+(0x203 if index==0 else 0x20a if index==1 else 0x2409);predecessor,_=self.predecessor(slot,predecessor_pc,ingress);self.eq(slot,'li2_tf_chain_slot',origin=1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual consumed domain transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref,distinct_peer=warm);self.source(zs,serial,entry,key,ref,terminal=True,distinct_peer=warm);need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'one complete source anchor held through all internal transfers')
        self.domain_source(self.f(entered,st,'domain_source'),refs,serial,False,es);self.domain_source(self.f(end,st,'domain_source'),refs,serial,True,zs)
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state');a=self.pin(er,estate,serial,0 if warm else heads,refs);z=self.pin(zr,zstate,serial,0 if warm else heads,refs,terminal=True);need(z>a and estate==zstate,'actual observed-unregistered pin and complete state unchanged throughout shared lifetime')
        if warm:
            # Unregistered ordinary instruction checks return before footprint
            # mutation; warm reuse performs no new cold-head inspection. Keep
            # the complete actual cold-B state, not the predecessor JMP's PC.
            prior_state=self.f(self.f(self.epochs[1],t,'terminal'),st,'state')
            need(estate==zstate==prior_state,'whole warm rseq state inherits cold-B terminal inspection')
        lastpc=self.page+(0x203 if index==0 else 0x2409);code,length=(8,3)if index==0 else(696,5)
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1);self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released shared fetch')
        for k,actual_value in(('source',zs),('domain_source',self.f(end,st,'domain_source')),('rseq',zr),('fetch',self.f(end,st,'fetch'))):need(self.f(c,'pda_completion',k)==actual_value,'joint completion retains whole actual '+k)
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal domain exit invents no unexpected recovery')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False);model=app_model.trace_model(self.app);lo,hi=((1,1412),(1413,1416),(1417,2834))[index];need(bm==dict(data=model[lo][3],stack=model[lo][4])and am==dict(data=model[hi][3],stack=model[hi][4]),'whole actual cross-pair guest memory effects')
        # Directory pages are sealed exact bytes at entry and drain, including all padding.
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes']);need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole actual immutable directory throughout shared lifetime')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'all actual zero-link slot pages')
        initial_spill=self.f(b,t,'initial_spill');terminal_spill=self.f(b,t,'terminal_spill')
        for i,member in enumerate(members):
            init=initial_spill[i*PAGE:(i+1)*PAGE];final=terminal_spill[i*PAGE:(i+1)*PAGE];zero(init[32:],'all initial cells and spill tails zero');zero(final[32:],'all final cells and spill tails zero')
            slotindex=member[0];is_a=self.i(refs[i],'li2_pgd_ref','root')==self.head
            regs=model[1416 if warm and not is_a else hi][1]
            scratch=(0,1,2,3)
            need(final[:32]==struct.pack('<4Q',*(regs[j]for j in scratch)),'whole actual final initialized scratch for its owning certificate')
            gend=self.f(zrows[slotindex],'pdo_slot','generation');lastcell=self.r.items(gend,gt,'cell','pg_dispatch_cell_transition')[2];target=0
            need(self.i(lastcell,'pg_dispatch_cell_transition','before')==target,'actual final reset binds its last committed directory hit')
            if warm:
                old_epoch=self.epochs[0 if is_a else 1];need(init==self.f(old_epoch,t,'terminal_spill')[:PAGE],'warm actual spill page equals prior completed owning certificate')
            else:zero(init,'actual cold spill initialization')
        zero(initial_spill[count*PAGE:],'unused initial spill member');zero(terminal_spill[count*PAGE:],'unused terminal spill member')
        entries=[self.focal_entry(stage,self.f(payload,'pe_payload','plan'),key,entry,heads,serial,chosen,gen,buildserial)for stage in(entered,end)]
        need(entries[0]==entries[1],'whole focal entry immutable through drain')
        frontier=history.direct_history(self,c)
        direct=self.f(c,'pda_completion','direct_exit')
        self.eq(direct,'pda_direct_exit',complete=1,member=0,heads=heads,head=(1,3,7)[index],
                exits=1 if index==1 else 2,index=1 if warm else 0,arm=1 if warm else 0,
                reserved=0,flags=after['greg'][17])
        certificate=self.certificates[int(index==1)]
        cp=self.f(self.f(certificate,'pdo_certificate','payload'),'pe_payload','plan')
        need(self.f(direct,'pda_direct_exit','row')==self.r.items(cp,'li2_pg_compact','head','li2_pe_head')[(1,3,7)[index]]and
             self.f(direct,'pda_direct_exit','original')==self.r.items(cp,'li2_pg_compact','original','li2_span_decoded')[(1,3,7)[index]]and
             self.f(direct,'pda_direct_exit','direct')==self.f(cp,'li2_pg_compact','instruction')[144*(1,3,7)[index]:144*(1,3,7)[index]+120],
             'every cold and warm direct completion binds its whole independently reconstructed certificate')
        mapping=[]
        return dict(frontier_member=frontier['member'],frontier_arm=frontier['arm'],
                    frontier_pc=frontier['pc'],frontier_target=frontier['target'],actual_entry=dict(pc=entry,compiled_root=entry,head=0,slot=chosen,generation=gen,build_serial=buildserial,subentry=False),rseq_mapping=mapping,kind='domain'if warm else'cold',mode=0,slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17*count,domain_members=count,anchor_released=1,permit=1,interior_signals=0,members=members,shared_lifetime=1,completion_id=nextid+1,claim_members=tuple(range(count)),joint_complete=1,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot,dispatch_pc=exitpc,domain_raw=zd)

    def next_trace(self,b,last,epoch):
        t='pdo_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id');need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));flags=(last['logical']['greg'][17]&~RF)|TF;self.trace(frame,self.page+0x223,flags)
        self.preserved_context(last['logical'],frame)
        need(frame['greg'][22]==self.page+0x221 and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains ordinary final Jcc CR2 and post-close TLS')
        before,ref=self.predecessor(slot,self.page+0x221,frame);owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original Jcc begins at actual retained exit NX frame')
        fetch=self.f(self.f(epoch,'pdo_epoch','terminal'),'pdo_stage','fetch');need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary Jcc borrows after actual retained source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        h=self.h;t='pdo_wire';r=self.r
        need(type(status)is int and status==0 and self.app['mode']==0,'actual successful loop-only process and mode')
        need(h[:9]==(0x414f50445049324c,13,5421440,r.layout['registrations']['pe']['bytes'],362656,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,0),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdo_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=((2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8)+544
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need({k:v for k,v in storage.items()if k!='domain'}==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(storage['domain']['bytes']==225832 and storage['domain']['offset']+225832<=h[3]and h[33]==self.symbol('pe')+storage['domain']['offset']and h[34]==self.symbol('pg_domain_source'),'actual protected domain field and separate shared source state')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(self.head==self.page+0x206 and self.page+16384<1<<31 and h[31:33]==(self.head,self.page+0x2400)and h[35]==3 and h[36]>=1 and h[37]>=3 and h[38]==0 and h[39]==self.page+0x223 and canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(225832,71368,11312,12288,3,0)and h[47:53]==(1,0,0,0,h[16],0)and h[53:57]==(self.symbol('pdo_encoded'),4<<20,1,1)and not any(h[57:]),'exact three shared-domain epochs and successful complete record')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        need(r.transport['status']==r.transport['code']==0,'actual successful encoded-body transport')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),'actual bridge/app CPUID hardware equality')
        for key,objid in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):self.image_header(self.f(self.b,t,key),objid)
        self.eq(self.f(self.b,t,'session'),'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(self.f(self.b,t,'session'),'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        obj,_,loads=self.objects[self.image['main_object']];bias=self.bases[self.image['main_object']]
        owners=[p for p in loads if p[1]==5 and bias+p[3]<=self.page and self.page+16384<=bias+p[3]+p[5]]
        need(len(owners)==1 and self.source_offset==owners[0][2]+self.page-bias-owners[0][3]and obj['data'][self.source_offset:self.source_offset+16384]==self.app['source'],'whole four-page original ELF bytes')
        need(self.page+5*PAGE<=bias+owners[0][3]+owners[0][5]and
             obj['data'][self.source_offset+4*PAGE:self.source_offset+5*PAGE]==self.capture_page(),
             'whole real fifth executable page is the exact original low-to-high capture carrier')

        epochs=r.items(self.b,t,'epochs','pdo_epoch');self.epochs=epochs
        initial_slots=r.items(self.f(epochs[0],'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'pdo_slot','banks','ped_bank')[1],'ped_bank','generated');self.h_proof_alloc=self.i(initial_slots[1],'pdo_slot','proof')
        initial_domain=self.f(self.b,t,'initial_domain')
        a=self.epoch(epochs[0],0,initial_domain);b=self.epoch(epochs[1],1,a['domain_raw']);warm=self.epoch(epochs[2],2,b['domain_raw'])
        self.preserved_context(a['after'],b['ingress'])
        self.preserved_context(b['after'],warm['ingress'])
        for index,previous in((1,a),(2,b)):
            need(self.f(epochs[index],'pdo_epoch','prior_counts')==previous['counts_raw']and self.f(epochs[index],'pdo_epoch','prior')==previous['slots_raw'],'next focal activation follows complete prior closure without hidden offer')
        need(a['slot']!=b['slot']and b['generation']==a['generation']+1,'two distinct actual retained identities')
        need((warm['slot'],warm['generation'],warm['build_serial'])==(a['slot'],a['generation'],a['build_serial'])and warm['members']==[a['members'][0],b['members'][0]],'joint A entry retains both exact cold generations')
        need(b['begin']==a['terminal_ordinal']+1 and warm['begin']==b['terminal_ordinal']+1,'complete focal raw-event chronology')
        self.next_trace(self.f(self.b,t,'next'),warm,epochs[2]);cancellation=self.cancellation(self.f(self.b,t,'cancellation'),warm);need(raw[0]>=cancellation['next_ordinal'],'whole chronological active-domain ingress ordinals')
        final=self.pf_partition(self.f(self.b,t,'final_counts'));last=self.counts(cancellation['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(a>=b for a,b in zip(final['misses'],last['misses'],strict=True)),'final counters retain every focal event without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,t,'final_row'));need(len(values)==len(names),'whole exact retained terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(1,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,t,'final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+final['subentry_hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])+final['pf_backward_cancelled']==final['cancelled']and final['pf_backward_refused']==final['pf_backward_cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits']+final['subentry_hits']+row['dual_entries'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==h[36]and 1<=row['dual_entries']<=final['hits']+final['subentry_hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and h[37]==final['completed'],'exact actual joint completion/member accounting')
        subvalues=q(self.f(self.b,t,'final_subentry'));subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split();sub=dict(zip(subnames,subvalues,strict=True))
        need(subvalues[:7]==(1,0,0,final['subentry_selections'],final['subentry_hits'],final['subentry_entries'],final['subentry_completed']),'whole protected subentry counter row')
        need(final['subentry_selections']>=final['subentry_hits']==final['subentry_entries']==final['subentry_completed'],'completed global subentry events form their own exact bucket')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),'actual final completed entry names final selected generation')
        else:need(not any(subvalues[7:]),'last cancelled attempt has no invented entry receipt')
        replacements=a['prior_generation_installed']+b['prior_generation_installed']
        mapping=[]
        return dict(pf_refusal_stages=self.pf_stages(3,True),pf_refusals=pf_row(final,0,0),cancellation=cancellation,plan_version=11,rseq_mapping=mapping,terminal=row,subentry_terminal=sub,subentry_entries=0,mode=0,attempts=[a,b,warm],cold_publications=2,warm_entries=1,dual_entries=1,replacements=replacements,permit_claims=replacements+2,interior_signals=0,source=self.app['source'],lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,word_available=False,tls_complete=1,status=0,code=0,detail=0,qualification_credit=False)

    def entry_value(self,e,key,actual,layout,root=None):
        t='li2_pgs_entry';v=self.f(e,t,'target');vt='li2_pgs_target';row=self.f(e,t,'row');d=self.f(self.f(e,t,'original'),'li2_span_decoded','decoded')
        serial=self.i(actual,'li2_pg_sources','serial');root=self.i(key,'li2_pg_source_key','entry')if key is not None else root
        self.eq(e,t,complete=1,reserved=0);self.eq(self.f(e,t,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
        transfer,gen,build=self.v(e,t,'transfer_serial generation build_serial');slot,bank=self.v(e,t,'slot bank')
        need(0<transfer<U64 and 0<gen<U64 and 0<build<=serial and slot in(0,1)and bank in(0,1),'bounded actual entry token/generation/build/slot/bank')
        need(layout==self.bank_layouts[slot][bank],'actual entry bank names immutable fixed allocation')
        need(self.f(e,t,'anchor')==self.f(actual,'li2_pg_sources','anchor'),'actual entry retains fresh source anchor')
        self.eq(actual,'li2_pg_sources',complete=1,reserved=0)
        anchor=self.f(e,t,'anchor');need(self.i(anchor,'li2_fetch_ref','owner')!=0 and self.i(anchor,'li2_fetch_ref','sequence')>0,'actual entry owns a nonempty source reference')
        heads,head,member,local,page=self.v(v,vt,'heads head member local source_page');pc=self.i(v,vt,'pc')
        need(1<=heads<=128 and head<heads and member==head//64 and local==head%64 and page in(0,1),'exact entry head/member/local/source coordinates')
        pages=q(self.f(v,vt,'page'));actual_key=self.f(actual,'li2_pg_sources','key');self.eq(v,vt,version=1,root=root,generated=q(layout)[member]+local*512,pc=self.i(actual_key,'li2_pg_source_key','entry'))
        need((pc==root)==(head==0),'compiled root remains distinct from actual subentry')
        offset,length,generated=self.v(row,'li2_pe_head','source_offset source_length generated_length');need(offset<=PAGE-15 and 1<=length<=15 and 1<=generated<=512,'whole external head window and generated slot')
        self.eq(row,'li2_pe_head',source_page=page);need(self.i(row,'li2_pe_head','kind')in(1,2,5),'actual supported entry kind')
        self.eq(d,'li2_decoded',abi_version=1,decode_status=0,pc=pc,next_pc=pc+length,length=length,available=15)
        source_rows=self.r.items(actual_key,'li2_pg_source_key','page','li2_pg_source_page')
        need(pages==tuple(self.i(self.f(x,'li2_pg_source_page','identity'),'li2_fetch_page','address')for x in source_rows)and pc==pages[page]+offset,'entry keeps actual source pair')
        need(self.f(d,'li2_decoded','bytes')[:15]==self.f(source_rows[page],'li2_pg_source_page','bytes')[offset:offset+15],'actual entry decoder window equals fresh complete source')
        if key is not None:
            self.pair_key(actual_key,key)
            if pc==root:self.key_identity(actual_key,key)
        return head

    def cancellation(self,b,last):
        t='pbo_cancel';st='pdo_stage';pt='li2_pg_progress';ct='pbo_miss_plan';rt='li2_pg_rseq_progress'
        self.pf_partition(self.f(self.f(b,t,'held'),st,'counts'),1)
        self.pf_partition(self.f(self.f(b,t,'resumed'),st,'counts'))
        h=q(self.f(b,t,'h'));pc=self.page+0x223
        need(h[0]==h[4]==h[5]==h[9]==h[10]==1 and h[1]==h[6]==last['next_trace_ordinal'] and h[11]==h[1]+1 and h[7]==1 and h[3]in(0,1)and h[8]==1-h[3]and h[12:]==(0,0,0,0),'one actual held miss, RUNNING cancellation and immediate next hardware event')
        before=self.frame(self.f(b,t,'before'));returned=self.frame(self.f(b,t,'returned'));nxt=self.normalized(self.f(b,t,'next'),before)
        ingress=last['next_trace'];flags=ingress['greg'][17]&~TF
        self.trace(before,pc,flags);self.same_event(ingress,before,flags)
        self.trace(returned,pc,flags|TF);self.same_event(before,returned,flags|TF)
        self.trace(nxt,pc+3,flags|TF)
        self.preserved_context(returned,nxt)
        wanted=list(returned['greg']);wanted[16]=pc+3
        need(nxt['greg']==tuple(wanted)and nxt['fp']==returned['fp']and nxt['fp_bytes']==returned['fp_bytes']and nxt['mask']==returned['mask']and(nxt['fs'],nxt['gs'])==(before['fs'],before['gs']),'real ordinary store executes once with complete GPR/FP/mask/TLS unchanged')
        need(before['greg'][22]==returned['greg'][22]==nxt['greg'][22]==self.page+0x221,'cancellation retains real final-branch CR2')
        held=self.f(b,t,'held');resumed=self.f(b,t,'resumed');serial=h[2]
        self.eq(held,st,busy=1,active=0,failing=0,resuming=0,route=0,pending=0)
        self.eq(resumed,st,busy=1,active=0,failing=0,resuming=1,route=2,pending=1)
        hp=self.f(held,st,'progress');zp=self.f(resumed,st,'progress')
        self.eq(hp,pt,serial=serial,registration_epoch=0,publication=0,generation=0,phase=4,first_error=0,source_count=2,opened_pages=0,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0)
        self.eq(zp,pt,phase=14,anchor_released=1,registration_rechecked=1)
        self.r.change(hp,zp,pt,observed=('phase','anchor_released','registration_rechecked'))
        need(serial==last['serial']+1 and self.i(hp,pt,'transfer_serial')>0 and q(self.f(hp,pt,'source'))==(self.page,self.page+PAGE),'actual next owner serial and B source pair')
        self.delta(last['counts_raw'],self.f(held,st,'counts'),next_serial=1,offers=1,cold_attempts=1,miss_reason=1)
        self.delta(self.f(held,st,'counts'),self.f(resumed,st,'counts'),cancelled=1)
        need(self.f(b,t,'initial_registry')==self.f(b,t,'terminal_registry')==self.f(self.epochs[2],'pdo_epoch','terminal_registry'),'no registration invented by unsupported-frontier cancellation')
        self.registry(self.f(b,t,'initial_registry'))
        # Reset removes active work, never the three immutable completion cells.
        domain=self.domain_checkpoint(self.f(held,st,'domain'),last['domain_raw'])
        need(self.f(held,st,'domain')==self.f(resumed,st,'domain'),'no domain binding or completion from a cancelled plan')
        work=self.f(domain,'pda_state','work');expected=bytearray(len(work))
        for k,v in(('peer',2),('receipt',3),('exit_member',2),('recovery_member',2)):
            struct.pack_into('<I',expected,self.r.types['pda_work']['fields'][k]['offset'],v)
        need(work==bytes(expected),'actual untouched reset domain work')
        self.r.change(last['domain_raw'],domain,'pda_state',observed=('work',))
        for stage in(held,resumed):
            zero(self.f(stage,st,'entry'),'cancelled plan has no admitted subentry')
            zero(self.f(stage,st,'domain_source'),'cancelled plan has no active member source lease')
        rows,selected=self.storage(self.f(held,st,'slots'),self.counts(self.f(held,st,'counts')),(0,1),domain)
        self.storage(self.f(resumed,st,'slots'),self.counts(self.f(resumed,st,'counts')),(0,1),domain)
        self.same_slots(last['slots_raw'],self.f(held,st,'slots'));need(self.f(held,st,'slots')==self.f(resumed,st,'slots'),'cancelled candidate preserves every retained slot and selection')
        need(selected==self.choose(rows,pc,domain),'actual unsupported frontier uses unchanged victim selection')
        self.geometry=self.layout(self.f(hp,pt,'layout'));self.proof=self.i(hp,pt,'proof');self.table=self.i(hp,pt,'table');self.generated=self.geometry[0];self.spill=self.geometry[4]
        need(self.f(hp,pt,'layout')==self.bank_layouts[selected][0]and self.i(hp,pt,'generated')==self.generated and self.i(hp,pt,'spill')==self.spill and self.proof==self.i(rows[selected],'pdo_slot','proof')and self.table==self.proof+self.r.types['pe_payload']['fields']['plan']['offset']+self.r.types['li2_pg_compact']['fields']['table']['offset'],'actual unentered candidate uses its existing low bank/proof geometry')
        hs=self.f(held,st,'source');zs=self.f(resumed,st,'source');source=self.f(hs,'li2_pg_source_progress','source');key=self.f(source,'li2_pg_sources','key');ref=self.f(source,'li2_pg_sources','anchor')
        self.source(hs,serial,pc,key,ref,cancel=True);self.source(zs,serial,pc,key,ref,terminal=True,cancel=True)
        need(source==self.f(zs,'li2_pg_source_progress','source'),'whole held/released candidate source identity')
        oldslot=self.f(b,t,'closed_slot');newslot=self.f(b,t,'resumed_slot')
        need(oldslot==self.f(self.f(self.b,'pdo_wire','next'),'pdo_next','closed')and self.i(oldslot,'li2_tf_chain_slot','index')==h[3],'same real just-closed branch predecessor')
        self.transfer(self.f(held,st,'transfer'),oldslot,ingress,before,ref,consumed=False)
        tr=self.f(resumed,st,'transfer');tt='li2_span_transfer_progress'
        self.eq(tr,tt,phase=5,issued=1,consume_attempted=0,consumed=0,resume_attempted=1,resumed=1,previous=h[3],next=h[8],successor_installed=1,first_error=0,first_detail=0,fresh_borrow=self.i(ref,'li2_fetch_ref','sequence'),pc=pc,flags=flags,refault_attempted=0,refaulted=0)
        self.r.change(self.f(held,st,'transfer'),tr,tt,observed=('phase','resume_attempted','resumed','next','successor_installed','fresh_borrow','fresh'))
        self.observation(self.f(tr,tt,'fresh'),pc,False,ref)
        need(self.i(hp,pt,'transfer_serial')==self.i(tr,tt,'serial'),'actual cancellation progress binds full transfer serial')
        self.eq(newslot,'li2_tf_chain_slot',index=h[8],origin=2)
        prior_slot=last['closed_slot']
        need(self.i(prior_slot,'li2_tf_chain_slot','index')==h[8]and
             self.i(newslot,'li2_tf_chain_slot','generation')==self.i(prior_slot,'li2_tf_chain_slot','generation')+1,
             'resumed slot advances its own last captured generation exactly once')
        _,fresh=self.predecessor(newslot,pc,returned,closed=False)
        oldref=self.f(self.f(oldslot,'li2_tf_chain_slot','fetch'),'li2_chain_fetch','ref')
        need(self.i(fresh,'li2_fetch_ref','owner')==self.i(ref,'li2_fetch_ref','owner')==self.i(oldref,'li2_fetch_ref','owner'),
             'cancelled source and resumed predecessor retain the actual fetch singleton identity')
        self.step_frame(self.f(self.f(self.f(newslot,'li2_tf_chain_slot','owner'),'li2_tf_owner','step'),'li2_step_owner','before'),before)
        need(self.i(fresh,'li2_fetch_ref','sequence')>self.i(ref,'li2_fetch_ref','sequence')and self.i(newslot,'li2_tf_chain_slot','event_id')==self.i(tr,tt,'event'),'real new successor borrow after cancelled source release')
        self.progress(self.f(held,st,'fetch'),self.i(ref,'li2_fetch_ref','sequence'),True)
        self.progress(self.f(resumed,st,'fetch'),self.i(fresh,'li2_fetch_ref','sequence'),True)
        for stage,terminal in((held,False),(resumed,True)):
            pin=self.f(stage,st,'rseq')
            self.eq(pin,rt,active=int(not terminal),checking=0,first_error=0,unsafe_terminal=0,seed_complete=1,entry_complete=0,close_complete=0,first_detail=0,pid=self.pid,tid=self.pid,session=self.symbol('selected_session'),registration_epoch=0,registration_calls=0,address=0,page=0,length=0,signature=0,word_before=0,word_entry=0,word_after=0,cold_heads=0,cold_stores=0,cold_stubs=0,cancel_started=int(terminal),cancel_complete=int(terminal),lifetime_mode=2,word_observed=0,tls_complete=1,fs=before['fs'],gs=before['gs'],fs_result=0,gs_result=0,fs_selector=0,gs_selector=0,domain_bound=0,domain_count=0)
            self.eq(self.f(pin,rt,'token'),'li2_pg_token',owner=self.symbol('pe'),serial=serial)
            for k in('before','observed','after','current_observed','current_after','domain_ref'):zero(self.f(pin,rt,k),'no fabricated registered or domain observation in cancellation '+k)
        need(self.i(self.f(resumed,st,'rseq'),rt,'raw_checks')>self.i(self.f(held,st,'rseq'),rt,'raw_checks')>0,'real completed unregistered cancel queries')
        need(self.f(held,st,'state')==self.f(resumed,st,'state')==self.f(self.f(self.epochs[2],'pdo_epoch','terminal'),st,'state'),'no cold or generated instruction proof during unsupported-root cancellation')
        miss=self.f(b,t,'miss');self.eq(miss,'li2_pg_miss',version=11,status=1,reason=1,site=1,pc=pc,detail=5)
        p=self.f(b,t,'plan');ft='li2_pg_plan';full=bytearray(self.r.types[ft]['bytes'])
        for k in('version','bytes','ready','result','heads','exits','stores','source_bytes','source_mask','decoder_result','guard_result','reserved','member_heads','links','reserved2','page','entry','layout','source','table'):
            f=self.r.types[ft]['fields'][k];value=self.f(p,ct,k);need(len(value)==f['bytes'],'whole unready PB field extent');full[f['offset']:f['offset']+f['bytes']]=value
        fields=self.r.types[ft]['fields'];omitted=len(full)-fields['image']['offset']-fields['table']['bytes']
        self.eq(p,ct,scan_started=1,scan_complete=1,scanned=omitted,nonzero=0,first_nonzero=0,first_value=0)
        full=bytes(full);self.r.walk(full,ft)
        self.eq(full,ft,version=11,bytes=981320,ready=0,result=1,heads=0,exits=0,stores=0,source_bytes=0,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=pc)
        need(q(self.f(full,ft,'page'))==(self.page,self.page+PAGE)and self.f(full,ft,'layout')==self.f(hp,pt,'layout')and self.f(full,ft,'source')==self.app['source'][:8192],'whole unready PB plan prefix and both source pages')
        need(self.f(full,ft,'table')==plan.table(self.ranges+[(self.page+i*PAGE,self.page+(i+1)*PAGE)for i in range(4)],self.table),'whole cancelled-plan exclusion table')
        for k in('member_heads','image','stub_image','head','original','frontier','instruction','exit_pc','edge','guard'):zero(self.f(full,ft,k),'unready PB miss has no invented authority')
        return dict(serial=serial,ordinal=h[1],next_ordinal=h[11],before=before,returned=returned,next=nxt,reason=1,detail=5,source_released=1,generated_entries=0,publications=0,completion_permits=0,ordinary_store_executed=1,counts_raw=self.f(resumed,st,'counts'))


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    raw,transport=codec.decode(data,raw_bytes=5421440,schema_version=13)
    r=wire.Reader(raw,layout);r.transport=transport
    result=Check(r,image,app,pid,cpu).finish(exit_status);result['transport']=transport
    return result

PF_KEYS=('version','policy_version','reason','status','failure_code','refused','cancelled')
PF_COUNTERS=('pf_backward_refused','pf_backward_cancelled')

def pf_row(counts,status,code):
    return dict(version=1,policy_version=11,reason=256,status=status,failure_code=code,
                refused=counts['pf_backward_refused'],cancelled=counts['pf_backward_cancelled'])

def pf_terminal(parsed,owner):
    need(type(parsed)is dict and tuple(parsed)==PF_KEYS and
         all(type(v)is int and 0<=v<U64 for v in parsed.values())and parsed==owner['pf_refusals'],
         'whole actual protected PF refusal terminal row')
    return dict(version=1,policy_version=11,reason=256,protected_fields=7,complete=True)

def terminal(parsed,owner):
    expected=owner['terminal'];need(type(parsed)is dict and set(parsed)==set(expected)and all(type(v)is int for k,v in parsed.items()if k!='misses')and type(parsed['misses'])is list and all(type(v)is int for v in parsed['misses'])and parsed==expected,'whole actual protected direct-frontier terminal row')
    return dict(fields=len(expected),protected_direct_frontier_row=1,inherited_row_protection=0)

def subentry_terminal(parsed,owner):
    expected=owner['subentry_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and all(type(v)is int for v in parsed.values())and parsed==expected,'whole actual protected direct-frontier subentry event row')
    return dict(fields=15,protected_subentry_event_row=1)


CONTROL_COUNTS={0:204}
def controls(data,layout,image,app,pid,cpu,exit_status):
    """PB-specific supplied corruption controls. Old native41/404 is separate."""
    read(data,layout,image,app,pid,cpu,exit_status)
    raw,_=codec.decode(data,raw_bytes=5421440,schema_version=13);types=layout['types'];tests=[]
    def at(t,k,base=0,index=0,child=None):
        return base+types[t]['fields'][k]['offset']+(index*types[child]['bytes']if child else index)
    def add(name,t,k,base=0,index=0,child=None):tests.append((name,at(t,k,base,index,child)))
    for j in range(2):
        name='certificate'+str(j)+'_';c=at('pdo_wire','certificates',index=j,child='pdo_certificate');p=at('pdo_certificate','payload',c);cp=at('pe_payload','plan',p)
        for k in('version','heads','exits','stores','source_mask','source','layout','image','head','original','frontier','instruction','guard','exit_pc','table'):add(name+k,'li2_pg_compact',k,cp)
        for k in('complete','generation','tail','code'):add(name+k,'pdo_certificate',k,c)
    for j in range(3):
        name='epoch'+str(j)+'_';e=at('pdo_wire','epochs',index=j,child='pdo_epoch')
        a=at('pdo_epoch','entered',e);z=at('pdo_epoch','terminal',e)
        for prefix,stage in(('entered',a),('closed',z)):
            for t,field,parent in(('li2_pg_progress','phase','progress'),('li2_pg_rseq_progress','active','rseq'),('li2_pg_source_progress','opened_pages','source'),('li2_fetch_progress','held','fetch')):
                add(name+prefix+'_'+field,t,field,at('pdo_stage',parent,stage))
        for k in('greg','fp'):add(name+'after_'+k,'li2_step_frame',k,at('le_frame','frame',at('pdo_epoch','after',e)))
        add(name+'after_UC','le_frame','uc',at('pdo_epoch','after',e))
        for k in('data','stack'):add(name+'after_'+k,'li2_pdo_memory',k,at('pdo_epoch','after_memory',e))
        for k in('initial_directory','terminal_directory','initial_slots','terminal_slots','terminal_spill'):add(name+k,'pdo_epoch',k,e)
        domain=at('pdo_epoch','terminal_domain',e);work=at('pda_state','work',domain)
        cell=struct.unpack_from('<I',raw,at('pda_work','receipt',work))[0];need(cell<3,'actual PB completion cell for supplied controls')
        c=at('pda_state','completion',domain,cell,'pda_completion');d=at('pda_completion','direct_exit',c)
        for k in('complete','member','heads','head','exits','index','arm','row','original','direct'):add(name+'direct_'+k,'pda_direct_exit',k,d)
    c=at('pdo_wire','cancellation');name='cancel_'
    for i in range(13):tests.append((name+'header'+str(i),at('pbo_cancel','h',c)+8*i))
    for field in('before','returned','next'):
        f=at('pbo_cancel',field,c)
        for k in('greg','fp'):add(name+field+'_'+k,'li2_step_frame',k,at('le_frame','frame',f))
        add(name+field+'_UC','le_frame','uc',f)
    for field in('held','resumed'):
        stage=at('pbo_cancel',field,c)
        for t,k,parent in(('li2_pg_progress','phase','progress'),('li2_pg_progress','completion_permit','progress'),('li2_pg_source_progress','release_complete','source'),('li2_pg_source_progress','opened_pages','source'),('li2_pg_rseq_progress','entry_complete','rseq'),('li2_pg_rseq_progress','cancel_complete','rseq'),('li2_span_transfer_progress','consumed','transfer'),('li2_span_transfer_progress','resumed','transfer'),('li2_fetch_progress','held','fetch')):
            add(name+field+'_'+parent+'_'+k,t,k,at('pdo_stage',parent,stage))
        for k in('entry','domain_source','domain'):add(name+field+'_'+k,'pdo_stage',k,stage)
    for k in('version','status','reason','site','pc','detail'):add(name+'miss_'+k,'li2_pg_miss',k,at('pbo_cancel','miss',c))
    for k in('version','ready','heads','source_mask','source','table','scan_started','scan_complete','scanned','nonzero','first_nonzero','first_value'):add(name+'plan_'+k,'pbo_miss_plan',k,at('pbo_cancel','plan',c))
    for field in('closed_slot','resumed_slot'):
        slot=at('pbo_cancel',field,c)
        for k in('phase','origin','generation','event_id','decoded','fetch','owner'):add(name+field+'_'+k,'li2_tf_chain_slot',k,slot)
    for k in('final_counts','final_row','final_subentry','raw_ingress'):add(k,'pdo_wire',k)
    need(len(tests)==len({n for n,_ in tests})==CONTROL_COUNTS[0],'all literal distinct PB owner corruption controls')
    refused=[]
    for name,offset in tests:
        need(0<=offset<len(raw),'whole actual supplied mutation offset');mutant=bytearray(raw);mutant[offset]^=1
        try:read(codec.encode_for_control(bytes(mutant),schema_version=13),layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted supplied PB owner corruption '+name)
    return dict(original_sha256=hashlib.sha256(data).hexdigest(),refusals=refused,native_operations=0,mode=0)


PF_REFUSAL_CONTROL_COUNT=28

def pf_refusal_controls(data,layout,image,app,pid,cpu,exit_status):
    read(data,layout,image,app,pid,cpu,exit_status)
    raw,_=codec.decode(data,raw_bytes=5421440,schema_version=13)
    return pf_controls(data,raw,layout,(image,app,pid,cpu,exit_status),read,
        lambda b:codec.encode_for_control(b,schema_version=13),epochs=3,cancellation=True)

def pf_controls(data,raw,layout,args,reader,encode,*,epochs,cancellation):
    import copy
    types=layout['types'];tests=[]
    def at(t,k,base=0):return base+types[t]['fields'][k]['offset']
    for index in range(epochs):
        e=at('pdo_wire','epochs')+index*types['pdo_epoch']['bytes']
        tests.append(('epoch'+str(index)+'_prior',at('pdo_epoch','prior_counts',e)))
        for stage in ('entered','terminal'):
            tests.append(('epoch'+str(index)+'_'+stage,at('pdo_stage','counts',at('pdo_epoch',stage,e))))
    if cancellation:
        c=at('pdo_wire','cancellation')
        for stage in ('held','resumed'):
            tests.append(('cancel_'+stage,at('pdo_stage','counts',at('pbo_cancel',stage,c))))
    tests.append(('final',at('pdo_wire','final_counts')))
    refused=[]
    for name,base in tests:
        for key in PF_COUNTERS:
            changed=bytearray(raw);changed[at('pdo_counts',key,base)]^=1
            try:reader(encode(bytes(changed)),layout,*args)
            except ValueError:refused.append(name+'_'+key)
            else:raise ValueError('accepted literal protected PF count mutation '+name+'_'+key)
    for name in ('previous_last','refused_offset','cancelled_width','owner_extent'):
        changed=copy.deepcopy(layout);pf=changed['pf_refusals']
        if name=='previous_last':pf['previous_last']['bytes']+=8
        elif name=='refused_offset':pf['fields']['pf_backward_refused']['offset']+=8
        elif name=='cancelled_width':pf['fields']['pf_backward_cancelled']['bytes']=4
        else:changed['registrations']['pe']['bytes']+=64
        try:reader(data,changed,*args)
        except ValueError:refused.append('layout_'+name)
        else:raise ValueError('accepted changed actual PF field witness '+name)
    expected=28 if cancellation else 12
    need(len(refused)==len(set(refused))==expected,'all literal PF snapshot and field-witness controls')
    return dict(refusals=refused,original_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)
