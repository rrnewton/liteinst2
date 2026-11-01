"""Actual cold policy12 focal completion; companion lifecycle is separate.

The inherited PF owner predicates remain strict. This profile changes only
source-bound geometry, the independently reconstructed policy and literal
one-lifetime populations; it never grants mixed/warm/replacement credit.
"""
import importlib.util,struct
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
state=load('loop_actual_state',HERE/'state.py')
application=load('loop_paired_application',HERE.parent/'tunables_loop_paired_app/read.py')
need,zero,q,canonical=state.need,state.zero,state.q,state.canonical
PAGE,TF,RF,MASK,U64,GREG=state.PAGE,state.TF,state.RF,state.MASK,state.U64,state.GREG
history=state.history

class Check(state.Check):
    def model_before_cut(self,pc):
        g,flags=self.app['seed'][:2];actual=self.app['predecessor'];back=[0]*6;cuts=[0]*2;unknown=0
        path=application.PATH[self.app['mode']]
        need(path[-2]in(12,86)and pc==self.base+path[-2],'literal terminal branch before external cut')
        for off in path[:-2]:
            need(actual==self.base+off,'whole independent finite path reaches each actual original instruction')
            g,flags,actual,undefined=application.advance(g,flags,actual,self.base,self.app['endpoint'],self.app['data'],back,cuts,self.head)
            if off in(0,4,8,18,63,71,75,83):unknown=0
            elif off in(32,59,79):unknown=(unknown&~0x8c5)|16
            elif off==48:unknown=(unknown&~0xc5)|0x810
            need(undefined==(16 if off in(32,59,79)else 0x810 if off==48 else 0),'exact original undefined flag effects')
        need(actual==pc and unknown==0,'terminal branch flags fully defined by actual original arithmetic')
        return g,flags
    def epoch(self,b,baseline):
        t='pdo_epoch';st='pdo_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pdo_epoch_info';warm=False;count=1;index=0
        entry=self.head;ci=0;heads=28;exitpc=self.base+(12 if self.app['mode']==1 else 86)
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
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=installed,loop_chooser_attempts=1,loop_chooser_selected=1,loop_publications12=1,loop_entries_with12=1,loop_actual_entries12=1)
        if warm:inc.update(hits=1)
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed)
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1,loop_completed_with12=1)
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
        boundary=next(x for x in self.graph['boundary_rows']if x['target']==self.h[39])
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=1,exit_index=boundary['index'],recovery_started=1,recovery_complete=1,guest_data_fault=0,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=self.graph['gpr_written'],flags_written=self.graph['flags_written'],ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
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
        predecessor_pc=self.app['predecessor'];predecessor,_=self.predecessor(slot,predecessor_pc,ingress);self.eq(slot,'li2_tf_chain_slot',origin=1)
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
        decoded=self.graph['last_none_decoded'];lastpc,lastnext=struct.unpack_from('<2Q',decoded);code=struct.unpack_from('<I',decoded,24)[0];length=struct.unpack_from('<I',decoded,48)[0]
        need(lastnext==lastpc+length,'whole independently rebuilt final NONE proof')
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1);self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+length,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released shared fetch')
        for k,actual_value in(('source',zs),('domain_source',self.f(end,st,'domain_source')),('rseq',zr),('fetch',self.f(end,st,'fetch'))):need(self.f(c,'pda_completion',k)==actual_value,'joint completion retains whole actual '+k)
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal domain exit invents no unexpected recovery')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False)
        need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'whole readonly focal data and stack remain exact')
        expected,expected_flags=self.model_before_cut(exitpc)
        need(tuple(after['greg'][i]for i in GREG)==expected and after['greg'][17]==expected_flags|RF,'all actual focal GPR and literal fully-defined exit flags')
        need(tuple(before['greg'][i]for i in GREG)==self.app['seed'][0]and flags==self.app['seed'][1],'actual entry follows the genuine flag/GPR-preserving E9')
        # Directory pages are sealed exact bytes at entry and drain, including all padding.
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes']);need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole actual immutable directory throughout shared lifetime')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'all actual zero-link slot pages')
        initial_spill=self.f(b,t,'initial_spill');terminal_spill=self.f(b,t,'terminal_spill')
        for i,member in enumerate(members):
            init=initial_spill[i*PAGE:(i+1)*PAGE];final=terminal_spill[i*PAGE:(i+1)*PAGE];zero(init[32:],'all initial cells and spill tails zero');zero(final[32:],'all final cells and spill tails zero')
            slotindex=member[0];is_a=self.i(refs[i],'li2_pgd_ref','root')==self.head
            regs=expected
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
        self.eq(direct,'pda_direct_exit',complete=1,member=0,heads=heads,head=boundary['head'],
                exits=2,index=boundary['index'],arm=boundary['arm'],
                reserved=0,flags=after['greg'][17])
        certificate=self.certificates[int(index==1)]
        cp=self.f(self.f(certificate,'pdo_certificate','payload'),'pe_payload','plan')
        need(self.f(direct,'pda_direct_exit','row')==self.r.items(cp,'li2_pg_compact','head','li2_pe_head')[boundary['head']]and
             self.f(direct,'pda_direct_exit','original')==self.r.items(cp,'li2_pg_compact','original','li2_span_decoded')[boundary['head']]and
             self.f(direct,'pda_direct_exit','direct')==self.f(cp,'li2_pg_compact','instruction')[144*boundary['head']:144*boundary['head']+120],
             'every cold and warm direct completion binds its whole independently reconstructed certificate')
        loops=[self.loop_state(self.f(b,t,'prior_loop'),prior),self.loop_state(self.f(entered,st,'loop'),self.f(entered,st,'counts'),focal=True),self.loop_state(self.f(end,st,'loop'),self.f(end,st,'counts'),focal=True)]
        self.loop_direct(loops,(prior_domain,ed,zd))
        mapping=[]
        return dict(loop_stages=loops,frontier_member=frontier['member'],frontier_arm=frontier['arm'],
                    frontier_pc=frontier['pc'],frontier_target=frontier['target'],actual_entry=dict(pc=entry,compiled_root=entry,head=0,slot=chosen,generation=gen,build_serial=buildserial,subentry=False),rseq_mapping=mapping,kind='cold',mode=self.app['mode'],slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17*count,domain_members=count,anchor_released=1,permit=1,interior_signals=0,members=members,shared_lifetime=1,completion_id=nextid+1,claim_members=tuple(range(count)),joint_complete=1,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot,dispatch_pc=exitpc,domain_raw=zd)
    def next_trace(self,b,last,epoch):
        t='pdo_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id');need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));flags=(last['logical']['greg'][17]&~RF)|TF;self.trace(frame,self.h[39],flags)
        self.preserved_context(last['logical'],frame)
        need(frame['greg'][22]==last['logical']['greg'][16] and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains ordinary final Jcc CR2 and post-close TLS')
        before,ref=self.predecessor(slot,last['logical']['greg'][16],frame);owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original Jcc begins at actual retained exit NX frame')
        fetch=self.f(self.f(epoch,'pdo_epoch','terminal'),'pdo_stage','fetch');need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary Jcc borrows after actual retained source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')

    def finish(self,status):
        epoch,initial,raw=self.envelope(status)
        need(status==0 and self.app['mode']<5,'only complete actual positive focal subjects')
        a=self.epoch(epoch,initial);self.next_trace(self.f(self.b,'pdo_wire','next'),a,epoch)
        need(raw[0]>=a['next_trace_ordinal']==a['terminal_ordinal']+1==a['begin']+2,
             'exact actual entry, final branch NX and original branch TRACE with zero interior signals')
        final=self.pf_partition(self.f(self.b,'pdo_wire','final_counts'));last=self.counts(a['counts_raw'])
        need(all(final[k]>=last[k]for k in final if k!='misses')and all(x>=y for x,y in zip(final['misses'],last['misses'],strict=True)),
             'actual final counters retain every focal observation without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,'pdo_wire','final_row'));need(len(values)==len(names),'whole exact retained terminal schema');row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(1,0,0,0,0),'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,'pdo_wire','final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+final['subentry_hits']and final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])+final['pf_backward_cancelled']==final['cancelled']and final['pf_backward_refused']==final['pf_backward_cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and final['permit_claims']==final['retirements']+final['hits']+final['subentry_hits']+row['dual_entries'],'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==self.h[36]and 0<=row['dual_entries']<=final['hits']+final['subentry_hits']and row['domain_members']in((1,2)if row['phase']==13 else(0,))and self.h[37]==final['completed'],'exact actual joint completion/member accounting')
        subvalues=q(self.f(self.b,'pdo_wire','final_subentry'));subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split();sub=dict(zip(subnames,subvalues,strict=True))
        need(subvalues[:7]==(1,0,0,final['subentry_selections'],final['subentry_hits'],final['subentry_entries'],final['subentry_completed']),'whole protected subentry counter row')
        need(final['subentry_selections']>=final['subentry_hits']==final['subentry_entries']==final['subentry_completed'],'completed global subentry events form their own exact bucket')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),'actual final completed entry names final selected generation')
        else:need(not any(subvalues[7:]),'last cancelled attempt has no invented entry receipt')

        final_loop=self.loop_state(self.f(self.b,'pdo_wire','final_loop'),self.f(self.b,'pdo_wire','final_counts'))
        self.loop_direct([final_loop],(initial,a['domain_raw']))
        loop=self.loop_terminal(final_loop,0,0)
        return dict(mode=self.app['mode'],placement=self.app['placement'],plan_version=12,fallback_policy=11,
            status=0,code=0,detail=0,source=self.app['source'],terminal=row,subentry_terminal=sub,
            pf_refusal_stages=self.pf_stages(1,False),pf_refusals=state.base.prior.pf_row(final,0,0),
            loop_terminal=loop,loop_stages=a['loop_stages']+[final_loop],attempt=a,
            cold_publications=1,generated_entries=1,generated_completed=1,completion_permits=1,
            anchor_released=1,interior_signals=0,original_branch_replays=1,
            lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,
            focal_only=True,cold_warm_validated=False,mixed_policy_validated=False,
            replacement_validated=False,held_cancellation_validated=False,
            qualification_credit=False,performance_credit=False)
