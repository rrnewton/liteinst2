"""Full actual four-lifetime transition checks; no collector or acceptance stub."""
import importlib.util,struct
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
base=load('lifecycle_owner_base',HERE/'base.py')
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK,U64,GREG=base.PAGE,base.TF,base.RF,base.MASK,base.U64,base.GREG
history=base.history
class Check(base.Check):
    def epoch(self,b,index,baseline):
        t='pdo_epoch';st='pdo_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pdo_epoch_info';warm=index==2;count=2 if warm else 1
        need(index in(0,1,2,4),'four actual completed companion lifetimes')
        entry=self.offer(index);ci=2 if index==4 else 1 if index==1 else 0
        heads=4 if entry==self.roots[1]else 2 if index==4 else 5
        self.exit_member=int(warm and self.app['mode']==1)
        lo,hi=self.native_positions(index);native_before=self.native_frames[lo];native_after=self.native_frames[hi]
        exitpc=native_after['greg'][16];target=self.base+29 if index==4 else self.offer(index+1)
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
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=2 if warm else installed,
                 loop_entries_with12=int(warm or entry!=self.roots[1]),loop_actual_entries12=int(entry!=self.roots[1]))
        if warm:inc.update(hits=1,loop_hits12=int(entry!=self.roots[1]))
        else:inc.update(next_generation=1,publications=1,cold_attempts=1,retirements=installed,
                        loop_chooser_attempts=1,loop_chooser_selected=int(entry!=self.roots[1]),
                        loop_chooser_no_envelope=int(entry==self.roots[1]),loop_publications12=int(entry!=self.roots[1]))
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),completed=1,loop_completed_with12=int(warm or entry!=self.roots[1]))
        self.pf_partition(self.f(entered,st,'counts'));self.pf_partition(self.f(end,st,'counts'))
        ed=self.domain_checkpoint(self.f(entered,st,'domain'),baseline);zd=self.f(b,t,'terminal_domain');need(self.domain_checkpoint(self.f(end,st,'domain'),zd)==zd,'whole terminal domain checkpoint and literal state equality')
        self.domain_state(ed,serial);self.domain_state(zd,serial)
        self.r.change(prior_domain,ed,'pda_state',values=dict(dual_entries=self.i(prior_domain,'pda_state','dual_entries')+int(warm)),observed=('work','claimed'))
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots');active=(chosen,1-chosen)if warm else(chosen,)
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),set(range(3 if index==4 else 2 if index else 1)),ed,active)
        zrows,zselected=self.storage(zslots,self.counts(self.f(end,st,'counts')),set(range(3 if index==4 else 2 if index else 1)),zd)
        need(selected==zselected==chosen and self.f(eslots,'pdo_slots','previous_selection')==self.f(prior_slots,'pdo_slots','selection')and self.f(zslots,'pdo_slots','previous_selection')==self.f(eslots,'pdo_slots','previous_selection'),'actual previous and selected typed slot identities')
        if not warm:need(prior_rows[1-chosen]==erows[1-chosen]==zrows[1-chosen],'inactive retained slot unchanged through cold publication')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'pdo_slot','generation');eg=self.f(terminal,'pdo_slot','generation');buildserial=self.i(g,gt,'build_serial')
        payload=self.certificate(ci,actual,entry,buildserial,gen);key=self.f(payload,'pe_payload','source');ph=self.f(payload,'pe_payload','header')
        need(gen==(self.i(rg,gt,'generation')if warm else pc['next_generation']+1)and buildserial==(self.i(rg,gt,'build_serial')if warm else serial),'exact cold publication or retained primary generation')
        need(not warm or installed==1,'shared entry requires actual prior completed A')
        ew=self.f(ed,'pda_state','work');zw=self.f(zd,'pda_state','work');refs,members,cell=self.work(ew,erows,count,serial);zrefs,zmem,zcell=self.work(zw,zrows,count,serial,True)
        need(refs==zrefs and members==zmem and cell==zcell,'whole stable shared member set through closure')
        self.r.change(ew,zw,'pda_work',values=dict(exit_member=self.exit_member,completion=1),observed=('proof_exit','directory_closed'))
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
        exit_ref=refs[self.exit_member];exit_ci,exit_graph=self.graph_for(exit_ref)
        boundary=next(x for x in exit_graph['boundary_rows']if x['target']==target)
        need(self.page+exit_graph['offsets'][boundary['head']]==exitpc,'actual native branch equals complete member frontier')
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
        predecessor_pc=self.predecessor_pc(index);predecessor,_=self.predecessor(slot,predecessor_pc,ingress)
        self.eq(slot,'li2_tf_chain_slot',origin=2 if index==4 else 1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual consumed domain transfer')
        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref,distinct_peer=False);self.source(zs,serial,entry,key,ref,terminal=True,distinct_peer=False);need(self.f(es,'li2_pg_source_progress','source')==self.f(zs,'li2_pg_source_progress','source'),'one complete source anchor held through all internal transfers')
        self.domain_source(self.f(entered,st,'domain_source'),refs,serial,False,es);self.domain_source(self.f(end,st,'domain_source'),refs,serial,True,zs)
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state');a=self.pin(er,estate,serial,0 if warm else heads,refs);z=self.pin(zr,zstate,serial,0 if warm else heads,refs,terminal=True);need(z>a and estate==zstate,'actual observed-unregistered pin and complete state unchanged throughout shared lifetime')
        if warm:
            # Unregistered ordinary instruction checks return before footprint
            # mutation; warm reuse performs no new cold-head inspection. Keep
            # the complete actual cold-B state, not the predecessor JMP's PC.
            prior_state=self.f(self.f(self.epochs[1],t,'terminal'),st,'state')
            need(estate==zstate==prior_state,'whole warm rseq state inherits cold-B terminal inspection')
        if not warm:
            decoded=self.graph['last_rseq_decoded'];lastpc,lastnext=struct.unpack_from('<2Q',decoded)
            code=struct.unpack_from('<I',decoded,24)[0];length=struct.unpack_from('<I',decoded,48)[0]
            need(lastnext==lastpc+length,'whole independently rebuilt final NONE proof')
            self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1)
            self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastnext,
                    first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        self.progress(self.f(entered,st,'fetch'),seq,True);self.progress(self.f(end,st,'fetch'),seq,False);need(self.f(info,it,'final_fetch')==self.f(end,st,'fetch'),'whole actual released shared fetch')
        for k,actual_value in(('source',zs),('domain_source',self.f(end,st,'domain_source')),('rseq',zr),('fetch',self.f(end,st,'fetch'))):need(self.f(c,'pda_completion',k)==actual_value,'joint completion retains whole actual '+k)
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        self.live_rseq(lives[2],zstate,after);self.proof_query(self.f(info,it,'proof_exit'),self.proof,1)
        for k in('code_exit','recovered','recovery_scratch'):zero(self.f(info,it,k),'normal domain exit invents no unexpected recovery')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),False)
        need(bm==dict(data=native_before['data'],stack=native_before['stack'])and
             am==dict(data=native_after['data'],stack=native_after['stack']),
             'whole actual guest memory at independently observed native lifetime boundaries')
        expected=tuple(native_after['greg'][j]for j in GREG);expected_flags=native_after['actual_flags']
        need(tuple(after['greg'][j]for j in GREG)==expected and after['greg'][17]==expected_flags|RF,
             'all actual native terminal GPR and literal flags including undefined AF')
        need(tuple(before['greg'][j]for j in GREG)==tuple(native_before['greg'][j]for j in GREG)and
             flags==native_before['actual_flags'],'literal actual native entry state before each generated lifetime')
        # Directory pages are sealed exact bytes at entry and drain, including all padding.
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes']);need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole actual immutable directory throughout shared lifetime')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'all actual zero-link slot pages')
        initial_spill=self.f(b,t,'initial_spill');terminal_spill=self.f(b,t,'terminal_spill')
        for i,member in enumerate(members):
            init=initial_spill[i*PAGE:(i+1)*PAGE];final=terminal_spill[i*PAGE:(i+1)*PAGE];zero(init[32:],'all initial cells and spill tails zero');zero(final[32:],'all final cells and spill tails zero')
            slotindex=member[0];member_ci,member_graph=self.graph_for(refs[i])
            direct_pcs={self.page+member_graph['offsets'][h]for h in member_graph['direct_models']}
            last=next((j for j in range(hi,lo-1,-1)if self.native_frames[j]['greg'][16]in direct_pcs),None)
            need(last is not None,'every member has an actually reached source DIRECT boundary')
            regs=tuple(self.native_frames[last]['greg'][j]for j in GREG)
            need(final[:32]==struct.pack('<4Q',*(regs[j]for j in(0,1,2,3))),
                 'complete final member scratch equals last actual native DIRECT boundary')
            gend=self.f(zrows[slotindex],'pdo_slot','generation')
            lastcell=self.r.items(gend,gt,'cell','pg_dispatch_cell_transition')[2]
            need(self.i(lastcell,'pg_dispatch_cell_transition','before')==0,'actual final reset binds completed directory dispatch')
            if warm:
                old_epoch=self.epochs[member_ci]
                need(init==self.f(old_epoch,t,'terminal_spill')[:PAGE],'whole warm scratch equals prior owning certificate completion')
            else:zero(init,'actual cold publication initializes whole scratch')
        zero(initial_spill[count*PAGE:],'unused initial spill member');zero(terminal_spill[count*PAGE:],'unused terminal spill member')
        entries=[self.focal_entry(stage,self.f(payload,'pe_payload','plan'),key,entry,heads,serial,chosen,gen,buildserial)for stage in(entered,end)]
        need(entries[0]==entries[1],'whole focal entry immutable through drain')
        frontier=history.direct_history(self,c)
        direct=self.f(c,'pda_completion','direct_exit')
        self.eq(direct,'pda_direct_exit',complete=1,member=self.exit_member,heads=exit_graph['heads'],head=boundary['head'],
                exits=exit_graph['exits'],index=boundary['index'],arm=boundary['arm'],
                reserved=0,flags=after['greg'][17])
        certificate=self.certificates[exit_ci]
        cp=self.f(self.f(certificate,'pdo_certificate','payload'),'pe_payload','plan')
        need(self.f(direct,'pda_direct_exit','row')==self.r.items(cp,'li2_pg_compact','head','li2_pe_head')[boundary['head']]and
             self.f(direct,'pda_direct_exit','original')==self.r.items(cp,'li2_pg_compact','original','li2_span_decoded')[boundary['head']]and
             self.f(direct,'pda_direct_exit','direct')==self.f(cp,'li2_pg_compact','instruction')[144*boundary['head']:144*boundary['head']+120],
             'every cold and warm direct completion binds its whole independently reconstructed certificate')
        loops=[self.loop_state(self.f(b,t,'prior_loop'),prior,3*index),self.companion_loop(self.f(entered,st,'loop'),self.f(entered,st,'counts'),index,3*index+1,warm),self.companion_loop(self.f(end,st,'loop'),self.f(end,st,'counts'),index,3*index+2,warm)]
        self.effects_transition(loops,index,warm)
        self.loop_direct(loops,(prior_domain,ed,zd))
        need(frontier['member']==self.exit_member and frontier['pc']==exitpc and frontier['target']==target,
             'whole actual saved DIRECT completion names the original branch and selected outside target')
        mapping=[]
        return dict(index=index,native_before=lo,native_after=hi,target=target,loop_stages=loops,frontier_member=frontier['member'],frontier_arm=frontier['arm'],
                    frontier_pc=frontier['pc'],frontier_target=frontier['target'],actual_entry=dict(pc=entry,compiled_root=entry,head=0,slot=chosen,generation=gen,build_serial=buildserial,subentry=False),rseq_mapping=mapping,kind='mixed'if warm else'cold',mode=self.app['mode'],slot=chosen,generation=gen,build_serial=buildserial,prior_generation_installed=installed,begin=h[3],event=h[17],terminal_ordinal=h[11],ingress=ingress,before=before,returned=returned,logical=after,after=after,predecessor_before=predecessor,before_memory=bm,after_memory=am,completed=1,closed_pages=17*count,domain_members=count,anchor_released=1,permit=1,interior_signals=0,members=members,shared_lifetime=1,completion_id=nextid+1,claim_members=tuple(range(count)),joint_complete=1,slots_raw=zslots,counts_raw=self.f(end,st,'counts'),serial=serial,closed_slot=slot,dispatch_pc=exitpc,domain_raw=zd)
    def next_trace(self,b,last,epoch):
        t='pdo_next';slot=self.f(b,t,'closed');st='li2_tf_chain_slot'
        self.eq(b,t,expected_ordinal=last['terminal_ordinal']+1,raw_ordinal=last['terminal_ordinal']+1,capture_result=0,ingress_complete=1,closed_complete=1,tls_complete=1)
        index=self.i(b,t,'slot_index');event=self.i(b,t,'event_id');need(index in(0,1)and self.i(slot,st,'index')==index and event>self.i(slot,st,'event_id')>0,'actual next TRACE chain/index/event and closed predecessor')
        self.eq(slot,st,origin=1);frame=self.frame(self.f(b,t,'frame'));flags=(last['logical']['greg'][17]&~RF)|TF;self.trace(frame,last['target'],flags)
        self.preserved_context(last['logical'],frame)
        need(frame['greg'][22]==last['logical']['greg'][16] and(frame['fs'],frame['gs'])==tuple(self.app['machine'][1:3]),'actual next TRACE retains ordinary final Jcc CR2 and post-close TLS')
        before,ref=self.predecessor(slot,last['logical']['greg'][16],frame);owner=self.f(slot,st,'owner');step=self.f(owner,'li2_tf_owner','step');self.step_frame(self.f(step,'li2_step_owner','before'),last['logical'])
        need(before['greg']==last['logical']['greg']and before['fp']==last['logical']['fp'],'ordinary original Jcc begins at actual retained exit NX frame')
        fetch=self.f(self.f(epoch,'pdo_epoch','terminal'),'pdo_stage','fetch');need(self.i(ref,'li2_fetch_ref','sequence')>self.i(fetch,'li2_fetch_progress','sequence'),'ordinary Jcc borrows after actual retained source release')
        last['next_trace']=frame;last['next_trace_ordinal']=self.i(b,t,'raw_ordinal')
        need(q(self.f(self.b,'pdo_wire','next_target'))[last['index']]==last['target'],
             'separate actual DIRECT target and next-event slot agree')
