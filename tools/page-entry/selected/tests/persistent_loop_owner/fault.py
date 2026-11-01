"""Actual policy14 copied-read faults with held authority and full NX cleanup.

Expected terminal125 remains a failed subject outcome. It grants neither
completion nor released-source authority and cannot replace a success case.
"""
import importlib.util,struct
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
state=load('loop_fault_state',HERE/'state.py')
application=load('loop_fault_app',HERE.parent/'tunables_loop_paired_app/read.py')
old_fault=load('loop_fault_codec',HERE.parent/'persistent_fused_owner/fault_read.py')
need,zero,q,canonical=state.need,state.zero,state.q,state.canonical
PAGE,TF,RF,MASK,U64,GREG=state.PAGE,state.TF,state.RF,state.MASK,state.U64,state.GREG

class Check(state.Check):
    def entered_member(self,entry,serial):
        t='pdo_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362664,proof_verified=364544)
        need(q(self.f(g,gt,'member_generation'))==(2*gen,2*gen+1)and q(self.f(g,gt,'member_refs'))==(1,1),'exact typed internal member refs');zero(self.f(g,gt,'incoming'),'zero graph links have no incoming refs')
        self.query3(self.f(g,gt,'code_writable'),3);self.proof_query(self.f(g,gt,'proof_writable'),self.proof,3);self.query(self.f(g,gt,'spill_query'),self.spill,3);zero(self.f(g,gt,'slot_query'),'unused aggregate slot query')
        self.permission3(self.f(g,gt,'code_sealed'),1);self.proof_permission(self.f(g,gt,'proof_sealed'),self.proof,1);self.permission3(self.f(g,gt,'open'),5)
        zero(self.f(g,gt,'close'),'no premature member close');zero(self.f(g,gt,'cleanup'),'no failed member cleanup')
        ts=self.r.items(g,gt,'slots','pg_slot_transition');self.slots_transition(ts[0],False);self.slots_transition(ts[1],True);zero(ts[2],'no premature member slot reset')
        cs=self.r.items(g,gt,'cell','pg_dispatch_cell_transition')
        self.cell(cs[0],gen,build,0);self.cell(cs[1],gen,serial,0);zero(cs[2],'no premature dispatch-cell reset')
        banks=self.r.items(entry,t,'banks','ped_bank');selected=[i for i,b in enumerate(banks)if self.f(b,'ped_bank','layout')==self.f(g,gt,'layout')]
        need(len(selected)==1,'one actual entered bank');self.eq(banks[selected[0]],'ped_bank',virgin=0,prot=5)
    def failed_slots(self,entered,terminal):
        self.r.change(entered,terminal,'pdo_slots',observed=('slots',))
        erows=self.r.items(entered,'pdo_slots','slots','pdo_slot');zrows=self.r.items(terminal,'pdo_slots','slots','pdo_slot');pages=0
        for a,b in zip(erows,zrows,strict=True):
            g,z=(self.f(s,'pdo_slot','generation')for s in(a,b))
            if self.i(g,'li2_pg_generation','installed'):
                self.r.change(a,b,'pdo_slot',observed=('generation',))
                self.r.change(g,z,'li2_pg_generation',values=dict(ready_generation=0),observed=('cleanup',))
                saved=self.geometry;self.geometry=self.layout(self.f(g,'li2_pg_generation','layout'))
                self.permission3(self.f(z,'li2_pg_generation','cleanup'),1);self.geometry=saved;pages+=17
            else:need(a==b,'whole uninstalled slot unchanged on failed cleanup')
        need(pages in(17,34),'all and only actual installed code banks closed NX')
        return zrows,pages
    def failed_epoch(self,b,baseline):
        t='pdo_epoch';st='pdo_stage';gt='li2_pg_generation';pt='li2_pg_progress';it='pdo_epoch_info';warm=False;count=1;index=0
        entry=self.head;ci=0;heads=28;exitpc=self.base+(18 if self.app['mode']==5 else 56)
        h=q(self.f(b,t,'h'));need(h[:3]==(1,index,entry)and h[3]>0 and h[4:11]==(1,1,h[3],0,0,1,1)and h[11]==h[3]+1 and h[12:15]==(0,0,1)and h[24]in(0,1)and not any(h[25:]),'actual entry then one terminal fault/rejection signal, no hidden interior signal')
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
        self.delta(prior,self.f(entered,st,'counts'),**inc);self.delta(self.f(entered,st,'counts'),self.f(end,st,'counts'),unexpected=1)
        self.pf_partition(self.f(entered,st,'counts'));self.pf_partition(self.f(end,st,'counts'))
        ed=self.domain_checkpoint(self.f(entered,st,'domain'),baseline);zd=self.f(b,t,'terminal_domain');need(self.domain_checkpoint(self.f(end,st,'domain'),ed)==zd,'whole terminal domain checkpoint and literal state equality')
        self.domain_state(ed,serial);self.domain_state(zd,serial)
        self.r.change(prior_domain,ed,'pda_state',values=dict(dual_entries=self.i(prior_domain,'pda_state','dual_entries')+int(warm)),observed=('work','claimed'))
        eslots=self.f(entered,st,'slots');zslots=self.f(end,st,'slots');active=(chosen,1-chosen)if warm else(chosen,)
        erows,selected=self.storage(eslots,self.counts(self.f(entered,st,'counts')),set(range(2 if index else 1)),ed,active)

        zrows,closed_pages=self.failed_slots(eslots,zslots)
        need(selected==chosen and self.f(eslots,'pdo_slots','previous_selection')==self.f(prior_slots,'pdo_slots','selection'),'actual prior/selected cold identities')
        need(prior_rows[1-chosen]==erows[1-chosen],'inactive slot unchanged before entry')
        actual=erows[chosen];terminal=zrows[chosen];self.setup(actual);g=self.f(actual,'pdo_slot','generation');buildserial=self.i(g,gt,'build_serial')
        self.entered_member(actual,serial)
        payload=self.certificate(0,actual,entry,buildserial,gen);key=self.f(payload,'pe_payload','source')
        need(gen==pc['next_generation']+1 and buildserial==serial,'actual first cold generation')
        ew=self.f(ed,'pda_state','work');zw=self.f(zd,'pda_state','work');refs,members,cell=self.work(ew,erows,1,serial)
        self.r.change(ed,zd,'pda_state',observed=('work',))
        self.r.change(ew,zw,'pda_work',values=dict(aborting=1,recovery_member=0))
        # Claim consumption precedes choosing the first fully reusable completion cell.
        masks=list(struct.unpack('<3I',self.f(prior_domain,'pda_state','claimed')))
        for slot in active:
            if warm or(slot==chosen and installed):
                _,_,prior_cell,member=self.claim(prior_rows[slot],prior_domain);masks[prior_cell]|=1<<member
        need(struct.unpack('<3I',self.f(ed,'pda_state','claimed'))==tuple(masks),'exact member claim bits consumed before domain entry')
        cells=self.state_cells(ed);available=[i for i,c in enumerate(cells)if not any(c)or masks[i]==(1<<self.i(c,'pda_completion','count'))-1]
        need(available and cell==available[0],'first complete unclaimed cell is the only reused receipt')

        self.eq(p,pt,serial=serial,registration_epoch=0,publication=1,generation=gen,phase=9,first_error=0,source_count=2,opened_pages=17,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0,generated=self.generated,proof=self.proof,table=self.table,spill=self.spill)
        need(q(self.f(p,pt,'source'))==(self.page,self.page+PAGE)and self.layout(self.f(p,pt,'layout'))==self.geometry,'actual two-page source layout')
        self.r.change(p,ep,pt,values=dict(phase=15,first_error=3304,first_detail=self.signal))
        self.eq(entered,st,busy=1,active=1,failing=0,resuming=0,pending=1)
        self.eq(end,st,busy=1,active=1,failing=1,resuming=0,pending=1)
        need(0<self.i(entered,st,'route')<32 and self.f(entered,st,'route')==self.f(end,st,'route'),'actual unchanged generated route remains failed and pending')
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=0,exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=1,cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=self.graph['gpr_written'],flags_written=self.graph['flags_written'],ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
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

        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref)
        need(es==zs,'whole source lease remains genuinely held; no release invented')
        ds=self.f(entered,st,'domain_source');self.domain_source(ds,refs,serial,False,es)
        need(ds==self.f(end,st,'domain_source'),'whole shared source lease retained on fatal abort')
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state')
        a=self.pin(er,estate,serial,28,refs);z=self.pin(zr,zstate,serial,28,refs)
        need(z>a and estate==zstate,'actual gateway pin checks advance without rseq closure')
        self.r.change(er,zr,'li2_pg_rseq_progress',values=dict(raw_checks=z))
        decoded=self.graph['last_none_decoded'];lastpc,lastnext=struct.unpack_from('<2Q',decoded);code=struct.unpack_from('<I',decoded,24)[0];length=struct.unpack_from('<I',decoded,48)[0]
        need(lastnext==lastpc+length,'whole independently reconstructed last NONE proof')
        self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=code,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastnext,first=0,end=0,abi_version=1,policy=1,code=code,length=length)
        fetch=self.f(entered,st,'fetch');self.progress(fetch,seq,True)
        need(fetch==self.f(end,st,'fetch'),'whole actual fetch remains held on failed cleanup')
        zero(self.f(info,it,'final_fetch'),'no fictitious completed fetch release')
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        zero(lives[2],'no successful terminal live-rseq or closure')
        for k in('proof_exit','code_exit'):zero(self.f(info,it,k),'failed recovery has no successful exit query '+k)
        zero(self.f(info,it,'recovery_scratch'),'copied offset-zero recovery never writes a fabricated DIRECT/MOV recovery plan')
        head=self.graph['offsets'].index(exitpc-self.page);pc=self.geometry[head//64]+512*(head%64)
        expected=self.app['seed'][0];raw=after['greg'];flags=self.app['seed'][1]
        need(tuple(before['greg'][i]for i in GREG)==expected and before['greg'][17]==flags,
             'actual fault entry follows the genuine flag/GPR-preserving E9')
        need(tuple(raw[i]for i in GREG)==expected and raw[16]==pc and raw[17]==flags|RF and raw[18]==0x2b000000000033 and raw[21]==MASK,
             'all actual GPR and literal flags at copied read before-effect boundary')
        si=bytearray(128);struct.pack_into('<iii',si,0,11,0,2);struct.pack_into('<Q',si,16,application.GUARD)
        need(after['sig']==11 and after['si']==bytes(si)and raw[19:21]==(4,14)and raw[22]==application.GUARD,
             'actual copied read SIGSEGV/ACCERR/#PF error4 and literal CR2')
        rec=self.f(info,it,'recovered');self.eq(rec,'li2_pg_recovered',flags=raw[17],original_pc=exitpc,member=0,head=head,link=4294967295,kind=1,phase=0,complete=1)
        need(q(self.f(rec,'li2_pg_recovered','gpr'))==expected,'all recovered original registers before the faulting read')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),True)
        need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'every source-only failed store leaves whole data and stack unchanged')
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes'])
        need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole immutable directory retained on failure')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'whole zero-link slot pages')
        zero(self.f(b,t,'initial_spill'),'whole cold spill starts zero')
        zero(self.f(b,t,'terminal_spill'),'NOP and copied-read paths execute no guard, directory or spill write')
        entries=[self.focal_entry(stage,self.f(payload,'pe_payload','plan'),key,entry,28,serial,chosen,gen,buildserial)for stage in(entered,end)]
        need(entries[0]==entries[1],'whole entry retained through abort without revocation claim')
        loops=[self.loop_state(self.f(b,t,'prior_loop'),prior),self.loop_state(self.f(entered,st,'loop'),self.f(entered,st,'counts'),focal=True),self.loop_state(self.f(end,st,'loop'),self.f(end,st,'counts'),focal=True)]
        self.loop_direct(loops,(prior_domain,ed,zd))
        return dict(loop_stages=loops,predecessor_before=predecessor,mode=self.app['mode'],slot=chosen,generation=gen,build_serial=buildserial,serial=serial,ingress=ingress,before=before,returned=returned,after=after,recovered=dict(gpr=expected,pc=exitpc,flags=raw[17],phase=0),before_memory=bm,after_memory=am,closed_pages=closed_pages,prior_installed=installed,prior_counts_raw=prior,counts_raw=self.f(end,st,'counts'),progress_raw=ep,domain_raw=zd,terminal_slots=zslots,entry=self.f(end,st,'entry'),begin=h[3],terminal_ordinal=h[11],interior_signals=0)

    def finish(self,status):
        epoch,initial,raw=self.envelope(status)
        need(status==125 and self.app['mode']in(5,6),'actual copied-read fault125, never a positive completion')
        self.signal=11;h=self.h;t='pdo_wire'
        a=self.failed_epoch(epoch,initial)
        need(raw[0]==a['terminal_ordinal']==a['begin']+1,'no post-failure signal or hidden interior event')
        need(self.f(self.b,t,'final_counts')==a['counts_raw']and self.f(self.b,t,'final_progress')==a['progress_raw'],'final failed report retains exact terminal counters and progress')
        counts=self.counts(a['counts_raw']);prior=self.counts(a['prior_counts_raw']);domain=a['domain_raw']
        need(h[36]==self.i(domain,'pda_state','dual_entries')and h[37]==self.i(domain,'pda_state','next_id'),'actual prior joint completion identities unchanged')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,t,'final_row'));row=dict(zip(names,values,strict=True));row['misses']=list(counts['misses'])
        slots=self.r.items(a['terminal_slots'],'pdo_slots','slots','pdo_slot')
        expected=dict(version=1,status=125,failure_code=3304,detail_abs=self.signal,detail_negative=0,phase=15,serial=a['serial'],generation=a['generation'],build_serial=a['build_serial'],permit=0,opened_pages=17,closed_pages=0,anchor_released=0,registration_rechecked=0,guest_data_fault=int(self.signal==11),recovery_complete=1,first_error=3304,active=1,busy=1,selected_slot=a['slot'],domain_members=1,dual_entries=self.i(domain,'pda_state','dual_entries'),dual_completed=self.i(domain,'pda_state','dual_completed'))
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):expected[k]=counts[k]
        for i,s in enumerate(slots):
            expected['slot%d_generation'%i]=self.i(self.f(s,'pdo_slot','identity'),'li2_ptr_slot_ref','generation')
            expected['slot%d_permit'%i]=self.i(self.f(s,'pdo_slot','claim'),'li2_pgd_claim','valid')
            expected['slot%d_completed_serial'%i]=self.i(s,'pdo_slot','last_completed')
        need({k:row[k]for k in names}==expected,'whole exact failed125 terminal row; no completed negative relabel')
        subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split()
        sub=dict(zip(subnames,q(self.f(self.b,t,'final_subentry')),strict=True));entry=a['entry'];target=self.f(entry,'li2_pgs_entry','target')
        want=dict(version=1,status=125,failure_code=3304,selections=counts['subentry_selections'],hits=counts['subentry_hits'],entries=counts['subentry_entries'],completed=counts['subentry_completed'],serial=a['serial'],generation=a['generation'],root=self.head,pc=self.head,head=0,slot=a['slot'],bank=self.i(entry,'li2_pgs_entry','bank'),complete=1)
        need(sub==want,'whole actual failed-subentry row is an entry receipt, never completion authority')

        need(counts['entries']==counts['completed']+1 and counts['unexpected']==1 and
             counts['loop_entries_with12']==counts['loop_completed_with12']+1,
             'exact one entered but uncompleted failed activation in both actual partitions')
        final_loop=self.loop_state(self.f(self.b,t,'final_loop'),self.f(self.b,t,'final_counts'),focal=True)
        need(self.f(self.b,t,'final_loop')==self.f(self.f(epoch,'pdo_epoch','terminal'),'pdo_stage','loop'),
             'whole failed policy scratch and counters unchanged after terminal capture')
        self.loop_direct([final_loop],(initial,a['domain_raw']))
        loop=self.loop_terminal(final_loop,125,3304)
        return dict(mode=self.app['mode'],placement=self.app['placement'],plan_version=12,fallback_policy=11,
            status=125,code=3304,detail=11,source=self.app['source'],terminal=row,subentry_terminal=sub,
            pf_refusal_stages=self.pf_stages(1,False),pf_refusals=state.base.prior.pf_row(counts,125,3304),
            loop_terminal=loop,loop_stages=a['loop_stages']+[final_loop],attempt=a,
            cold_publications=1,generated_entries=1,generated_completed=0,completion_permits=0,
            anchor_released=0,cleanup_closed_pages=a['closed_pages'],interior_signals=0,
            actual_signal=11,native_fault_signal=11,recovery_phase=0,guest_effects=0,
            focal_only=True,cold_warm_validated=False,mixed_policy_validated=False,
            replacement_validated=False,held_cancellation_validated=False,
            qualification_credit=False,performance_credit=False)
