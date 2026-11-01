"""Exact cancellation successor for descriptive reconstruction observations.

Every actual event counter remains equal across the preceding source replay.
The inherited delta also requires unchanged misses and only permits the already
explicit monotone read-only historical-reconstruction counter. The frozen
schema15 draft is retained whole in cancellation.py.
"""
import importlib.util,struct
from pathlib import Path
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
prior=load('lifecycle_cancel_frozen',HERE/'cancellation.py')
epochs=prior.epochs
need,zero,q,canonical=prior.need,prior.zero,prior.q,prior.canonical
PAGE,TF,RF,MASK,U64,GREG=prior.PAGE,prior.TF,prior.RF,prior.MASK,prior.U64,prior.GREG
plan=prior.plan
class Check(prior.Check):
    def cancellation(self,b,last):
        t='pbo_cancel';st='pdo_stage';pt='li2_pg_progress';ct='pbo_miss_plan';rt='li2_pg_rseq_progress'
        self.pf_partition(self.f(self.f(b,t,'held'),st,'counts'),1)
        self.pf_partition(self.f(self.f(b,t,'resumed'),st,'counts'))
        h=q(self.f(b,t,'h'));pc=self.base+19
        need(h[0]==h[4]==h[5]==h[9]==h[10]==1 and h[1]==h[6]==last['next_trace_ordinal'] and h[11]==h[1]+1 and h[7]==1 and h[3]in(0,1)and h[8]==1-h[3]and h[12:]==(0,0,0,0),'one actual held miss, RUNNING cancellation and immediate next hardware event')
        before=self.frame(self.f(b,t,'before'));returned=self.frame(self.f(b,t,'returned'));nxt=self.normalized(self.f(b,t,'next'),before)
        ingress=last['next_trace'];flags=ingress['greg'][17]&~TF
        self.trace(before,pc,flags);self.same_event(ingress,before,flags)
        self.trace(returned,pc,flags|TF);self.same_event(before,returned,flags|TF)
        self.trace(nxt,pc+4,flags|TF)
        self.preserved_context(returned,nxt)
        wanted=list(returned['greg']);wanted[16]=pc+4
        need(nxt['greg']==tuple(wanted)and nxt['fp']==returned['fp']and nxt['fp_bytes']==returned['fp_bytes']and nxt['mask']==returned['mask']and(nxt['fs'],nxt['gs'])==(before['fs'],before['gs']),'real ordinary store executes once with complete GPR/FP/mask/TLS unchanged')
        need(before['greg'][22]==returned['greg'][22]==nxt['greg'][22]==self.base+17,'cancellation retains real final-branch CR2')
        held=self.f(b,t,'held');resumed=self.f(b,t,'resumed');serial=h[2]
        self.eq(held,st,busy=1,active=0,failing=0,resuming=0,route=0,pending=0)
        self.eq(resumed,st,busy=1,active=0,failing=0,resuming=1,route=2,pending=1)
        hp=self.f(held,st,'progress');zp=self.f(resumed,st,'progress')
        self.eq(hp,pt,serial=serial,registration_epoch=0,publication=0,generation=0,phase=4,first_error=0,source_count=2,opened_pages=0,closed_pages=0,anchor_released=0,registration_rechecked=0,completion_permit=0,first_detail=0)
        self.eq(zp,pt,phase=14,anchor_released=1,registration_rechecked=1)
        self.r.change(hp,zp,pt,observed=('phase','anchor_released','registration_rechecked'))
        need(serial==last['serial']+1 and self.i(hp,pt,'transfer_serial')>0 and q(self.f(hp,pt,'source'))==(self.page,self.page+PAGE),'actual next owner serial and B source pair')
        self.delta(last['counts_raw'],self.f(held,st,'counts'),next_serial=1,offers=1,cold_attempts=1,miss_reason=1,loop_chooser_attempts=1,loop_chooser_no_envelope=1)
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
        self.source(hs,serial,pc,key,ref,cancel=True,distinct_peer=False);self.source(zs,serial,pc,key,ref,terminal=True,cancel=True,distinct_peer=False)
        need(source==self.f(zs,'li2_pg_source_progress','source'),'whole held/released candidate source identity')
        oldslot=self.f(b,t,'closed_slot');newslot=self.f(b,t,'resumed_slot')
        need(oldslot==self.f(self.r.items(self.b,'pdo_wire','next','pdo_next')[2],'pdo_next','closed')and self.i(oldslot,'li2_tf_chain_slot','index')==h[3],'same real just-closed branch predecessor')
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
        # Actual 66 89 4f 08 is the independent source-bound m16 write.
        # It remains UNSUPPORTED in both v1/v2 scalar/guarded-store domains.
        miss=self.f(b,t,'miss');self.eq(miss,'li2_pg_miss',version=11,status=1,reason=1,site=1,pc=pc,detail=1)
        p=self.f(b,t,'plan');ft='li2_pg_plan';full=bytearray(self.r.types[ft]['bytes'])
        for k in('version','bytes','ready','result','heads','exits','stores','source_bytes','source_mask','decoder_result','guard_result','reserved','member_heads','links','reserved2','page','entry','layout','source','table'):
            f=self.r.types[ft]['fields'][k];value=self.f(p,ct,k);need(len(value)==f['bytes'],'whole unready PB field extent');full[f['offset']:f['offset']+f['bytes']]=value
        fields=self.r.types[ft]['fields'];omitted=len(full)-fields['image']['offset']-fields['table']['bytes']
        self.eq(p,ct,scan_started=1,scan_complete=1,scanned=omitted,nonzero=0,first_nonzero=0,first_value=0)
        full=bytes(full);self.r.walk(full,ft)
        self.eq(full,ft,version=11,bytes=981320,ready=0,result=1,heads=0,exits=0,stores=0,source_bytes=0,source_mask=1,decoder_result=0,guard_result=0,reserved=0,links=0,reserved2=0,entry=pc)
        need(q(self.f(full,ft,'page'))==(self.page,self.page+PAGE)and self.f(full,ft,'layout')==self.f(hp,pt,'layout')and self.f(full,ft,'source')==self.app['source'][:8192],'whole unready PB plan prefix and both source pages')
        need(self.f(full,ft,'table')==plan.table(self.ranges+[(self.page+i*PAGE,self.page+(i+1)*PAGE)for i in range(2)],self.table),'whole cancelled-plan exclusion table')
        for k in('member_heads','image','stub_image','head','original','frontier','instruction','exit_pc','edge','guard'):zero(self.f(full,ft,k),'unready PB miss has no invented authority')
        # The fifth source offer is not a fabricated successful epoch. The held
        # fourth offer preserves its complete real preclose evidence and zero
        # future entry/exit storage.
        epoch=self.epochs[3];et='pdo_epoch';eh=q(self.f(epoch,et,'h'))
        need(eh[:5]==(1,3,pc,h[1],1)and not any(eh[5:15])and
             eh[15]==h[3]and eh[16]==self.symbol('selected_session')and
             eh[17]==self.i(tr,tt,'event')and 0<eh[17]and eh[18]<U64 and
             eh[19:24]==(h[3],1,0,0,1)and eh[24]==selected and not any(eh[25:]),
             'actual selected fourth offer stops after preclose without entry or completion')
        self.delta(last['counts_raw'],self.f(epoch,et,'prior_counts'))
        need(self.f(epoch,et,'prior')==last['slots_raw']and
             self.domain_checkpoint(self.f(epoch,et,'prior_domain'),last['domain_raw'])==last['domain_raw'],
             'whole actual preceding completion at the cancelled offer')
        need(self.f(epoch,et,'initial_registry')==self.f(b,t,'initial_registry'),
             'whole actual held-offer registry')
        for k in('terminal_registry','returned','after','entered','terminal','info','before_memory','after_memory',
                 'initial_slots','terminal_slots','initial_spill','terminal_spill',
                 'initial_directory','terminal_directory','terminal_domain'):
            zero(self.f(epoch,et,k),'cancelled offer has no invented '+k)
        observed_ingress=self.normalized(self.f(epoch,et,'ingress'),before)
        observed_before=self.normalized(self.f(epoch,et,'before'),before)
        self.same_event(ingress,observed_ingress,ingress['greg'][17])
        self.same_event(before,observed_before,flags)
        projection=self.f(epoch,et,'predecessor')
        self.eq(projection,'pdo_predecessor',complete=1,
                unexpected_compared=self.r.types['li2_step_frame']['bytes'],unexpected_nonzero=0)
        need(self.f(projection,'pdo_predecessor','closed')==
             oldslot[:self.r.types['li2_tf_chain_slot']['fields']['unexpected']['offset']],
             'whole held-offer closed predecessor equals the immediately captured original branch')
        prefix=self.f(projection,'pdo_predecessor','before_prefix');wanted=bytearray(prefix)
        sf=self.r.types['li2_tf_chain_slot']['fields'];of=self.r.types['li2_tf_owner']['fields'];tf=self.r.types['li2_step_owner']['fields']
        struct.pack_into('<I',wanted,sf['phase']['offset'],5)
        at=sf['owner']['offset']+of['step']['offset']
        for k,v in(('phase',5),('trace_seen',1),('revoke_sync_started',1)):
            struct.pack_into('<I',wanted,at+tf[k]['offset'],v)
        need(bytes(wanted)==oldslot[:len(prefix)],'whole actual fourth-offer predecessor close transition')
        # Source/chooser authority is independently reconstructed even for the
        # refused candidate. There is no plan ready-bit or completion credit.
        loops=[self.loop_state(self.f(epoch,et,'prior_loop'),self.f(epoch,et,'prior_counts')),
               self.companion_loop(self.f(held,st,'loop'),self.f(held,st,'counts'),3),
               self.companion_loop(self.f(resumed,st,'loop'),self.f(resumed,st,'counts'),3)]
        self.loop_direct(loops,(last['domain_raw'],domain,domain))
        need(loops[1]['witnesses']['choice']['result']==loops[2]['witnesses']['choice']['result']==1,
             'complete genuine NO_ENVELOPE before exact PF unsupported-root refusal')
        n=(42,34)[self.app['mode']]
        nf,na=self.native_frames[n],self.native_frames[n+1]
        need(tuple(before['greg'][j]for j in GREG)==tuple(nf['greg'][j]for j in GREG)and
             flags==nf['actual_flags']and
             tuple(nxt['greg'][j]for j in GREG)==tuple(na['greg'][j]for j in GREG)and
             (nxt['greg'][17]&~TF)==na['actual_flags'],
             'full actual native state before and after the one ordinary m16 replay')
        expected=bytearray(nf['data']);struct.pack_into('<H',expected,8,nf['greg'][14]&65535)
        need(na['data']==bytes(expected)and na['stack']==nf['stack'],
             'actual native one-write memory transition, not a fabricated owner snapshot')
        return dict(serial=serial,ordinal=h[1],next_ordinal=h[11],ingress=ingress,
                    before=before,returned=returned,next=nxt,reason=1,detail=1,
                    source_released=1,generated_entries=0,publications=0,completion_permits=0,
                    ordinary_store_executed=1,native_before=n,native_after=n+1,
                    counts_raw=self.f(resumed,st,'counts'),domain_raw=domain,
                    slots_raw=self.f(resumed,st,'slots'),closed_slot=oldslot,resumed_slot=newslot,
                    loop_stages=loops)
