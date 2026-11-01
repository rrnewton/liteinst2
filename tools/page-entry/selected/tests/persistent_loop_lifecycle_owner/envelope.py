"""Complete schema15 chronology; only actual closed records can reach finish.

The five offers are four completed lifetimes and one refused before-effect
offer. Global counters remain separate from this bounded source history. The
descriptive reconstruction counter is never used to infer an event.
"""
import importlib.util,struct
from pathlib import Path
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
cancellation=load('lifecycle_cancel_reader',HERE/'cancellation_v2.py')
base=cancellation.epochs.base
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK,U64=base.PAGE,base.TF,base.RF,base.MASK,base.U64

class Check(cancellation.Check):
    def envelope(self,status):
        h=self.h;t='pdo_wire';r=self.r;mode=self.app['mode']
        need(type(status)is int and status==0 and self.app['lane']==1 and
             type(mode)is int and mode in(0,1)and self.app['placement']in(0,1),
             'actual completed companion process, explicit orientation and placement')
        need(h[:9]==(0x314f434c5049324c,15,r.types[t]['bytes'],4248704,362664,364544,69632,968,128),
             'distinct schema15 and independently declared whole captured extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and
             h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],
             'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and
             h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,mode),
             'actual altstack, empty write-only FD3 and explicit orientation')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdo_wire','pg_source','pg_rseq','selected_chain','span_progress')),
             'all actual protected lifecycle addresses')
        storage=r.layout['retained_storage'];prefix=storage['retained']['offset'];size=r.types['li2_ptr_slot']['bytes']
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and
             h[31:35]==(self.roots[0],self.roots[1],self.symbol('pe')+storage['domain']['offset'],self.symbol('pg_domain_source')),
             'actual two retained slots and whole source-bound companion roots')
        need(h[35]==5 and h[36]>=1 and h[37]>=4 and h[38]==0 and h[39]==self.base+29 and
             canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(225880,71384,11312,12288,3,0)and
             h[47:53]==(1,0,0,0,h[16],0)and h[53:57]==(self.symbol('pdo_encoded'),4<<20,1,1)and not any(h[57:]),
             'five actual offers, completed source history and unchanged bounded transport')
        selection=self.f(self.b,t,'selection');st='plc_selection'
        self.eq(selection,st,version=1,protocol=1,case_id=mode,placement=self.app['placement'],lane=1,
                entry=self.app['entry'],predecessor=self.app['predecessor'],cancel=self.base+19,
                stub=self.base+29,high=self.app['endpoint'],expected_offers=5,expected_completed=4)
        need(q(self.f(selection,st,'source_page'))==(self.page,self.page+PAGE)and
             q(self.f(selection,st,'root'))==self.roots and
             q(self.f(selection,st,'source_checked'))==(4,4,2)and
             q(self.f(selection,st,'source_compared'))==(32768,32768,16384)and
             q(self.f(selection,st,'predecessor_checked'))==(1,1,1,1,1),
             'all actual entry/drain source scans and five genuine closed predecessors')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for key in('sink_initial','sink_terminal'):
            value=self.f(self.b,t,key);fact=self.stat(value)
            need(fact['mode']&0xffff==0x8180 and fact['size']==0,'actual empty regular0600 capture sink')
            self.eq(value,'stat',st_nlink=1,st_uid=self.image['uid'])
        r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        need(r.transport['status']==r.transport['code']==0,'actual successful encoded-body terminal outcome')
        hardware=self.f(self.b,t,'hardware');self.eq(hardware,'li2_selected_hardware',abi_version=1,reserved=0)
        for i,k in enumerate(('leaf0','leaf1','leaf7')):
            need(struct.unpack('<4I',self.f(hardware,'li2_selected_hardware',k))==tuple(self.app['hardware'][i][2:]),
                 'whole actual application and owner CPUID equality')
        for key,obj in(('main',self.image['main_object']),('interpreter',self.image['interpreter_object'])):
            self.image_header(self.f(self.b,t,key),obj)
        session=self.f(self.b,t,'session')
        self.eq(session,'li2_step_session',pid=self.pid,tid=self.pid,sync_register=0,application_mask=MASK,initialized=1,self_test_complete=1)
        need(self.i(session,'li2_step_session','sync_query')&96==96,'actual registered membarrier support')
        self.epochs=r.items(self.b,t,'epochs','pdo_epoch');need(len(self.epochs)==5,'five literal actual offer records')
        nexts=r.items(self.b,t,'next','pdo_next');need(len(nexts)==5,'five independently declared next-event cells')
        zero(nexts[3],'cancelled offer has no generated completion or final-branch replay cell')
        targets=q(self.f(self.b,t,'next_target'))
        need(targets==(self.offer(1),self.offer(2),self.offer(3),0,self.base+29),
             'all actual DIRECT targets and explicitly absent cancelled target')
        initial_slots=r.items(self.f(self.epochs[0],'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.h_alloc=self.i(r.items(initial_slots[1],'pdo_slot','banks','ped_bank')[1],'ped_bank','generated')
        self.h_proof_alloc=self.i(initial_slots[1],'pdo_slot','proof')
        return self.f(self.b,t,'initial_domain'),raw,nexts

    def previous(self,index,last):
        prior=self.f(self.epochs[index],'pdo_epoch','prior_counts')
        self.delta(last['counts_raw'],prior)
        need(self.f(self.epochs[index],'pdo_epoch','prior')==last['slots_raw'],
             'whole retained identities and permissions unchanged between actual offers')

    def stages(self):
        rows=[]
        def take(name,b):
            c=self.counts(b);rows.append(dict(stage=name,refused=c['pf_backward_refused'],cancelled=c['pf_backward_cancelled']))
        for index,e in enumerate(self.epochs):
            take('epoch'+str(index)+'_prior',self.f(e,'pdo_epoch','prior_counts'))
            if index!=3:
                for name in('entered','terminal'):
                    take('epoch'+str(index)+'_'+name,self.f(self.f(e,'pdo_epoch',name),'pdo_stage','counts'))
            else:
                c=self.f(self.b,'pdo_wire','cancellation')
                for name in('held','resumed'):take('cancel_'+name,self.f(self.f(c,'pbo_cancel',name),'pdo_stage','counts'))
        take('final',self.f(self.b,'pdo_wire','final_counts'))
        need(len(rows)==16 and len({r['stage']for r in rows})==16,'all16 actual lifecycle PF refusal snapshots')
        return rows

    def finish(self,status):
        initial,raw,nexts=self.envelope(status)
        a=self.epoch(self.epochs[0],0,initial);self.next_trace(nexts[0],a,self.epochs[0])
        self.previous(1,a);b=self.epoch(self.epochs[1],1,a['domain_raw']);self.next_trace(nexts[1],b,self.epochs[1])
        self.previous(2,b);warm=self.epoch(self.epochs[2],2,b['domain_raw']);self.next_trace(nexts[2],warm,self.epochs[2])
        for earlier,later in((a,b),(b,warm)):
            need(later['begin']==earlier['next_trace_ordinal']==earlier['terminal_ordinal']+1,
                 'next genuine offer is the immediate original branch TRACE')
            self.same_event(earlier['next_trace'],later['ingress'],later['ingress']['greg'][17])
        need(a['slot']!=b['slot']and b['generation']==a['generation']+1 and
             (warm['slot'],warm['generation'],warm['build_serial'])==(a['slot'],a['generation'],a['build_serial'])and
             warm['members']==[a['members'][0],b['members'][0]]and warm['domain_members']==2,
             'actual two cold generations and exact mixed-policy warm directory membership')
        cancel=self.cancellation(self.f(self.b,'pdo_wire','cancellation'),warm)
        self.previous(4,cancel);last=self.epoch(self.epochs[4],4,cancel['domain_raw']);self.next_trace(nexts[4],last,self.epochs[4])
        need(last['begin']==cancel['next_ordinal']==cancel['ordinal']+1,
             'one ordinary store TRACE is the actual replacement offer')
        self.same_event(cancel['next'],last['ingress'],last['ingress']['greg'][17])
        need(raw[0]>=last['next_trace_ordinal']and all(x['terminal_ordinal']==x['begin']+1 for x in(a,b,warm,last)),
             'complete actual zero-interior chronology with one drain event per generated lifetime')
        need(last['generation']==b['generation']+1 and last['prior_generation_installed']==1 and
             last['slot']in(a['slot'],b['slot'])and last['slot']==min(a['slot'],b['slot'])and
             last['members'][0][1]==last['generation'],
             'actual oldest-completed tie replacement consumes one old generation and installs the next')
        victim=next(x for x in(a,b)if x['slot']==last['slot'])
        need(last['generation']!=victim['generation']and last['build_serial']>warm['serial']and
             last['completion_id']==warm['completion_id']+1,
             'replacement creates a new generation/build and one genuine completion after cancellation')
        # The cancellation has no owner memory snapshot. Its one real write
        # is joined through the two adjacent actual generated boundaries.
        nf=self.native_frames[cancel['native_before']];na=self.native_frames[cancel['native_after']]
        need(warm['after_memory']==dict(data=nf['data'],stack=nf['stack'])and
             last['before_memory']==dict(data=na['data'],stack=na['stack']),
             'whole actual memory before cancellation and after exactly one ordinary replay')
        final=self.pf_partition(self.f(self.b,'pdo_wire','final_counts'));tail=self.counts(last['counts_raw'])
        need(all(final[k]>=tail[k]for k in final if k!='misses')and
             all(x>=y for x,y in zip(final['misses'],tail['misses'],strict=True)),
             'actual final counters retain every companion observation without attributing later work')
        names='version status failure_code detail_abs detail_negative phase serial generation build_serial offers cold_attempts publications hits cancelled retirements permit_claims entries completed unexpected permit opened_pages closed_pages anchor_released registration_rechecked guest_data_fault recovery_complete first_error active busy selected_slot slot0_generation slot1_generation slot0_permit slot1_permit slot0_completed_serial slot1_completed_serial domain_members dual_entries dual_completed'.split()
        values=q(self.f(self.b,'pdo_wire','final_row'));need(len(values)==len(names),'whole exact retained terminal schema')
        row=dict(zip(names,values,strict=True));row['misses']=list(final['misses'])
        need((row['version'],row['status'],row['failure_code'],row['detail_abs'],row['detail_negative'])==(1,0,0,0,0),
             'actual protected retained terminal outcome')
        for k in('offers','cold_attempts','publications','hits','cancelled','retirements','permit_claims','entries','completed','unexpected'):
            need(row[k]==final[k],'whole final counter-to-report join '+k)
        p=self.f(self.b,'pdo_wire','final_progress');pt='li2_pg_progress'
        for k in('phase','serial','opened_pages','closed_pages','anchor_released','registration_rechecked','first_error'):
            need(row[k]==self.i(p,pt,k),'actual retained progress-to-report join '+k)
        need(row['selected_slot']in(0,1)and 0<row['build_serial']<=row['serial'],'actual final selected slot/build serial')
        gs=(row['slot0_generation'],row['slot1_generation']);ps=(row['slot0_permit'],row['slot1_permit']);cs=(row['slot0_completed_serial'],row['slot1_completed_serial'])
        need(all(0<g<=final['next_generation']for g in gs)and gs[0]!=gs[1]and ps==(1,1)and
             all(0<c<=final['next_serial']for c in cs)and row['generation']==gs[row['selected_slot']]and row['permit']==ps[row['selected_slot']],
             'actual final two retained identities and completed permits')
        need(final['offers']==final['entries']+final['cancelled']and final['entries']==final['publications']+final['hits']+final['subentry_hits']and
             final['cold_attempts']==final['publications']+final['cancelled']and sum(final['misses'])+final['pf_backward_cancelled']==final['cancelled']and
             final['pf_backward_refused']==final['pf_backward_cancelled']and final['next_serial']==final['offers']and final['next_generation']==final['publications'],
             'whole completed/cancelled retained partition')
        need(final['entries']==final['completed']and final['unexpected']==0 and final['retirements']==final['publications']-2 and
             final['permit_claims']==final['retirements']+final['hits']+final['subentry_hits']+row['dual_entries'],
             'whole two-resident permit/publication accounting')
        need(row['phase']in(13,14)and row['active']==row['busy']==row['first_error']==row['guest_data_fault']==0 and
             row['anchor_released']==row['registration_rechecked']==1,'actual final closed retained epoch or completed cancellation')
        need((row['opened_pages'],row['closed_pages'],row['recovery_complete'])==
             ((17*row['domain_members'],17*row['domain_members'],1)if row['phase']==13 else(0,0,0)),
             'exact final retained extent and recovery for its terminal phase')
        need(row['dual_entries']==row['dual_completed']==self.h[36]and 1<=row['dual_entries']<=final['hits']+final['subentry_hits']and
             row['domain_members']in((1,2)if row['phase']==13 else(0,))and self.h[37]==final['completed'],
             'exact actual joint completion/member accounting')
        subvalues=q(self.f(self.b,'pdo_wire','final_subentry'));subnames='version status failure_code selections hits entries completed serial generation root pc head slot bank complete'.split()
        sub=dict(zip(subnames,subvalues,strict=True))
        need(subvalues[:7]==(1,0,0,final['subentry_selections'],final['subentry_hits'],final['subentry_entries'],final['subentry_completed']),
             'whole protected subentry counter row')
        need(final['subentry_selections']>=final['subentry_hits']==final['subentry_entries']==final['subentry_completed'],
             'completed global subentry events form their own exact bucket')
        if sub['complete']:
            need(sub['complete']==1 and sub['serial']==row['serial']and sub['generation']==row['generation']and
                 sub['slot']==row['selected_slot']and sub['bank']in(0,1)and sub['head']<128 and
                 canonical(sub['root'])and canonical(sub['pc'])and(sub['pc']==sub['root'])==(sub['head']==0),
                 'actual final completed entry names final selected generation')
        else:need(not any(subvalues[7:]),'last cancelled attempt has no invented entry receipt')
        final_loop=self.loop_state(self.f(self.b,'pdo_wire','final_loop'),self.f(self.b,'pdo_wire','final_counts'))
        self.loop_direct([final_loop],(initial,a['domain_raw'],b['domain_raw'],warm['domain_raw'],cancel['domain_raw'],last['domain_raw']))
        loop=self.loop_terminal(final_loop,0,0)
        replacements=sum(x['prior_generation_installed']for x in(a,b,last))
        return dict(mode=self.app['mode'],placement=self.app['placement'],plan_version=12,fallback_policy=11,schema_version=15,
            status=0,code=0,detail=0,source=self.app['source'],terminal=row,subentry_terminal=sub,
            pf_refusal_stages=self.stages(),pf_refusals=base.focal.base.prior.pf_row(final,0,0),loop_terminal=loop,
            attempts=[a,b,warm,last],cancellation=cancel,orientation=(12,11)if self.app['mode']==0 else(11,12),
            cold_publications=3,warm_entries=1,generated_entries=4,generated_completed=4,dual_entries=1,
            completion_permits=5,original_branch_replays=4,ordinary_store_replays=1,interior_signals=0,
            replacements=replacements,companion_replacements=1,permit_claims=replacements+2,
            replacement=dict(slot=last['slot'],old_generation=victim['generation'],new_generation=last['generation'],
                             old_build_serial=victim['build_serial'],new_build_serial=last['build_serial']),
            loop_stages=a['loop_stages']+b['loop_stages']+warm['loop_stages']+cancel['loop_stages']+last['loop_stages']+[final_loop],
            lifetime_mode=2,registration_epoch=0,registration_calls=0,word_observed=0,
            single_orientation_only=True,reversed_primary_order_validated=False,full_state_pair_validated=False,
            qualification_credit=False,performance_credit=False)
