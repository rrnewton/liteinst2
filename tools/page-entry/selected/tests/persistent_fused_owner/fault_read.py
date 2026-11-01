"""PF13 terminal MOV recovery observations, never successful owner completions.

The old mode0 reader and its204 controls stay separate. These two profiles
require actual PE_EVENT125, held source/references, literal recovery and complete
NX cleanup. SIGSEGV store fault and SIGILL guard rejection are distinct outcomes.
"""
import importlib.util,struct,hashlib,copy
from pathlib import Path
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
base=load('pf_positive_owner',HERE/'read.py')
application=load('pf_fault_application',HERE.parent/'persistent_fused_app/fault_read.py')
need,zero,q,canonical=base.need,base.zero,base.q,base.canonical
PAGE,TF,RF,MASK,U64,GREG=base.PAGE,base.TF,base.RF,base.MASK,base.U64,base.GREG

LIMIT,HEADER,FOOTER,MAGIC,END,VERSION,LITERAL,RUN=(getattr(base.codec,k)for k in('LIMIT','HEADER','FOOTER','MAGIC','END','VERSION','LITERAL','RUN'))
_packets=base.codec._packets

def decode_failure(data,*,raw_bytes,schema_version):
    need(type(raw_bytes)is int and 0<raw_bytes<1<<32 and
         type(schema_version)is int and 0<schema_version<1<<64,'independent exact raw schema bound')
    need(type(data)is bytes and HEADER+FOOTER<=len(data)<LIMIT,'complete strict4MiB transport bound')
    h=struct.unpack_from('<8Q',data)
    need(h[:4]==(MAGIC,VERSION,schema_version,raw_bytes)and
         h[5:]==(HEADER,FOOTER,0),'exact distinct lossless transport header')
    size=h[4];body=HEADER+size
    need(size>0 and body+FOOTER==len(data),'exact encoded payload and no trailing bytes')
    footer=struct.unpack_from('<8Q',data,body)
    need(footer[:4]==(END,VERSION,body,body)and 1<=footer[4]<=64 and
         0<footer[5]<=body and footer[6:]==(125,3304),'actual complete encoded-body write footer')
    need((footer[4]==1 and footer[5]==body)or
         (footer[4]>1 and footer[4]-1<=body-footer[5]),'actual positive body partial-write geometry')
    # Header equality above precedes this one exact bounded allocation.
    out=bytearray(raw_bytes);at=HEADER;used=0
    while at<body:
        need(body-at>=5,'complete packet header')
        tag,n=struct.unpack_from('<BI',data,at);at+=5
        need(n>0 and n<=raw_bytes-used,'bounded nonempty packet expansion')
        if tag==0:
            need(n<=LITERAL and n<=body-at,'complete bounded literal packet')
            out[used:used+n]=data[at:at+n];at+=n
        else:
            need(tag==1 and n>=RUN and at<body,'complete canonical run packet')
            block=data[at:at+1]*min(n,LITERAL);at+=1
            filled=0
            while filled<n:
                k=min(len(block),n-filled);out[used+filled:used+filled+k]=block[:k];filled+=k
        used+=n
    need(at==body and used==raw_bytes,'whole exact raw expansion')
    # Streaming canonical comparison has only bounded literal temporaries. It
    # rejects alternate partitions, never substitutes an equivalent encoding.
    at=HEADER
    for prefix,payload in _packets(out):
        for part in (prefix,payload):
            need(len(part)<=body-at and data[at:at+len(part)]==part,'whole canonical packet encoding')
            at+=len(part)
    need(at==body,'complete canonical payload')
    return memoryview(out).toreadonly(),dict(schema_version=schema_version,raw_bytes=raw_bytes,
        payload_bytes=size,body_bytes=body,stream_bytes=len(data),
        body_write_calls=footer[4],body_last_write=footer[5],status=footer[6],code=footer[7])

def encode_failed_control(raw,*,schema_version):
    """Synthetic reader-control transport only: never evidence of real writes.

    Mutate the whole decoded raw object, then use this to reach its original
    semantic predicate. New transport refusals are counted separately.
    """
    need(type(raw)is bytes and 0<len(raw)<1<<32 and
         type(schema_version)is int and 0<schema_version<1<<64,'synthetic exact raw control input')
    payload=bytearray()
    for prefix,part in _packets(raw):
        need(HEADER+len(payload)+len(prefix)+len(part)+FOOTER<LIMIT,'synthetic strict4MiB transport bound')
        payload+=prefix;payload+=part
    h=struct.pack('<8Q',MAGIC,VERSION,schema_version,len(raw),len(payload),HEADER,FOOTER,0)
    n=len(h)+len(payload)
    return h+bytes(payload)+struct.pack('<8Q',END,VERSION,n,n,1,n,125,3304)

class Check(base.Check):
    def entered_member(self,entry,serial):
        t='pdo_slot';gt='li2_pg_generation';g=self.f(entry,t,'generation');self.setup(entry);gen=self.i(g,gt,'generation');build=self.i(g,gt,'build_serial')
        self.eq(g,gt,installed=1,complete=1,proof_complete=1,ready_generation=gen,plan_proofs=2,none_proofs=1,generated=self.generated,proof=self.proof,spill=self.spill,active_refs=1,linked=1,domain_refs=1,code_copied=69632,code_verified=69632,proof_zeroed=364544,proof_copied=362656,proof_verified=364544)
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
        entry=self.page+(0x2400 if index==1 else 0x206);ci=int(index==1);heads=4 if index==1 else 10;exitpc=self.page+(0x20a if index==0 else 0x2409 if index==1 else 0x221)
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
        inc=dict(next_serial=1,offers=1,entries=1,permit_claims=2 if warm else installed)
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
        info=self.f(b,t,'info');bank=self.i(refs[0],'li2_pgd_ref','bank');self.eq(info,it,selected_bank=bank,warm=int(warm),initialized=1,registered=1,code_allocated=2,proof_allocated=1,code_registered=2,proof_registered=1,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,build_started=int(not warm),build_returned=int(not warm),redirected=1,exit_seen=0,exit_index=0,recovery_started=1,recovery_complete=1,guest_data_fault=int(self.app['mode']==1),cleanup_started=0,cleanup_complete=0,consumed=1,plan_proofs=0 if warm else 2,none_proofs=0 if warm else 1,code_allocation=self.h_alloc,proof_allocation=self.h_proof_alloc,build_result=0,recovery_result=0,release_result=0,gpr_written=(7,5,7)[index],flags_written=0 if index==1 else 0x8d5,ticket=self.symbol('span_transfer'),registry_count=len(self.ranges))
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
        predecessor_pc=self.page+(0x203 if index==0 else 0x20a if index==1 else 0x2409);predecessor,_=self.predecessor(slot,predecessor_pc,ingress);self.eq(slot,'li2_tf_chain_slot',origin=1)
        ref=self.f(info,it,'ref');seq=self.i(ref,'li2_fetch_ref','sequence');tr=self.f(entered,st,'transfer');self.transfer(tr,slot,ingress,before,ref)
        need(tr==self.f(end,st,'transfer')and self.i(tr,'li2_span_transfer_progress','event')==h[17]and self.i(tr,'li2_span_transfer_progress','serial')==self.i(p,pt,'transfer_serial'),'whole actual consumed domain transfer')

        es=self.f(entered,st,'source');zs=self.f(end,st,'source');self.source(es,serial,entry,key,ref)
        need(es==zs,'whole source lease remains genuinely held; no release invented')
        ds=self.f(entered,st,'domain_source');self.domain_source(ds,refs,serial,False,es)
        need(ds==self.f(end,st,'domain_source'),'whole shared source lease retained on fatal abort')
        er=self.f(entered,st,'rseq');zr=self.f(end,st,'rseq');estate=self.f(entered,st,'state');zstate=self.f(end,st,'state')
        a=self.pin(er,estate,serial,10,refs);z=self.pin(zr,zstate,serial,10,refs)
        need(z>a and estate==zstate,'actual gateway pin checks advance without rseq closure')
        self.r.change(er,zr,'li2_pg_rseq_progress',values=dict(raw_checks=z))
        lastpc=self.page+0x203;self.eq(estate,'li2_rseq_state',last_first=0,last_end=0,last_pc=lastpc,last_code=8,last_policy=1)
        self.eq(self.f(estate,'li2_rseq_state','last_footprint'),'li2_write_footprint',pc=lastpc,next_pc=lastpc+3,first=0,end=0,abi_version=1,policy=1,code=8,length=3)
        fetch=self.f(entered,st,'fetch');self.progress(fetch,seq,True)
        need(fetch==self.f(end,st,'fetch'),'whole actual fetch remains held on failed cleanup')
        zero(self.f(info,it,'final_fetch'),'no fictitious completed fetch release')
        lives=self.r.items(info,it,'live','li2_link_rseq_live')
        for x in lives[:2]:self.live_rseq(x,estate,before)
        zero(lives[2],'no successful terminal live-rseq or closure')
        for k in('proof_exit','code_exit'):zero(self.f(info,it,k),'failed recovery has no successful exit query '+k)
        model=self.compact(payload,entry);guard=model['guard_models'][5]
        need(self.f(info,it,'recovery_scratch')==guard['whole'],'whole independently reconstructed PF MOV recovery descriptor')
        phase=1 if self.app['mode']==1 else 3
        pc=self.generated+5*512+guard['store_offset'if phase==1 else'reject_offset']
        expected=application.trace_model(self.app)[6][1];raw=after['greg']
        need(tuple(raw[i]for i in GREG)==expected and raw[16]==pc and raw[17]==0x206|RF and raw[18]==0x2b000000000033 and raw[21]==MASK,'all actual GPR/flags at precise initialized guard boundary')
        si=bytearray(128);struct.pack_into('<iii',si,0,self.signal,0,2)
        struct.pack_into('<Q',si,16,self.app['fault_address']if phase==1 else pc)
        need(after['sig']==self.signal and after['si']==bytes(si)and raw[19:21]==((6,14)if phase==1 else(0,6))and raw[22]==(self.app['fault_address']if phase==1 else self.page+0x203),'literal actual data-fault versus UD2 rejection event; no signal substitution')
        rec=self.f(info,it,'recovered');self.eq(rec,'li2_pg_recovered',flags=raw[17],original_pc=self.page+0x21b,member=0,head=5,link=4294967295,kind=4,phase=phase,complete=1)
        need(q(self.f(rec,'li2_pg_recovered','gpr'))==expected,'whole typed recovered original before-store state')
        bm=self.memory(self.f(b,t,'before_memory'),False);am=self.memory(self.f(b,t,'after_memory'),True)
        need(bm==am==dict(data=self.app['data'],stack=self.app['stack']),'every source-only failed store leaves whole data and stack unchanged')
        directory=self.f(ew,'pda_work','directory')+bytes(12288-self.r.types['li2_jd_domain_directory']['bytes'])
        need(self.f(b,t,'initial_directory')==self.f(b,t,'terminal_directory')==directory,'whole immutable directory retained on failure')
        for k in('initial_slots','terminal_slots'):zero(self.f(b,t,k),'whole zero-link slot pages')
        zero(self.f(b,t,'initial_spill'),'whole cold spill starts zero')
        spill=self.f(b,t,'terminal_spill')
        need(spill[:32]==struct.pack('<4Q',*(expected[i]for i in guard['scratch_regs'])),'actual initialized MOV scratch cells')
        zero(spill[32:],'all untouched spill cells and unused member')
        entries=[self.focal_entry(stage,self.f(payload,'pe_payload','plan'),key,entry,10,serial,chosen,gen,buildserial)for stage in(entered,end)]
        need(entries[0]==entries[1],'whole entry retained through abort without revocation claim')
        return dict(mode=self.app['mode'],slot=chosen,generation=gen,build_serial=buildserial,serial=serial,ingress=ingress,before=before,returned=returned,after=after,recovered=dict(gpr=expected,pc=self.page+0x21b,flags=raw[17],phase=phase),before_memory=bm,after_memory=am,closed_pages=closed_pages,prior_installed=installed,prior_counts_raw=prior,counts_raw=self.f(end,st,'counts'),progress_raw=ep,domain_raw=zd,terminal_slots=zslots,entry=self.f(end,st,'entry'),begin=h[3],terminal_ordinal=h[11],interior_signals=0)

    def finish(self,status):
        h=self.h;t='pdo_wire';r=self.r
        need(type(status)is int and status==125 and self.app['mode']in(1,2),'actual explicit PF terminal negative')
        self.signal=11 if self.app['mode']==1 else 4
        need(h[:9]==(0x414f50445049324c,13,5421440,r.layout['registrations']['pe']['bytes'],362656,364544,69632,968,128),'actual distinct group record version and complete extents')
        need(canonical(self.bias)and self.bias%PAGE==0 and h[9:12]==tuple(self.symbol(n)for n in('li2_raw6','li2_gateway_start','li2_gateway_end'))and h[10]<=h[9]<h[11],'actual emitted gateway identity')
        need(h[12]%PAGE==0 and h[13]==524288 and h[14:16]==(1,0)and h[16]&(3|0x400|0x800)==1 and h[17:20]==(0,1,self.app['mode']),'actual altstack and FD3/profile')
        need(h[20:26]==tuple(self.symbol(n)for n in('pe','pdo_wire','pg_source','pg_rseq','selected_chain','span_progress')),'actual protected group addresses')
        storage=r.layout['retained_storage'];size=r.types['li2_ptr_slot']['bytes'];prefix=((2*r.types['li2_pg_progress']['bytes']+9*8+18*8+3*4+7)&-8)+544
        selected=prefix+2*size;selection=(selected+4+7)&-8
        need({k:v for k,v in storage.items()if k!='domain'}==dict(retained=dict(offset=prefix,bytes=2*size),selected_slot=dict(offset=selected,bytes=4),selection=dict(offset=selection,bytes=24),previous_selection=dict(offset=selection+24,bytes=24)),'actual owner retained-array fields match independent source prefix')
        need(storage['domain']['bytes']==225832 and storage['domain']['offset']+225832<=h[3]and h[33]==self.symbol('pe')+storage['domain']['offset']and h[34]==self.symbol('pg_domain_source'),'actual protected domain field and separate shared source state')
        need(h[26:31]==(self.symbol('pe')+prefix,self.symbol('pe')+prefix+size,2,size,24)and prefix+2*size<=h[3],'actual fixed retained-slot addresses/extent')
        need(self.head==self.page+0x206 and self.page+16384<1<<31 and h[31:33]==(self.head,self.page+0x2400)and h[35]==1 and h[38]==0 and h[39]==self.page+0x223 and canonical(h[40],12288)and h[40]%PAGE==0 and h[41:47]==(225832,71368,11312,12288,3,1)and h[47:53]==(1,125,3304,self.signal,h[16],0)and h[53:57]==(self.symbol('pdo_encoded'),4<<20,1,1)and not any(h[57:]),'one actual PF failure record with no successful completion label')
        raw=q(self.f(self.b,t,'raw_ingress'));need(sum(raw[1:])==raw[0]>0,'whole actual signal population')
        for k in('sink_initial','sink_terminal'):
            st=self.f(self.b,t,k);d=self.stat(st);need(d['mode']&0xffff==0x8180 and d['size']==0,'actual empty regular0600 sink');self.eq(st,'stat',st_nlink=1,st_uid=self.image['uid'])
        self.r.change(self.f(self.b,t,'sink_initial'),self.f(self.b,t,'sink_terminal'),'stat',observed=('st_atim','st_mtim','st_ctim'))
        need(r.transport['status']==125 and r.transport['code']==3304,'actual failed encoded-body transport')
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
        for e in epochs[1:]:zero(e,'no invented later owner activation')
        zero(self.certificates[1],'no second focal publication')
        for k in('next','cancellation'):zero(self.f(self.b,t,k),'no successful continuation or held cancellation '+k)
        initial=r.items(self.f(epochs[0],'pdo_epoch','prior'),'pdo_slots','slots','pdo_slot')
        self.h_alloc=self.i(r.items(initial[1],'pdo_slot','banks','ped_bank')[1],'ped_bank','generated');self.h_proof_alloc=self.i(initial[1],'pdo_slot','proof')
        a=self.failed_epoch(epochs[0],self.f(self.b,t,'initial_domain'))
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
        return dict(pf_refusal_stages=self.pf_stages(1,False),pf_refusals=base.pf_row(counts,125,3304),mode=self.app['mode'],status=125,code=3304,detail=self.signal,terminal=row,subentry_terminal=sub,attempt=a,source=self.app['source'],cold_publications=1,generated_entries=1,generated_completed=0,completion_permits=0,anchor_released=0,cleanup_closed_pages=a['closed_pages'],interior_signals=0,native_fault_signal=11,actual_signal=self.signal,recovery_phase=1 if self.signal==11 else 3,qualification_credit=False)

def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,'actual process and reserved CPU')
    raw,transport=decode_failure(data,raw_bytes=5421440,schema_version=13)
    r=base.wire.Reader(raw,layout);r.transport=transport
    result=Check(r,image,app,pid,cpu).finish(exit_status);result['transport']=transport;return result

pf_terminal=base.pf_terminal
terminal=base.terminal
subentry_terminal=base.subentry_terminal
CONTROL_COUNT=28
def controls(data,layout,image,app,pid,cpu,exit_status):
    read(data,layout,image,app,pid,cpu,exit_status)
    raw,_=decode_failure(data,raw_bytes=5421440,schema_version=13);types=layout['types']
    def at(t,k,base=0):return base+types[t]['fields'][k]['offset']
    e=at('pdo_wire','epochs');entered=at('pdo_epoch','entered',e);end=at('pdo_epoch','terminal',e);info=at('pdo_epoch','info',e)
    after=at('pdo_epoch','after',e);f=at('le_frame','frame',after);p=at('pdo_stage','progress',end);work=at('pda_state','work',at('pdo_epoch','terminal_domain',e))
    tests=[('header_status',48*8),('header_mode',19*8),('interior_event',at('pdo_epoch','h',e)+11*8),('future_epoch',e+types['pdo_epoch']['bytes']),('future_certificate',at('pdo_wire','certificates')+types['pdo_certificate']['bytes']),('frame_UC',at('le_frame','uc',after)),('frame_SI',at('le_frame','si',after)),('frame_FP',at('li2_step_frame','fp',f)+160),('frame_PC',at('li2_step_frame','greg',f)+16*8),('frame_CR2',at('li2_step_frame','greg',f)+22*8),('source_release',at('li2_pg_progress','anchor_released',p)),('completion_permit',at('li2_pg_progress','completion_permit',p)),('closed_page_credit',at('li2_pg_progress','closed_pages',p)),('failed_phase',at('li2_pg_progress','phase',p)),('completed_counter',at('pdo_counts','completed',at('pdo_stage','counts',end))),('domain_completion',at('pda_work','completion',work)),('domain_recovery_member',at('pda_work','recovery_member',work)),('recovered_pc',at('li2_pg_recovered','original_pc',at('pdo_epoch_info','recovered',info))),('recovered_phase',at('li2_pg_recovered','phase',at('pdo_epoch_info','recovered',info))),('recovered_RAX',at('li2_pg_recovered','gpr',at('pdo_epoch_info','recovered',info))),('scratch_descriptor',at('pdo_epoch_info','recovery_scratch',info)),('retained_fetch',at('li2_fetch_progress','held',at('pdo_stage','fetch',end))),('source_byte',at('pdo_certificate','payload',at('pdo_wire','certificates'))+types['pe_payload']['fields']['source']['offset']+types['li2_pg_source_key']['fields']['page']['offset']+types['li2_pg_source_page']['fields']['bytes']['offset']),('whole_data',at('li2_pdo_memory','data',at('pdo_epoch','after_memory',e))),('whole_stack',at('li2_pdo_memory','stack',at('pdo_epoch','after_memory',e))),('spill',at('pdo_epoch','terminal_spill',e)),('directory',at('pdo_epoch','terminal_directory',e)),('terminal_row',at('pdo_wire','final_row')+2*8)]
    need(len(tests)==len(set(n for n,_ in tests))==CONTROL_COUNT,'all literal PF failed-owner controls')
    refused=[]
    for name,offset in tests:
        changed=bytearray(raw);changed[offset]^=1
        encoded=encode_failed_control(bytes(changed),schema_version=13)
        try:read(encoded,layout,image,app,pid,cpu,exit_status)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed PF terminal negative '+name)
    return dict(refusals=refused,original_sha256=hashlib.sha256(data).hexdigest(),native_operations=0)

def pair(native,gated,owner):
    mode=gated['mode'];need(mode in(1,2)and native['mode']==mode==owner['mode'],'same exact independent negative mode')
    need(native['suffix']is not None and gated['suffix']is None and len(native['observations'])==1 and not gated['observations'],'native stopped original fault versus failed gated prefix')
    need(all(native[k]==gated[k]for k in('head','source_page_address','source','hardware','xcr0','data','stack','rsp','seed','machine','fault_pc','fault_address'))and owner['source']==native['source'],'whole same original fault input and hardware')
    signal=11 if mode==1 else 4;phase=1 if mode==1 else 3
    need((owner['status'],owner['code'],owner['detail'],owner['cold_publications'],owner['generated_entries'],owner['generated_completed'],owner['completion_permits'],owner['anchor_released'],owner['interior_signals'],owner['native_fault_signal'],owner['actual_signal'],owner['recovery_phase'])==(125,3304,signal,1,1,0,0,0,0,11,signal,phase),'failure stays125 with held anchor and no completion authority')
    a=owner['attempt'];need(a['closed_pages']==owner['cleanup_closed_pages']and a['closed_pages']in(17,34),'all actual installed code banks observed NX')
    observation=native['observations'][0];frames=observation['frames'];need(len(frames)==3,'all three full original negative frames')
    need(a['before_memory']==a['after_memory']==dict(data=observation['data'],stack=observation['stack'])==dict(data=native['data'],stack=native['stack']),'whole before-effect original and generated data/stack equality')
    expected=tuple(frames[2]['greg'][i]for i in GREG)
    need(a['recovered']==dict(gpr=expected,pc=native['fault_pc'],flags=frames[2]['greg'][17]&~TF,phase=phase),'whole PF recovered before-store state matches real native fault')
    def context(actual,ref,event):
        want=list(ref['greg']);si=bytearray(ref['si'])
        if event in('closed','redirect'):want[17]&=~TF
        if event=='redirect':want[16]=a['returned']['greg'][16]
        if event=='fault':
            want[16]=a['after']['greg'][16];want[17]&=~TF
            if mode==2:
                want[19],want[20],want[22]=0,6,native['predecessor']
                struct.pack_into('<iii',si,0,4,0,2);struct.pack_into('<Q',si,16,want[16])
        need(actual['greg']==tuple(want)and actual['si']==bytes(si)and actual['sig']==(signal if event=='fault'else 5),'all23 GREG and128 SI with only actual owned event coordinates')
        need(actual['fp']==ref['fp']and actual['fp_bytes']==ref['header'][9]and actual['mask']==MASK and(actual['fs'],actual['gs'])==native['machine'][1:3],'whole65536 FP storage/mask/TLS equality on the real boundary')
        uc=actual['uc'];nuc=ref['uc'];h=ref['header'];alt,cap=actual['altstack'];fp=actual['fp_address']
        need(len(uc)==968 and len(nuc)==1024 and nuc[968:]==bytes(56)and cap==h[11]==524288 and alt%PAGE==0 and fp%16==0 and alt<=fp<=alt+cap-actual['fp_bytes']and h[10]<=h[8]<=h[10]+h[11]-h[9]and fp-alt==h[8]-h[10],'whole independently bounded native/generated altstack and FP geometry')
        need(q(uc,16)[0]==alt and q(uc,32)[0]==cap and q(uc,224)[0]==fp and q(nuc,16)[0]==h[10]and q(nuc,32)[0]==h[11]and q(nuc,224)[0]==h[8],'actual context aliases in both lanes')
        expected=bytearray(nuc[:968]);struct.pack_into('<Q',expected,16,alt);struct.pack_into('<Q',expected,224,fp);struct.pack_into('<23Q',expected,40,*want);expected[304:432]=si
        need(uc==bytes(expected),'all968 native/protected UC bytes, no tail masking')
    context(a['ingress'],frames[1],'original');context(a['before'],frames[1],'closed')
    context(a['returned'],frames[1],'redirect');context(a['after'],frames[2],'fault')
    return dict(observed_pf_terminal_negative=1,mode=mode,plan_version=11,native_steps=6,native_full_frames=3,owner_full_frames=4,actual_signal=signal,native_signal=11,recovery_phase=phase,cold_publications=1,generated_entries=1,generated_completed=0,completion_permits=0,anchor_released=0,closed_pages=a['closed_pages'],interior_signals=0,guest_effects=0,exit_status=125,whole_profile_qualified=False,performance_credit=False)

PAIR_CONTROL_COUNT=12
def pair_controls(native,gated,owner):
    pair(native,gated,owner);refused=[]
    names=('status','recovery_pc','recovered_RAX','phase','raw_signal','raw_CR2','raw_UC','raw_FP','data','stack','source','held_anchor')
    for name in names:
        value=copy.deepcopy(owner);a=value['attempt']
        if name=='status':value['status']=0
        elif name=='held_anchor':value['anchor_released']=1
        elif name=='recovery_pc':a['recovered']['pc']^=1
        elif name=='phase':a['recovered']['phase']^=1
        elif name=='recovered_RAX':g=list(a['recovered']['gpr']);g[0]^=1;a['recovered']['gpr']=tuple(g)
        elif name=='raw_signal':a['after']['sig']^=1
        elif name=='raw_CR2':g=list(a['after']['greg']);g[22]^=1;a['after']['greg']=tuple(g)
        elif name in('raw_UC','raw_FP'):
            key='uc'if name=='raw_UC'else'fp';b=bytearray(a['after'][key]);b[0 if key=='uc'else 160]^=1;a['after'][key]=bytes(b)
        elif name in('data','stack'):b=bytearray(a['after_memory'][name]);b[0]^=1;a['after_memory'][name]=bytes(b)
        else:b=bytearray(value['source']);b[0]^=1;value['source']=bytes(b)
        try:pair(native,gated,value)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted changed PF terminal pair '+name)
    need(len(refused)==len(set(refused))==PAIR_CONTROL_COUNT,'all separate terminal native/generated pair controls')
    return dict(refusals=refused,native_operations=0)


PF_REFUSAL_CONTROL_COUNT=12

def pf_refusal_controls(data,layout,image,app,pid,cpu,exit_status):
    read(data,layout,image,app,pid,cpu,exit_status)
    raw,_=decode_failure(data,raw_bytes=5421440,schema_version=13)
    return base.pf_controls(data,raw,layout,(image,app,pid,cpu,exit_status),read,
        lambda b:encode_failed_control(b,schema_version=13),epochs=1,cancellation=False)
