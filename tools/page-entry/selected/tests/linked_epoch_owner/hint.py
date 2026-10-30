"""Actual advisory receipt, GRAPH/TRACE/NX/native witness; no permission authority."""
import struct

def need(value,message):
    if not value:raise ValueError(message)
def zero(value,message):need(not any(value),message)
def q(value):return struct.unpack('<'+'Q'*(len(value)//8),value)
T='li2_link_native_hint_progress'
COUNTERS='publications evictions lookups hits invalidations next_nx admitted refused errors'.split()
PROVENANCE='receipt_sequence receipt_publication selected_publication selected_serial selected_event selected_pc selected_seeds selected_published'.split()
ROW='ready pending outcome_complete'.split()+COUNTERS+PROVENANCE+['outcome_result']

def values(c,b):return {k:c.i(b,T,k)for k in ROW}

def changed(c,a,b,t,values,message):
    """Compare every byte after only the specified typed scalar writes."""
    want=bytearray(a)
    for key,value in values.items():
        f=c.r.types[t]['fields'][key]
        payload=value if type(value)is bytes else value.to_bytes(f['bytes'],'little',signed=value<0)
        need(len(payload)==f['bytes'],'whole typed advisory field size')
        want[f['offset']:f['offset']+f['bytes']]=payload
    need(bytes(want)==b,message)

def receipt(c,b):
    p=values(c,b);s=c.f(b,T,'receipt');S='li2_native_pair_slot';page=c.f(s,S,'page');P='li2_fetch_page'
    if not p['publications']:
        zero(b,'no native hint publication means whole hint is zero');return p
    need(p['receipt_sequence']>0 and p['receipt_publication']>0,'actual positive native publication identity')
    c.eq(s,S,prepared=1,published=1,policy=0)
    a,allocation,generation,offset,extent=c.v(page,P,'address allocation generation offset initial_extent')
    backing,obj,logical,closed=c.v(page,P,'backing object logical closed_prot')
    need(a%4096==0 and 0x200000000<=a<1<<47 and allocation>0 and generation>0 and backing==1 and logical==5 and closed==1 and obj in c.objects,'actual retained positive hint page identity')
    original,_,loads=c.objects[obj];data=original['data'];left,right,n,initialized=c.v(s,S,'window_before window_after window_bytes window_initialized')
    owners=[x for x in loads if x[1]==5 and (x[2]&-4096)<=offset and offset+4096<=((x[2]+x[5]+4095)&-4096)]
    need(len(owners)==1 and offset%4096==0,'hint page has one actual original executable load')
    seg=owners[0];bias=a-((seg[3]&-4096)+offset-(seg[2]&-4096))
    need(bias>=0 and bias%4096==0,'actual positive hint ELF load bias')
    if obj in c.bases:need(c.bases[obj]==bias,'positive hint retains actual object bias')
    else:c.bases[obj]=bias
    maximum=max((x[3]+x[6]+4095)&-4096 for x in loads)
    need(extent in((0,maximum)if offset==0 and obj not in(c.image['main_object'],c.image['interpreter_object'])else(0,)),'exact hint original extent annotation')
    neighbors=struct.unpack('<2I',c.f(b,T,'neighbors'))
    need(neighbors in((0,0),(0,1),(1,0),(1,1))and(left,right)==tuple(14*x for x in neighbors)and n==initialized==4096+left+right,'actual complete hint policy window and present halos')
    need(c.i(s,S,'pc')>=a and c.i(s,S,'pc')<a+4096,'actual historical policy candidate belongs to receipt page')
    ids=c.r.items(b,T,'identity','li2_link_native_hint_identity');I='li2_link_native_hint_identity'
    c.eq(ids[0],I,address=a,allocation=allocation,generation=generation,offset=offset,initial_extent=extent,backing=backing,object=obj,logical=logical)
    expected=[]
    for i,item in enumerate(ids):
        present=not i or neighbors[i-1]
        if not present:zero(item,'absent halo has whole zero identity');continue
        addr,alloc,gen,off,initial=c.v(item,I,'address allocation generation offset initial_extent');bo,ob,lo=c.v(item,I,'backing object logical')
        need(addr==(a if not i else a-4096 if i==1 else a+4096)and alloc>0 and gen>0 and bo==1 and lo==5 and ob in c.objects,'actual sealed present hint identity')
        blob=c.objects[ob][0]['data'];start=off if i!=1 else off+4096-14;length=4096 if not i else 14
        need(0<=start<=len(blob)-length,'whole actual hint object bytes')
        expected.append((i,blob[start:start+length]))
    chunks=dict(expected);window=chunks.get(1,b'')+chunks[0]+chunks.get(2,b'')
    need(c.f(s,S,'window')==window+bytes(4124-len(window)),'full immutable native hint page and halo bytes')
    back=c.f(s,S,'backing');c.eq(back,'li2_fetch_backing',seals_observed=1,stat_observed=1,seals=15,stat_result=0)
    fd=c.i(back,'li2_fetch_backing','retained_fd');st=c.stat(c.f(back,'li2_fetch_backing','stat'))
    need(200<=fd<1<<31 and st['size']==original['carrier_bytes']and st['mode']&0xf000==0x8000,'actual sealed positive hint backing descriptor')
    if obj==c.image['main_object']:need(st==c.stat(c.f(c.b,'leto_wire','main_backing')),'positive hint original main backing identity')
    elif obj!=c.image['interpreter_object']:
        expected=original['backing'];need(all(st[k]==expected[k]for k in('dev','ino','size'))and expected['seals']==15,'positive hint exact dependency carrier identity')
    first,end,major,minor,inode,vmaoff=c.v(page,P,'vma_first vma_end vma_major vma_minor vma_inode vma_offset');dev=st['dev']
    need(first%4096==end%4096==vmaoff%4096==0 and first<=a<a+4096<=end and vmaoff+a-first==offset and(major,minor,inode)==(((dev>>8)&0xfff)|((dev>>32)&0xfffff000),(dev&255)|((dev>>12)&0xffffff00),st['ino']),'complete positive hint VMA and sealed object identity')
    need(c.i(b,T,'allocation_epoch')>=allocation and c.i(b,T,'generation_epoch')>=generation and c.i(b,T,'records_epoch')>0,'actual hint publication lifetime epochs')
    return p

def terminal_state(c):
    b=c.f(c.b,'leto_wire','terminal_hint');p=values(c,b)if c.hint_control else receipt(c,b);count=c.counts['graph_refaults']
    need(all(p[k]in(0,1)for k in('ready','pending','outcome_complete')),'literal actual hint state flags')
    need(p['ready']+p['evictions']+p['hits']+p['invalidations']==p['publications']and p['hits']<=p['lookups'],'one-use positive hint conservation')
    need(p['lookups']<=q(c.f(c.b,'leto_wire','events'))[8],'every advisory lookup follows an actual GRAPH refusal')
    # All fixed failures occur outside a pending hint-selected native API. An
    # undeclared incomplete fatal prefix remains failed, never refused/admitted.
    need(p['pending']==p['errors']==p['refused']==0 and p['hits']==count==p['next_nx']==p['admitted'],'all declared finite hint selections reached actual native admission')
    need(count<=q(c.f(c.b,'leto_wire','events'))[8],'every graph retry is an actual counted GRAPH refusal')
    owners=c.f(c.b,'leto_wire','terminal_owners');life=c.f(owners,'leto_owners','lifecycle');pair=c.f(owners,'leto_owners','pair')
    need(p['publications']==p['receipt_publication']==c.i(life,'li2_native_pair_lifecycle','published')and 0<p['receipt_sequence']<=c.i(life,'li2_native_pair_lifecycle','sequence'),'all actual native publications feed the bounded advisory receipt')
    if not p['hits']:
        need(not any(p[k]for k in('outcome_complete','outcome_result')+tuple(PROVENANCE[2:])),'no selection means no invented native outcome')
    else:
        need(p['outcome_complete']==1 and p['outcome_result']==1 and 0<p['selected_publication']<p['receipt_publication']and p['selected_serial']>0 and p['selected_pc']>=0x200000000,'actual completed hint native outcome and older selected receipt')
        need(p['selected_publication']<=p['selected_published']<p['receipt_publication']and p['selected_serial']<=c.counts['offers']and p['selected_event']<c.i(pair,'li2_native_pair_progress','events')and p['selected_seeds']<c.i(pair,'li2_native_pair_progress','seeds'),'actual selected receipt precedes terminal native lifecycle')
    r=c.f(c.b,'leto_wire','terminal_record');R='le_record';checked,hit,pub=c.v(r,R,'hint_checked hint_hit hint_publication')
    need(checked in(0,1)and hit in(0,1)and hit<=checked and bool(pub)==bool(hit),'exact actual current hint flags/publication')
    if checked:
        c.eq(r,R,build_started=1,build_returned=1,build_result=2403,miss_release_complete=1,miss_release_result=0)
        source=c.f(r,R,'source');key=c.f(source,'li2_span_source','key');need(c.i(key,'li2_span_source_key','entry')>=0x200000000,'actual high GRAPH lookup source')
    if hit:
        need(pub==p['selected_publication']and c.i(c.f(r,R,'transfer'),'li2_span_transfer_progress','serial')==p['selected_serial'],'current hit binds the actual one-use selection')
    return p

def terminal_row(c,outcome):
    p=values(c,c.f(c.b,'leto_wire','terminal_hint'));r=c.f(c.b,'leto_wire','terminal_record')
    return dict(version=1,status=outcome['status'],failure_code=outcome['failure_code'],**p,
        current_checked=c.i(r,'le_record','hint_checked'),current_hit=c.i(r,'le_record','hint_hit'),current_publication=c.i(r,'le_record','hint_publication'))

def terminal_transfer(c):
    t='li2_span_transfer_progress';b=c.f(c.b,'leto_wire','terminal_transfer');r=c.f(c.b,'leto_wire','terminal_record');R='le_record'
    need(c.counts['refaults']<=q(c.f(c.b,'leto_wire','events'))[9],'actual retry count bounded by actual relocation refusals')
    phase=c.i(b,t,'phase');done=phase==6
    need(c.v(b,t,'refault_attempted refaulted')==((1,1)if done else(0,0))and c.v(r,R,'refault_started refault_complete refault_result')==((1,1,0)if done else(0,0,0)),'actual terminal retry phase and completion fields')
    if done:
        result=c.i(r,R,'build_result');need(result in(2403,2404),'actual distinct GRAPH or relocation retry result')
        c.eq(r,R,slot_present=0,redirected=0,completed=0,build_started=1,build_returned=1,close_complete=1,prepare_complete=1,miss_release_complete=1,miss_release_result=0,resume_started=0,resume_complete=0)
        need(c.counts['graph_refaults'if result==2403 else'refaults']>0 and c.i(b,t,'serial')==c.counts['offers']and c.i(b,t,'pc')>=0x200000000 and 0<c.i(b,t,'previous_borrow')<c.i(b,t,'fresh_borrow'),'terminal retry is actual high miss and newer released borrow')
        c.eq(b,t,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0)
        c.progress(c.f(r,R,'miss_fetch'),c.i(b,t,'fresh_borrow'),False)
        fresh=c.f(b,t,'fresh');F='li2_span_fetch_observation'
        c.eq(fresh,F,complete=1,pc=c.i(b,t,'pc'),length=15,page_count=1,pid=c.pid,tid=c.pid)
        c.eq(c.f(fresh,F,'ref'),'li2_fetch_ref',sequence=c.i(b,t,'fresh_borrow'))
        need(c.f(fresh,F,'progress')==c.f(r,R,'miss_fetch'),'whole actual terminal released fresh observation')
        if result==2403:c.eq(r,R,hint_checked=1,hint_hit=1);need(c.i(r,R,'hint_publication')>0,'positive receipt selected GRAPH retry')
        else:c.eq(r,R,hint_checked=0,hint_hit=0,hint_publication=0)

def idle(c,b,before):
    I='leto_hint_idle';c.eq(b,I,initialized=1,phase=2,in_handler=0,first_error=0,first_detail=0,live=0,entry_pending=0)
    r=c.f(b,I,'rseq');c.eq(r,'li2_rseq_state',initialized=1,registered=0,held=0,phase=0,first_error=0,first_detail=0,pid=c.pid,tid=c.pid,calls=0,registrations=0,unregistrations=0,kernel_errors=0,epoch=0)
    zero(c.f(b,I,'rseq_native'),'whole unused one-page native owner before advisory')
    l=c.f(b,I,'lifecycle');L='li2_native_pair_lifecycle';c.eq(l,L,initialized=1,busy=0,live=0,first_error=0,first_detail=0,opening=0,pid=c.pid,tid=c.pid)
    need(c.i(l,L,'published')==c.i(l,L,'closed_pages'),'actual prior native pages closed')
    q0=c.f(b,I,'rseq_pair');Q='li2_rseq_pair_progress';c.eq(q0,Q,initialized=1,active=0,checking=0,entry_checked=0,first_error=0,first_detail=0,unsafe_terminal=0,pid=c.pid,tid=c.pid,registered=0,address=0,page=0,length=0,signature=0)
    need(c.i(q0,Q,'owner')==c.i(l,L,'owner'),'actual native/rseq quiet ownership')
    need(c.i(q0,Q,'published')==c.i(l,L,'published'),'actual rseq page publications match lifecycle')
    need(c.i(q0,Q,'attempts')==c.i(q0,Q,'closed'),'actual rseq quiet completed epochs')
    need(c.i(q0,Q,'preentries')==c.i(q0,Q,'entries'),'actual rseq quiet completed entries')
    return l

def closed(c,w,before):
    W='leto_hint';t='li2_span_transfer_progress';tr=c.f(w,W,'before_transfer');previous=c.i(tr,t,'previous');chain=q(c.f(w,W,'chain'))
    need(chain[:7]==(1,0,0,0,0,previous,c.i(tr,t,'event'))and previous<2 and chain[7]>0 and chain[8]==chain[9]==chain[10]+chain[11]and chain[15]==0,'actual closed predecessor chain identity and accounting')
    s=c.f(w,W,'closed');S='li2_tf_chain_slot';c.eq(s,S,phase=5,fallback=0,unexpected_frame_observed=0,generation=c.i(tr,t,'previous_generation'))
    o=c.f(s,S,'owner');step=c.f(o,'li2_tf_owner','step');c.eq(step,'li2_step_owner',phase=5,first_error=0,first_detail=0,in_handler=0,trace_seen=1,revoke_sync_started=1,open_sync=0,revoke_sync=0)
    c.eq(o,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0,unexpected_frame_observed=0,actual_post_pc=c.head,actual_post_flags=before['greg'][17]|256)
    c.step_frame(c.f(step,'li2_step_owner','after'),before,before['greg'][17]|256)
    c.eq(c.f(step,'li2_step_owner','request'),'li2_step_request',page_count=1)
    for k in('open_started','opened','revoke_started','revoked'):need(struct.unpack('<2I',c.f(step,'li2_step_owner',k))==(1,0),'actual hint predecessor exact permission masks')
    for k in('open_result','revoke_result'):zero(c.f(step,'li2_step_owner',k),'actual hint predecessor permission results')
    c.eq(c.f(s,S,'query'),'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0,pc=c.head)
    c.eq(c.f(s,S,'release'),'li2_chain_release',started=1,complete=1,result=0)
    fetch=c.f(s,S,'fetch');pc=c.i(fetch,'li2_chain_fetch','pc');ref=c.chain_fetch(fetch,pc,False)
    need(c.i(ref,'li2_fetch_ref','sequence')==c.i(tr,t,'previous_borrow'),'hint predecessor original released borrow')
    c.observation(c.f(tr,t,'released'),pc,False,ref)


def native(c,w,before,nx):
    wt='leto_hint';a,b,z=(c.f(w,wt,k)for k in('idle','admitted','closed_native'))
    c.owners(z)
    P,L,R='li2_native_pair_progress','li2_native_pair_lifecycle','li2_rseq_pair_progress'
    al,ar=(c.f(a,'leto_hint_idle',k)for k in('lifecycle','rseq_pair'))
    bp,bl,br=(c.f(b,'leto_owners',k)for k in('pair','lifecycle','rseq_pair'))
    zp,zl,zr=(c.f(z,'leto_owners',k)for k in('pair','lifecycle','rseq_pair'))
    c.eq(b,'leto_owners',captured=1,word=0,word_observed=0)
    c.eq(bp,P,initialized=1,phase=4,in_handler=0,first_error=0,first_detail=0,live=1,entry_pending=0,first_observed=1,second_observed=0,pid=c.pid,tid=c.pid,session=c.symbol('selected_session'),signal_number=11,signal_code=2,signal_errno=0,pc=c.head,signal_address=c.head)
    c.step_frame(c.f(bp,P,'first'),nx)
    for key in('events','seeds'):need(c.i(bp,P,key)==c.i(a,'leto_hint_idle',key)+1,'advisory actual one native seed')
    for key in('extensions','epochs_closed','one_page_closes','two_page_closes','policy_closes','capacity_closes','refaults','refault_completed'):need(c.i(bp,P,key)==c.i(a,'leto_hint_idle',key),'no invented native predecessor completion')
    c.eq(bl,L,initialized=1,busy=0,live=1,first_error=0,first_detail=0,opening=0,post_verified=1,pid=c.pid,tid=c.pid,candidate=c.head,candidate_policy=0,candidate_eligible=1)
    for key in('sequence','attempts','published'):need(c.i(bl,L,key)==c.i(al,L,key)+1,'exact actual native page admission')
    for key in('closed_pages','close_calls'):need(c.i(bl,L,key)==c.i(al,L,key),'admission does not invent closure')
    c.maps(c.f(bl,L,'before'));c.maps(c.f(bl,L,'after'))
    slots=c.r.items(bl,L,'slots','li2_native_pair_slot');s=slots[0];T='li2_native_pair_slot';zero(slots[1],'no second published page on initial advisory seed')
    c.eq(s,T,prepared=1,published=1,slot=0,pc=c.head,policy=0)
    c.page_row(c.f(s,T,'page'));c.backing(c.f(s,T,'backing'))
    left,right,n,initialized=c.v(s,T,'window_before window_after window_bytes window_initialized')
    need(left in(0,14)and right in(0,14)and n==initialized==left+4096+right,'whole actual native page plus halos')
    obj,_,loads=c.objects[c.image['main_object']];bias=c.bases[c.image['main_object']]
    def memory(address,size):
        rows=[p for p in loads if p[1]==5 and bias+p[3]<=address and address+size<=bias+p[3]+p[5]]
        need(len(rows)==1,'actual helper and halo wholly in one immutable executable source load')
        p=rows[0];off=p[2]+address-bias-p[3];return obj['data'][off:off+size]
    expected_left=14 if any(p[1]==5 and bias+p[3]<=c.page-4096 and c.page<=bias+p[3]+p[5]for p in loads)else 0
    expected_right=14 if any(p[1]==5 and bias+p[3]<=c.page+4096 and c.page+8192<=bias+p[3]+p[5]for p in loads)else 0
    need((left,right)==(expected_left,expected_right),'actual ELF neighbor policy window geometry')
    need(c.f(s,T,'window')==memory(c.page-left,n)+bytes(4124-n),'complete actual native policy bytes including halo and padding')
    c.eq(br,R,initialized=1,registered=0,active=1,checking=0,entry_checked=0,first_error=0,first_detail=0,unsafe_terminal=0,pid=c.pid,tid=c.pid,address=0,page=0,length=0,signature=0,word_before=0,word_entry=0,word_after=0)
    for k in('before','after'):zero(c.f(br,R,k),'unregistered advisory pair has no invented pin')
    need(c.i(br,R,'owner')==c.i(bl,L,'owner')==c.i(ar,R,'owner'),'actual same private native/rseq owner')
    for k in('attempts','published'):need(c.i(br,R,k)==c.i(ar,R,k)+1,'actual rseq-bound native seed/publication')
    need(c.v(br,R,'fs_before gs_before')==(before['fs'],before['gs']),'native actual TLS seed equals closed TRACE observation')
    state=c.f(b,'leto_owners','rseq');c.eq(state,'li2_rseq_state',initialized=1,registered=0,held=0,phase=0,first_error=0,first_detail=0,pid=c.pid,tid=c.pid,tls_attempted=1,tls_complete=1,fs_result=0,gs_result=0,fs_base=before['fs'],gs_base=before['gs'])
    c.r.change(c.f(a,'leto_hint_idle','rseq'),state,'li2_rseq_state',observed=('fs_base','gs_base','fs_result','gs_result','tls_attempted','tls_complete'))
    need(c.f(z,'leto_owners','rseq')==state,'complete advisory native excursion preserves registration and static NONE history')
    zero(c.f(b,'leto_owners','rseq_native'),'no one-page native owner invented by advisory')
    for key in('seeds','extensions'):need(c.i(zp,P,key)==c.i(bp,P,key),'one actual published page until complete close')
    need(c.i(zp,P,'events')==c.i(bp,P,'events')+1 and c.i(zp,P,'epochs_closed')==c.i(bp,P,'epochs_closed')+1 and c.i(zp,P,'one_page_closes')==c.i(bp,P,'one_page_closes')+1,'next actual native boundary closes the complete one-page epoch')
    need(c.i(zl,L,'closed_pages')==c.i(bl,L,'closed_pages')+1 and c.i(zr,R,'closed')==c.i(br,R,'closed')+1,'actual page/rseq close conservation')
    close=c.f(zl,L,'close');C='li2_native_close'
    c.eq(close,C,busy=0,complete=1,first_error=0,first_detail=0,pages=1,attempted=1,returned=1,closed=1,verified=1,last_address=c.page,last_result=0,sync_started=1,sync_returned=1,sync_result=0,cleanup_started=0,cleanup_complete=0,pid=c.pid,tid=c.pid)
    c.maps(c.f(close,C,'before'));c.maps(c.f(close,C,'after'))
    need(c.f(zp,P,'first_close')==close,'whole real close is retained by native pair')
    need(c.v(zr,R,'fs_before gs_before')==c.v(zr,R,'fs_after gs_after')==(before['fs'],before['gs']),'actual native entry/exit TLS brackets')
    return dict(native_seed=1,native_closed=1)

def check(c):
    W='leto_hint';w=c.f(c.b,'leto_wire','hint');h=q(c.f(w,W,'h'));control=c.hint_control
    need(h[0]==control and not any(h[26:]),'exact advisory selector and unused header')
    terminal=terminal_state(c)
    required=bool(control)or(c.app['mode']==5 and not c.control)
    if not h[1]:
        need(not required,'mandatory actual GRAPH advisory and native excursion')
        zero(w,'whole absent advisory witness');return dict(present=0)
    need(h[1]==1 and 0<h[2]<=q(c.f(c.b,'leto_wire','raw_ingress'))[0]and h[9]==1,'actual advisory observation after exactly first focal completion')
    source=c.f(w,W,'source');key=c.f(source,'li2_span_source','key');pc=c.i(key,'li2_span_source_key','entry');page=pc&-4096
    need(pc>=0x200000000 and 0<=pc-page<=4096-15,'actual bounded high helper advisory source')
    obj,_,loads=c.objects[c.image['main_object']];bias=c.bases[c.image['main_object']]
    rows=[p for p in loads if p[1]==5 and bias+p[3]<=page and page+4096<=bias+p[3]+p[5]]
    need(len(rows)==1,'one immutable original helper page for advisory witness')
    off=rows[0][2]+page-bias-rows[0][3];data=obj['data'][off:off+4096]
    saved=c.head,c.page,c.app,c.h;c.head=pc;c.page=page;c.app=dict(c.app,source=data);c.h=list(c.h);c.h[21]=off
    try:
        s=c.source(source);before=c.frame(c.f(w,W,'before'));c.trace(before,pc,before['greg'][17])
        need(not before['greg'][17]&(256|65536),'actual advisory logical flags after predecessor close')
        b=c.f(w,W,'before_transfer');A=c.f(w,W,'after_transfer');S='li2_span_transfer_progress'
        c.eq(b,S,phase=2,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0,first_error=0,first_detail=0,pc=pc,flags=before['greg'][17],fresh_borrow=0,refault_attempted=0,refaulted=0)
        need(0<c.i(b,S,'serial')<=c.counts['offers']and 0<c.i(b,S,'previous_borrow')<s['borrow'],'advisory current serial and strictly newer source borrow')
        zero(c.f(b,S,'fresh'),'unconsumed advisory has no invented fresh transfer observation')
        closed(c,w,before);c.progress(c.f(w,W,'fresh'),s['borrow'],False)
        l=idle(c,c.f(w,W,'idle'),before);prior=c.f(w,W,'before_hint');p=receipt(c,prior)
        need(p['ready']==1 and p['pending']==p['errors']==0 and p['receipt_publication']<=c.i(l,'li2_native_pair_lifecycle','published'),'actual matching ready positive receipt before advisory choice')
        need(p['publications']==p['receipt_publication']==c.i(l,'li2_native_pair_lifecycle','published')and p['receipt_sequence']<=c.i(l,'li2_native_pair_lifecycle','sequence')and 1+p['evictions']+p['hits']+p['invalidations']==p['publications']and p['hits']==p['next_nx']==p['admitted']and p['refused']==0 and all(p[k]<=terminal[k]for k in COUNTERS),'complete prior positive receipt accounting precedes terminal state')
        need(c.v(prior,T,'allocation_epoch generation_epoch records_epoch')==c.v(l,'li2_native_pair_lifecycle','allocation_epoch generation_epoch records_epoch'),'actual ready receipt retains current complete lifecycle epochs')
        slot=c.f(prior,T,'receipt');page0=c.f(slot,'li2_native_pair_slot','page');actual=c.f(key,'li2_span_source_key','page')
        fields='address allocation generation offset initial_extent backing object logical closed_prot'
        need(c.v(page0,'li2_fetch_page',fields)==c.v(actual,'li2_fetch_page',fields),'advisory receipt matches complete actual source identity')
        back=c.f(slot,'li2_native_pair_slot','backing');current=c.f(key,'li2_span_source_key','backing')
        need(c.v(back,'li2_fetch_backing','retained_fd seals')==c.v(current,'li2_fetch_backing','retained_fd seals')and all(c.stat(c.f(back,'li2_fetch_backing','stat'))[k]==c.stat(c.f(current,'li2_fetch_backing','stat'))[k]for k in('dev','ino','size','mode')),'advisory receipt matches actual retained backing')
        need(h[7:9]==(1,int(not control))and h[10:20]==(1,1,2403,1,1,1,0,1,int(not control),p['receipt_publication']if not control else 0),'actual GRAPH/ref-release/choose prefix')
        after=c.f(w,W,'after_hint')
        if control:
            need(h[3:7]==(0,0,0,0)and h[20]==1 and h[22:26]==(0,0,1,h[2]),'actual advisory rejection terminates before any retry or native event')
            mutation=c.f(w,W,'changed_hint');want=bytearray(prior)
            if control==1:
                at=(pc-page+15)%4096;need(h[21]==at and not pc-page<=at<pc-page+15,'actual corrupted receipt byte lies beyond fresh first15')
                f=c.r.types[T]['fields']['receipt'];g=c.r.types['li2_native_pair_slot']['fields'];j=f['offset']+g['window']['offset']+c.i(slot,'li2_native_pair_slot','window_before')+at
            else:
                neighbors=struct.unpack('<2I',c.f(prior,T,'neighbors'));index=0 if control==2 else 1 if neighbors[0]else 2
                need(h[21]==index and(control==2 or neighbors[index-1]==1),'actual corrupted present main or halo generation')
                j=c.r.types[T]['fields']['identity']['offset']+index*c.r.types['li2_link_native_hint_identity']['bytes']+c.r.types['li2_link_native_hint_identity']['fields']['generation']['offset']
            want[j]^=1;need(bytes(want)==mutation,'exact one-field actual advisory receipt mutation')
            changed(c,mutation,after,T,dict(lookups=p['lookups']+1,invalidations=p['invalidations']+1,ready=0),'whole actual choose rejection invalidates exactly once without a hit')
            need(A==b and c.f(c.b,'leto_wire','terminal_hint')==after,'actual advisory rejection retains closed transfer and whole terminal receipt')
            returned=c.normalized(c.f(w,W,'returned'),before);c.same_event(before,returned,before['greg'][17])
            for k in('nx','admitted','closed_native','outcome_hint'):zero(c.f(w,W,k),'advisory rejection invents no hardware or native outcome')
            current=c.f(c.b,'leto_wire','terminal_record');R='le_record'
            need(c.f(current,R,'source')==source and c.f(current,R,'before')==before['raw']and c.f(current,R,'transfer')==A and c.f(current,R,'miss_fetch')==c.f(w,W,'fresh'),'actual rejected advisory is the complete terminal current source/frame/transfer')
            c.eq(current,R,slot_present=0,redirected=0,exit_seen=0,completed=0,build_started=1,build_returned=1,build_result=2403,miss_release_started=1,miss_release_complete=1,miss_release_result=0,resume_started=0,resume_complete=0,refault_started=0,refault_complete=0,refault_result=0,hint_checked=1,hint_hit=0,hint_publication=0)
            return dict(present=1,control=control,advisory_rejected=1,native_refused=0,trace_ordinal=h[2],retained_serial=c.i(b,S,'serial'))
        zero(c.f(w,W,'changed_hint'),'positive advisory has no receipt mutation')
        need(h[3]==h[2]and h[4]==h[5]==h[2]+1 and h[6]==h[5]+1 and not any(h[20:]),'immediate actual hint NX and next native close ordinals')
        I='leto_hint_idle';idle0=c.f(w,W,'idle')
        selected=dict(ready=0,pending=1,outcome_complete=0,outcome_result=0,lookups=p['lookups']+1,hits=p['hits']+1,
            selected_publication=p['receipt_publication'],selected_serial=c.i(b,S,'serial'),selected_event=c.i(idle0,I,'events'),selected_pc=pc,
            selected_seeds=c.i(idle0,I,'seeds'),selected_published=c.i(l,'li2_native_pair_lifecycle','published'))
        changed(c,prior,after,T,selected,'whole actual one-use advisory selection without permission change')
        c.observation(c.f(A,S,'fresh'),pc,False,s['ref'])
        changed(c,b,A,S,dict(phase=6,fresh_borrow=s['borrow'],refault_attempted=1,refaulted=1,fresh=c.f(A,S,'fresh')),'whole genuine closed TRACE to consumed refault transition')
        need(c.f(c.f(A,S,'fresh'),'li2_span_fetch_observation','progress')==c.f(w,W,'fresh'),'whole released fresh borrow remains unchanged through advisory/refault')
        returned=c.normalized(c.f(w,W,'returned'),before);c.same_event(before,returned,before['greg'][17])
        nx=c.frame(c.f(w,W,'nx'),False);c.nx(nx,pc);want=list(before['greg']);want[17]|=65536;want[19],want[20],want[22]=21,14,pc
        need(nx['greg']==tuple(want)and nx['fp']==before['fp']and nx['fp_bytes']==before['fp_bytes']and nx['mask']==before['mask'],'all23 actual advisory TRACE-to-NX GREG and complete FP/mask')
        result=native(c,w,before,nx)
        admitted=c.f(w,W,'admitted');life=c.f(admitted,'leto_owners','lifecycle');slot=c.r.items(life,'li2_native_pair_lifecycle','slots','li2_native_pair_slot')[0]
        outcome=c.f(w,W,'outcome_hint');receipt(c,outcome)
        changes=dict(ready=1,pending=0,outcome_complete=1,outcome_result=1,publications=p['publications']+1,next_nx=p['next_nx']+1,admitted=p['admitted']+1,
            receipt_sequence=c.i(life,'li2_native_pair_lifecycle','sequence'),receipt_publication=c.i(life,'li2_native_pair_lifecycle','published'),receipt=slot)
        changed(c,after,outcome,T,changes,'whole actual next-NX publication and admission outcome')
        need(c.counts['graph_refaults']>0 and terminal['hits']>=p['hits']+1,'observed positive advisory is in actual terminal graph-retry population')
        return dict(present=1,control=0,trace_ordinal=h[2],nx_ordinal=h[4],closed_ordinal=h[6],retained_serial=c.i(b,S,'serial'),**result)
    finally:c.head,c.page,c.app,c.h=saved
