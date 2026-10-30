"""Exact actual TRACE/released-borrow/NX/native-pair witness; no execution authority."""
import struct

def need(value,message):
    if not value:raise ValueError(message)
def zero(value,message):need(not any(value),message)
def q(value):return struct.unpack('<'+'Q'*(len(value)//8),value)

def closed(c,chain,transfer,ingress):
    t='li2_span_transfer_progress';previous=c.i(transfer,t,'previous');need(previous<2,'retry actual predecessor index')
    c.eq(chain,'li2_tf_chain',initialized=1,first_error=0,first_detail=0,in_handler=0,pending=0,active=previous,event_id=c.i(transfer,t,'event'))
    s=c.r.items(chain,'li2_tf_chain','slots','li2_tf_chain_slot')[previous];st='li2_tf_chain_slot'
    c.eq(s,st,phase=5,fallback=0,unexpected_frame_observed=0,generation=c.i(transfer,t,'previous_generation'))
    o=c.f(s,st,'owner');step=c.f(o,'li2_tf_owner','step')
    c.eq(step,'li2_step_owner',phase=5,first_error=0,first_detail=0,in_handler=0,trace_seen=1,revoke_sync_started=1,open_sync=0,revoke_sync=0)
    c.eq(o,'li2_tf_owner',continuation_started=1,continuation_complete=1,continuation_result=0,unexpected_frame_observed=0,actual_post_pc=c.head,actual_post_flags=ingress['greg'][17])
    c.step_frame(c.f(step,'li2_step_owner','after'),ingress)
    n=c.i(c.f(step,'li2_step_owner','request'),'li2_step_request','page_count');need(n==1,'actual same-page closed predecessor')
    for k in('open_started','opened','revoke_started','revoked'):need(struct.unpack('<2I',c.f(step,'li2_step_owner',k))==(1,0),'retry predecessor exact full permission actions')
    for k in('open_result','revoke_result'):zero(c.f(step,'li2_step_owner',k),'retry predecessor permission results')
    c.eq(c.f(s,st,'query'),'li2_tf_continuation',attempted=1,page_observed=1,complete=1,result=0,pc=c.head)
    c.eq(c.f(s,st,'release'),'li2_chain_release',started=1,complete=1,result=0)
    fetch=c.f(s,st,'fetch');priorpc=c.i(fetch,'li2_chain_fetch','pc');ref=c.chain_fetch(fetch,priorpc,False)
    need(c.i(ref,'li2_fetch_ref','sequence')==c.i(transfer,t,'previous_borrow'),'retry predecessor actual released ref')
    c.observation(c.f(transfer,t,'released'),priorpc,False,ref)

def native(c,w,before,nx):
    wt='lpef_refault';a,b,z=(c.f(w,wt,k)for k in('native_before','native_admitted','native_closed'))
    c.owners(a);c.owners(z)
    P,L,R='li2_native_pair_progress','li2_native_pair_lifecycle','li2_rseq_pair_progress'
    ap,al,ar=(c.f(a,'lpef_owners',k)for k in('pair','lifecycle','rseq_pair'))
    bp,bl,br=(c.f(b,'lpef_owners',k)for k in('pair','lifecycle','rseq_pair'))
    zp,zl,zr=(c.f(z,'lpef_owners',k)for k in('pair','lifecycle','rseq_pair'))
    c.eq(b,'lpef_owners',captured=1,word=0,word_observed=0)
    c.eq(bp,P,initialized=1,phase=4,in_handler=0,first_error=0,first_detail=0,live=1,entry_pending=0,first_observed=1,second_observed=0,pid=c.pid,tid=c.pid,session=c.symbol('selected_session'),signal_number=11,signal_code=2,signal_errno=0,pc=c.head,signal_address=c.head)
    c.step_frame(c.f(bp,P,'first'),nx)
    for key in('events','seeds'):need(c.i(bp,P,key)==c.i(ap,P,key)+1,'retry actual one native seed')
    for key in('extensions','epochs_closed','one_page_closes','two_page_closes','policy_closes','capacity_closes','refaults','refault_completed'):need(c.i(bp,P,key)==c.i(ap,P,key),'no invented native predecessor completion')
    c.eq(bl,L,initialized=1,busy=0,live=1,first_error=0,first_detail=0,opening=0,post_verified=1,pid=c.pid,tid=c.pid,candidate=c.head,candidate_policy=0,candidate_eligible=1)
    for key in('sequence','attempts','published'):need(c.i(bl,L,key)==c.i(al,L,key)+1,'exact actual native page admission')
    for key in('closed_pages','close_calls'):need(c.i(bl,L,key)==c.i(al,L,key),'admission does not invent closure')
    c.maps(c.f(bl,L,'before'));c.maps(c.f(bl,L,'after'))
    slots=c.r.items(bl,L,'slots','li2_native_pair_slot');s=slots[0];T='li2_native_pair_slot';zero(slots[1],'no second published page on initial retry seed')
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
    for k in('before','after'):zero(c.f(br,R,k),'unregistered retry pair has no invented pin')
    need(c.i(br,R,'owner')==c.i(bl,L,'owner')==c.i(ar,R,'owner'),'actual same private native/rseq owner')
    for k in('attempts','published'):need(c.i(br,R,k)==c.i(ar,R,k)+1,'actual rseq-bound native seed/publication')
    need(c.v(br,R,'fs_before gs_before')==(before['fs'],before['gs']),'native actual TLS seed equals closed TRACE observation')
    state=c.f(b,'lpef_owners','rseq');c.eq(state,'li2_rseq_state',initialized=1,registered=0,held=0,phase=0,first_error=0,first_detail=0,pid=c.pid,tid=c.pid,tls_attempted=1,tls_complete=1,fs_result=0,gs_result=0,fs_base=before['fs'],gs_base=before['gs'])
    c.r.change(c.f(a,'lpef_owners','rseq'),state,'li2_rseq_state',observed=('fs_base','gs_base','fs_result','gs_result','tls_attempted','tls_complete'))
    need(c.f(z,'lpef_owners','rseq')==state,'complete retry native excursion preserves registration and static NONE history')
    zero(c.f(b,'lpef_owners','rseq_native'),'no one-page native owner invented by retry')
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
    W,T='lpef_refault','li2_span_transfer_progress';w=c.f(c.b,'lpef_wire','refault');h=q(c.f(w,W,'h'));control=c.refault_control
    need(h[0]==control and not any(h[7:8]+h[18:]),'exact retry control and unused witness header')
    required=bool(control)or(c.app['mode']==5 and not c.control)
    if not h[1]:
        need(not required,'mandatory genuine helper retry witness');zero(w,'no partial or invented absent retry witness');return dict(present=0)
    need(h[1]==1 and h[2]>0,'actual positive retry observation ordinal')
    need(h[2]<=q(c.f(c.b,'lpef_wire','raw_ingress'))[0],'retry ordinal belongs to actual ingress population')
    r=c.f(w,W,'record');R='le_record';source=c.f(r,R,'source');key=c.f(source,'li2_span_source','key');pc=c.i(key,'li2_span_source_key','entry');page=pc&-4096
    need(pc>=0x200000000 and 0<=pc-page<=4096-15,'real high main helper source')
    obj,_,loads=c.objects[c.image['main_object']];bias=c.bases[c.image['main_object']]
    rows=[p for p in loads if p[1]==5 and bias+p[3]<=page and page+4096<=bias+p[3]+p[5]];need(len(rows)==1,'one actual immutable main helper page')
    off=rows[0][2]+page-bias-rows[0][3];data=obj['data'][off:off+4096]
    saved=c.head,c.page,c.app,c.h;c.head=pc;c.page=page;c.app=dict(c.app,source=data);c.h=list(c.h);c.h[21]=off
    try:
        s=c.source(source);before=c.frame(c.f(r,R,'before'));ingress=c.normalized(c.f(r,R,'ingress'),before)
        c.trace(ingress,pc,before['greg'][17]|256);c.same_event(ingress,before,before['greg'][17])
        need(not before['greg'][17]&(256|65536),'retry returns logical flags without TF/RF invention')
        c.eq(r,R,slot_present=0,redirected=0,exit_seen=0,completed=0,build_started=1,build_returned=1,build_result=2404,close_started=1,close_complete=1,prepare_started=1,prepare_complete=1,prepare_result=0,resume_started=0,resume_complete=0,resume_result=0)
        if c.native_hint:c.eq(r,R,hint_checked=0,hint_hit=0,hint_publication=0)
        bt=c.f(w,W,'before_transfer');c.eq(bt,T,phase=2,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0,first_error=0,first_detail=0,pc=pc,flags=before['greg'][17],refault_attempted=0,refaulted=0)
        need(c.i(bt,T,'serial')==h[11]>0 and c.i(bt,T,'previous_borrow')<s['borrow'],'current retained serial and strictly newer real source borrow')
        zero(c.f(bt,T,'fresh'),'fresh observation is obtained only inside actual retry API')
        closed(c,c.f(w,W,'closed_chain'),bt,ingress)
        c.progress(c.f(w,W,'before_fetch'),s['borrow'],control==3)
        c.owners(c.f(w,W,'native_before'))
        tr=c.f(r,R,'transfer');complete=int(control in(0,2));code={0:0,1:3002,2:3002,3:3001,4:3003}[control];detail=0 if not control else 5 if control in(1,2)else 3
        c.eq(tr,T,phase=6 if complete else 2,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0,first_error=code,first_detail=detail,pc=pc,flags=before['greg'][17],serial=h[11],refault_attempted=complete,refaulted=complete)
        need(c.f(tr,T,'released')==c.f(bt,T,'released'),'whole original predecessor release remains exact')
        if complete:
            c.observation(c.f(tr,T,'fresh'),pc,False,s['ref']);c.eq(tr,T,fresh_borrow=s['borrow'])
        else:zero(c.f(tr,T,'fresh'),'rejected retry does not invent consumed fresh observation');c.eq(tr,T,fresh_borrow=0)
        c.eq(r,R,refault_started=complete,refault_complete=complete,refault_result=0,miss_release_started=int(control!=3),miss_release_complete=int(control!=3),miss_release_result=0)
        if control==3:zero(c.f(r,R,'miss_fetch'),'held-borrow refusal precedes real release')
        else:c.progress(c.f(r,R,'miss_fetch'),s['borrow'],False)
        scratch=c.f(w,W,'scratch');c.eq(scratch,'li2_preedge_plan',version=2,bytes=40744,reserved=0,ready=0,entry=pc,page=page,decoder_result=0)
        need(c.f(scratch,'li2_preedge_plan','source')==data and 0<c.i(scratch,'li2_preedge_plan','heads')<=64 and 0<c.i(scratch,'li2_preedge_plan','exits')<=8,'actual full source and bounded discovered graph before relocation refusal')
        generated=c.i(scratch,'li2_preedge_plan','generated');need(generated%4096==0 and c.storage[0]<=generated<c.storage[0]+c.storage[2],'actual chosen high code arena for refused relocation')
        if control:
            need(h[12:18]==(1,h[8]if control==1 else h[11],1,code,1,h[2]),'real negative call, exact error, and terminal observation')
            need(not any(h[3:7]),'required retry refusal never returns or claims native execution')
            need(r==c.f(c.b,'lpef_wire','terminal_record'),'whole actual failed retry is terminal current record')
            if control==1:
                p=c.f(w,W,'prior');c.eq(p,T,phase=6,serial=h[8],issued=1,refault_attempted=1,refaulted=1,first_error=0,first_detail=0)
                need(0<h[8]<h[11]and 0<h[9]<h[10]<h[2],'genuine completed older serial tested against newer real CLOSED occupation')
                c.eq(c.f(w,W,'prior_close'),'li2_native_close',complete=1,first_error=0,pages=1,closed=1,verified=1)
            else:
                need(not any(h[8:11]),'no invented retained prior serial');zero(c.f(w,W,'prior'),'unused prior token whole zero');zero(c.f(w,W,'prior_close'),'unused prior close whole zero')
            for k in('returned','nx','native_admitted','native_closed'):zero(c.f(w,W,k),'negative retry never invents hardware/native completion')
            if control==4:
                changed=c.frame(c.f(w,W,'changed'),False);want=bytearray(c.f(r,R,'before'));F=c.r.types['le_frame']['fields'];G=c.r.types['li2_step_frame']['fields'];actual=c.f(w,W,'changed')
                for a in(F['uc']['offset']+40+13*8,F['frame']['offset']+G['greg']['offset']+13*8):struct.pack_into('<Q',want,a,struct.unpack_from('<Q',want,a)[0]^1)
                for k in('fs','gs','fs_result','gs_result','tls_complete'):f=F[k];want[f['offset']:f['offset']+f['bytes']]=actual[f['offset']:f['offset']+f['bytes']]
                need(bytes(want)==actual,'actual changed-frame stimulus is exactly RAX xor1 in UC and full frame')
            else:zero(c.f(w,W,'changed'),'no invented saved-frame mutation')
            return dict(present=1,control=control,required_refusal=code,retained_serial=h[11])
        need(h[3]==h[2]and h[4]==h[5]==h[3]+1 and h[6]==h[5]+1 and not any(h[8:11]+h[12:]),'immediate actual NX followed by exactly one native boundary and complete close')
        zero(c.f(w,W,'prior'),'normal retry no stale token');zero(c.f(w,W,'prior_close'),'normal retry no prior close');zero(c.f(w,W,'changed'),'normal retry no frame stimulus')
        returned=c.normalized(c.f(w,W,'returned'),before);c.same_event(before,returned,before['greg'][17])
        nx=c.frame(c.f(w,W,'nx'),False);c.nx(nx,pc);expected=list(before['greg']);expected[17]|=65536;expected[19],expected[20],expected[22]=21,14,pc
        need(nx['greg']==tuple(expected)and nx['fp']==before['fp']and nx['fp_bytes']==before['fp_bytes']and nx['mask']==before['mask'],'all23 actual retry-to-NX GREG including AF and whole FP/mask')
        out=native(c,w,before,nx)
        return dict(present=1,control=0,retained_serial=h[11],trace_ordinal=h[2],nx_ordinal=h[4],closed_ordinal=h[6],**out)
    finally:c.head,c.page,c.app,c.h=saved


def terminal_state(c):
    t='li2_span_transfer_progress';b=c.f(c.b,'lpef_wire','terminal_transfer');r=c.f(c.b,'lpef_wire','terminal_record');R='le_record'
    need(c.counts['refaults']<=q(c.f(c.b,'lpef_wire','events'))[9],'actual retry count bounded by actual relocation refusals')
    phase=c.i(b,t,'phase');done=phase==6
    need(c.v(b,t,'refault_attempted refaulted')==((1,1)if done else(0,0))and c.v(r,R,'refault_started refault_complete refault_result')==((1,1,0)if done else(0,0,0)),'actual terminal retry phase and completion fields')
    if done:
        c.eq(r,R,slot_present=0,redirected=0,completed=0,build_started=1,build_returned=1,build_result=2404,close_complete=1,prepare_complete=1,miss_release_complete=1,miss_release_result=0,resume_started=0,resume_complete=0)
        need(c.counts['refaults']>0 and c.i(b,t,'serial')==c.counts['offers']and c.i(b,t,'pc')>=0x200000000 and 0<c.i(b,t,'previous_borrow')<c.i(b,t,'fresh_borrow'),'terminal retry is actual high relocation miss and newer released borrow')
        c.eq(b,t,issued=1,consume_attempted=0,consumed=0,resume_attempted=0,resumed=0,successor_installed=0)
        c.progress(c.f(r,R,'miss_fetch'),c.i(b,t,'fresh_borrow'),False)
        fresh=c.f(b,t,'fresh');F='li2_span_fetch_observation'
        c.eq(fresh,F,complete=1,pc=c.i(b,t,'pc'),length=15,page_count=1,pid=c.pid,tid=c.pid)
        c.eq(c.f(fresh,F,'ref'),'li2_fetch_ref',sequence=c.i(b,t,'fresh_borrow'))
        need(c.f(fresh,F,'progress')==c.f(r,R,'miss_fetch'),'whole actual terminal released fresh observation')
