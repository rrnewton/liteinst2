/* Capture-only finite D3 evidence. No callback supplies a token, owner count,
   closure or source permission. Every snapshot follows the real owner gate. */
#include "resident_three_observe.h"
#define R3O_MAGIC UINT64_C(0x3152334f5732494c)
#define R3O_FOOTER UINT64_C(0x3152334f4632494c)
struct r3o_scan { uint64_t compared,differences,first_offset,expected,actual; };
struct r3o_state {
    unsigned phase,busy,active,consumed,released,exit_seen,first_error,registry_bound;
    long first_detail;
    uint64_t serial,publications,entries,completed,cancelled,unexpected,ingresses;
    uintptr_t arena,directory,root;
    unsigned count,planned,exit_member,exit_index,registry_count;
    struct li2_r3_token token;
    struct li2_rsl_ref source;
    unsigned source_pages;
    uint64_t flags,gpr_written,flags_written;
    unsigned references[3],closed[3],installed[3];
    uint64_t generation[3];
    struct li2_fetch_progress fetch;
    struct li2_r3_rseq_progress rseq;
    struct li2_rsl_progress source_progress;
    struct li2_rsl_resident_progress resident_progress;
    struct li2_maps_stats maps;
};
struct r3o_certificate {
    struct li2_sealed_identity identity;
    struct r3_payload payload;
    unsigned char proof_tail[R3_PROOF_BYTES-sizeof(struct r3_payload)];
    unsigned char code[R3_CODE_BYTES],slots[PAGE],spill_entered[PAGE],spill_closed[PAGE];
    struct li2_sealed_code_query published[3],opened[3],drained[3],proof[2];
    struct li2_private_code_query slot_query[2],spill_query[2];
    struct r3o_scan proof_scan,code_scan,slot_scan;
};
struct r3o_wire {
    uint64_t h[48],ingress[6];
    uint64_t bootstrap[9];
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct li2_span_transfer_progress transfer;
    struct li2_span_fetch_observation held;
    struct r3o_state entered,terminal,closed,final;
    struct le_frame before,after,next;
    struct li2_r3o_memory memory[3];
    struct li2_fork_range registry[RANGES];
    struct li2_pg_source_page source[LI2_RSL_PAGES];
    struct r3o_certificate certificate[3];
    unsigned char directory[LI2_JD_DOMAIN_BYTES];
    struct li2_private_code_query directory_query[2];
    struct r3o_scan directory_scan,unexpected_scan;
    struct li2_tf_chain_slot next_closed;
};
static struct r3o_wire r3o_wire;
static unsigned r3o_ready,r3o_frozen,r3o_busy,r3o_finished;
static const uint64_t r3o_step_frame_fp_alignment __attribute__((used))=
    __alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct r3o_wire)+64<4U*1024U*1024U,"unchanged strict owned-record ceiling");
static void r3o_callback(void) {
    if(r3o_frozen){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
static void r3o_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void r3o_compare(struct r3o_scan *o,const void *expected,const void *actual,size_t bytes) {
    const unsigned char *a=expected;const volatile unsigned char *b=actual;
    for(size_t i=0;i<bytes;i++) {
        unsigned char x=b[i],y=a?a[i]:0;
        if(x!=y){if(!o->differences){o->first_offset=o->compared;o->expected=y;o->actual=x;}++o->differences;}
        ++o->compared;
    }
    r3_need(!o->differences,R3_RESULT,110);
}
/* The old two-member owner may have rebound source after the last guest RAW.
   Retain its complete actual progress immediately before the real D3 bind;
   this copy supplies no token, validation or source permission. */
static void r3o_source_before_bind(void) {
    r3o_callback();uint64_t *h=r3o_wire.h;
    _Static_assert(sizeof(struct li2_rsl_progress)==7U*sizeof(uint64_t),
        "whole source progress occupies the seven reserved header words");
    r3_need(r3o_ready && !r3o_busy && !h[24] && !h[41] &&
        r3.phase==LI2_R3_HELD && r3.busy && !r3.active && r3.serial==1 &&
        !r3.consumed && !r3.publications && !r3.entries,R3_STATE,126);
    const struct li2_rsl_progress *p=li2_rsl_progress();
    const struct li2_rsl_resident_progress *r=li2_rsl_resident_progress();
    r3_need(p->initialized==1 && p->valid<=1 && p->epoch && !p->reserved &&
        p->pages && p->pages<=LI2_RSL_PAGES && p->bindings<UINT64_MAX &&
        !r->last_serial && !r->bindings && !r->snapshots && !r->plans &&
        !r->validations && !r->authentications,R3_SOURCE,127);
    r3o_copy(h+41,p,sizeof *p);
}
static void r3o_state(struct r3o_state *o) {
#define O(n) o->n=r3.n
    O(phase);O(busy);O(active);O(consumed);O(released);O(exit_seen);O(first_error);O(first_detail);
    O(registry_bound);O(serial);O(publications);O(entries);O(completed);O(cancelled);O(unexpected);O(ingresses);
    O(arena);O(directory);O(root);O(count);O(planned);O(exit_member);O(exit_index);O(registry_count);
    O(token);O(source);O(source_pages);O(flags);O(gpr_written);O(flags_written);
#undef O
    for(unsigned i=0;i<3;i++) {
        o->references[i]=r3.certificate[i].active_refs;o->closed[i]=r3.certificate[i].closed;
        o->installed[i]=r3.certificate[i].installed;o->generation[i]=r3.certificate[i].generation;
    }
    r3o_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    r3o_copy(&o->rseq,li2_r3_rseq_progress(),sizeof o->rseq);
    r3o_copy(&o->source_progress,li2_rsl_progress(),sizeof o->source_progress);
    r3o_copy(&o->resident_progress,li2_rsl_resident_progress(),sizeof o->resident_progress);
    li2_maps_stats_read(&o->maps);
}
static void r3o_memory(unsigned site) {
    r3_need(site<3 && !li2_lifecycle_r3o_memory(r3o_wire.h[22],site,&r3o_wire.memory[site]),R3_FRAME,111);
    const struct li2_r3o_stack *a=&r3o_wire.memory[0].origin,*b=&r3o_wire.memory[site].origin;
    r3_need(a->anchor==b->anchor && a->origin_first==b->origin_first && a->origin_end==b->origin_end &&
        a->origin_acquisition==b->origin_acquisition && a->first==b->first && a->end==b->end &&
        a->first==r3o_wire.h[22]-256 && a->end==r3o_wire.h[22]+264,R3_FRAME,112);
    if(site)r3_need(equal(r3o_wire.memory[0].stack,r3o_wire.memory[site].stack,520),R3_RESULT,113);
}
static void r3o_initialize(void) {
    r3o_callback();__asm__ volatile(""::"r"(&r3o_step_frame_fp_alignment):"memory");
    r3_need(!r3o_ready && !r3o_finished && !r3.initialized && !original_main.bias,R3_STATE,100);
    uint64_t *h=r3o_wire.h;
    h[0]=R3O_MAGIC;h[1]=2;h[2]=sizeof r3o_wire;h[3]=sizeof r3;h[4]=sizeof(struct r3_payload);
    h[5]=R3_PROOF_BYTES;h[6]=R3_CODE_BYTES;h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);
    h[9]=(uintptr_t)&r3;h[10]=(uintptr_t)&r3o_wire;h[11]=(uintptr_t)&selected_chain;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    r3_need(!selected_run_protect_add(0,(uintptr_t)&r3o_wire,sizeof r3o_wire),R3_STATE,101);h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&r3o_wire.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    r3_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(r3o_wire.sink_initial.st_mode) && (r3o_wire.sink_initial.st_mode&07777)==0600 &&
        r3o_wire.sink_initial.st_nlink==1 && !r3o_wire.sink_initial.st_size,R3_STATE,102);h[18]=1;
    h[19]=LI2_R3_ROOT_RVA;h[20]=LI2_R3_TERMINAL_RVA;h[21]=LI2_R3_CAPTURE_RVA;
    h[23]=LI2_R3_CAPTURE_POINTER_RVA;
    r3o_copy(&r3o_wire.main,&original_main,sizeof original_main);
    r3o_copy(&r3o_wire.interpreter,&original_interpreter,sizeof original_interpreter);
    r3o_copy(&r3o_wire.hardware,&selected_hardware,sizeof selected_hardware);
    r3o_copy(&r3o_wire.session,&selected_session,sizeof selected_session);
    r3o_copy(r3o_wire.bootstrap,rsl_initialization,sizeof r3o_wire.bootstrap);
    const uint64_t *boot=r3o_wire.bootstrap;
    r3_need(selected_session.pid>0 && selected_session.pid==selected_session.tid &&
        boot[0]==(uint64_t)selected_session.pid && boot[1]==boot[0] && boot[2]==boot[0] &&
        boot[3]==boot[0] && boot[4]==boot[0] && !boot[5] && !boot[6] &&
        boot[7]==3*sizeof(uintptr_t) && boot[8]==1,R3_STATE,125);
    r3o_ready=1;
}
static void r3o_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    r3o_callback();if(!r3o_ready)return;
    r3_need(!r3o_busy && r3o_wire.ingress[0]!=UINT64_MAX,R3_STATE,103);
    ++r3o_wire.ingress[0];unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    r3_need(r3o_wire.ingress[i]!=UINT64_MAX,R3_STATE,104);++r3o_wire.ingress[i];
    uint64_t *h=r3o_wire.h;
    if(h[25] && !h[26]) {
        r3_need(!handling && uc && si && r3.phase==LI2_R3_DRAINED && !r3.active && !r3.busy &&
            r3o_wire.ingress[0]==h[29]+1 && selected_pending_route==SELECTED_GENERIC_TF &&
            selected_step_pending==1 && selected_chain.active>=0 && selected_chain.active<2 &&
            sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            (uintptr_t)si->si_addr==h[21] && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[21] &&
            uc->uc_mcontext.gregs[REG_TRAPNO]==1 && !uc->uc_mcontext.gregs[REG_ERR] &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_CR2]==h[20] &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==h[22] &&
            (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(UINT64_C(0x246)|SELECTED_TF),R3_EVENT,105);
        r3_need(!le_capture(&r3o_wire.next,sig,si,uc),R3_FRAME,106);
        h[26]=1;h[30]=r3o_wire.ingress[0];h[31]=(uint64_t)selected_chain.active;
    }
}
static void r3o_entered(const siginfo_t *si,const ucontext_t *uc) {
    r3o_callback();uint64_t *h=r3o_wire.h;
    r3_need(r3o_ready && !r3o_busy && !h[24] && !h[25] && r3.phase==LI2_R3_ACTIVE &&
        r3.active==1 && r3.busy==1 && r3.serial==1 && r3.count==3 && r3.planned==3 &&
        r3.publications==3 && r3.entries==1 && !r3.completed && !r3.ingresses && !r3.unexpected &&
        r3.consumed==1 && !r3.released && r3.registry_bound==1 && r3_registry() &&
        r3.before.complete==1 && r3.before.tls_complete==1 && le_unchanged(&r3.before,si,uc) &&
        r3.transfer.phase==LI2_ST_CONSUMED && r3.transfer.consumed==1 &&
        r3.source_pages>0 && r3.source_pages<=LI2_RSL_PAGES &&
        r3.root==h[19] && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[19] &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==UINT64_C(0xad7) &&
        uc->uc_mcontext.gregs[REG_RAX]==1 && uc->uc_mcontext.gregs[REG_RCX]==4 &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_R11]==h[23] &&
        selected_pending_route==SELECTED_RESIDENT_THREE && selected_step_pending==1,R3_STATE,114);
    r3o_busy=1;h[22]=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];h[28]=r3o_wire.ingress[0];
    r3o_copy(&r3o_wire.before,&r3.before,sizeof r3.before);
    r3o_copy(&r3o_wire.transfer,&r3.transfer,sizeof r3.transfer);
    r3o_copy(&r3o_wire.held,&r3.fetch,sizeof r3.fetch);
    r3o_copy(r3o_wire.registry,r3.registry,r3.registry_count*sizeof *r3.registry);
    for(unsigned i=0;i<r3.source_pages;i++)
        r3_need(!li2_rsl_page_at(&r3.source,i,&r3o_wire.source[i]),R3_SOURCE,115);
    for(unsigned i=0;i<3;i++) {
        const struct r3_certificate *c=&r3.certificate[i];struct r3o_certificate *o=&r3o_wire.certificate[i];
        r3_need(c->active_refs==1 && !c->closed && c->installed==1 && c->generation==i+1 &&
            !r3_bytes(i),R3_PUBLICATION,116);
        r3o_copy(&o->identity,&c->identity,sizeof o->identity);
        r3o_copy(&o->payload,(const void *)c->proof,sizeof o->payload);
        r3o_copy(o->proof_tail,(const void *)(c->proof+sizeof o->payload),sizeof o->proof_tail);
        r3o_copy(o->code,(const void *)c->identity.code,sizeof o->code);
        r3_need(!li2_lifecycle_private_code_query(c->layout.slots,PAGE,PROT_READ,&o->slot_query[0]) &&
            !li2_lifecycle_private_code_query(c->layout.spill,PAGE,PROT_READ|PROT_WRITE,&o->spill_query[0]),
            R3_PUBLICATION,117);
        r3o_copy(o->slots,(const void *)c->layout.slots,PAGE);
        r3o_copy(o->spill_entered,(const void *)c->layout.spill,PAGE);
        r3o_copy(o->published,c->published,sizeof o->published);
        r3o_copy(o->opened,c->opened,sizeof o->opened);
        r3o_copy(o->proof,c->proof_query,sizeof o->proof);
    }
    r3_need(!li2_lifecycle_private_code_query(r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,
        &r3o_wire.directory_query[0]) && r3_directory_equal(),R3_PUBLICATION,118);
    r3o_copy(r3o_wire.directory,(const void *)r3.directory,LI2_JD_DOMAIN_BYTES);
    r3o_memory(0);r3o_state(&r3o_wire.entered);h[24]=1;r3o_busy=0;
}
static void r3o_terminal(void) {
    r3o_callback();uint64_t *h=r3o_wire.h;
    r3_need(r3o_ready && !r3o_busy && h[24]==1 && !h[25] && !h[26] &&
        r3.phase==LI2_R3_DRAINED && !r3.busy && !r3.active && r3.serial==1 &&
        r3.publications==3 && r3.entries==1 && r3.completed==1 && r3.ingresses==1 &&
        !r3.unexpected && !r3.first_error && r3.consumed==1 && r3.released==1 &&
        r3.exit_seen==1 && r3_registry() && r3o_wire.ingress[0]==h[28]+1 &&
        r3.after.complete && r3.after.tls_complete && r3.after.sig==SIGSEGV &&
        (uintptr_t)r3.after.frame.greg[REG_RIP]==h[20] &&
        (uintptr_t)r3.after.frame.greg[REG_RSP]==h[22] &&
        r3.after.frame.greg[REG_RAX]==29 && !r3.after.frame.greg[REG_RCX] &&
        (uint64_t)r3.after.frame.greg[REG_EFL]==(UINT64_C(0x246)|SELECTED_RF) &&
        selected_pending_route==SELECTED_NO_STEP && !selected_step_pending,R3_STATE,119);
    r3o_busy=1;r3o_copy(&r3o_wire.after,&r3.after,sizeof r3.after);
    for(unsigned i=0;i<3;i++) {
        const struct r3_certificate *c=&r3.certificate[i];struct r3o_certificate *o=&r3o_wire.certificate[i];
        r3_need(!c->active_refs && c->closed==1 && c->generation==i+1 &&
            equal(&o->identity,&c->identity,sizeof o->identity),R3_PUBLICATION,120);
        r3o_copy(o->drained,c->drained,sizeof o->drained);
        r3o_compare(&o->proof_scan,&o->payload,(const void *)c->proof,sizeof o->payload);
        r3o_compare(&o->proof_scan,o->proof_tail,(const void *)(c->proof+sizeof o->payload),sizeof o->proof_tail);
        r3o_compare(&o->code_scan,o->code,(const void *)c->identity.code,R3_CODE_BYTES);
        r3o_compare(&o->slot_scan,o->slots,(const void *)c->layout.slots,PAGE);
        r3_need(!li2_lifecycle_private_code_query(c->layout.slots,PAGE,PROT_READ,&o->slot_query[1]) &&
            !li2_lifecycle_private_code_query(c->layout.spill,PAGE,PROT_READ|PROT_WRITE,&o->spill_query[1]),
            R3_PUBLICATION,121);
        r3o_copy(o->spill_closed,(const void *)c->layout.spill,PAGE);
    }
    r3_need(!li2_lifecycle_private_code_query(r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,
        &r3o_wire.directory_query[1]),R3_PUBLICATION,122);
    r3o_compare(&r3o_wire.directory_scan,r3o_wire.directory,(const void *)r3.directory,LI2_JD_DOMAIN_BYTES);
    r3o_memory(1);r3o_state(&r3o_wire.terminal);h[29]=r3o_wire.ingress[0];h[25]=1;r3o_busy=0;
}
void li2_r3o_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    r3o_callback();if(!r3o_ready || !r3o_wire.h[25] || r3o_wire.h[27])return;
    uint64_t *h=r3o_wire.h;unsigned selected=(unsigned)h[31];
    r3_need(!r3o_busy && h[26]==1 && selected<2 && h[30]==h[29]+1 &&
        h[30]==r3o_wire.ingress[0] && chain==&selected_chain && slot==&chain->slots[selected] &&
        chain->active==(int)selected && chain->in_handler==1 && chain->pending==1 && handling==1 &&
        chain->event_id>slot->event_id && !chain->first_error && !chain->unexpected_events &&
        slot->phase==LI2_CHAIN_CLOSED && !slot->unexpected_frame_observed &&
        slot->decoded.pc==h[20] && slot->owner.actual_post_pc==h[21] &&
        r3o_wire.next.complete && (uintptr_t)r3o_wire.next.frame.greg[REG_RIP]==h[21],R3_STATE,123);
    r3o_busy=1;r3o_copy(&r3o_wire.next_closed,slot,sizeof *slot);
    r3o_compare(&r3o_wire.unexpected_scan,0,&slot->unexpected,sizeof slot->unexpected);
    r3_tls(&r3o_wire.next);r3o_memory(2);r3o_state(&r3o_wire.closed);
    h[27]=1;h[32]=chain->event_id;r3o_busy=0;
}
static void r3o_finish(unsigned status,unsigned code,long detail) {
    if(!r3o_ready || r3o_finished)return;
    r3o_finished=1;uint64_t *h=r3o_wire.h;
    unsigned incomplete=h[24]!=1 || h[25]!=1 || h[26]!=1 || h[27]!=1 ||
        r3o_busy || r3o_wire.next.tls_complete!=1 || r3o_wire.memory[2].complete!=1 ||
        r3.publications!=3 || r3.entries!=1 || r3.completed!=1 || r3.ingresses!=1 ||
        r3.active || r3.busy || r3.first_error || r3.unexpected;
    unsigned forced=!status && incomplete;
    if(forced){status=125;code=R3_STATE;detail=124;}
    h[33]=incomplete;h[34]=status;h[35]=code;h[36]=(uint64_t)detail;h[37]=1;
    r3o_state(&r3o_wire.final);
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&r3o_wire.sink_terminal,0,0,0,0);h[38]=(uint64_t)flags;h[39]=(uint64_t)result;
    const struct stat *a=&r3o_wire.sink_initial,*b=&r3o_wire.sink_terminal;
    unsigned sink_ok=!result && flags==(long)h[16] && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
        a->st_nlink==b->st_nlink && !b->st_size;
    if(sink_ok) {
        h[40]=1;r3o_frozen=1;__asm__ volatile("":::"memory");
        size_t at=0;uint64_t calls=0;result=0;
        while(at<sizeof r3o_wire && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)&r3o_wire+at),sizeof r3o_wire-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof r3o_wire-at)goto done;
            at+=(size_t)result;
        }
        if(at!=sizeof r3o_wire)goto done;
        const uint64_t footer[]={R3O_FOOTER,2,sizeof r3o_wire,at,calls,(uint64_t)result,status,code};
        at=0;calls=0;
        while(at<sizeof footer && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof footer-at)goto done;
            at+=(size_t)result;
        }
    }
done:
    if(forced || !sink_ok){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
