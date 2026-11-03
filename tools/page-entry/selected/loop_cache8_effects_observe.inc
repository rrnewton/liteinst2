/* Actual effect observations only. No permit, generation, RIP or return value
   is assigned here. The sole guest write is a descriptive private-address
   mailbox after its genuine RW/NX and private-range checks. */
#include "loop_cache8_effects_observe.h"
#define LC8E_MAGIC UINT64_C(0x314538434132494c)
#define LC8E_FOOTER UINT64_C(0x314645384332494c)
enum { LC8E_BINDS=32 };
struct lc8e_step {uint64_t h[16],greg[23];unsigned char fp[65536];};
struct lc8e_slot {uint64_t h[64];struct lc8e_step before,after,unexpected;};
struct lc8e_bind {uint64_t h[32],member[8][16];unsigned char directory[12288];};
struct lc8e_wire {
    uint64_t h[32],calls[2][32],counts[8][32],code[4][3][3][16];
    struct lc8e_memory memory[7];
    struct lc8e_bind bind[LC8E_BINDS];
    struct li2_pg_source_key new_b;
    struct lc8e_slot slot[2];
};
_Static_assert(sizeof(struct lc8e_step)==65848 && sizeof(struct lc8e_slot)==198056 &&
    sizeof(struct lc8e_bind)==13568,"fixed real-effect scalar/frame wire");
_Static_assert(sizeof(struct lc8e_wire)==1092536,"literal real-effect appended wire");
_Static_assert(sizeof(struct lc8e_wire)+sizeof(struct lc8o_wire)+128<4U*1024U*1024U,
    "unchanged bounded descriptor capacity");
static struct {
    struct lc8e_wire wire;
    struct li2_pgd_ref saved[3];
    struct li2_private_code_query query[4][3][3];
    unsigned initialized,first,unsafe,issued,returned,binds,active,finished,reported;
} lc8e;
static void lc8e_memory(unsigned index) {
    lc8o_need(index<7 && !li2_lifecycle_cache8_effects_memory(&lc8e.wire.memory[index]),50+index);
    const struct lc8e_memory *m=&lc8e.wire.memory[index];
    lc8o_need(m->h[1]==1 && m->h[4]==6 && m->h[5]==24576 && m->h[6]==8192 && m->h[7]==224,57);
    if(index)lc8o_need(equal(m->source,lc8e.wire.memory[0].source,sizeof m->source),58);
}
static int lc8e_initialize(void) {
    if(lc8e.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lc8e,sizeof lc8e))return PE_STATE;
    uint64_t *h=lc8e.wire.h;h[0]=LC8E_MAGIC;h[1]=2;h[2]=sizeof lc8e.wire;
    h[3]=LI2_LOOP_CACHE8_CONTROL;h[4]=(uintptr_t)&lc8e;h[5]=LC8E_BINDS;
    lc8e.initialized=1;return 0;
}
static void lc8e_closed(unsigned stage,unsigned identity) {
    lc8o_need(stage<4 && !pe_active,59);
    for(unsigned i=0;i<3;i++) {
        const struct li2_pgd_ref *s=&lc8e.saved[i];
        lc8o_need(s->slot<8,60);
        if(identity) {
            const struct li2_pg_generation *g=&pe.retained[s->slot].generation;
            lc8o_need(g->generation==s->generation && g->installed==1 && g->complete==1 &&
                !g->domain_refs && !g->active_refs && !g->linked && !g->member_refs[0] &&
                !g->member_refs[1] && !g->incoming[0] && !g->incoming[1] &&
                pe.rx.slot[s->slot].phase==LPRX_REVOKED,61);
        }
        lc8o_need(!pg_queries(&s->layout,PROT_READ,lc8e.query[stage][i]),62);
        for(unsigned j=0;j<3;j++) {
            const struct li2_private_code_query *q=&lc8e.query[stage][i][j];
            const uint64_t v[]={q->first,q->end,q->first_vma,q->last_vma_end,q->pages_checked,
                q->attempted,q->complete,(uint64_t)q->expected_prot,(uint64_t)q->actual_prot,
                (uint64_t)q->result,(uint64_t)q->detail,q->maps.observation.acquisition_id,
                q->maps.observation.handler_id,q->maps.observation.mutation_epoch,
                q->maps.observation.kind,q->maps.observation.io_performed};
            copy(lc8e.wire.code[stage][i][j],v,sizeof v);
            lc8o_need(q->attempted==1 && q->complete==1 && !q->result &&
                q->expected_prot==PROT_READ && q->actual_prot==PROT_READ,63);
        }
    }
}
static void lc8e_completed_first(const struct pda_completion *c) {
    if(lc8o.epochs!=3)return;
    lc8o_need(lc8e.initialized && !lc8e.first && c->count==3 && pda_receipt(c) &&
        c->member[0].identity.root==UINT64_C(0x414600) &&
        c->member[1].identity.root==UINT64_C(0x410200) &&
        c->member[2].identity.root==UINT64_C(0x412400),64);
    for(unsigned i=0;i<3;i++)lc8e.saved[i]=c->member[i].identity;
    lc8e_memory(0);lc8o_counts(lc8e.wire.counts[0]);
    for(unsigned i=0;i<32;i++)lc8o_need(!lc8e.wire.memory[0].state[i],65);
    lc8e.wire.h[6]=c->id;lc8e.wire.h[7]=c->serial;lc8e.first=1;
#if LI2_LOOP_CACHE8_CONTROL == 4
    const struct lc8o_member *b=&lc8o.wire.epoch[2].member[2];
    const struct pe_payload *payload=(const void *)lc8e.saved[2].proof;
    struct li2_pgs_target target;
    lc8o_need(li2_pgs_head_lookup(&payload->plan,UINT64_C(0x412400),&target)==1 &&
        target.root==UINT64_C(0x412400) && target.generated>=b->h[12] &&
        target.generated<UINTPTR_MAX && selected_run_protect_contains(target.generated+1,1),66);
    lc8e.wire.h[8]=target.generated;lc8e.wire.h[9]=target.generated+1;
    volatile uint64_t *state=(void *)LC8E_STATE;state[12]=target.generated+1;
    lc8o_need(state[12]==lc8e.wire.h[9],67);
#endif
}
static void lc8e_unsafe(unsigned reason) {
    if(!lc8e.first || lc8e.unsafe)return;
    lc8e_closed(0,1);lc8e_memory(1);lc8o_counts(lc8e.wire.counts[1]);
    lc8e.wire.h[10]=reason;lc8e.wire.h[11]=1;lc8e.unsafe=1;
}
static int lc8e_call(long n,const long a[6],const ucontext_t *uc,unsigned *index) {
    if(!lc8e.first || n!=SYS_mprotect || !uc)return 0;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(pc!=UINT64_C(0x41604a) && pc!=UINT64_C(0x416071))return 0;
    *index=pc==UINT64_C(0x41604a)?0U:1U;
    lc8o_need(LI2_LOOP_CACHE8_CONTROL==2 && a[0]==UINT64_C(0x412000) && a[1]==PAGE &&
        a[2]==(*index?PROT_READ|PROT_EXEC:PROT_READ),68);return 1;
}
static void lc8e_syscall_before(long n,const long a[6],const ucontext_t *uc) {
    unsigned i;if(!lc8e_call(n,a,uc,&i))return;
    lc8o_need(lc8e.unsafe && lc8e.issued==i && lc8e.returned==i && !pe_active && !pe_busy,69);
    uint64_t *h=lc8e.wire.calls[i];h[0]=1;h[2]=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];h[3]=(uint64_t)n;
    for(unsigned k=0;k<6;k++)h[4+k]=(uint64_t)a[k];
    lc8e_closed(i+1,1);lc8e_memory(2+2*i);lc8o_counts(lc8e.wire.counts[2+2*i]);++lc8e.issued;
}
static void lc8e_syscall_after(long n,const long a[6],long result,const ucontext_t *uc) {
    unsigned i;if(!lc8e_call(n,a,uc,&i))return;
    lc8o_need(lc8e.issued==i+1 && lc8e.returned==i && lc8e.wire.calls[i][0]==1,70);
    uint64_t *h=lc8e.wire.calls[i];h[1]=1;h[10]=(uint64_t)result;
    lc8e_memory(3+2*i);lc8o_counts(lc8e.wire.counts[3+2*i]);
    const struct lc8e_memory *before=&lc8e.wire.memory[2+2*i],*after=&lc8e.wire.memory[3+2*i];
    lc8o_need(!result && before->source_page[2][7]==(i?1U:5U) &&
        after->source_page[2][7]==(i?5U:1U) && before->source_page[2][8]==1 &&
        after->source_page[2][8]==1 && after->source_page[2][2]>before->source_page[2][2] &&
        after->life[1]==before->life[1]+1 && after->life[3]==before->life[3]+1 &&
        after->life[4]==before->life[4]+1 && after->life[5]==before->life[5],71);
    ++lc8e.returned;
}
static void lc8e_bound(void) {
    if(!lc8e.first || lc8e.finished)return;
    lc8o_need(!lc8e.active && lc8e.binds<LC8E_BINDS && pda_ready(0),72);
    const struct li2_pgd_view *v=&pe.domain.work.view;
    struct lc8e_bind *out=&lc8e.wire.bind[lc8e.binds];
    uint64_t *h=out->h;h[0]=1;h[4]=v->entry.target.pc;h[5]=pe.p.serial;h[6]=v->count;
    h[7]=pe.warm;h[8]=v->entry.slot;h[9]=v->entry.generation;h[10]=v->entry.target.generated;
    h[11]=v->directory;h[12]=lc8e.returned;copy(out->directory,(void *)v->directory,sizeof out->directory);
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pgd_member *m=&v->member[i];
        const struct li2_pg_generation *g=&pe.retained[m->identity.slot].generation;
        const uint64_t row[]={m->identity.slot,m->identity.bank,m->identity.generation,g->build_serial,
            m->identity.root,m->identity.proof,m->key->entry,m->key->page[0].identity.generation,
            m->key->page[1].identity.generation,m->plan->version,m->plan->heads,m->plan->exits,m->plan->links,
            m->identity.layout.generated[0],m->identity.layout.generated[1],m->identity.layout.stubs};
        copy(out->member[i],row,sizeof row);
        if(lc8e.returned && m->identity.root==UINT64_C(0x412400)) {
            lc8o_need(m->identity.generation!=lc8e.saved[2].generation &&
                m->key->page[0].identity.generation!=lc8o.wire.epoch[2].member[2].key.page[0].identity.generation &&
                equal(m->key->page[0].bytes,lc8e.wire.memory[0].source+2*PAGE,PAGE) &&
                equal(m->key->page[1].bytes,lc8e.wire.memory[0].source+3*PAGE,PAGE),73);
            if(!lc8e.wire.h[12]) {
                copy(&lc8e.wire.new_b,m->key,sizeof lc8e.wire.new_b);
                lc8e.wire.h[12]=m->identity.generation;lc8e.wire.h[13]=g->build_serial;
            }
        }
    }
    lc8e.active=++lc8e.binds;
}
static void lc8e_enter(void) {
    if(!lc8e.active)return;
    struct lc8e_bind *o=&lc8e.wire.bind[lc8e.active-1];
    lc8o_need(o->h[0]==1 && !o->h[1] && o->h[5]==pe.p.serial && pda_ready(1),74);
    o->h[1]=1;o->h[13]=pe.domain.work.rx_retained_mask;
}
static void lc8e_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!lc8e.active)return;
    struct lc8e_bind *o=&lc8e.wire.bind[lc8e.active-1];
    lc8o_need(o->h[1]==1 && !o->h[2] && si && uc,75);
    o->h[2]=1;o->h[14]=(unsigned)sig;o->h[15]=(uint64_t)si->si_code;
    o->h[16]=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];o->h[17]=(uintptr_t)si->si_addr;
}
static void lc8e_completed(const struct pda_completion *c) {
    if(!lc8e.active)return;
    struct lc8e_bind *o=&lc8e.wire.bind[lc8e.active-1];
    lc8o_need(o->h[2]==1 && !o->h[3] && c->serial==o->h[5] && c->count==o->h[6] && pda_receipt(c),76);
    o->h[3]=1;o->h[18]=c->id;o->h[19]=(uintptr_t)pe.after.frame.greg[REG_RIP];lc8e.active=0;
    if(o->h[19]==UINT64_C(0x41461c)) {
        lc8o_need(LI2_LOOP_CACHE8_CONTROL==2 && lc8e.returned==2 && lc8e.wire.h[12],77);
        lc8e.finished=1;lc8o_counts(lc8e.wire.counts[6]);
    }
}
static void lc8e_step(struct lc8e_step *out,const struct li2_step_frame *in) {
    out->h[0]=in->mask;out->h[1]=in->fp_address;out->h[2]=in->fp_bytes;out->h[3]=in->initialized;
    copy(out->greg,in->greg,sizeof out->greg);copy(out->fp,in->fp,sizeof out->fp);
}
static void lc8e_report(unsigned status,unsigned code) {
    if(!lc8e.initialized || lc8e.reported)return;
    lc8e.reported=1;
    uint64_t *h=lc8e.wire.h;h[14]=lc8e.first;h[15]=lc8e.unsafe;h[16]=lc8e.issued;h[17]=lc8e.returned;
    h[18]=lc8e.binds;h[19]=lc8e.active;h[20]=lc8e.finished;h[21]=status;h[22]=code;
    h[23]=selected_chain.first_error;h[24]=(uint64_t)selected_chain.first_detail;
    h[25]=(uint64_t)selected_chain.active;h[26]=selected_chain.unexpected_events;
    h[27]=pe.p.first_error;h[28]=(uint64_t)pe.p.first_detail;
    if(lc8e.first) {
        lc8e_closed(3,LI2_LOOP_CACHE8_CONTROL!=2);
#if LI2_LOOP_CACHE8_CONTROL != 2
        lc8e_memory(6);
#endif
    }
    lc8o_counts(lc8e.wire.counts[7]);
    for(unsigned i=0;i<2;i++) {
        const struct li2_tf_chain_slot *s=&selected_chain.slots[i];
        const struct li2_tf_owner *t=&s->owner;const struct li2_step_owner *p=&t->step;
        struct lc8e_slot *o=&lc8e.wire.slot[i];
        const uint64_t v[]={(uint64_t)s->phase,s->index,s->origin,s->fallback,s->generation,s->event_id,
            s->decoded.pc,s->decoded.code,s->decoded.length,s->unexpected_frame_observed,
            (uint64_t)s->unexpected_signal,(uint64_t)s->unexpected_code,(uint64_t)s->unexpected_errno,s->unexpected_address,
            (uint64_t)p->phase,p->first_error,(uint64_t)p->first_detail,p->trace_seen,
            p->request.decoded.pc,p->request.decoded.code,p->request.decoded.length,p->request.page_count,
            p->request.original_flags,(uint64_t)p->signal_number,(uint64_t)p->signal_code,
            (uint64_t)p->signal_errno,p->signal_address,t->actual_post_pc,t->actual_post_flags,
            t->continuation_started,t->continuation_complete,(uint64_t)t->continuation_result,
            s->query.pc,s->query.attempted,s->query.page_observed,s->query.complete,(uint64_t)s->query.result,
            s->release.started,s->release.complete,(uint64_t)s->release.result};copy(o->h,v,sizeof v);
#if LI2_LOOP_CACHE8_CONTROL != 2
        /* Descriptive copy of the consumed real TRACE entry. The failure
           paths clear only valid; neither produces a successor entry. Slot
           generations are independent, so retain both exact identities. */
        o->h[52]=s->fetch.ref.sequence;
        if(i==(unsigned)selected_chain.active) {
            const struct li2_tf_trace_entry *e=&selected_chain.entry;
            const uint64_t entry[]={
                (uint64_t)__atomic_load_n(&e->valid,__ATOMIC_ACQUIRE),e->previous,e->next,
                e->event_id,e->sequence,e->previous_generation,e->next_generation,
                e->pc,e->flags,e->previous_borrow_sequence,
                selected_chain.sequence,selected_chain.event_id};
            copy(&o->h[40],entry,sizeof entry);
        }
#endif
        lc8e_step(&o->before,&p->before);lc8e_step(&o->after,&p->after);lc8e_step(&o->unexpected,&s->unexpected);
    }
    size_t at=0;uint64_t calls=0;long result=0;
    while(at<sizeof lc8e.wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lc8e.wire+at),sizeof lc8e.wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lc8e.wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lc8e.wire)return;
    const uint64_t footer[]={LC8E_FOOTER,2,sizeof lc8e.wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
