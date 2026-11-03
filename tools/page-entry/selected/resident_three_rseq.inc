/* Included after the existing rseq/region helpers. This is a separate actual
   lifetime; pg_rseq and the two-member domain retain their original shape. */
#include "resident_three_owner.h"
static struct li2_r3_rseq_progress r3r;
static struct li2_dd_plan r3r_direct;
const struct li2_r3_rseq_progress *li2_r3_rseq_progress(void) {return &r3r;}
static _Noreturn void r3r_unsafe(void) {
    /* An invalid live registration cannot safely return through RAW cleanup. */
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int r3r_token(const struct li2_r3_token *t) {
    return t && t->owner==r3r.token.owner && t->serial && t->serial==r3r.token.serial &&
        li2_r3_owner_phase(t) && r3r.active==1;
}
static int r3r_binding(void) {
    const struct li2_native_pair_progress *p=li2_native_pair_progress();
    const struct li2_step_session *s=r3r.session;
    if(!r3r_token(&r3r.token) || !state.initialized || state.first_error ||
       !s || s->initialized!=1 || s->self_test_complete!=1 || s->pid<=0 || s->pid!=s->tid ||
       s->sync_register || s->sync_query<0 || (s->sync_query&96)!=96 ||
       p->initialized!=1 || p->session!=s || p->pid!=s->pid || p->tid!=s->tid ||
       state.pid!=r3r.pid || state.tid!=r3r.tid || s->pid!=r3r.pid ||
       state.registered!=r3r.registered || state.epoch!=r3r.epoch || state.calls!=r3r.calls ||
       state.tls_attempted!=1 || state.tls_complete!=1 || state.fs_result || state.gs_result ||
       state.fs_base!=r3r.fs || state.gs_base!=r3r.gs)return 0;
    if(!r3r.registered)return !state.held && state.phase==LI2_RSEQ_IDLE &&
        !r3r.address && !r3r.page && !r3r.length && !r3r.signature && !r3r.word_observed &&
        li2_pgu_zero(&r3r.before,sizeof r3r.before) && li2_pgu_zero(&r3r.observed,sizeof r3r.observed);
    return r3r.registered==1 && native_pin() && state.address==r3r.address &&
        state.page==r3r.page && state.length==r3r.length && state.signature==r3r.signature &&
        same_data(&state.data,&r3r.before);
}
static void r3r_word(uint64_t *out) {
    if(r3r.checking || !r3r_binding())r3r_unsafe();
    r3r.checking=1;__asm__ volatile("":::"memory");
    if(r3r.registered) {
        *out=*(const volatile uint64_t *)(r3r.address+8);r3r.word_observed=1;
    }
    if(*out)r3r_unsafe();
    __asm__ volatile("":::"memory");r3r.checking=0;
}
void li2_r3_rseq_raw(void) {
    if(!r3r.active)return;
    r3r_word(&r3r.word_entry);
    if(r3r.raw_checks==UINT64_MAX)r3r_unsafe();
    ++r3r.raw_checks;
}
void li2_r3_rseq_preentry(void) {if(r3r.active)r3r_word(&r3r.word_entry);}
static int r3r_tls(void) {
    uint64_t fs=0,gs=0;uint16_t fs_selector,gs_selector;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(fs_selector),"=r"(gs_selector)::"memory");
    if(CALL(SYS_arch_prctl,ARCH_GET_FS,&fs,0,0,0,0) ||
       CALL(SYS_arch_prctl,ARCH_GET_GS,&gs,0,0,0,0) || fs!=r3r.fs || gs!=r3r.gs ||
       fs_selector!=r3r.fs_selector || gs_selector!=r3r.gs_selector)return LI2_RN_TLS;
    r3r.tls_complete=1;return 0;
}
int li2_r3_rseq_begin(const struct li2_r3_token *t,const ucontext_t *uc) {
    struct li2_r3_seed seed={0};
    if(!t || li2_r3_owner_phase(t)!=LI2_R3_HELD || r3r.active || r3r.checking ||
       (r3r.token.serial && (!r3r.close_complete || t->serial<=r3r.token.serial)) ||
       li2_r3_owner_seed(t,&seed) || seed.complete!=1 || !region_rseq_current(uc) ||
       ready() || pg_rseq.active || !private_range)return LI2_RN_STATE;
    for(size_t i=0;i<sizeof r3r;i++)if(!private_range((uintptr_t)&r3r+i,1))return LI2_RN_STATE;
    for(size_t i=0;i<sizeof r3r_direct;i++)if(!private_range((uintptr_t)&r3r_direct+i,1))return LI2_RN_STATE;
    if(state.registered) {if(!native_pin())r3r_unsafe();}
    else if(state.held || state.phase!=LI2_RSEQ_IDLE)return LI2_RN_STATE;
    /* Fresh TLS before activation, then keep the real cache complete during
       every returning RAW. This is the same distinction as the old owner. */
    li2_maps_phase_end();if(tls_observe())return LI2_RN_TLS;
    if(!region_rseq_current(uc))return LI2_RN_STATE;
    r3r=(struct li2_r3_rseq_progress){.token=*t,.session=seed.session,.pid=seed.pid,.tid=seed.tid,
        .registered=state.registered,.epoch=state.epoch,.calls=state.calls,
        .fs=state.fs_base,.gs=state.gs_base};
    if(r3r.registered) {
        r3r.address=state.address;r3r.page=state.page;r3r.length=state.length;
        r3r.signature=state.signature;r3r.before=state.data;
    }
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(r3r.fs_selector),"=r"(r3r.gs_selector)::"memory");
    r3r.active=1;r3r_word(&r3r.word_before);
    if(r3r.registered) {
        struct li2_rseq_current_data observed={0};li2_maps_phase_end();
        int error=li2_lifecycle_rseq_data_current(r3r.address,&observed);r3r.observed=observed.data;
        if(error || !same_data(&r3r.before,&r3r.observed))return LI2_RN_PIN;
    }
    int error=r3r_tls();if(error)return error;
    r3r_word(&r3r.word_before);r3r.seed_complete=1;return 0;
}
int li2_r3_rseq_live(const struct li2_r3_token *t,const ucontext_t *uc,struct li2_link_rseq_live *out) {
    if(!r3r_token(t) || !r3r.seed_complete || !region_rseq_current(uc))return LI2_RN_STATE;
    r3r_word(&r3r.word_entry);
    int error=li2_rseq_link_live(uc,out);
    if(error || !out || out->complete!=1 || out->registered!=r3r.registered ||
       out->epoch!=r3r.epoch || out->session!=(uintptr_t)r3r.session)return LI2_RN_PIN;
    r3r_word(&r3r.word_entry);r3r.entry_complete=1;return 0;
}
int li2_r3_rseq_cold(const struct li2_r3_token *t,unsigned index,const ucontext_t *uc) {
    const struct li2_pg_compact *p=li2_r3_owner_plan(t,index);
    if(!r3r_token(t) || li2_r3_owner_phase(t)!=LI2_R3_PLANNING || !r3r.seed_complete ||
       index>=LI2_R3_CERTIFICATES || r3r.cold[index] || !region_rseq_current(uc) ||
       !p || !p->heads || p->heads>LI2_PE_HEADS || p->stores || p->links ||
       !p->exits || p->exits>LI2_PG_BOUNDARIES)return LI2_RSEQ_PLAN;
    unsigned bytes=0;r3r_word(&r3r.word_entry);
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        if(h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE || !h->source_length ||
           h->source_length>15 || d->decoded.pc!=p->page[h->source_page]+h->source_offset ||
           (h->kind!=LI2_PE_NONE && h->kind!=LI2_PG_DIRECT))return LI2_RSEQ_PLAN;
        unsigned char window[15]={0};size_t n=0;
        for(;n<15;n++) {
            uintptr_t at=d->decoded.pc+n;unsigned page;
            for(page=0;page<2;page++)if(at>=p->page[page] && at-p->page[page]<LI2_REGION_PAGE)break;
            if(page==2)break;
            window[n]=p->source[page][at-p->page[page]];
        }
        struct li2_span_decoded actual={0};struct li2_write_footprint independent={0};
        if(li2_decoder_span_describe(d->decoded.pc,window,n,&actual) ||
           !region_rseq_equal(d,&actual,sizeof actual) || actual.ready!=1 || actual.refusal ||
           li2_decoder_link_none(d->decoded.pc,window,n,&independent) ||
           independent.abi_version!=1 || independent.policy!=LI2_WRITE_NONE ||
           independent.first || independent.end || independent.pc!=d->decoded.pc ||
           independent.next_pc!=d->decoded.next_pc || independent.code!=d->decoded.code ||
           independent.length!=h->source_length)return LI2_RSEQ_PLAN;
        if(h->kind==LI2_PG_DIRECT) {
            if(li2_pg_compact_direct(p,i/64,i%64,&r3r_direct) || li2_dd_validate(&r3r_direct))
                return LI2_RSEQ_PLAN;
        }
        int error=decoded_footprint(&actual.decoded,uc,1);if(error)return error;
        bytes+=h->source_length;
    }
    if(bytes!=p->source_bytes || !region_rseq_current(uc))return LI2_RSEQ_PLAN;
    r3r_word(&r3r.word_entry);r3r.cold[index]=1;return 0;
}
#ifdef LI2_RESIDENT_RX
/* Same actual TLS/current-data/word proof, distinct execution-release authority.
   The old close wrapper below continues to require actual all-NX closure. */
static int r3r_finish(const struct li2_r3_token *t,const ucontext_t *uc,
                     int (*completed)(const struct li2_r3_token *)) {
#else
int li2_r3_rseq_close(const struct li2_r3_token *t,const ucontext_t *uc) {
#endif
    if(!r3r_token(t) || !r3r.seed_complete || r3r.close_complete ||
       !region_rseq_current(uc) || li2_lifecycle_fetch_interlock() ||
#ifdef LI2_RESIDENT_RX
       !completed(t))return LI2_RN_STATE;
#else
       !li2_r3_owner_closed(t))return LI2_RN_STATE;
#endif
    r3r_word(&r3r.word_after);
    if(r3r.registered) {
        struct li2_rseq_current_data after={0};li2_maps_phase_end();
        int error=li2_lifecycle_rseq_data_current(r3r.address,&after);r3r.after=after.data;
        if(error || !same_data(&r3r.before,&r3r.after))return LI2_RN_PIN;
    }
    int error=r3r_tls();if(error)return error;
    r3r_word(&r3r.word_after);r3r.close_complete=1;
    __asm__ volatile("":::"memory");r3r.active=0;return 0;
}

#ifdef LI2_RESIDENT_RX
int li2_r3_rseq_close(const struct li2_r3_token *t,const ucontext_t *uc) {
    return r3r_finish(t,uc,li2_r3_owner_closed);
}
int li2_r3_rseq_release(const struct li2_r3_token *t,const ucontext_t *uc) {
    return r3r_finish(t,uc,li2_r3_rx_execution_closed);
}
#endif
