/* Included after the existing region/link helpers. The first executable
   primitive deliberately requires actual registered ACTIVE state. It does
   not broaden the old NONE domain or the old unregistered/default paths. */
#include "persistent_runtime.h"
static struct li2_pe_rseq_progress pe_rseq;
const struct li2_pe_rseq_progress *li2_pe_rseq_progress(void) {return &pe_rseq;}
static int per_bad(unsigned code,long detail) {
    if(!pe_rseq.first_error) {pe_rseq.first_error=code;pe_rseq.first_detail=detail;}
    return (int)pe_rseq.first_error;
}
static _Noreturn void per_unsafe(unsigned code,long detail) {
    (void)per_bad(code,detail);pe_rseq.unsafe_terminal=1;
    __asm__ volatile("":::"memory");
    /* No returning syscall, report, descriptor repair or claimed cleanup. */
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int per_token(const struct li2_pe_token *t) {
    return t && t->owner==pe_rseq.token.owner && t->serial && t->serial==pe_rseq.token.serial &&
        li2_pe_owner_phase(t) && pe_rseq.active;
}
static int per_binding(void) {
    return per_token(&pe_rseq.token) && native_pin() && state.pid==pe_rseq.pid && state.tid==pe_rseq.tid &&
        state.address==pe_rseq.address && state.page==pe_rseq.page && state.length==pe_rseq.length &&
        state.signature==pe_rseq.signature && state.epoch==pe_rseq.registration_epoch &&
        same_data(&state.data,&pe_rseq.before) && li2_native_pair_progress()->session==pe_rseq.session;
}
static void per_zero(uint64_t *out) {
    if(pe_rseq.checking)per_unsafe(LI2_RN_REENTRY,500);
    pe_rseq.checking=1;__asm__ volatile("":::"memory");
    if(!per_binding())per_unsafe(LI2_RN_PIN,500);
    *out=*(const volatile uint64_t *)(pe_rseq.address+8);
    if(*out)per_unsafe(LI2_RN_WORD,500);
    __asm__ volatile("":::"memory");pe_rseq.checking=0;
}
void li2_pe_rseq_raw(void) {
    if(!pe_rseq.active)return;
    per_zero(&pe_rseq.word_entry);
    if(pe_rseq.raw_checks==UINT64_MAX)per_unsafe(LI2_RN_OVERFLOW,500);
    ++pe_rseq.raw_checks;
}
void li2_pe_rseq_preentry(void) {
    if(pe_rseq.active)per_zero(&pe_rseq.word_entry);
}
static int per_tls(void) {
    uint16_t fs,gs;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(fs),"=r"(gs)::"memory");
    /* Do not clear state.tls_complete around these RAWs: its actual pin is
       intentionally required at each gateway. No admitted instruction changes
       TLS; observe into distinct protected storage and compare actual bases. */
    pe_rseq.fs_result=CALL(SYS_arch_prctl,ARCH_GET_FS,&pe_rseq.fs,0,0,0,0);
    pe_rseq.gs_result=CALL(SYS_arch_prctl,ARCH_GET_GS,&pe_rseq.gs,0,0,0,0);
    if(pe_rseq.fs_result || pe_rseq.gs_result || pe_rseq.fs!=state.fs_base ||
       pe_rseq.gs!=state.gs_base || fs!=pe_rseq.fs_selector || gs!=pe_rseq.gs_selector)
        return per_bad(LI2_RN_TLS,500);
    return 0;
}
int li2_pe_rseq_begin(const struct li2_pe_token *t,const struct li2_step_session *session,const ucontext_t *uc) {
    if(!t || li2_pe_owner_phase(t)!=LI2_PE_SEEDING || pe_rseq.active || pe_rseq.token.owner ||
       !session || session!=li2_native_pair_progress()->session ||
       li2_lifecycle_fetch_interlock() || !private_range)
        return per_bad(LI2_RN_STATE,500);
    /* The selected registered entry cannot return through cleanup RAW if its
       actual registration pin is already contradictory. */
    if(!native_pin() || !region_rseq_current(uc))per_unsafe(LI2_RN_PIN,501);
    for(size_t i=0;i<sizeof pe_rseq;i++)if(!private_range((uintptr_t)&pe_rseq+i,1))
        return per_bad(LI2_RN_STATE,501);
    pe_rseq.token=*t;pe_rseq.session=session;pe_rseq.pid=state.pid;pe_rseq.tid=state.tid;
    pe_rseq.registration_epoch=state.epoch;pe_rseq.address=state.address;pe_rseq.page=state.page;
    pe_rseq.length=state.length;pe_rseq.signature=state.signature;pe_rseq.before=state.data;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(pe_rseq.fs_selector),"=r"(pe_rseq.gs_selector)::"memory");
    pe_rseq.active=1;__asm__ volatile("":::"memory");per_zero(&pe_rseq.word_before);
    li2_maps_phase_end();int e=li2_lifecycle_rseq_data(state.address,&pe_rseq.observed);
    if(e || !same_data(&pe_rseq.before,&pe_rseq.observed))return per_bad(LI2_RN_PIN,e?e:501);
    if((e=per_tls()))return e;
    per_zero(&pe_rseq.word_before);pe_rseq.seed_complete=1;return 0;
}
int li2_pe_rseq_live(const struct li2_pe_token *t,const ucontext_t *uc,struct li2_link_rseq_live *out) {
    if(!per_token(t) || pe_rseq.first_error || !pe_rseq.seed_complete || !region_rseq_current(uc))
        return per_bad(LI2_RN_STATE,502);
    per_zero(&pe_rseq.word_entry);
    int e=li2_rseq_link_live(uc,out);
    if(e || !out || out->complete!=1 || out->registered!=1 ||
       out->epoch!=pe_rseq.registration_epoch || out->session!=(uintptr_t)pe_rseq.session)
        return per_bad(LI2_RN_PIN,e?e:502);
    per_zero(&pe_rseq.word_entry);pe_rseq.entry_complete=1;return 0;
}
int li2_pe_rseq_cold(const struct li2_pe_token *t,const struct li2_pe_plan *p,const ucontext_t *uc) {
    if(!per_token(t) || pe_rseq.first_error || !pe_rseq.seed_complete || !region_rseq_current(uc) ||
       !p || p->version!=LI2_PE_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       !p->heads || p->heads>LI2_PE_HEADS || !p->exits || p->exits>LI2_PE_EXITS)
        return per_bad(LI2_RSEQ_PLAN,500);
    per_zero(&pe_rseq.word_entry);unsigned bytes=0,stores=0;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        if(h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE || !h->source_length || h->source_length>15 ||
           d->decoded.pc!=p->page[h->source_page]+h->source_offset)return per_bad(LI2_RSEQ_PLAN,501);
        unsigned char window[15]={0};size_t n=0;
        for(;n<15;n++) {
            uintptr_t at=d->decoded.pc+n;unsigned page;
            for(page=0;page<2;page++)if(at>=p->page[page] && at-p->page[page]<LI2_REGION_PAGE)break;
            if(page==2)break;
            window[n]=p->source[page][at-p->page[page]];
        }
        struct li2_span_decoded actual={0};
        if(li2_decoder_span_describe(d->decoded.pc,window,n,&actual) ||
           !region_rseq_equal(d,&actual,sizeof actual))return per_bad(LI2_RSEQ_PLAN,502);
        if(h->kind==LI2_PE_NONE) {
            struct li2_write_footprint independent={0};
            if(actual.ready!=1 || actual.refusal || li2_decoder_link_none(d->decoded.pc,window,n,&independent) ||
               independent.abi_version!=1 || independent.policy!=LI2_WRITE_NONE || independent.first || independent.end ||
               independent.pc!=d->decoded.pc || independent.next_pc!=d->decoded.next_pc ||
               independent.code!=d->decoded.code || independent.length!=h->source_length)
                return per_bad(LI2_RSEQ_PLAN,503);
            int e=decoded_footprint(&actual.decoded,uc,1);if(e)return per_bad((unsigned)e,504);
        } else if(h->kind==LI2_PE_MOV) {
            struct li2_mg_store actual_store={0};
            if(actual.ready || !actual.refusal || li2_decoder_mov_store(d->decoded.pc,window,n,&actual_store) ||
               actual_store.ready!=1 || actual_store.refusal ||
               !region_rseq_equal(&actual_store,&p->store_original[i],sizeof actual_store) ||
               !region_rseq_equal(&actual_store,&p->guard[i].original,sizeof actual_store))
                return per_bad(LI2_RSEQ_PLAN,505);
            ++stores;
        } else return per_bad(LI2_RSEQ_PLAN,506);
        bytes+=h->source_length;
    }
    if(bytes!=p->source_bytes || stores!=p->stores || !region_rseq_current(uc))return per_bad(LI2_RSEQ_PLAN,507);
    per_zero(&pe_rseq.word_entry);pe_rseq.cold_heads=p->heads;pe_rseq.cold_stores=stores;return 0;
}
int li2_pe_rseq_close(const struct li2_pe_token *t,const ucontext_t *uc) {
    if(!per_token(t) || pe_rseq.first_error || !pe_rseq.seed_complete || !pe_rseq.entry_complete ||
       li2_lifecycle_fetch_interlock() || !region_rseq_current(uc))return per_bad(LI2_RN_STATE,503);
    per_zero(&pe_rseq.word_after);li2_maps_phase_end();
    int e=li2_lifecycle_rseq_data(state.address,&pe_rseq.after);
    if(e || !same_data(&pe_rseq.before,&pe_rseq.after))return per_bad(LI2_RN_PIN,e?e:503);
    if((e=per_tls()))return e;
    per_zero(&pe_rseq.word_after);pe_rseq.close_complete=1;
    __asm__ volatile("":::"memory");pe_rseq.active=0;return 0;
}
