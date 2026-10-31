/* Included after the existing region/link helpers. The first executable
   primitive deliberately requires actual registered ACTIVE state. It does
   not broaden the old NONE domain or the old unregistered/default paths. */
#include "persistent_group_runtime.h"
static struct li2_pg_rseq_progress pg_rseq;
static struct li2_pg_rseq_progress pg_rseq_previous;
const struct li2_pg_rseq_progress *li2_pg_rseq_progress(void) {return &pg_rseq;}
static int pgr_bad(unsigned code,long detail) {
    if(!pg_rseq.first_error) {pg_rseq.first_error=code;pg_rseq.first_detail=detail;}
    return (int)pg_rseq.first_error;
}
static _Noreturn void pgr_unsafe(unsigned code,long detail) {
    (void)pgr_bad(code,detail);pg_rseq.unsafe_terminal=1;
    __asm__ volatile("":::"memory");
    /* No returning syscall, report, descriptor repair or claimed cleanup. */
    (void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int pgr_token(const struct li2_pg_token *t) {
    return t && t->owner==pg_rseq.token.owner && t->serial && t->serial==pg_rseq.token.serial &&
        li2_pg_owner_phase(t) && pg_rseq.active;
}
static int pgr_binding(void) {
    return pgr_token(&pg_rseq.token) && native_pin() && state.pid==pg_rseq.pid && state.tid==pg_rseq.tid &&
        state.address==pg_rseq.address && state.page==pg_rseq.page && state.length==pg_rseq.length &&
        state.signature==pg_rseq.signature && state.epoch==pg_rseq.registration_epoch &&
        same_data(&state.data,&pg_rseq.before) && li2_native_pair_progress()->session==pg_rseq.session;
}
static void pgr_zero(uint64_t *out) {
    if(pg_rseq.checking)pgr_unsafe(LI2_RN_REENTRY,500);
    pg_rseq.checking=1;__asm__ volatile("":::"memory");
    if(!pgr_binding())pgr_unsafe(LI2_RN_PIN,500);
    *out=*(const volatile uint64_t *)(pg_rseq.address+8);
    if(*out)pgr_unsafe(LI2_RN_WORD,500);
    __asm__ volatile("":::"memory");pg_rseq.checking=0;
}
void li2_pg_rseq_raw(void) {
    if(!pg_rseq.active)return;
    pgr_zero(&pg_rseq.word_entry);
    if(pg_rseq.raw_checks==UINT64_MAX)pgr_unsafe(LI2_RN_OVERFLOW,500);
    ++pg_rseq.raw_checks;
}
void li2_pg_rseq_preentry(void) {
    if(pg_rseq.active)pgr_zero(&pg_rseq.word_entry);
}
static int pgr_tls(void) {
    uint16_t fs,gs;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(fs),"=r"(gs)::"memory");
    /* Do not clear state.tls_complete around these RAWs: its actual pin is
       intentionally required at each gateway. No admitted instruction changes
       TLS; observe into distinct protected storage and compare actual bases. */
    pg_rseq.fs_result=CALL(SYS_arch_prctl,ARCH_GET_FS,&pg_rseq.fs,0,0,0,0);
    pg_rseq.gs_result=CALL(SYS_arch_prctl,ARCH_GET_GS,&pg_rseq.gs,0,0,0,0);
    if(pg_rseq.fs_result || pg_rseq.gs_result || pg_rseq.fs!=state.fs_base ||
       pg_rseq.gs!=state.gs_base || fs!=pg_rseq.fs_selector || gs!=pg_rseq.gs_selector)
        return pgr_bad(LI2_RN_TLS,500);
    return 0;
}

/* The lifecycle source owns these actual queries. Rseq closure independently
   binds all three rows, not an aggregate17 or one old eight-page query. */
static int pgr_source_terminal(const struct li2_pg_token *t,unsigned cancelled) {
    const struct li2_pg_source_progress *s=li2_pg_source_progress();
    const struct li2_pg_layout *l=li2_pg_owner_layout(t);
    if(!s || !l || !li2_pg_source_view(t) || s->serial!=t->serial ||
       s->source.serial!=t->serial || s->source.complete!=1 || s->first_error || s->aborted ||
       s->release_started!=1 || s->release_complete!=1 ||
       !region_rseq_equal(&s->layout,l,sizeof *l))return 0;
    if(cancelled) {
        if(s->phase!=LI2_PGS_CANCELLED || s->cancel_started!=1 || s->cancel_complete!=1 ||
           s->cancel_extents!=3 || s->cancel_pages!=17 || s->opened_extents || s->opened_pages ||
           s->closed_extents || s->closed_pages || s->cancelled_fetch.complete!=1 ||
           s->cancelled_fetch.progress.held || s->cancelled_fetch.progress.complete!=1 ||
           s->cancelled_fetch.progress.first_error ||
           s->cancelled_fetch.ref.owner!=s->source.anchor.owner ||
           s->cancelled_fetch.ref.sequence!=s->source.anchor.sequence)return 0;
    } else if(s->phase!=LI2_PGS_RELEASED || s->cancel_started || s->cancel_complete ||
              s->opened_extents!=3 || s->opened_pages!=17 || s->closed_extents!=3 || s->closed_pages!=17)
        return 0;
    for(unsigned i=0;i<3;i++) {
        uintptr_t first=i<2?l->generated[i]:l->stubs;
        size_t bytes=i<2?LI2_PE_IMAGE_BYTES:LI2_PG_STUB_BYTES;
        const struct li2_private_code_query *q=cancelled?&s->cancel_code[i]:&s->closed[i];
        int prot=cancelled?s->cancel_expected_prot[i]:PROT_READ;
        if((prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE)) || q->attempted!=1 || q->complete!=1 ||
           q->result || q->first!=first || q->end!=first+bytes || q->pages_checked!=bytes/LI2_REGION_PAGE ||
           q->expected_prot!=prot || q->actual_prot!=prot)return 0;
        if(cancelled) {
            if(s->opened[i].attempted || s->closed[i].attempted)return 0;
        } else {
            q=&s->opened[i];
            if(q->attempted!=1 || q->complete!=1 || q->result || q->first!=first || q->end!=first+bytes ||
               q->pages_checked!=bytes/LI2_REGION_PAGE || q->expected_prot!=(PROT_READ|PROT_EXEC) ||
               q->actual_prot!=(PROT_READ|PROT_EXEC))return 0;
        }
    }
    return 1;
}
static int pgr_stub(const struct li2_pg_plan *p,unsigned i,const ucontext_t *uc) {
    const struct li2_pg_edge *e=&p->edge[i];
    if(e->kind!=LI2_PG_CAPACITY_LINK || e->source_head>=p->heads || e->target_head>=p->heads ||
       e->source_head/64==e->target_head/64 || e->successor>=p->head[e->source_head].successor_count ||
       e->successor>=2 || p->head[e->source_head].successors[e->successor]!=e->target_head ||
       e->original_target!=p->original[e->target_head].decoded.pc ||
       e->generated_target!=p->layout.generated[e->target_head/64]+(uintptr_t)(e->target_head%64)*LI2_PE_SLOT_BYTES ||
       e->stub!=p->layout.stubs+6U*i || e->slot!=p->layout.slots+8U*i)return pgr_bad(LI2_RSEQ_PLAN,520);
    for(unsigned j=0;j<i;j++)if(p->edge[j].source_head==e->source_head &&
        p->edge[j].successor==e->successor)return pgr_bad(LI2_RSEQ_PLAN,521);
    uintptr_t next=e->stub+6;uint32_t displacement;
    if(e->slot>=next) {
        uintptr_t n=e->slot-next;if(n>UINT32_C(0x7fffffff))return pgr_bad(LI2_RSEQ_PLAN,522);
        displacement=(uint32_t)n;
    } else {
        uintptr_t n=next-e->slot;if(n>UINT32_C(0x80000000))return pgr_bad(LI2_RSEQ_PLAN,522);
        displacement=0U-(uint32_t)n;
    }
    unsigned char bytes[6]={0xff,0x25,0,0,0,0};
    for(unsigned j=0;j<4;j++)bytes[2+j]=(unsigned char)(displacement>>(8*j));
    if(!region_rseq_equal(bytes,p->stub_image+6U*i,sizeof bytes))return pgr_bad(LI2_RSEQ_PLAN,523);
    struct li2_decoded actual={0},expected={.pc=e->stub,.next_pc=next,.abi_version=1,
        .decode_status=LI2_VALID,.code=765,.kind=LI2_NONE,.destination=16,
        .step_disposition=LI2_STEP_UNSUPPORTED,.available=6,.length=6};
    for(unsigned j=0;j<6;j++)expected.bytes[j]=bytes[j];
    struct li2_tf_classification tf={0},tf_expected={.pc=e->stub,.next_pc=next,
        .abi_version=1,.policy=1,.code=765,.length=6,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_BRANCH};
    if(li2_decoder_decode(e->stub,bytes,sizeof bytes,&actual) ||
       !region_rseq_equal(&actual,&expected,sizeof actual) ||
       li2_decoder_tf_classify(e->stub,bytes,sizeof bytes,&tf) ||
       !region_rseq_equal(&tf,&tf_expected,sizeof tf))return pgr_bad(LI2_RSEQ_PLAN,524);
    /* link_none intentionally excludes this non-span form. The existing
       actual footprint API must independently return NONE, never a range. */
    int result=decoded_footprint(&actual,uc,1);
    return result?pgr_bad((unsigned)result,525):0;
}

int li2_pg_rseq_begin(const struct li2_pg_token *t,const struct li2_step_session *session,const ucontext_t *uc) {
    if(!t || !t->serial || li2_pg_owner_phase(t)!=LI2_PG_SEEDING || pg_rseq.active ||
       pg_rseq.checking || pg_rseq.first_error || pg_rseq.unsafe_terminal ||
       t->serial<=pg_rseq.token.serial || !session || session!=li2_native_pair_progress()->session ||
       li2_lifecycle_fetch_interlock() || !private_range)return pgr_bad(LI2_RN_STATE,500);
    const struct li2_pg_source_progress *source=li2_pg_source_progress();
    if(!source || source->phase!=LI2_PGS_SEEDING || source->serial!=t->serial ||
       !source->initialized || source->first_error || source->aborted || source->source.complete)
        return pgr_bad(LI2_RN_STATE,509);
    for(size_t i=0;i<sizeof pg_rseq;i++)
        if(!private_range((uintptr_t)&pg_rseq+i,1))return pgr_bad(LI2_RN_STATE,501);
    if(pg_rseq.token.serial) {
        if(pg_rseq.token.owner!=t->owner || !pg_rseq.seed_complete ||
           !((pg_rseq.close_complete==1 && !pg_rseq.cancel_started && !pg_rseq.cancel_complete) ||
             (!pg_rseq.close_complete && pg_rseq.cancel_started==1 && pg_rseq.cancel_complete==1)))
            return pgr_bad(LI2_RN_STATE,505);
        for(size_t i=0;i<sizeof pg_rseq_previous;i++)
            if(!private_range((uintptr_t)&pg_rseq_previous+i,1))return pgr_bad(LI2_RN_STATE,506);
        pg_rseq_previous=pg_rseq;
        volatile unsigned char *b=(void *)&pg_rseq;for(size_t i=0;i<sizeof pg_rseq;i++)b[i]=0;
    } else if(pg_rseq.token.owner || pg_rseq.seed_complete || pg_rseq.close_complete ||
              pg_rseq.cancel_started || pg_rseq.cancel_complete)return pgr_bad(LI2_RN_STATE,507);
    /* The selected registered entry cannot return through cleanup RAW if its
       actual registration pin is already contradictory. */
    if(!native_pin() || !region_rseq_current(uc))pgr_unsafe(LI2_RN_PIN,501);
    for(size_t i=0;i<sizeof pg_rseq;i++)if(!private_range((uintptr_t)&pg_rseq+i,1))
        return pgr_bad(LI2_RN_STATE,501);
    pg_rseq.token=*t;pg_rseq.session=session;pg_rseq.pid=state.pid;pg_rseq.tid=state.tid;
    pg_rseq.registration_epoch=state.epoch;pg_rseq.address=state.address;pg_rseq.page=state.page;
    pg_rseq.length=state.length;pg_rseq.signature=state.signature;pg_rseq.before=state.data;
    __asm__ volatile("mov %%fs,%0; mov %%gs,%1":"=r"(pg_rseq.fs_selector),"=r"(pg_rseq.gs_selector)::"memory");
    pg_rseq.active=1;__asm__ volatile("":::"memory");pgr_zero(&pg_rseq.word_before);
    li2_maps_phase_end();int e=li2_lifecycle_rseq_data(state.address,&pg_rseq.observed);
    if(e || !same_data(&pg_rseq.before,&pg_rseq.observed))return pgr_bad(LI2_RN_PIN,e?e:501);
    if((e=pgr_tls()))return e;
    pgr_zero(&pg_rseq.word_before);pg_rseq.seed_complete=1;return 0;
}
int li2_pg_rseq_live(const struct li2_pg_token *t,const ucontext_t *uc,struct li2_link_rseq_live *out) {
    if(!pgr_token(t) || pg_rseq.first_error || !pg_rseq.seed_complete || !region_rseq_current(uc))
        return pgr_bad(LI2_RN_STATE,502);
    pgr_zero(&pg_rseq.word_entry);
    int e=li2_rseq_link_live(uc,out);
    if(e || !out || out->complete!=1 || out->registered!=1 ||
       out->epoch!=pg_rseq.registration_epoch || out->session!=(uintptr_t)pg_rseq.session)
        return pgr_bad(LI2_RN_PIN,e?e:502);
    pgr_zero(&pg_rseq.word_entry);pg_rseq.entry_complete=1;return 0;
}
int li2_pg_rseq_cold(const struct li2_pg_token *t,const struct li2_pg_plan *p,const ucontext_t *uc) {
    if(!pgr_token(t) || pg_rseq.first_error || !pg_rseq.seed_complete || !region_rseq_current(uc) ||
       !p || p->version!=LI2_PG_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       p->reserved || p->reserved2 ||
#ifdef LI2_PERSISTENT_DISPATCH
       !p->heads || p->heads>LI2_PG_HEADS ||
       p->member_heads[0]!=(p->heads<64?p->heads:64) ||
       p->member_heads[1]!=(p->heads>64?p->heads-64:0) ||
       !p->exits || p->exits>8 || p->links>8 || p->links+p->exits>8)
#else
       p->heads<=64 || p->heads>LI2_PG_HEADS ||
       p->member_heads[0]!=64 || p->member_heads[1]!=p->heads-64 ||
       !p->exits || p->exits>8 || !p->links || p->links>8 || p->links+p->exits>8)
#endif
        return pgr_bad(LI2_RSEQ_PLAN,500);
    const struct li2_pg_sources *source=li2_pg_source_view(t);
    const struct li2_pg_layout *layout=li2_pg_owner_layout(t);
    if(li2_pg_owner_phase(t)!=LI2_PG_HELD || !source || !layout ||
       !region_rseq_equal(layout,&p->layout,sizeof *layout) || p->entry!=source->key.entry)
        return pgr_bad(LI2_RSEQ_PLAN,508);
    for(unsigned i=0;i<2;i++)if(p->page[i]!=source->key.page[i].identity.address ||
        !region_rseq_equal(p->source[i],source->key.page[i].bytes,LI2_REGION_PAGE))
            return pgr_bad(LI2_RSEQ_PLAN,509);
    pgr_zero(&pg_rseq.word_entry);unsigned bytes=0,stores=0;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_pe_head *h=&p->head[i];const struct li2_span_decoded *d=&p->original[i];
        if(h->source_page>=2 || h->source_offset>=LI2_REGION_PAGE || !h->source_length || h->source_length>15 ||
           d->decoded.pc!=p->page[h->source_page]+h->source_offset)return pgr_bad(LI2_RSEQ_PLAN,501);
        unsigned char window[15]={0};size_t n=0;
        for(;n<15;n++) {
            uintptr_t at=d->decoded.pc+n;unsigned page;
            for(page=0;page<2;page++)if(at>=p->page[page] && at-p->page[page]<LI2_REGION_PAGE)break;
            if(page==2)break;
            window[n]=p->source[page][at-p->page[page]];
        }
        struct li2_span_decoded actual={0};
        if(li2_decoder_span_describe(d->decoded.pc,window,n,&actual) ||
           !region_rseq_equal(d,&actual,sizeof actual))return pgr_bad(LI2_RSEQ_PLAN,502);
        if(h->kind==LI2_PE_NONE) {
            struct li2_write_footprint independent={0};
            if(actual.ready!=1 || actual.refusal || li2_decoder_link_none(d->decoded.pc,window,n,&independent) ||
               independent.abi_version!=1 || independent.policy!=LI2_WRITE_NONE || independent.first || independent.end ||
               independent.pc!=d->decoded.pc || independent.next_pc!=d->decoded.next_pc ||
               independent.code!=d->decoded.code || independent.length!=h->source_length)
                return pgr_bad(LI2_RSEQ_PLAN,503);
            int e=decoded_footprint(&actual.decoded,uc,1);if(e)return pgr_bad((unsigned)e,504);
        } else if(h->kind==LI2_PE_MOV) {
            struct li2_mg_store actual_store={0};
            if(actual.ready || !actual.refusal || li2_decoder_mov_store(d->decoded.pc,window,n,&actual_store) ||
               actual_store.ready!=1 || actual_store.refusal ||
#ifdef LI2_PERSISTENT_DISPATCH
               !region_rseq_equal(&actual_store,&p->instruction[i].mov,sizeof actual_store) ||
               !region_rseq_equal(&actual_store,&p->guard[i].mov.original,sizeof actual_store))
#else
               !region_rseq_equal(&actual_store,&p->store_original[i],sizeof actual_store) ||
               !region_rseq_equal(&actual_store,&p->guard[i].original,sizeof actual_store))
#endif
                return pgr_bad(LI2_RSEQ_PLAN,505);
            ++stores;
#ifdef LI2_PERSISTENT_DISPATCH
        } else if(h->kind==LI2_PG_DISPATCH) {
            struct li2_jd_descriptor descriptor={0};
            const struct li2_jd_plan *guard=&p->guard[i].dispatch;
            const uintptr_t delta=offsetof(struct li2_pg_plan,table)-offsetof(struct li2_pg_plan,original);
            if(actual.ready || !actual.refusal || h->successor_count || h->successors[0] || h->successors[1] ||
               li2_jd_describe(d->decoded.pc,window,n,&descriptor) || descriptor.ready!=1 || descriptor.refusal ||
               !region_rseq_equal(&descriptor.decoded,&actual.decoded,sizeof actual.decoded) ||
               !region_rseq_equal(&descriptor,&p->instruction[i].dispatch,sizeof descriptor) ||
               !region_rseq_equal(&descriptor,&guard->original,sizeof descriptor) ||
               p->table.address<delta || guard->binding.rows!=p->table.address-delta ||
               guard->binding.heads!=p->heads || guard->binding.head!=i ||
               !region_rseq_equal(guard->binding.image,p->layout.generated,sizeof p->layout.generated) ||
               guard->generated!=p->layout.generated[i/64]+(uintptr_t)(i%64)*LI2_PE_SLOT_BYTES ||
               guard->spill!=p->layout.spill || guard->record.image_bytes!=h->generated_length ||
               li2_jd_validate(guard))return pgr_bad(LI2_RSEQ_PLAN,528);
            /* Independently authenticate the original guest's NONE footprint.
               Trusted private spill/cell writes are established by the exact
               emitter and retained protected range, never called guest NONE. */
            int e=decoded_footprint(&actual.decoded,uc,1);if(e)return pgr_bad((unsigned)e,529);
#endif
        } else return pgr_bad(LI2_RSEQ_PLAN,506);
        bytes+=h->source_length;
    }
    if(bytes!=p->source_bytes || stores!=p->stores || !region_rseq_current(uc))return pgr_bad(LI2_RSEQ_PLAN,507);
    for(unsigned i=0;i<p->links;i++) {int e=pgr_stub(p,i,uc);if(e)return e;}
    for(size_t i=6U*p->links;i<LI2_PG_STUB_BYTES;i++)if(p->stub_image[i]!=0xcc)
        return pgr_bad(LI2_RSEQ_PLAN,526);
    if(!region_rseq_current(uc))return pgr_bad(LI2_RSEQ_PLAN,527);
    pgr_zero(&pg_rseq.word_entry);pg_rseq.cold_heads=p->heads;pg_rseq.cold_stores=stores;
    pg_rseq.cold_stubs=p->links;return 0;
}
int li2_pg_rseq_close(const struct li2_pg_token *t,const ucontext_t *uc) {
    if(!pgr_token(t) || pg_rseq.first_error || !pg_rseq.seed_complete || !pg_rseq.entry_complete ||
       li2_lifecycle_fetch_interlock() || !region_rseq_current(uc) || !pgr_source_terminal(t,0))
        return pgr_bad(LI2_RN_STATE,503);
    pgr_zero(&pg_rseq.word_after);li2_maps_phase_end();
    int e=li2_lifecycle_rseq_data(state.address,&pg_rseq.after);
    if(e || !same_data(&pg_rseq.before,&pg_rseq.after))return pgr_bad(LI2_RN_PIN,e?e:503);
    if((e=pgr_tls()))return e;
    pgr_zero(&pg_rseq.word_after);pg_rseq.close_complete=1;
    __asm__ volatile("":::"memory");pg_rseq.active=0;return 0;
}
int li2_pg_rseq_cancel(const struct li2_pg_token *t,const ucontext_t *uc) {
    if(!pgr_token(t) || li2_pg_owner_phase(t)!=LI2_PG_CANCELLING || pg_rseq.first_error ||
       !pg_rseq.seed_complete || pg_rseq.close_complete || pg_rseq.cancel_started ||
       pg_rseq.cancel_complete || li2_lifecycle_fetch_interlock() || !region_rseq_current(uc))
        return pgr_bad(LI2_RN_STATE,508);
    if(!pgr_source_terminal(t,1))return pgr_bad(LI2_RN_STATE,510);
    pg_rseq.cancel_started=1;pgr_zero(&pg_rseq.word_after);li2_maps_phase_end();
    int e=li2_lifecycle_rseq_data(state.address,&pg_rseq.after);
    if(e || !same_data(&pg_rseq.before,&pg_rseq.after))return pgr_bad(LI2_RN_PIN,e?e:508);
    if((e=pgr_tls()))return e;
    pgr_zero(&pg_rseq.word_after);pg_rseq.cancel_complete=1;
    __asm__ volatile("":::"memory");pg_rseq.active=0;return 0;
}
