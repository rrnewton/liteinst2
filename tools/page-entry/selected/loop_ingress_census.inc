/* Observation only: no result is consumed as routing or execution authority.
   Included after the real owner definitions. No decode, source read, maps
   query, allocation or syscall occurs in lic_ingress/its pure selector. */
#if LI2_LOOP_INGRESS_CENSUS != 1 || LI2_PERSISTENT_LOOP_RUNTIME != 1 || \
    LI2_PERSISTENT_LOOP_CAPTURE != 1 || LI2_MAPS_MAINTAINED != 1 || \
    LI2_TF_HANDOFF != 1 || LI2_PG_LOOP_ENCODING_VERSION != 2 || defined(LI2_MAPS_DIFFERENTIAL)
#error "ingress census is a separate maintained LOOP capture diagnostic"
#endif
#define LIC_SITES 1024U
struct lic_key {
    uint64_t pc,route,producer,page_count;
    int64_t signal,code;
    struct li2_decoded decoded;
    struct li2_step_page pages[2];
};
_Static_assert(sizeof(struct lic_key)==200,"whole tuple has no implicit padding");
struct lic_site { struct lic_key key; uint64_t count; };
static struct {
    unsigned initialized,sealed,error;
    uint64_t total,overflow,used,signals[5],start[6],end[6],bias[3];
    struct lic_site sites[LIC_SITES];
    char output[1024*1024];size_t output_used;
} lic;
_Static_assert(sizeof lic<2*1024*1024,"fixed diagnostic storage bound");
static void lic_bad(unsigned code) { if(!lic.error)lic.error=code; }
static void lic_snapshot(uint64_t out[6]) {
    out[0]=__atomic_load_n(PGC_EVENT_REF,__ATOMIC_ACQUIRE);
    for(unsigned i=0;i<5;i++)out[i+1]=__atomic_load_n(PGC_SIGNAL_REF(i),__ATOMIC_ACQUIRE);
}
static void lic_initialize(void) {
    if(lic.initialized || selected_run_protect_add(0,(uintptr_t)&lic,sizeof lic) ||
       selected_run_protect_contains(0,(uintptr_t)&lic,sizeof lic)!=1) {lic_bad(1);return;}
    const struct image *b=bridge_runtime_image();
    if(!b || !selected_session.initialized || !selected_session.self_test_complete) {lic_bad(1);return;}
    lic.bias[0]=original_main.bias;lic.bias[1]=original_interpreter.bias;lic.bias[2]=b->bias;
    lic_snapshot(lic.start);lic.initialized=1;
}
/* A candidate descriptor comes only from a still-running real owner. This is
   a descriptive snapshot before its existing full TRACE validator runs, not
   a substitute for that validator. Unknown has a whole-zero descriptor. */
static void lic_predecessor(struct lic_key *key,int sig,const siginfo_t *si,const ucontext_t *uc) {
    const greg_t *g=uc->uc_mcontext.gregs;
    if(sig!=SIGTRAP || si->si_signo!=SIGTRAP || si->si_code!=TRAP_TRACE || si->si_errno ||
       g[REG_TRAPNO]!=1 || g[REG_ERR] || (uintptr_t)si->si_addr!=key->pc ||
       handling!=1 || selected_selftesting || !selected_session.initialized ||
       !selected_session.self_test_complete || selected_step_pending!=1)return;
    const struct li2_step_owner *p=0;
    const struct li2_chain_fetch *f=0;
    unsigned producer=0;
    const struct li2_tf_classification *classification=0;
    if(selected_pending_route==SELECTED_GENERIC_TF) {
        const struct li2_tf_chain *c=&selected_chain;
        if(!c->initialized || c->session!=&selected_session || c->active<0 || c->active>1 ||
           c->pending!=1 || c->in_handler || c->first_error)return;
        const struct li2_tf_chain_slot *s=&c->slots[c->active];
        if(s->chain!=c || s->index!=(unsigned)c->active || s->phase!=LI2_CHAIN_EXECUTING ||
           !s->generation || !s->event_id || s->event_id>=c->event_id ||
           !s->prepare_complete || !s->decode_complete || s->prepare_result || s->decode_result ||
           s->release.started || s->unexpected_frame_observed ||
           !equal(&s->decoded,&s->owner.step.request.decoded,sizeof s->decoded))return;
        f=&s->fetch;
        if(!f->ref.owner || !f->ref.sequence || f->ref.sequence!=f->progress.sequence ||
           !f->progress.held || !f->progress.complete || f->progress.first_error ||
           !f->identity_observed || f->pid!=selected_session.pid || f->tid!=selected_session.tid)return;
        p=&s->owner.step;classification=&s->owner.classification;producer=1;
    } else if(selected_pending_route==SELECTED_OLD_STEP) {
        p=&selected_step;producer=2;
    } else return;
    const struct li2_step_request *r=&p->request;const struct li2_decoded *d=&r->decoded;
    if(p->phase!=LI2_STEP_RUNNING || p->first_error || p->in_handler || p->self_test ||
       p->trace_seen || p->revoke_sync_started || p->session!=&selected_session ||
       p->open_sync || r->page_count<1 || r->page_count>2 ||
       d->abi_version!=1 || d->decode_status!=LI2_VALID || d->kind!=LI2_NONE || d->reserved ||
       !d->code || !d->length || d->length>15 || d->available<d->length || d->available>15 ||
       d->pc>UINT64_MAX-d->length || d->next_pc!=d->pc+d->length)return;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof mask);
    if(p->before.greg[REG_RIP]!=(greg_t)d->pc || p->before.mask!=selected_session.application_mask ||
       mask!=selected_session.application_mask || g[REG_CSGSFS]!=p->before.greg[REG_CSGSFS] ||
       ((uint64_t)g[REG_EFL]&(LI2_STEP_TF|LI2_STEP_RF))!=LI2_STEP_TF)return;
    if(classification) {
        if(classification->abi_version!=1 || classification->policy!=1 ||
           classification->pc!=d->pc || classification->next_pc!=d->next_pc ||
           classification->code!=d->code || classification->length!=d->length ||
           (classification->flow!=LI2_TF_FALLTHROUGH && classification->flow!=LI2_TF_NEAR_FLOW) ||
           (classification->flow==LI2_TF_FALLTHROUGH && key->pc!=d->next_pc))return;
    } else {
        if(!equal(d,&selected_decoded,sizeof *d) || d->step_disposition!=LI2_STEP_CANDIDATE ||
           key->pc!=d->next_pc || !selected_borrow.owner || !selected_borrow.sequence ||
           selected_view.pc!=d->pc || selected_view.length!=d->available ||
           !selected_view.identity_observed || selected_view.pid!=selected_session.pid ||
           selected_view.tid!=selected_session.tid || !equal(selected_view.bytes,d->bytes,d->available))return;
    }
    uintptr_t first=d->pc&~(PAGE-1),last=(d->next_pc-1)&~(PAGE-1);
    if(r->page_count!=(first==last?1U:2U))return;
    for(size_t i=0;i<2;i++) {
        if(p->revoke_started[i] || p->revoked[i] || p->revoke_result[i])return;
        if(i<r->page_count) {
            const struct li2_step_page *v=&r->pages[i];
            if(v->address!=first+i*PAGE || !v->object || !v->generation ||
               v->closed_prot!=PROT_READ || v->open_prot!=(PROT_READ|PROT_EXEC) ||
               p->open_started[i]!=1 || p->opened[i]!=1 || p->open_result[i])return;
            if(f && (f->page_count!=r->page_count || f->pages[i].address!=v->address ||
               f->pages[i].allocation!=v->object || f->pages[i].generation!=v->generation ||
               f->pages[i].offset!=v->offset))return;
        } else if(p->open_started[i] || p->opened[i] || p->open_result[i])return;
    }
    if(f && (f->pc!=d->pc || f->length!=d->available ||
             !equal(f->bytes,d->bytes,d->available)))return;
    key->producer=producer;key->page_count=r->page_count;key->decoded=*d;
    for(size_t i=0;i<r->page_count;i++)key->pages[i]=r->pages[i];
}
static void lic_ingress(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!lic.initialized || lic.sealed)return;
    /* Arithmetic exhaustion invalidates the census explicitly. The actual
       process/owner behavior and all its existing checks remain untouched. */
    if(lic.total==UINT64_MAX) {lic_bad(2);return;}
    ++lic.total;
    unsigned signal=sig==SIGSEGV?0:sig==SIGTRAP?1:sig==SIGILL?2:sig==SIGSYS?3:4;
    ++lic.signals[signal];
    struct lic_key key={.pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP],
        .route=(unsigned)selected_pending_route,.signal=sig,.code=si->si_code};
    lic_predecessor(&key,sig,si,uc);
    uint64_t h=key.pc^((uint64_t)(uint32_t)sig<<32)^(uint32_t)si->si_code^key.decoded.pc;
    h^=h>>33;h*=UINT64_C(0xff51afd7ed558ccd);h^=h>>33;
    for(unsigned i=0;i<LIC_SITES;i++) {
        struct lic_site *s=&lic.sites[(h+i)&(LIC_SITES-1)];
        if(!s->count) {s->key=key;s->count=1;++lic.used;return;}
        if(equal(&s->key,&key,sizeof key)) {++s->count;return;}
    }
    ++lic.overflow;
}
static void lic_seal(void) {
    if(lic.sealed)return;
    lic.sealed=1;__asm__ volatile("":::"memory");lic_snapshot(lic.end);
    if(!lic.initialized)lic_bad(3);
}
static void lic_text(const char *s) {
    while(*s) {
        if(lic.output_used==sizeof lic.output) {lic_bad(4);return;}
        lic.output[lic.output_used++]=*s++;
    }
}
static void lic_number(uint64_t n) {
    char b[21];unsigned used=0;do {b[used++]=(char)('0'+n%10);n/=10;}while(n);
    while(used) {char s[2]={b[--used],0};lic_text(s);}
}
static void lic_signed(int64_t n) {
    if(n<0)lic_text("-");
    lic_number(n<0?0-(uint64_t)n:(uint64_t)n);
}
static void lic_field(const char *key,uint64_t value) {lic_text(key);lic_number(value);}
static void lic_array(const uint64_t *a,unsigned n) {
    lic_text("[");for(unsigned i=0;i<n;i++){if(i)lic_text(",");lic_number(a[i]);}lic_text("]");
}
static void lic_report(unsigned status,unsigned code) {
    /* Max 1024 keys: <=32 arbitrary unsigned fields plus signed32 signal/code
       and 16 bytes as 32 hex characters, with separators. One bounded line. */
    _Static_assert(LIC_SITES*(32*21+2*12+40)+2048<sizeof lic.output,"whole terminal line bound");
    lic_text("LI2_LOOP_INGRESS {\"version\":1");
    lic_field(",\"status\":",status);lic_field(",\"failure_code\":",code);
    lic_field(",\"initialized\":",lic.initialized);lic_field(",\"sealed\":",lic.sealed);
    lic_field(",\"error\":",lic.error);lic_field(",\"capacity\":",LIC_SITES);
    lic_field(",\"total\":",lic.total);lic_field(",\"overflow\":",lic.overflow);lic_field(",\"used\":",lic.used);
    lic_text(",\"signals\":");lic_array(lic.signals,5);
    lic_text(",\"start\":");lic_array(lic.start,6);lic_text(",\"end\":");lic_array(lic.end,6);
    lic_text(",\"bias\":");lic_array(lic.bias,3);lic_text(",\"sites\":[");
    unsigned rows=0;
    for(unsigned i=0;i<LIC_SITES;i++)if(lic.sites[i].count) {
        const struct lic_site *s=&lic.sites[i];const struct lic_key *k=&s->key;
        const struct li2_decoded *d=&k->decoded;
        if(rows++)lic_text(",");
        lic_text("[");lic_number(i);
        lic_text(",");lic_number(k->pc);lic_text(",");lic_signed(k->signal);
        lic_text(",");lic_signed(k->code);lic_text(",");lic_number(k->route);
        lic_text(",");lic_number(k->producer);lic_text(",");lic_number(s->count);
        uint64_t words[]={d->pc,d->next_pc,d->abi_version,d->decode_status,d->code,d->kind,
            d->destination,d->width_bits,d->step_disposition,d->available,d->length,d->reserved};
        lic_text(",");lic_array(words,12);lic_text(",\"");
        for(unsigned j=0;j<16;j++) {const char hex[]="0123456789abcdef";char b[]={hex[d->bytes[j]>>4],hex[d->bytes[j]&15],0};lic_text(b);}
        lic_text("\",");lic_number(k->page_count);lic_text(",[");
        for(unsigned j=0;j<2;j++) {
            const struct li2_step_page *p=&k->pages[j];
            uint64_t page[]={p->address,p->object,p->generation,p->offset,(unsigned)p->closed_prot,(unsigned)p->open_prot};
            if(j)lic_text(",");
            lic_array(page,6);
        }
        lic_text("]]");
    }
    lic_text("]}\n");
    /* Freeze preceded every original report syscall. No report callback feeds
       this census. A short write leaves an incomplete row and is refused. */
    (void)raw(SYS_write,report_fd<0?2:report_fd,(long)lic.output,lic.output_used,0,0,0);
}
