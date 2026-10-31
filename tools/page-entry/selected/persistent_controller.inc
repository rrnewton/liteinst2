/* Distinct registered, two-source cyclic primitive. One actual generation;
   no replacement/warm-cache or old-profile qualification is implied. */
#include "persistent_runtime.h"
#include "persistent_epoch_config.h"
#if LI2_PE_BINDING_VERSION != 1 || LI2_PERSISTENT_EPOCH != 1
#error "exact persistent archive, policy and original-image configuration required"
#endif
#if defined(LI2_LINKED_EPOCH_CAPTURE) || defined(LI2_LINKED_PREEDGE) || \
    defined(LI2_SCALAR_SPAN_CAPTURE) || defined(LI2_CURRENT_TF_CAPTURE) || \
    defined(LI2_SCALAR_REGION_CAPTURE) || defined(LI2_UNROLLED_HASH_CAPTURE) || \
    defined(LI2_EVENT_PROFILE) || defined(LI2_LINK_GRAPH_OBSERVE)
#error "persistent owner requires its own future capture; old public wires are rejected"
#endif
enum pe_error { PE_STATE=3300,PE_FRAME,PE_SOURCE,PE_PUBLICATION,PE_EVENT,
    PE_RESULT,PE_REENTRY,PE_OVERFLOW,PE_TLS,PE_RELEASE,PE_PLAN,PE_RSEQ };
struct pe_header {
    uint64_t version,serial,generation,registry,generated,spill,table;
    uint64_t plan_proof,none_proof,source_validations,registered_epoch;
    unsigned char archive[32],policy[32];
    uint64_t reserved[4];
};
struct pe_payload {
    struct pe_header header;
    struct li2_pe_source_key source;
    struct li2_pe_compact plan;
};
#define PE_PROOF_BYTES ((sizeof(struct pe_payload)+PAGE-1U)&~(PAGE-1U))
#define PE_CODE_BYTES LI2_PE_IMAGE_BYTES
#define PE_ALLOC_BYTES (PE_CODE_BYTES+PAGE)
_Static_assert(PE_PROOF_BYTES<=64U*PAGE,"one bounded immutable source/plan publication");
struct li2_pe_generation {
    unsigned installed,complete,proof_complete;
    uint64_t generation,ready_generation;
    uintptr_t generated,proof,spill;
    size_t code_copied,code_verified,proof_zeroed,proof_copied,proof_verified;
    struct li2_private_code_query code_writable,proof_writable,spill_query;
    struct le_permission code_sealed,proof_sealed,open,close,cleanup;
};
struct li2_pe_epoch {
    struct li2_pe_progress p;
    unsigned initialized,registered,code_allocated,proof_allocated,code_registered,proof_registered;
    unsigned close_started,close_complete,prepare_started,prepare_complete,build_started,build_returned;
    unsigned redirected,exit_seen,exit_index,recovery_started,recovery_complete,guest_data_fault;
    unsigned cleanup_started,cleanup_complete,consumed,plan_proofs,none_proofs;
    long code_allocation,proof_allocation;
    int build_result,recovery_result,release_result;
    uint64_t flags,gpr_written,flags_written,entries,completed,unexpected;
    struct li2_pe_token token;
    struct li2_step_session session;
    const struct li2_tf_span_transfer *ticket;
    struct li2_span_transfer_progress transfer;
    struct li2_fetch_ref ref;
    struct li2_pe_generation generation;
    struct le_frame ingress,before,after,unexpected_frame;
    struct li2_link_rseq_live live[3];
    struct li2_pe_recovered recovered;
    struct li2_fetch_progress final_fetch;
    struct li2_private_code_query proof_exit,code_exit;
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    struct li2_mg_range exclusions[LI2_MG_RANGES];
    struct li2_pe_plan cold,rebuild;
    struct li2_pe_compact compact_rebuild;
    struct pe_payload publication;
    struct li2_mg_plan recovery_scratch;
};
static struct li2_pe_epoch pe;
static volatile sig_atomic_t pe_busy,pe_active,pe_failing,pe_closing,pe_decoding,pe_terminal_ingress;
static const unsigned char pe_archive[32]=LI2_PE_ARCHIVE_SHA256;
static const unsigned char pe_policy[32]=LI2_PE_POLICY_SHA256;
static const unsigned pe_greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static _Noreturn void selected_persistent_abort(unsigned,long);
static void pe_need(int yes,unsigned code,long detail) {if(!yes)selected_persistent_abort(code,detail);}
unsigned li2_pe_owner_phase(const struct li2_pe_token *t) {
    return t && t->owner==&pe && t->serial && t->serial==pe.p.serial &&
        pe.initialized && pe.registered?pe.p.phase:0;
}
int li2_pe_epoch_interlock(void) {
    return pe_busy || pe_active || (pe.p.phase!=LI2_PE_IDLE && pe.p.phase!=LI2_PE_CLOSED);
}
const struct li2_pe_progress *li2_pe_epoch_progress(void) {return &pe.p;}
static int pe_token(const struct li2_pe_token *t) {return li2_pe_owner_phase(t)!=0;}
static const struct pe_payload *pe_payload(void) {return (const void *)pe.generation.proof;}
static int pe_registered_storage(void) {
    return pe.initialized && pe.registered && pe.code_allocated && pe.proof_allocated &&
        pe.code_registered && pe.proof_registered &&
        selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)==1 &&
        selected_run_protect_contains(0,pe.generation.generated,PE_ALLOC_BYTES)==1 &&
        selected_run_protect_contains(0,pe.generation.proof,PE_PROOF_BYTES)==1;
}
static int pe_registry(void) {
    return pe.registry_count==protected_count && protected_count<=RANGES &&
        equal(pe.registry,protected,protected_count*sizeof *protected);
}
static int pe_identity(void) {
    const struct li2_step_session *s=&pe.session;
    return equal(s,&selected_session,sizeof *s) && s->initialized==1 && s->self_test_complete==1 &&
        s->pid>0 && s->pid==s->tid && s->sync_query>=0 && (s->sync_query&96)==96 && !s->sync_register &&
        raw(SYS_getpid,0,0,0,0,0,0)==s->pid && raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
static int pe_query(uintptr_t address,size_t bytes,int prot,struct li2_private_code_query *q) {
    int e=li2_lifecycle_private_code_query(address,bytes,prot,q);
    return e || q->attempted!=1 || q->complete!=1 || q->result || q->first!=address ||
        q->end!=address+bytes || q->pages_checked!=bytes/PAGE || q->expected_prot!=prot ||
        q->actual_prot!=prot?PE_PUBLICATION:0;
}
static int pe_permission(uintptr_t address,size_t bytes,int prot,struct le_permission *p) {
    if(p->started)return PE_STATE;
    p->started=1;p->prot=prot;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,address,bytes,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int e=pe_query(address,bytes,prot,&p->query);
    if(p->result || p->sync_result || e)return PE_PUBLICATION;
    p->complete=1;return 0;
}
static int pe_bytes(void) {
    const struct li2_pe_generation *g=&pe.generation;
    const struct pe_payload *p=pe_payload();
    const volatile unsigned char *code=(const void *)g->generated,*proof=(const void *)g->proof;
    const unsigned char *expected=(const void *)&pe.publication;
    for(size_t i=0;i<PE_CODE_BYTES;i++)if(code[i]!=p->plan.image[i])return PE_PUBLICATION;
    for(size_t i=0;i<PE_PROOF_BYTES;i++)
        if(proof[i]!=(i<sizeof pe.publication?expected[i]:0))return PE_PUBLICATION;
    return 0;
}
/* Pure fixed-address generation authentication, before recovery scratch or
   any spill access. Mutable cold scratch alone never grants this authority. */
static int pe_ready(void) {
    const struct li2_pe_generation *g=&pe.generation;
    if(!pe_registered_storage() || !pe_registry() || !pe_token(&pe.token) ||
       g->installed!=1 || g->complete!=1 || g->proof_complete!=1 ||
       g->generation!=1 || g->ready_generation!=g->generation ||
       pe.p.generation!=g->generation || pe.p.publication!=1 || !pe.consumed ||
       !g->code_sealed.complete || !g->proof_sealed.complete ||
       g->code_copied!=PE_CODE_BYTES || g->code_verified!=PE_CODE_BYTES ||
       g->proof_zeroed!=PE_PROOF_BYTES || g->proof_copied!=sizeof(struct pe_payload) ||
       g->proof_verified!=PE_PROOF_BYTES)return 0;
    const struct pe_payload *p=pe_payload();
    const struct li2_pe_sources *s=li2_pe_source_view(&pe.token);
    return s && s->complete==1 && !s->reserved && s->serial==pe.p.serial &&
        equal(&p->header,&pe.publication.header,sizeof p->header) &&
        equal(&p->source,&s->key,sizeof p->source) && p->header.serial==pe.p.serial &&
        p->header.generation==g->generation && p->header.registry==(uintptr_t)&pe &&
        p->header.generated==g->generated && p->header.spill==g->spill &&
        p->header.table==g->proof+offsetof(struct pe_payload,plan.table) &&
        p->header.plan_proof==pe.plan_proofs && p->header.none_proof==pe.none_proofs &&
        p->header.plan_proof && p->header.none_proof &&
        p->plan.version==LI2_PE_COMPACT_VERSION && p->plan.bytes==sizeof p->plan &&
        p->plan.ready==1 && !p->plan.result && p->plan.generated==g->generated &&
        p->plan.spill==g->spill && p->plan.table.address==p->header.table &&
        p->plan.entry==p->source.entry && p->plan.heads && p->plan.heads<=LI2_PE_HEADS &&
        p->plan.exits && p->plan.exits<=LI2_PE_EXITS;
}
static void pe_tls(struct le_frame *f) {
    f->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->fs,0,0,0,0);
    f->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->gs,0,0,0,0);
    pe_need(!f->fs_result && !f->gs_result,PE_TLS,0);f->tls_complete=1;
}
static void selected_persistent_initialize(void) {
    pe_need(!pe.initialized && !pe_busy && !pe_active,PE_STATE,0);pe_busy=1;
    unsigned a=0,b=0;for(unsigned i=0;i<32;i++){a|=pe_archive[i];b|=pe_policy[i];}
    pe_need(a && b && selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)==1,PE_STATE,1);
    pe.registered=1;pe.session=selected_session;
    pe.code_allocation=raw(SYS_mmap,0,PE_ALLOC_BYTES,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
    long v=pe.code_allocation;
    pe_need(v>0 && !((uintptr_t)v&(PAGE-1)) && (uintptr_t)v<(UINT64_C(1)<<31)-PE_ALLOC_BYTES,PE_PUBLICATION,v);
    pe.generation.generated=(uintptr_t)v;pe.generation.spill=(uintptr_t)v+PE_CODE_BYTES;pe.code_allocated=1;
    pe_need(!selected_run_protect_add(0,(uintptr_t)v,PE_ALLOC_BYTES),PE_STATE,2);pe.code_registered=1;
    pe.proof_allocation=raw(SYS_mmap,0,PE_PROOF_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    v=pe.proof_allocation;
    pe_need(v>0 && !((uintptr_t)v&(PAGE-1)) && (uintptr_t)v<(UINT64_C(1)<<47)-PE_PROOF_BYTES,PE_PUBLICATION,v);
    pe.generation.proof=(uintptr_t)v;pe.proof_allocated=1;
    pe_need(!selected_run_protect_add(0,(uintptr_t)v,PE_PROOF_BYTES),PE_STATE,3);pe.proof_registered=1;
    pe_need(!pe_query(pe.generation.generated,PE_CODE_BYTES,PROT_READ|PROT_WRITE,&pe.generation.code_writable) &&
        !pe_query(pe.generation.proof,PE_PROOF_BYTES,PROT_READ|PROT_WRITE,&pe.generation.proof_writable) &&
        !pe_query(pe.generation.spill,PAGE,PROT_READ|PROT_WRITE,&pe.generation.spill_query),PE_PUBLICATION,1);
    pe_need(!li2_pe_source_initialize() && pe_identity(),PE_SOURCE,0);
    pe.initialized=1;pe_busy=0;
}
int li2_pe_epoch_begin(const struct li2_tf_span_transfer *ticket,uint64_t serial,
    struct li2_step_session *session,int sig,const siginfo_t *si,const ucontext_t *uc,struct li2_pe_token *out) {
    const struct li2_span_transfer_progress *t=li2_tf_chain_span_progress();
    if(!pe.initialized || !pe_busy || pe_active || pe.p.serial || !out || !ticket ||
       !serial || !t || t->serial!=serial || t->phase!=LI2_ST_CLOSED || t->issued!=1 ||
       li2_tf_chain_span_quiet(ticket) || session!=&selected_session ||
       sig!=pe.before.sig || !le_unchanged(&pe.before,si,uc) || !le_quiet(0))return PE_STATE;
    pe.p.serial=1;pe.p.transfer_serial=serial;pe.p.phase=LI2_PE_SEEDING;
    pe.p.generated=pe.generation.generated;pe.p.proof=pe.generation.proof;pe.p.spill=pe.generation.spill;
    pe.p.table=pe.generation.proof+offsetof(struct pe_payload,plan.table);
    pe.token=(struct li2_pe_token){&pe,pe.p.serial};pe.ticket=ticket;*out=pe.token;
    int e=li2_pe_source_begin(&pe.token,pe.p.generated);if(e)return e;
    e=li2_pe_rseq_begin(&pe.token,session,uc);if(e)return e;
    pe.p.registration_epoch=li2_pe_rseq_progress()->registration_epoch;
    pe.p.phase=LI2_PE_SEEDED;return 0;
}
int li2_pe_epoch_sources(const struct li2_pe_token *t,const struct li2_fetch_ref *ref,const uintptr_t pages[2]) {
    if(!pe_token(t) || pe.p.phase!=LI2_PE_SEEDED || !ref || !pages)return PE_STATE;
    pe.p.phase=LI2_PE_PREPARING;pe.ref=*ref;
    int e=li2_pe_source_prepare(t,ref,pages);if(e)return e;
    const struct li2_pe_sources *s=li2_pe_source_view(t);if(!s)return PE_SOURCE;
    pe.p.source_count=2;pe.p.source[0]=s->key.page[0].identity.address;pe.p.source[1]=s->key.page[1].identity.address;
    pe.p.phase=LI2_PE_HELD;return 0;
}
const struct li2_pe_sources *li2_pe_epoch_sources_view(const struct li2_pe_token *t) {
    return pe_token(t)?li2_pe_source_view(t):0;
}
static void pe_build(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct li2_pe_sources *s=li2_pe_source_view(&pe.token);
    pe_need(s && pe.p.phase==LI2_PE_HELD && !pe_decoding && !pe.build_started,PE_STATE,4);
    pe.registry_count=protected_count;pe_need(protected_count<=RANGES,PE_STATE,5);
    copy(pe.registry,protected,protected_count*sizeof *protected);
    size_t n=0;for(size_t i=0;i<protected_count;i++)
        pe.exclusions[n++]=(struct li2_mg_range){protected[i].first,protected[i].end};
    for(unsigned i=0;i<2;i++)pe.exclusions[n++]=(struct li2_mg_range){pe.p.source[i],pe.p.source[i]+PAGE};
    const struct li2_pe_rseq_progress *r=li2_pe_rseq_progress();
    pe_need(r->active && r->seed_complete && r->registration_epoch==pe.p.registration_epoch,PE_RSEQ,0);
    pe.exclusions[n++]=(struct li2_mg_range){r->address+8,r->address+16};
    pe_need(n<=LI2_MG_RANGES,PE_STATE,6);
    pe_need(!li2_mg_table_build(pe.exclusions,n,pe.p.table,&pe.publication.plan.table),PE_PLAN,0);
    uintptr_t pages[2]={pe.p.source[0],pe.p.source[1]};
    /* The actual held source copies remain independent; cold planner output
       owns its own two full byte arrays. No live guest operand is read here. */
    for(unsigned i=0;i<2;i++)copy(pe.publication.plan.source[i],s->key.page[i].bytes,PAGE);
    pe.build_started=1;pe_decoding=1;__asm__ volatile("":::"memory");
    pe.build_result=li2_pe_plan_pages(pages,pe.publication.plan.source,s->key.entry,pe.p.generated,pe.p.spill,
        &pe.publication.plan.table,&pe.cold);pe.build_returned=1;
    pe_need(!pe.build_result && pe.cold.ready==1,PE_PLAN,pe.build_result);
    pe_need(!li2_pe_compact_build(&pe.cold,&pe.rebuild,&pe.publication.plan),PE_PLAN,1);++pe.plan_proofs;
    pe_need(!li2_pe_compact_validate(&pe.publication.plan,&pe.rebuild,&pe.compact_rebuild),PE_PLAN,2);++pe.plan_proofs;
    pe_need(!li2_pe_rseq_cold(&pe.token,&pe.cold,uc),PE_RSEQ,1);++pe.none_proofs;
    __asm__ volatile("":::"memory");pe_decoding=0;selected_initialized();
    pe_need(!li2_pe_source_validate(&pe.token,&pe.publication.plan) && pe_registry() && pe_identity() &&
        le_quiet(&pe.ref) && !li2_pe_rseq_live(&pe.token,uc,&pe.live[0]) &&
        le_unchanged(&pe.before,si,uc),PE_SOURCE,1);
    for(unsigned i=0;i<pe.publication.plan.heads;i++)if(pe.publication.plan.head[i].kind==LI2_PE_NONE) {
        const struct li2_span_decoded *d=&pe.publication.plan.original[i];
        pe.gpr_written|=d->gpr_write;
        pe.flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
    }
    pe_need(!(pe.gpr_written&~UINT64_C(0xffff)) && !(pe.gpr_written&(UINT64_C(1)<<4)) &&
        !(pe.flags_written&~UINT64_C(0x8d5)),PE_PLAN,3);
    pe_need(li2_tf_chain_span_progress()->serial==pe.p.transfer_serial &&
        !li2_tf_chain_span_consume(pe.ticket,&selected_session,&pe.ref,s->key.entry,sig,si,uc),PE_EVENT,1);
    pe.transfer=*li2_tf_chain_span_progress();pe.consumed=1;pe.p.phase=LI2_PE_CONSUMED;
    pe_need(pe.transfer.phase==LI2_ST_CONSUMED && pe.transfer.consumed==1,PE_EVENT,2);
}
int li2_pe_epoch_bind(const struct li2_pe_token *t,const struct li2_pe_generation *generation) {
    if(!pe_token(t) || generation!=&pe.generation || pe.p.phase!=LI2_PE_CONSUMED ||
       !pe.consumed || pe.generation.installed || pe.generation.generation || pe.p.publication)return PE_STATE;
    struct li2_pe_generation *g=&pe.generation;
    g->installed=1;g->generation=1;pe.p.generation=1;pe.p.phase=LI2_PE_PUBLISHING;
    struct pe_header *h=&pe.publication.header;
    h->version=1;h->serial=pe.p.serial;h->generation=1;h->registry=(uintptr_t)&pe;
    h->generated=g->generated;h->spill=g->spill;h->table=pe.p.table;
    h->plan_proof=pe.plan_proofs;h->none_proof=pe.none_proofs;
    h->source_validations=li2_pe_source_progress()->validations;h->registered_epoch=pe.p.registration_epoch;
    copy(h->archive,pe_archive,32);copy(h->policy,pe_policy,32);
    pe.publication.source=li2_pe_source_view(t)->key;
    volatile unsigned char *code=(void *)g->generated,*proof=(void *)g->proof;
    for(size_t i=0;i<PE_CODE_BYTES;i++){code[i]=pe.publication.plan.image[i];g->code_copied=i+1;}
    for(size_t i=0;i<PE_PROOF_BYTES;i++){proof[i]=0;g->proof_zeroed=i+1;}
    const unsigned char *src=(const void *)&pe.publication;
    for(size_t i=0;i<sizeof pe.publication;i++){proof[i]=src[i];g->proof_copied=i+1;}
    int e=pe_permission(g->generated,PE_CODE_BYTES,PROT_READ,&g->code_sealed);if(e)return e;
    e=pe_permission(g->proof,PE_PROOF_BYTES,PROT_READ,&g->proof_sealed);if(e)return e;
    for(size_t i=0;i<PE_CODE_BYTES;i++){if(code[i]!=pe.publication.plan.image[i])return PE_PUBLICATION;g->code_verified=i+1;}
    for(size_t i=0;i<PE_PROOF_BYTES;i++) {
        if(proof[i]!=(i<sizeof pe.publication?src[i]:0))return PE_PUBLICATION;
        g->proof_verified=i+1;
    }
    g->proof_complete=1;g->complete=1;pe.p.publication=1;
    __asm__ volatile("":::"memory");g->ready_generation=1;pe.p.phase=LI2_PE_BOUND;
    return pe_ready()?0:PE_PUBLICATION;
}
int li2_pe_epoch_enter(const struct li2_pe_token *t,int sig,const siginfo_t *si,ucontext_t *uc) {
    if(!pe_token(t) || pe.p.phase!=LI2_PE_BOUND || !pe_ready() || !pe_busy || pe_active)return PE_STATE;
    const struct pe_payload *p=pe_payload();struct li2_pe_generation *g=&pe.generation;
    if(pe_bytes() || !pe_registry() || !le_unchanged(&pe.before,si,uc))return PE_PUBLICATION;
    pe.p.phase=LI2_PE_OPENING;
    int e=pe_permission(g->generated,PE_CODE_BYTES,PROT_READ|PROT_EXEC,&g->open);if(e)return e;
    pe.p.opened_pages=8;
    if((e=li2_pe_source_opened(t,&p->plan)))return e;
    if((e=li2_pe_rseq_live(t,uc,&pe.live[1])))return e;
    pe_tls(&pe.before);
    if(!pe_identity() || !le_quiet(&pe.ref) || !pe_ready() || pe_bytes() ||
       !le_unchanged(&pe.before,si,uc) || sig!=SIGTRAP)return PE_FRAME;
    /* The actual logical frame remains unchanged except its entry RIP. */
    pe.p.phase=LI2_PE_EXECUTING;pe.redirected=1;pe.entries=1;
    selected_step_pending=1;selected_pending_route=SELECTED_PERSISTENT_EPOCH;pe_active=1;
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)p->plan.generated;
    return 0;
}
static int pe_exit_index(uintptr_t pc) {
    if(!pe_ready())return -1;
    const struct li2_pe_compact *p=&pe_payload()->plan;
    for(unsigned i=0;i<p->exits;i++)if(p->exit_pc[i]==pc)return (int)i;
    return -1;
}
int li2_pe_epoch_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    /* Runs before old owners, event accounting and every returning RAW. */
    li2_pe_rseq_preentry();
    if(!pe_active && !pe_busy && selected_pending_route!=SELECTED_PERSISTENT_EPOCH)return 0;
    if(pe_busy || pe_closing || pe_decoding || handling || !pe_active || !pe.redirected ||
       pe.p.phase!=LI2_PE_EXECUTING || selected_pending_route!=SELECTED_PERSISTENT_EPOCH ||
       selected_step_pending!=1 || pe.p.first_error || !pe_ready())return PE_REENTRY;
    pe_busy=1;pe.p.phase=LI2_PE_RECOVERING;pe.recovery_started=1;__asm__ volatile("":::"memory");
    if(le_capture(&pe.after,sig,si,uc))return PE_FRAME;
    const greg_t *g=pe.after.frame.greg;uintptr_t pc=(uintptr_t)g[REG_RIP];
    int exit=pe_exit_index(pc);
    if(exit>=0 && sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR &&
       !si->si_errno && g[REG_TRAPNO]==14 && g[REG_ERR]==21 && (uintptr_t)si->si_addr==pc &&
       (uintptr_t)g[REG_CR2]==pc && ((uint64_t)g[REG_EFL]&(SELECTED_TF|SELECTED_RF))==SELECTED_RF &&
       ((uint64_t)g[REG_CSGSFS]&65535)==0x33 && (uint64_t)g[REG_RSP]<(UINT64_C(1)<<47) &&
       pe.after.frame.mask==pe.session.application_mask) {
        pe.exit_seen=1;pe.exit_index=(unsigned)exit;pe.recovery_complete=1;return 0;
    }
    ++pe.unexpected;
    uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[pe_greg[i]];
    /* Recovery owns this exact protected scratch before materialization.
       Donor recovery reads only initialized dirty spills; no blanket spill
       read or old-plan cast precedes its boundary-state validation. */
    pe.recovery_result=li2_pe_compact_recover(&pe_payload()->plan,pc,raw,(uint64_t)g[REG_EFL],
        (const uint64_t *)pe.generation.spill,&pe.recovery_scratch,&pe.recovered);
    if(!pe.recovery_result && pe.recovered.complete) {
        pe.recovery_complete=1;
        pe.guest_data_fault=sig==SIGSEGV && si->si_signo==SIGSEGV && !si->si_errno &&
            (si->si_code==SEGV_MAPERR || si->si_code==SEGV_ACCERR) && g[REG_TRAPNO]==14 &&
            !(g[REG_ERR]&16) && (uintptr_t)si->si_addr==(uintptr_t)g[REG_CR2] &&
            ((pe.recovered.kind==LI2_PE_GUARD && pe.recovered.phase==LI2_MG_STORE) ||
             (pe.recovered.kind==LI2_PE_COPIED && pe.recovered.phase==LI2_MG_BEFORE));
    }
    /* Fault/reject/interior/async remain actual terminal events. In particular
       AFTER maps the successor and is never replayed as an original store. */
    return PE_EVENT;
}
static void pe_preserved(void) {
    const greg_t *a=pe.before.frame.greg,*b=pe.after.frame.greg;
    for(unsigned i=0;i<16;i++)if(!(pe.gpr_written&(UINT64_C(1)<<i)))
        pe_need(a[pe_greg[i]]==b[pe_greg[i]],PE_RESULT,i);
    for(unsigned i=0;i<NGREG;i++) {
        unsigned ordinary=0;for(unsigned j=0;j<16;j++)if(i==pe_greg[j])ordinary=1;
        if(!ordinary && i!=REG_RIP && i!=REG_EFL && i!=REG_CR2 && i!=REG_TRAPNO && i!=REG_ERR)
            pe_need(a[i]==b[i],PE_RESULT,16+i);
    }
    pe_need(a[REG_TRAPNO]==1 && !a[REG_ERR] && b[REG_TRAPNO]==14 && b[REG_ERR]==21 &&
        ((uint64_t)b[REG_EFL]&(SELECTED_TF|SELECTED_RF))==SELECTED_RF &&
        ((uint64_t)b[REG_EFL]&~(pe.flags_written|SELECTED_RF))==(pe.flags&~pe.flags_written),PE_RESULT,40);
    pe_need(pe.before.frame.mask==pe.after.frame.mask &&
        equal(&pe.before.uc.uc_stack,&pe.after.uc.uc_stack,sizeof pe.before.uc.uc_stack) &&
        pe.before.uc.uc_flags==pe.after.uc.uc_flags && pe.before.uc.uc_link==pe.after.uc.uc_link &&
        pe.before.frame.fp_bytes==pe.after.frame.fp_bytes &&
        equal(pe.before.frame.fp,pe.after.frame.fp,LI2_STEP_FP_BYTES),PE_RESULT,41);
}
int li2_pe_epoch_drain(const struct li2_pe_token *t) {
    if(!pe_token(t) || !pe_active || !pe_busy || pe.p.phase!=LI2_PE_RECOVERING ||
       !pe.exit_seen || !pe.recovery_complete || !pe_ready())return PE_STATE;
    const struct pe_payload *p=pe_payload();struct li2_pe_generation *g=&pe.generation;
    pe.p.phase=LI2_PE_CLOSING;
    int e=pe_permission(g->generated,PE_CODE_BYTES,PROT_READ,&g->close);if(e)return e;
    pe.p.closed_pages=8;
    if(pe_bytes() || pe_query(g->proof,PE_PROOF_BYTES,PROT_READ,&pe.proof_exit))return PE_PUBLICATION;
    pe.p.phase=LI2_PE_RELEASING;
    pe.release_result=li2_pe_source_release(t,&p->plan);if(pe.release_result)return pe.release_result;
    pe.p.anchor_released=1;pe.final_fetch=*li2_lifecycle_fetch_progress();
    if(pe.final_fetch.held || !pe.final_fetch.complete || pe.final_fetch.first_error ||
       pe.final_fetch.sequence!=pe.ref.sequence)return PE_RELEASE;
    if((e=li2_pe_rseq_close(t,&pe.after.uc)))return e;
    pe.p.registration_rechecked=1;
    pe.p.phase=LI2_PE_CLOSED;
    return 0;
}
/* This fixed entry has no descriptive post-close miss. A planner/source
   refusal terminates under its installed owner; it never resumes a destroyed
   predecessor or grants a permit from a partial generation. */
int li2_pe_epoch_cancel(const struct li2_pe_token *t,int sig,siginfo_t *si,ucontext_t *uc,
    enum li2_chain_result *result) {
    (void)t;(void)sig;(void)si;(void)uc;(void)result;return PE_STATE;
}
static _Noreturn void selected_persistent_abort(unsigned code,long detail) {
    if(!pe.p.first_error){pe.p.first_error=code;pe.p.first_detail=detail;}
    if(pe_failing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_failing=1;pe_busy=1;pe.p.completion_permit=0;pe.generation.ready_generation=0;
    if(pe_closing)li2_tf_chain_abort(&selected_chain,code,detail);
    pe.p.phase=LI2_PE_FAILED;li2_maps_phase_fail();
    if(!pe.cleanup_started && pe.code_allocated && pe.code_registered) {
        pe.cleanup_started=1;
        int e=pe_permission(pe.generation.generated,PE_CODE_BYTES,PROT_READ,&pe.generation.cleanup);
        if(!e) {
            pe.p.closed_pages=8;
            if(pe.p.serial) {
                int released=li2_pe_source_abort(&pe.token);
                if(!released && li2_pe_source_progress()->release_complete) {
                    pe.p.anchor_released=1;pe.cleanup_complete=1;
                }
            } else if(!li2_lifecycle_fetch_interlock()) {
                pe.cleanup_complete=1;
            }
        }
    }
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();if(f)pe.final_fetch=*f;
    report(125,pe.p.first_error,pe.p.first_detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int selected_persistent_trace_try(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pe.initialized || pe.p.serial || pe_busy || pe_active || !le_trace_coarse(sig,si,uc))return 0;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(original_main.bias>UINTPTR_MAX-LI2_PE_APP_HEAD_RVA || pc!=original_main.bias+LI2_PE_APP_HEAD_RVA)return 0;
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    if(r->registered!=1 || r->phase!=LI2_RSEQ_ACTIVE)return 0;
    pe_closing=1;pe_busy=1;__asm__ volatile("":::"memory");
    pe_need(!le_capture(&pe.ingress,sig,si,uc),PE_FRAME,0);pe.close_started=1;
    int e=li2_tf_chain_span_close(&selected_chain,sig,si,uc,&pe.ticket);
    pe_need(!e && pe.ticket,PE_EVENT,e);pe.transfer=*li2_tf_chain_span_progress();
    pe_need(pe.transfer.phase==LI2_ST_CLOSED && pe.transfer.issued==1 &&
        pe.transfer.event==selected_chain.event_id && pe.transfer.pc==pc &&
        pe.transfer.flags==((uint64_t)pe.ingress.frame.greg[REG_EFL]&~SELECTED_TF),PE_EVENT,0);
    pe.close_complete=1;pe_closing=0;pe.flags=pe.transfer.flags;
    selected_logical_flags=pe.flags;selected_flags_known=1;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    pe_need(!le_capture(&pe.before,sig,si,uc),PE_FRAME,1);
    pe_need(!li2_pe_epoch_begin(pe.ticket,pe.transfer.serial,&selected_session,sig,si,uc,&pe.token),PE_RSEQ,2);
    le_zero(&selected_borrow,sizeof selected_borrow);le_zero(&selected_view,sizeof selected_view);
    pe.prepare_started=1;e=li2_lifecycle_fetch_prepare(pc,15,&selected_borrow);
    pe_need(!e,PE_SOURCE,e);e=li2_lifecycle_fetch_view(&selected_borrow,&selected_view);
    pe_need(!e && selected_view.pc==pc && selected_view.length==15 && selected_view.page_count==1 &&
        selected_view.identity_observed && selected_view.pid==pe.session.pid && selected_view.tid==pe.session.tid,PE_SOURCE,e);
    pe.prepare_complete=1;
    pe_need(original_main.bias<=UINTPTR_MAX-LI2_PE_APP_SECOND_PAGE_RVA,PE_SOURCE,2);
    uintptr_t pages[2]={pc&~(PAGE-1),original_main.bias+LI2_PE_APP_SECOND_PAGE_RVA};
    pe_need(pages[0]<pages[1] && !(pages[1]&(PAGE-1)) && image_code(&original_main,pages[0]) &&
        image_code(&original_main,pages[0]+PAGE-1) && image_code(&original_main,pages[1]) &&
        image_code(&original_main,pages[1]+PAGE-1),PE_SOURCE,3);
    pe_need(!li2_pe_epoch_sources(&pe.token,&selected_borrow,pages),PE_SOURCE,4);
    pe_build(sig,si,uc);pe_need(!li2_pe_epoch_bind(&pe.token,&pe.generation),PE_PUBLICATION,2);
    pe_need(!li2_pe_epoch_enter(&pe.token,sig,si,uc),PE_PUBLICATION,3);
    selected_initialized();__asm__ volatile("":::"memory");pe_busy=0;return 1;
}
static void selected_persistent_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    int e=li2_pe_epoch_preentry(sig,si,uc);
    if(e) {
        if(pe_terminal_ingress){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
        pe_terminal_ingress=1;__asm__ volatile("":::"memory");
        if(!pe.unexpected_frame.started)(void)le_capture(&pe.unexpected_frame,sig,si,uc);
        selected_persistent_abort((unsigned)e,sig);
    }
}
static void selected_persistent_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    pe_need(pe_active && pe_busy && pe.exit_seen && pe.p.phase==LI2_PE_RECOVERING &&
        selected_pending_route==SELECTED_PERSISTENT_EPOCH && selected_step_pending==1 &&
        pe.after.sig==sig && le_unchanged(&pe.after,si,uc),PE_STATE,7);
    pe_tls(&pe.after);pe_need(pe.before.fs==pe.after.fs && pe.before.gs==pe.after.gs,PE_TLS,1);
    pe_preserved();pe_need(pe_identity() && pe_ready() && le_quiet(&pe.ref) &&
        !li2_pe_rseq_live(&pe.token,uc,&pe.live[2]),PE_RSEQ,3);
    pe_need(!li2_pe_epoch_drain(&pe.token) && le_unchanged(&pe.after,si,uc) &&
        le_quiet(0) && pe_registry(),PE_RELEASE,0);
    pe.completed=1;pe.p.completion_permit=1;
    selected_logical_flags=(uint64_t)pe.after.frame.greg[REG_EFL]&~SELECTED_RF;selected_flags_known=1;
    pe_active=0;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    __asm__ volatile("":::"memory");pe_busy=0;selected_fetch(sig,si,uc);
}
static void selected_persistent_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};text(&w,"LI2_PERSISTENT_EPOCH {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"phase\":",pe.p.phase);field(&w,",\"serial\":",pe.p.serial);
    field(&w,",\"entries\":",pe.entries);field(&w,",\"completed\":",pe.completed);
    field(&w,",\"unexpected\":",pe.unexpected);field(&w,",\"permit\":",pe.p.completion_permit);
    field(&w,",\"opened_pages\":",pe.p.opened_pages);field(&w,",\"closed_pages\":",pe.p.closed_pages);
    field(&w,",\"anchor_released\":",pe.p.anchor_released);field(&w,",\"registration_rechecked\":",pe.p.registration_rechecked);
    field(&w,",\"guest_data_fault\":",pe.guest_data_fault);
    field(&w,",\"recovery_complete\":",pe.recovery_complete);
    field(&w,",\"first_error\":",pe.p.first_error);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(18*21+400<=sizeof(((struct writer *)0)->bytes),"bounded distinct primitive report");
