/* One immutable activation window, separate from retained generation code.
   The early guard is pure and precedes capture/reset/TRACE close. Mapping
   observations occur only after the old TRACE has actually closed. */
#include "linked_call_dispatch.h"
#include "maps_call_stack.h"
#if !defined(LI2_PERSISTENT_SUBENTRY) || LI2_PERSISTENT_SUBENTRY != 1
#error "CALL window uses the actual subentry source-pair selection"
#endif
struct pcw_seed {
    uintptr_t rsp,pc,first,end,page[2];
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
};
static struct {
    uintptr_t address;
    unsigned allocated,registered,prepared,bound;
    struct pcw_seed seed;
    struct li2_maps_call_stack prepared_stack,bound_stack;
    struct li2_cd_window expected;
    struct li2_private_code_query initial;
    struct le_permission initial_seal,write,seal;
} pcw;
static uintptr_t pcw_address(void) {return pcw.address;}
static int pcw_apart(uintptr_t first,uintptr_t end,uintptr_t base,size_t bytes) {
    return bytes && base<=UINTPTR_MAX-bytes && (end<=base || base+bytes<=first);
}
static int pcw_source(const struct pcw_seed *s,const struct li2_pg_source_key *key) {
    for(unsigned i=0;i<2;i++) {
        uintptr_t at=key->page[i].identity.address;
        if(at<PAGE || (at&(PAGE-1)) || at>(UINT64_C(1)<<47)-PAGE ||
           !pcw_apart(s->first,s->end+8,at,PAGE))return 0;
    }
    return 1;
}
static int pcw_ranges(const struct pcw_seed *s) {
    if(!s || s->first<PAGE || s->first>UINTPTR_MAX-512 || s->end!=s->first+512 ||
       s->end>=(UINT64_C(1)<<47)-8 || s->rsp!=s->first+256 ||
       !s->registry_count || s->registry_count!=protected_count || protected_count>RANGES ||
       !equal(s->registry,protected,protected_count*sizeof *protected) ||
       intersects(s->first,520))return 0;
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    if(!r || !r->initialized || r->first_error || r->pid<=0 || r->pid!=r->tid || r->registered>1)return 0;
    if(r->registered) {
        if(!r->held || r->phase!=LI2_RSEQ_ACTIVE || r->length!=32 ||
           r->address>UINTPTR_MAX-r->length || r->page!=(r->address&~(PAGE-1)) ||
           !pcw_apart(s->first,s->end+8,r->page,PAGE))return 0;
    } else if(r->held || r->phase!=LI2_RSEQ_IDLE)return 0;
    return 1;
}
static void pcw_initialize(void) {
    pe_need(!pcw.allocated && !pcw.registered && !pcw.address &&
        selected_run_protect_contains(0,(uintptr_t)&pcw,sizeof pcw)==1 &&
        protected_count<=RANGES-3U*LI2_PTR_SLOTS-2U,PE_STATE,130);
    pe_need(!selected_run_protect_add(0,(uintptr_t)&pcw,sizeof pcw),PE_STATE,133);
#ifdef LI2_PERSISTENT_RET_DISPATCH
    /* The bounded low-bank RET profile still requires exact emitter rel32
       reachability. Far high-bank RET plans decline with RELOCATION. */
    long address=raw(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT,-1,0);
#else
    long address=raw(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
#endif
    pe_need(address>0 && !((uintptr_t)address&(PAGE-1)) &&
        (uintptr_t)address<(UINT64_C(1)<<47)-PAGE,PE_PUBLICATION,address);
#ifdef LI2_PERSISTENT_RET_DISPATCH
    pe_need((uintptr_t)address<(UINT64_C(1)<<31)-PAGE,PE_PUBLICATION,177);
#endif
    pcw.address=(uintptr_t)address;pcw.allocated=1;
    pe_need(!selected_run_protect_add(0,pcw.address,PAGE),PE_STATE,131);pcw.registered=1;
    pe_need(!pe_query(pcw.address,PAGE,PROT_READ|PROT_WRITE,&pcw.initial) &&
        !pe_permission(pcw.address,PAGE,PROT_READ,&pcw.initial_seal),PE_PUBLICATION,130);
}
static void pcw_reset(void) {
#ifdef LI2_PERSISTENT_RET_DISPATCH
    pe_need(!prr_pending && !prr_busy,PE_STATE,170);
#endif
    pe_need(!pe_active && !pe.resuming && pcw.allocated==1 && pcw.registered==1,PE_STATE,132);
    pcw.prepared=pcw.bound=0;
    le_zero(&pcw.seed,sizeof pcw.seed);le_zero(&pcw.expected,sizeof pcw.expected);
    le_zero(&pcw.prepared_stack,sizeof pcw.prepared_stack);le_zero(&pcw.bound_stack,sizeof pcw.bound_stack);
    le_zero(&pcw.write,sizeof pcw.write);le_zero(&pcw.seal,sizeof pcw.seal);
}
static int pcw_coarse(const ucontext_t *uc,const uintptr_t pages[2],struct pcw_seed *out) {
    if(!uc || !pages || !out || pe_busy || pe_active || !pcw.address ||
       pcw.allocated!=1 || pcw.registered!=1 || !protected_count || protected_count>RANGES)return 0;
    uintptr_t rsp=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    if(rsp<PAGE+256 || rsp>=(UINT64_C(1)<<47)-264)return 0;
    uintptr_t first=rsp-256,end=rsp+256;
    if(intersects(first,520) || !li2_maps_call_stack_advisory(first,520))return 0;
    for(unsigned i=0;i<2;i++)if(pages[i]<PAGE || (pages[i]&(PAGE-1)) ||
       pages[i]>(UINT64_C(1)<<47)-PAGE || !pcw_apart(first,end+8,pages[i],PAGE))return 0;
    /* Every retained peer is excluded before selection can expand the domain.
       The actual held member keys are checked again at bind, not inferred. */
    struct pcw_seed seed={.rsp=rsp,.pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP],
        .first=first,.end=end,.page={pages[0],pages[1]},.registry_count=protected_count};
    copy(seed.registry,protected,protected_count*sizeof *protected);
    if(!pcw_ranges(&seed))return 0;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)if(pe.retained[i].generation.installed &&
        !pcw_source(&seed,&pe.retained[i].publication.source))return 0;
    *out=seed;return 1;
}
static int pcw_prepare(const struct pcw_seed *seed) {
    const struct li2_pg_sources *source=li2_pg_source_view(&pe.token);
    if(pcw.prepared || pcw.bound || !pe_busy || pe_active || pe.p.phase!=LI2_PG_HELD ||
       !pe.close_complete || !seed || !source || !source->complete ||
       seed->rsp!=(uintptr_t)pe.before.frame.greg[REG_RSP] ||
       seed->pc!=(uintptr_t)pe.before.frame.greg[REG_RIP] ||
       source->key.page[0].identity.address!=seed->page[0] ||
       source->key.page[1].identity.address!=seed->page[1] ||
       !pcw_ranges(seed) || !pcw_source(seed,&source->key))return PE_SOURCE;
    struct li2_maps_call_stack observed;
    if(li2_maps_call_stack_query(seed->first,520,&observed))return PE_SOURCE;
    pcw.seed=*seed;pcw.prepared_stack=observed;
    pcw.expected=(struct li2_cd_window){.version=LI2_CD_VERSION,.owner=(uintptr_t)&pe,
        .serial=pe.token.serial,.first=seed->first,.end=seed->end};
    pcw.prepared=1;return 0;
}
int li2_pg_call_window_check(const struct li2_pg_token *t,uintptr_t address,const ucontext_t *uc) {
    if(!t || !uc || !pe_token(t) || !pe_busy || pe_active || pcw.prepared!=1 ||
       (pe.p.phase!=LI2_PG_HELD && pe.p.phase!=LI2_PG_BOUND && pe.p.phase!=LI2_PG_OPENING) ||
       address!=pcw.address || pcw.allocated!=1 || pcw.registered!=1 ||
       pcw.expected.version!=LI2_CD_VERSION || pcw.expected.owner!=(uintptr_t)&pe ||
       pcw.expected.serial!=t->serial || pcw.expected.first!=pcw.seed.first || pcw.expected.end!=pcw.seed.end ||
       pcw.seed.rsp!=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP] ||
       !pcw_ranges(&pcw.seed) ||
       !li2_maps_call_stack_advisory(pcw.seed.first,520))return PE_SOURCE;
    const struct li2_pg_sources *source=li2_pg_source_view(t);
    if(!source || !source->complete || !pcw_source(&pcw.seed,&source->key))return PE_SOURCE;
    return 0;
}
static int pcw_equal(void) {
    if(pcw.bound!=1 || pcw.prepared!=1 || pcw.expected.serial!=pe.p.serial ||
       pcw.expected.version!=LI2_CD_VERSION || pcw.expected.owner!=(uintptr_t)&pe ||
       pcw.expected.first!=pcw.seed.first || pcw.expected.end!=pcw.seed.end || !pcw_ranges(&pcw.seed) ||
       pcw.seal.complete!=1 || pcw.seal.result || pcw.seal.sync_result ||
       !pg_query_complete(&pcw.seal.query,pcw.address,PAGE,PROT_READ))return 0;
    const volatile unsigned char *actual=(const void *)pcw.address;
    const unsigned char *expected=(const void *)&pcw.expected;
    for(size_t i=0;i<PAGE;i++)if(actual[i]!=(i<sizeof pcw.expected?expected[i]:0))return 0;
    return 1;
}
static int pcw_bind(const ucontext_t *uc) {
    if(pcw.bound || li2_pg_call_window_check(&pe.token,pcw.address,uc))return PE_SOURCE;
    const struct li2_pgd_view *v=li2_pgd_owner_view(&pe.token);
    if(!v || !v->count || v->count>LI2_PGD_MEMBERS)return PE_SOURCE;
    for(unsigned i=0;i<v->count;i++)if(!pcw_source(&pcw.seed,v->member[i].key) ||
        v->member[i].identity.layout.window!=pcw.address)return PE_SOURCE;
    if(li2_maps_call_stack_query(pcw.seed.first,520,&pcw.bound_stack) ||
       pcw.bound_stack.anchor!=pcw.prepared_stack.anchor ||
       pcw.bound_stack.origin_first!=pcw.prepared_stack.origin_first ||
       pcw.bound_stack.origin_end!=pcw.prepared_stack.origin_end ||
       pcw.bound_stack.origin_acquisition!=pcw.prepared_stack.origin_acquisition)return PE_SOURCE;
    int error=pe_permission(pcw.address,PAGE,PROT_READ|PROT_WRITE,&pcw.write);if(error)return error;
    volatile unsigned char *actual=(void *)pcw.address;const unsigned char *expected=(const void *)&pcw.expected;
    for(size_t i=0;i<PAGE;i++)actual[i]=i<sizeof pcw.expected?expected[i]:0;
    error=pe_permission(pcw.address,PAGE,PROT_READ,&pcw.seal);if(error)return error;
    pcw.bound=1;return pcw_equal()?0:PE_PUBLICATION;
}
#ifdef LI2_PERSISTENT_RET_DISPATCH
static uintptr_t pcw_ret_miss(uintptr_t generated) {
    unsigned found=0,slot=LI2_PTR_SLOTS;
    for(unsigned i=0;i<LI2_PTR_SLOTS;i++)for(unsigned j=0;j<2;j++)
        if(generated && pe.retained[i].banks[j].generated==generated) {++found;slot=i;}
    pe_need(found==1 && slot<LI2_PTR_SLOTS && pcw.address &&
        64U+8U*LI2_PTR_SLOTS*LI2_PG_HEADS<=PAGE,PE_PUBLICATION,170);
    return pcw.address+64U+8U*slot*LI2_PG_HEADS;
}
#endif
