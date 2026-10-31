/* Two immutable images and one stub page share one actual source/rseq lease.
   Link slots are data; code stays sealed across all internal group edges. */
#if !defined(LI2_PERSISTENT_GROUP) || LI2_PERSISTENT_GROUP != 1 || defined(LI2_PERSISTENT_EPOCH_CAPTURE)
#error "group release owner has its own future capture contract"
#endif
#include "persistent_group_plan.h"
#include "persistent_group_runtime.h"
#include "persistent_group_config.h"
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
#include "persistent_group_observe.h"
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
#include "persistent_resident_observe.h"
#endif
#if defined(LI2_PERSISTENT_DISPATCH)
#if LI2_PG_BINDING_VERSION != 1 || LI2_PG_GROUP_BINDING_VERSION != 2 || LI2_PERSISTENT_EPOCH != 1
#error "dispatch version2 policy and archive binding required"
#endif
#elif LI2_PG_BINDING_VERSION != 1 || LI2_PG_GROUP_BINDING_VERSION != 1 || LI2_PERSISTENT_EPOCH != 1
#error "exact group archive, policy and whole-image configuration required"
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
    struct li2_pg_layout layout;
    uint64_t member_generation[2];
    uint64_t plan_proof,none_proof,source_validations,registered_epoch;
    uint64_t rseq_address,rseq_length,rseq_signature;
    unsigned char archive[32],policy[32];
    uint64_t reserved[4];
};
struct pe_payload {
    struct pe_header header;
    struct li2_pg_source_key source;
    struct li2_pg_compact plan;
};
#define PE_PROOF_BYTES ((sizeof(struct pe_payload)+PAGE-1U)&~(PAGE-1U))
#define PE_CODE_BYTES (LI2_PG_CODE_PAGES*PAGE)
#define PE_ALLOC_BYTES (PE_CODE_BYTES+2U*PAGE)
_Static_assert(PE_PROOF_BYTES<=96U*PAGE,"one bounded immutable source/plan publication");
/* The private query API retains its 64-page limit. Both actual receipts cover
   the one 89-page proof; no fabricated aggregate query stands in for either. */
#define PG_PROOF_FIRST_BYTES (64U*PAGE)
_Static_assert(PE_PROOF_BYTES==89U*PAGE,"exact current group proof extent");
struct pg_proof_query { struct li2_private_code_query part[2]; };
struct pg_proof_permission {
    unsigned started,returned,sync_started,sync_returned,complete;
    int prot;
    long result,sync_result;
    struct pg_proof_query query;
};
_Static_assert(sizeof(struct pg_proof_query)==2U*sizeof(struct li2_private_code_query),
    "two complete actual bounded queries");
_Static_assert(offsetof(struct pg_proof_permission,query)==offsetof(struct le_permission,query),
    "unchanged whole permission transition prefix");
struct pg_slot_transition {
    struct li2_private_code_query code[3];
    struct le_permission write,seal;
    size_t copied,verified;
    unsigned started,linked,complete;
};
#ifdef LI2_PERSISTENT_DISPATCH
/* A cell is private mutable data, never patched executable code. Every reset
   occurs under the exact active generation, after all17 code pages are NX
   and before references/source authority can be released. */
struct pg_dispatch_cell_transition {
    uint64_t generation,serial,before,after;
    unsigned started,complete;
    struct li2_private_code_query mapping;
};
#endif
struct li2_pg_generation {
    unsigned installed,complete,proof_complete;
    uint64_t generation,ready_generation,build_serial,plan_proofs,none_proofs;
    uintptr_t generated,proof,spill;
    struct li2_pg_layout layout;
    uint64_t member_generation[2],active_refs,incoming[2],member_refs[2];
    unsigned linked;
    size_t code_copied,code_verified,proof_zeroed,proof_copied,proof_verified;
    struct li2_private_code_query code_writable[3];
    struct pg_proof_query proof_writable;
    struct li2_private_code_query spill_query,slot_query;
    struct le_permission code_sealed[3];
    struct pg_proof_permission proof_sealed;
    struct le_permission open[3],close[3],cleanup[3];
    struct pg_slot_transition slots[3]; /* initial RESET, LINKED, drained RESET */
#ifdef LI2_PERSISTENT_DISPATCH
    struct pg_dispatch_cell_transition cell[3];
#endif
};
struct ped_bank {
    uintptr_t generated,spill;
    struct li2_pg_layout layout;
    unsigned allocated,registered,virgin;
    int prot;
    struct li2_private_code_query initial[3],initial_spill,initial_slots;
};
struct ped_permit {
    unsigned valid;
    uint64_t serial,generation,ref_sequence;
    uintptr_t generated,proof;
    struct le_permission close[3];
    struct li2_pg_layout layout;
    uint64_t member_generation[2];
    struct li2_private_code_query reset_slots;
    struct pg_proof_query proof_query;
    struct li2_fetch_progress fetch;
    struct li2_pg_source_progress source;
    struct li2_pg_source_key generation_source;
    struct li2_pg_rseq_progress rseq;
};
struct li2_pg_epoch {
    struct li2_pg_progress p,last_terminal;
    uint64_t next_serial,next_generation,offers,publications,hits,cold_attempts,cancelled,retirements,permit_claims;
    uint64_t misses[LI2_PGD_REASON_COUNT];
    unsigned selected_bank,resuming,warm;
    struct ped_bank banks[2];
    struct ped_permit permit;
    struct li2_pg_miss miss;
    struct li2_private_code_query claim_code[3];
    struct pg_proof_query claim_proof;
    struct li2_private_code_query claim_spill,claim_slots,bank_before[3];
    struct pg_proof_query proof_before;
    struct le_permission reopen_code[3];
    struct pg_proof_permission reopen_proof;
    size_t candidate_registry_count;
    struct li2_fork_range candidate_registry[RANGES];
    struct pe_payload candidate;
    unsigned initialized,registered,code_allocated,proof_allocated,code_registered,proof_registered;
    unsigned close_started,close_complete,prepare_started,prepare_complete,build_started,build_returned;
    unsigned redirected,exit_seen,exit_index,recovery_started,recovery_complete,guest_data_fault;
    unsigned cleanup_started,cleanup_complete,consumed,plan_proofs,none_proofs;
    long code_allocation,proof_allocation;
    int build_result,recovery_result,release_result;
    uint64_t flags,gpr_written,flags_written,entries,completed,unexpected;
    struct li2_pg_token token;
    struct li2_step_session session;
    const struct li2_tf_span_transfer *ticket;
    struct li2_span_transfer_progress transfer;
    struct li2_fetch_ref ref;
    struct li2_pg_generation generation;
    struct le_frame ingress,before,after,unexpected_frame;
    struct li2_link_rseq_live live[3];
    struct li2_pg_recovered recovered;
    struct li2_fetch_progress final_fetch;
    struct pg_proof_query proof_exit;
    struct li2_private_code_query code_exit[3];
    size_t registry_count;
    struct li2_fork_range registry[RANGES];
    struct li2_mg_range exclusions[LI2_MG_RANGES];
    struct li2_pg_plan cold,rebuild;
    struct li2_pg_compact compact_rebuild;
    struct pe_payload publication;
#ifdef LI2_PERSISTENT_DISPATCH
    union li2_pg_guard recovery_scratch;
#else
    struct li2_mg_plan recovery_scratch;
#endif
};
static struct li2_pg_epoch pe;
static volatile sig_atomic_t pe_busy,pe_active,pe_failing,pe_closing,pe_decoding,pe_terminal_ingress;
static const unsigned char pe_archive[32]=LI2_PG_ARCHIVE_SHA256;
static const unsigned char pe_policy[32]=LI2_PG_POLICY_SHA256;
static const unsigned pe_greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static _Noreturn void selected_persistent_abort(unsigned,long);
static void pe_need(int yes,unsigned code,long detail) {if(!yes)selected_persistent_abort(code,detail);}
unsigned li2_pg_owner_phase(const struct li2_pg_token *t) {
    return t && t->owner==&pe && t->serial && t->serial==pe.p.serial &&
        pe.initialized && pe.registered?pe.p.phase:0;
}
int li2_pg_epoch_interlock(void) {
    return pe_busy || pe_active || (pe.p.phase!=LI2_PG_IDLE && pe.p.phase!=LI2_PG_CLOSED && pe.p.phase!=LI2_PG_CANCELLED);
}
const struct li2_pg_progress *li2_pg_epoch_progress(void) {return &pe.p;}
static int pe_token(const struct li2_pg_token *t) {return li2_pg_owner_phase(t)!=0;}
static const struct pe_payload *pe_payload(void) {return (const void *)pe.generation.proof;}
static int pe_registered_storage(void) {
    if(!pe.initialized || !pe.registered || pe.code_allocated!=2 || !pe.proof_allocated ||
       pe.code_registered!=2 || !pe.proof_registered || pe.selected_bank>1 ||
       selected_run_protect_contains(0,(uintptr_t)&pe,sizeof pe)!=1 ||
       selected_run_protect_contains(0,pe.generation.proof,PE_PROOF_BYTES)!=1)return 0;
    for(unsigned i=0;i<2;i++)if(pe.banks[i].allocated!=1 || pe.banks[i].registered!=1 ||
       selected_run_protect_contains(0,pe.banks[i].generated,PE_ALLOC_BYTES)!=1)return 0;
    return 1;
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
static int pg_proof_query(uintptr_t address,int prot,struct pg_proof_query *q) {
    if(!q || !address || (address&(PAGE-1)) || address>UINTPTR_MAX-PE_PROOF_BYTES)return PE_PUBLICATION;
    int e=pe_query(address,PG_PROOF_FIRST_BYTES,prot,&q->part[0]);
    if(e)return e;
    return pe_query(address+PG_PROOF_FIRST_BYTES,PE_PROOF_BYTES-PG_PROOF_FIRST_BYTES,prot,&q->part[1]);
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
static int pg_proof_permission(uintptr_t address,int prot,struct pg_proof_permission *p) {
    if(p->started)return PE_STATE;
    p->started=1;p->prot=prot;__asm__ volatile("":::"memory");
    p->result=raw(SYS_mprotect,address,PE_PROOF_BYTES,prot,0,0,0);p->returned=1;
    p->sync_started=1;__asm__ volatile("":::"memory");
    p->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);p->sync_returned=1;
    int e=pg_proof_query(address,prot,&p->query);
    if(p->result || p->sync_result || e)return PE_PUBLICATION;
    p->complete=1;return 0;
}
static uintptr_t pg_extent(const struct li2_pg_layout *l,unsigned i) {
    return i<2?l->generated[i]:l->stubs;
}
static size_t pg_extent_bytes(unsigned i) {return i<2?LI2_PE_IMAGE_BYTES:PAGE;}
static struct li2_pg_layout pg_layout(uintptr_t base) {
    return (struct li2_pg_layout){.generated={base,base+LI2_PE_IMAGE_BYTES},
        .stubs=base+2U*LI2_PE_IMAGE_BYTES,.slots=base+PE_CODE_BYTES,
        .spill=base+PE_CODE_BYTES+PAGE};
}
static int pg_layout_equal(const struct li2_pg_layout *a,const struct li2_pg_layout *b) {
    return equal(a,b,sizeof *a);
}
const struct li2_pg_layout *li2_pg_owner_layout(const struct li2_pg_token *t) {
    return pe_token(t)?&pe.p.layout:0;
}
static int pg_queries(const struct li2_pg_layout *l,int prot,struct li2_private_code_query q[3]) {
    for(unsigned i=0;i<3;i++) {
        int e=pe_query(pg_extent(l,i),pg_extent_bytes(i),prot,&q[i]);if(e)return e;
    }
    return 0;
}
static int pg_permissions(const struct li2_pg_layout *l,int prot,struct le_permission p[3],unsigned *pages) {
    if(pages)*pages=0;
    for(unsigned i=0;i<3;i++) {
        int e=pe_permission(pg_extent(l,i),pg_extent_bytes(i),prot,&p[i]);if(e)return e;
        if(pages)*pages+=(unsigned)(pg_extent_bytes(i)/PAGE);
    }
    return 0;
}
static int pg_query_complete(const struct li2_private_code_query *q,uintptr_t a,size_t n,int prot) {
    return q->attempted==1 && q->complete==1 && !q->result && q->first==a &&
        q->end==a+n && q->pages_checked==n/PAGE && q->expected_prot==prot && q->actual_prot==prot;
}
static int pg_proof_query_complete(const struct pg_proof_query *q,uintptr_t address,int prot) {
    return q && address && !(address&(PAGE-1)) && address<=UINTPTR_MAX-PE_PROOF_BYTES &&
        pg_query_complete(&q->part[0],address,PG_PROOF_FIRST_BYTES,prot) &&
        pg_query_complete(&q->part[1],address+PG_PROOF_FIRST_BYTES,
                          PE_PROOF_BYTES-PG_PROOF_FIRST_BYTES,prot);
}
static int pg_proof_permission_complete(const struct pg_proof_permission *p,uintptr_t address,int prot) {
    return p->started==1 && p->returned==1 && p->sync_started==1 && p->sync_returned==1 &&
        p->complete==1 && p->prot==prot && !p->result && !p->sync_result &&
        pg_proof_query_complete(&p->query,address,prot);
}
static int pg_closed(const struct li2_pg_layout *l,const struct le_permission rows[3]) {
    for(unsigned i=0;i<3;i++)if(rows[i].started!=1 || rows[i].returned!=1 ||
       rows[i].sync_started!=1 || rows[i].sync_returned!=1 || rows[i].complete!=1 ||
       rows[i].prot!=PROT_READ || rows[i].result || rows[i].sync_result ||
       !pg_query_complete(&rows[i].query,pg_extent(l,i),pg_extent_bytes(i),PROT_READ))return 0;
    return 1;
}
static unsigned char pg_code_byte(const struct li2_pg_compact *p,size_t i) {
    return i<2U*LI2_PE_IMAGE_BYTES?p->image[i/LI2_PE_IMAGE_BYTES][i%LI2_PE_IMAGE_BYTES]:
        p->stub_image[i-2U*LI2_PE_IMAGE_BYTES];
}
static int pg_slots(unsigned linked) {
    const struct li2_pg_generation *g=&pe.generation;
    const struct li2_pg_compact *p=&pe_payload()->plan;
#ifdef LI2_PERSISTENT_DISPATCH
    if(linked>1 || g->linked!=linked || !p->exits || p->exits>LI2_PG_BOUNDARIES ||
       p->links>LI2_PG_BOUNDARIES || p->links+p->exits>LI2_PG_BOUNDARIES)return 0;
#else
    if(linked>1 || g->linked!=linked || !p->links || p->links+p->exits>LI2_PG_BOUNDARIES)return 0;
#endif
    const volatile unsigned char *b=(const void *)g->layout.slots;
    for(unsigned i=0;i<PAGE;i++) {
        unsigned j=i/8,k=i%8;uint64_t value=0;
        if(j<p->links)value=linked?p->edge[j].generated_target:p->edge[j].original_target;
        if(b[i]!=(unsigned char)(value>>(8*k)))return 0;
    }
    return 1;
}
static int pg_refs(unsigned linked) {
    const struct li2_pg_generation *g=&pe.generation;
    if(linked>1 || g->active_refs!=linked || g->member_refs[0]!=linked || g->member_refs[1]!=linked)return 0;
    uint64_t incoming[2]={0,0};
    if(linked) {
        const struct li2_pg_compact *p=&pe_payload()->plan;
        for(unsigned i=0;i<p->links;i++) {
            if(p->edge[i].target_head>=p->heads)return 0;
            ++incoming[p->edge[i].target_head/LI2_PE_HEADS];
        }
    }
    return g->incoming[0]==incoming[0] && g->incoming[1]==incoming[1];
}
/* All code is independently queried NX before a slot write. A partial prefix
   retains references and cannot issue a completed replacement permit. */
static int pg_link_data(unsigned step) {
    struct li2_pg_generation *g=&pe.generation;
    const struct li2_pg_compact *p=&pe_payload()->plan;
    if(step>2 || !g->installed || !g->proof_complete || !g->complete)return PE_STATE;
    unsigned linked=step==1;
    struct pg_slot_transition *t=&g->slots[step];
    if(t->started || (step && (!pg_slots(!linked) || !pg_refs(!linked))) ||
       (!step && (g->linked || !pg_refs(0))))return PE_STATE;
    t->started=1;t->linked=linked;
    int e=pg_queries(&g->layout,PROT_READ,t->code);if(e)return e;
    if(linked) {
        g->active_refs=1;g->member_refs[0]=g->member_refs[1]=1;
        for(unsigned i=0;i<p->links;i++) {
            unsigned member=p->edge[i].target_head/LI2_PE_HEADS;
            if(member>=2 || g->incoming[member]==UINT64_MAX)return PE_STATE;
            ++g->incoming[member];
        }
    }
    if((e=pe_permission(g->layout.slots,PAGE,PROT_READ|PROT_WRITE,&t->write)))return e;
    volatile unsigned char *b=(void *)g->layout.slots;
    for(unsigned i=0;i<PAGE;i++) {
        unsigned j=i/8,k=i%8;uint64_t value=0;
        if(j<p->links)value=linked?p->edge[j].generated_target:p->edge[j].original_target;
        b[i]=(unsigned char)(value>>(8*k));t->copied=i+1;
    }
    if((e=pe_permission(g->layout.slots,PAGE,PROT_READ,&t->seal)))return e;
#ifdef LI2_PERSISTENT_DISPATCH
    struct pg_dispatch_cell_transition *cell=&g->cell[step];
    if(cell->started || cell->complete || !pe_busy || pe_closing)return PE_STATE;
    for(unsigned i=0;i<3;i++)if(!pg_query_complete(&t->code[i],pg_extent(&g->layout,i),
        pg_extent_bytes(i),PROT_READ))return PE_PUBLICATION;
    cell->started=1;cell->generation=g->generation;cell->serial=pe.p.serial;
    if((e=pe_query(g->spill,PAGE,PROT_READ|PROT_WRITE,&cell->mapping)))return e;
    volatile uint64_t *target=(void *)(g->spill+32);
    cell->before=*target;*target=0;__asm__ volatile("":::"memory");
    cell->after=*target;if(cell->after)return PE_PUBLICATION;
    cell->complete=1;
#endif
    g->linked=linked;
    if(!pg_slots(linked))return PE_PUBLICATION;
    t->verified=PAGE;
    if(!linked)g->active_refs=g->member_refs[0]=g->member_refs[1]=g->incoming[0]=g->incoming[1]=0;
    if(!pg_refs(linked))return PE_STATE;
    t->complete=1;return 0;
}
static int pe_bytes(void) {
    const struct li2_pg_generation *g=&pe.generation;
    const struct pe_payload *p=pe_payload();
    const volatile unsigned char *code=(const void *)g->generated,*proof=(const void *)g->proof;
    const unsigned char *expected=(const void *)&pe.publication;
    for(size_t i=0;i<PE_CODE_BYTES;i++)if(code[i]!=pg_code_byte(&p->plan,i))return PE_PUBLICATION;
    for(size_t i=0;i<PE_PROOF_BYTES;i++)
        if(proof[i]!=(i<sizeof pe.publication?expected[i]:0))return PE_PUBLICATION;
    return 0;
}
/* Pure fixed-address generation authentication, before recovery scratch or
   any spill access. Mutable cold scratch alone never grants this authority. */
static int ped_stored(void) {
    const struct li2_pg_generation *g=&pe.generation;
    if(!pe_registered_storage() || g->installed!=1 || g->complete!=1 || g->proof_complete!=1 ||
       !g->generation || g->generation!=pe.next_generation || g->ready_generation!=g->generation ||
       !g->build_serial || g->build_serial>pe.next_serial || !pg_closed(&g->layout,g->code_sealed) ||
       !pg_proof_permission_complete(&g->proof_sealed,g->proof,PROT_READ) ||
       g->code_copied!=PE_CODE_BYTES || g->code_verified!=PE_CODE_BYTES ||
       g->proof_zeroed!=PE_PROOF_BYTES || g->proof_copied!=sizeof(struct pe_payload) ||
       g->proof_verified!=PE_PROOF_BYTES || g->member_generation[0]!=2*g->generation ||
       g->member_generation[1]!=2*g->generation+1)return 0;
    unsigned found=0;
    for(unsigned i=0;i<2;i++)found+=g->generated==pe.banks[i].generated &&
        g->spill==pe.banks[i].spill && pg_layout_equal(&g->layout,&pe.banks[i].layout);
    if(found!=1)return 0;
    const struct pe_payload *p=pe_payload();
    return equal(&p->header,&pe.publication.header,sizeof p->header) &&
        equal(&p->source,&pe.publication.source,sizeof p->source) &&
        p->header.version==1 && p->header.serial==g->build_serial &&
        p->header.generation==g->generation && p->header.registry==(uintptr_t)&pe &&
        p->header.generated==g->generated && p->header.spill==g->spill &&
        pg_layout_equal(&p->header.layout,&g->layout) &&
        equal(p->header.member_generation,g->member_generation,sizeof g->member_generation) &&
        p->header.table==g->proof+offsetof(struct pe_payload,plan.table) &&
        p->header.plan_proof==g->plan_proofs && g->plan_proofs==2 &&
        p->header.none_proof==g->none_proofs && g->none_proofs==1 &&
        equal(p->header.archive,pe_archive,32) && equal(p->header.policy,pe_policy,32) &&
        p->plan.version==LI2_PG_COMPACT_VERSION && p->plan.bytes==sizeof p->plan &&
        p->plan.ready==1 && !p->plan.result && pg_layout_equal(&p->plan.layout,&g->layout) &&
        p->plan.table.address==p->header.table && p->plan.entry==p->source.entry &&
#ifdef LI2_PERSISTENT_DISPATCH
        p->plan.heads && p->plan.heads<=LI2_PG_HEADS &&
        p->plan.member_heads[0]==(p->plan.heads<LI2_PE_HEADS?p->plan.heads:LI2_PE_HEADS) &&
        p->plan.member_heads[1]==(p->plan.heads>LI2_PE_HEADS?p->plan.heads-LI2_PE_HEADS:0) &&
        p->plan.exits && p->plan.exits<=LI2_PG_BOUNDARIES && p->plan.links<=LI2_PG_BOUNDARIES &&
        p->plan.links+p->plan.exits<=LI2_PG_BOUNDARIES &&
        (uintptr_t)p->plan.original==g->proof+offsetof(struct pe_payload,plan.original);
#else
        p->plan.heads>LI2_PE_HEADS && p->plan.heads<=LI2_PG_HEADS &&
        p->plan.member_heads[0]==LI2_PE_HEADS && p->plan.member_heads[1]==p->plan.heads-LI2_PE_HEADS &&
        p->plan.links && p->plan.exits && p->plan.links+p->plan.exits<=LI2_PG_BOUNDARIES;
#endif
}
static int pe_ready(void) {
    if(!ped_stored() || !pe_token(&pe.token) || !pe_registry() || !pe.consumed ||
       pe.p.generation!=pe.generation.generation || pe.p.publication!=1 ||
       !pg_layout_equal(&pe.p.layout,&pe.generation.layout))return 0;
    const struct li2_pg_sources *s=li2_pg_source_view(&pe.token);
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    const struct pe_payload *p=pe_payload();
    return s && s->complete==1 && !s->reserved && s->serial==pe.p.serial &&
        li2_pg_source_key_equal(&p->source,&s->key) && r && r->active && r->seed_complete &&
        p->header.registered_epoch==r->registration_epoch &&
        p->header.rseq_address==r->address && p->header.rseq_length==r->length &&
        p->header.rseq_signature==r->signature;
}
#ifdef LI2_PERSISTENT_GROUP_COUNTERS
#include "persistent_group_counters.h"
_Static_assert(LI2_PGD_REASON_COUNT==18,"complete actual group miss census");
#define PGC_REF(n) (&li2_pgc_current->group.n)
#define PGC_VALUE(n) __atomic_load_n(PGC_REF(n),__ATOMIC_ACQUIRE)
#define PGC_MISS_REF(i) (&li2_pgc_current->misses[i])
#define PGC_MISS_VALUE(i) __atomic_load_n(PGC_MISS_REF(i),__ATOMIC_ACQUIRE)
static void ped_count(uint64_t *v) {
    uint64_t old=__atomic_load_n(v,__ATOMIC_ACQUIRE);
    pe_need(old!=UINT64_MAX,PE_OVERFLOW,0);__atomic_store_n(v,old+1,__ATOMIC_RELEASE);
}
#else
#define PGC_REF(n) (&pe.n)
#define PGC_VALUE(n) (pe.n)
#define PGC_MISS_REF(i) (&pe.misses[i])
#define PGC_MISS_VALUE(i) (pe.misses[i])
static void ped_count(uint64_t *v) {pe_need(*v!=UINT64_MAX,PE_OVERFLOW,0);++*v;}
#endif
static unsigned ped_bank_for(uintptr_t pc) {return pc<(UINT64_C(1)<<31)?0:1;}
static int ped_capacity(void) {
    if(pe.next_serial==UINT64_MAX || pe.next_generation>=UINT64_MAX/2 || PGC_VALUE(offers)==UINT64_MAX ||
       PGC_VALUE(publications)==UINT64_MAX || PGC_VALUE(hits)==UINT64_MAX || PGC_VALUE(cold_attempts)==UINT64_MAX ||
       PGC_VALUE(cancelled)==UINT64_MAX || PGC_VALUE(retirements)==UINT64_MAX || PGC_VALUE(permit_claims)==UINT64_MAX ||
       PGC_VALUE(entries)==UINT64_MAX || PGC_VALUE(completed)==UINT64_MAX)return 0;
    for(unsigned i=0;i<LI2_PGD_REASON_COUNT;i++)if(PGC_MISS_VALUE(i)==UINT64_MAX)return 0;
    return 1;
}
int li2_pg_owner_cancel_prot(const struct li2_pg_token *t,unsigned extent) {
    if(extent>=3 || !pe_token(t) || pe.p.phase!=LI2_PG_CANCELLING || !pe_busy || pe_active ||
       pe.consumed || pe.redirected || pe.p.opened_pages || pe.selected_bank>1 ||
       !pg_layout_equal(&pe.p.layout,&pe.banks[pe.selected_bank].layout) || !pe_registered_storage())return 0;
    const struct ped_bank *b=&pe.banks[pe.selected_bank];
    if(b->virgin==1 && b->prot==(PROT_READ|PROT_WRITE) &&
       pg_query_complete(&b->initial[extent],pg_extent(&b->layout,extent),pg_extent_bytes(extent),
                         PROT_READ|PROT_WRITE))return PROT_READ|PROT_WRITE;
    return !b->virgin && b->prot==PROT_READ?PROT_READ:0;
}
static int ped_permitted(void) {
    const struct ped_permit *p=&pe.permit;
    const struct li2_pg_generation *g=&pe.generation;
    const struct li2_pg_source_progress *s=&p->source;
    const struct li2_pg_rseq_progress *r=&p->rseq;
    if(!(p->valid==1 && p->serial && p->serial<=pe.next_serial && ped_stored() &&
        p->generation==g->generation && p->generated==g->generated && p->proof==g->proof &&
        pg_layout_equal(&p->layout,&g->layout) &&
        equal(p->member_generation,g->member_generation,sizeof g->member_generation) &&
        !g->linked && !g->active_refs && !g->member_refs[0] && !g->member_refs[1] &&
        !g->incoming[0] && !g->incoming[1] && pg_slots(0) &&
        pg_query_complete(&p->reset_slots,g->layout.slots,PAGE,PROT_READ) &&
        p->ref_sequence && p->fetch.sequence==p->ref_sequence && !p->fetch.held &&
        p->fetch.complete==1 && !p->fetch.first_error &&
        equal(p->close,g->close,sizeof p->close) && pg_closed(&g->layout,p->close) &&
        pg_proof_query_complete(&p->proof_query,g->proof,PROT_READ) &&
        s->serial==p->serial && s->phase==LI2_PGS_RELEASED && !s->first_error &&
        s->release_started==1 && s->release_complete==1 && s->source.complete==1 &&
        s->closed_extents==3 && s->closed_pages==17 &&
        pg_layout_equal(&s->layout,&g->layout) && s->source.anchor.sequence==p->ref_sequence &&
        equal(&p->generation_source,&pe.publication.source,sizeof p->generation_source) &&
        li2_pg_source_key_equal(&s->source.key,&p->generation_source) &&
        r->token.owner==&pe && r->token.serial==p->serial && !r->active && !r->first_error &&
        !r->unsafe_terminal && r->seed_complete==1 && r->entry_complete==1 && r->close_complete==1 &&
        !r->cancel_started && !r->cancel_complete &&
        r->registration_epoch==pe.publication.header.registered_epoch &&
        r->address==pe.publication.header.rseq_address && r->length==pe.publication.header.rseq_length &&
        r->signature==pe.publication.header.rseq_signature &&
        !r->word_before && !r->word_entry && !r->word_after))return 0;
    for(unsigned i=0;i<3;i++)if(!pg_query_complete(&s->closed[i],pg_extent(&g->layout,i),
        pg_extent_bytes(i),PROT_READ))return 0;
#ifdef LI2_PERSISTENT_DISPATCH
    const struct pg_dispatch_cell_transition *cell=&g->cell[2];
    if(cell->started!=1 || cell->complete!=1 || cell->generation!=g->generation ||
       cell->serial!=p->serial || cell->after ||
       !pg_query_complete(&cell->mapping,g->spill,PAGE,PROT_READ|PROT_WRITE) ||
       *(const volatile uint64_t *)(g->spill+32))return 0;
#endif
    return 1;
}
static void ped_claim(void) {
    pe_need(ped_permitted() && !pe_bytes(),PE_RELEASE,10);
    pe_need(!pg_queries(&pe.generation.layout,PROT_READ,pe.claim_code) &&
        !pg_proof_query(pe.generation.proof,PROT_READ,&pe.claim_proof) &&
        !pe_query(pe.generation.spill,PAGE,PROT_READ|PROT_WRITE,&pe.claim_spill) &&
        !pe_query(pe.generation.layout.slots,PAGE,PROT_READ,&pe.claim_slots),PE_RELEASE,11);
    pe.permit.valid=0;ped_count(PGC_REF(permit_claims));__asm__ volatile("":::"memory");
}
static void ped_reset_attempt(void) {
    pe_need(!pe_busy && !pe_active && !pe.resuming &&
        (pe.p.phase==LI2_PG_IDLE || pe.p.phase==LI2_PG_CLOSED || pe.p.phase==LI2_PG_CANCELLED) &&
        !pe.p.first_error && (!pe.generation.installed || ped_permitted()),PE_STATE,30);
    pe.last_terminal=pe.p;
    le_zero(&pe.p,sizeof pe.p);le_zero(&pe.ingress,sizeof pe.ingress);le_zero(&pe.before,sizeof pe.before);
    le_zero(&pe.after,sizeof pe.after);le_zero(&pe.unexpected_frame,sizeof pe.unexpected_frame);
    le_zero(&pe.live,sizeof pe.live);le_zero(&pe.recovered,sizeof pe.recovered);
    le_zero(&pe.transfer,sizeof pe.transfer);le_zero(&pe.ref,sizeof pe.ref);
    le_zero(&pe.final_fetch,sizeof pe.final_fetch);le_zero(&pe.proof_exit,sizeof pe.proof_exit);
    le_zero(&pe.code_exit,sizeof pe.code_exit);le_zero(&pe.miss,sizeof pe.miss);
    le_zero(&pe.claim_code,sizeof pe.claim_code);le_zero(&pe.claim_proof,sizeof pe.claim_proof);
    le_zero(&pe.claim_spill,sizeof pe.claim_spill);le_zero(&pe.claim_slots,sizeof pe.claim_slots);
    le_zero(&pe.bank_before,sizeof pe.bank_before);le_zero(&pe.proof_before,sizeof pe.proof_before);
    le_zero(&pe.reopen_code,sizeof pe.reopen_code);le_zero(&pe.reopen_proof,sizeof pe.reopen_proof);
    pe.close_started=pe.close_complete=pe.prepare_started=pe.prepare_complete=0;
    pe.build_started=pe.build_returned=pe.redirected=pe.exit_seen=pe.exit_index=0;
    pe.recovery_started=pe.recovery_complete=pe.guest_data_fault=0;
    pe.cleanup_started=pe.cleanup_complete=pe.consumed=pe.plan_proofs=pe.none_proofs=0;
    pe.build_result=pe.recovery_result=pe.release_result=0;
    pe.flags=pe.gpr_written=pe.flags_written=0;pe.ticket=0;pe.warm=0;
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
    for(unsigned i=0;i<2;i++) {
        long v=raw(SYS_mmap,0,PE_ALLOC_BYTES,PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS|(i?0:MAP_32BIT),-1,0);
        pe.code_allocation=v;
        pe_need(v>0 && !((uintptr_t)v&(PAGE-1)) && (uintptr_t)v<(UINT64_C(1)<<47)-PE_ALLOC_BYTES &&
            (i || (uintptr_t)v<(UINT64_C(1)<<31)-PE_ALLOC_BYTES),PE_PUBLICATION,v);
        struct ped_bank *bank=&pe.banks[i];bank->generated=(uintptr_t)v;bank->layout=pg_layout((uintptr_t)v);bank->spill=bank->layout.spill;
        bank->allocated=1;bank->virgin=1;bank->prot=PROT_READ|PROT_WRITE;++pe.code_allocated;
        pe_need(!selected_run_protect_add(0,(uintptr_t)v,PE_ALLOC_BYTES),PE_STATE,2);
        bank->registered=1;++pe.code_registered;
        pe_need(!pg_queries(&bank->layout,PROT_READ|PROT_WRITE,bank->initial),PE_PUBLICATION,1);
    }
    pe.generation.generated=pe.banks[0].generated;pe.generation.spill=pe.banks[0].spill;
    pe.generation.layout=pe.banks[0].layout;
    pe.proof_allocation=raw(SYS_mmap,0,PE_PROOF_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long v=pe.proof_allocation;
    pe_need(v>0 && !((uintptr_t)v&(PAGE-1)) && (uintptr_t)v<(UINT64_C(1)<<47)-PE_PROOF_BYTES,PE_PUBLICATION,v);
    pe.generation.proof=(uintptr_t)v;pe.proof_allocated=1;
    pe_need(!selected_run_protect_add(0,(uintptr_t)v,PE_PROOF_BYTES),PE_STATE,3);pe.proof_registered=1;
    pe_need(!pg_proof_query(pe.generation.proof,PROT_READ|PROT_WRITE,&pe.generation.proof_writable),PE_PUBLICATION,2);
    for(unsigned i=0;i<2;i++)pe_need(!pe_query(pe.banks[i].spill,PAGE,PROT_READ|PROT_WRITE,
        &pe.banks[i].initial_spill),PE_PUBLICATION,3);
    for(unsigned i=0;i<2;i++)pe_need(!pe_query(pe.banks[i].layout.slots,PAGE,PROT_READ|PROT_WRITE,
        &pe.banks[i].initial_slots),PE_PUBLICATION,4);
    pe_need(!li2_pg_source_initialize() && pe_identity(),PE_SOURCE,0);
    pe.initialized=1;pe_busy=0;
}
int li2_pg_epoch_begin(const struct li2_tf_span_transfer *ticket,uint64_t serial,
    struct li2_step_session *session,int sig,const siginfo_t *si,const ucontext_t *uc,struct li2_pg_token *out) {
    const struct li2_span_transfer_progress *t=li2_tf_chain_span_progress();
    if(!pe.initialized || !pe_busy || pe_active || pe.p.serial || !out || !ticket ||
       !serial || !t || t->serial!=serial || t->phase!=LI2_ST_CLOSED || t->issued!=1 ||
       li2_tf_chain_span_quiet(ticket) || session!=&selected_session ||
       sig!=pe.before.sig || !le_unchanged(&pe.before,si,uc) || !le_quiet(0) ||
       pe.selected_bank>1 || pe.next_serial==UINT64_MAX)return PE_STATE;
    pe.p.serial=++pe.next_serial;pe.p.transfer_serial=serial;pe.p.phase=LI2_PG_SEEDING;
    pe.p.generated=pe.banks[pe.selected_bank].generated;pe.p.spill=pe.banks[pe.selected_bank].spill;
    pe.p.layout=pe.banks[pe.selected_bank].layout;
    pe.p.proof=pe.generation.proof;pe.p.table=pe.p.proof+offsetof(struct pe_payload,plan.table);
    pe.token=(struct li2_pg_token){&pe,pe.p.serial};pe.ticket=ticket;*out=pe.token;
    int e=li2_pg_source_begin(&pe.token,&pe.p.layout);if(e)return e;
    e=li2_pg_rseq_begin(&pe.token,session,uc);if(e)return e;
    pe.p.registration_epoch=li2_pg_rseq_progress()->registration_epoch;
    pe.p.phase=LI2_PG_SEEDED;return 0;
}
int li2_pg_epoch_sources(const struct li2_pg_token *t,const struct li2_fetch_ref *ref,const uintptr_t pages[2]) {
    if(!pe_token(t) || pe.p.phase!=LI2_PG_SEEDED || !ref || !pages)return PE_STATE;
    pe.p.phase=LI2_PG_PREPARING;pe.ref=*ref;
    int e=li2_pg_source_prepare(t,ref,pages);if(e)return e;
    const struct li2_pg_sources *s=li2_pg_source_view(t);if(!s)return PE_SOURCE;
    pe.p.source_count=2;pe.p.source[0]=s->key.page[0].identity.address;pe.p.source[1]=s->key.page[1].identity.address;
    pe.p.phase=LI2_PG_HELD;return 0;
}
const struct li2_pg_sources *li2_pg_epoch_sources_view(const struct li2_pg_token *t) {
    return pe_token(t)?li2_pg_source_view(t):0;
}
static int pe_build(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const struct li2_pg_sources *s=li2_pg_source_view(&pe.token);
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    pe_need(s && pe.p.phase==LI2_PG_HELD && !pe_decoding && !pe.build_started &&
        r && r->active && r->seed_complete && r->registration_epoch==pe.p.registration_epoch,PE_STATE,4);
    pe.candidate_registry_count=protected_count;pe_need(protected_count<=RANGES,PE_STATE,5);
    copy(pe.candidate_registry,protected,protected_count*sizeof *protected);
    if(pe.generation.installed && ped_stored() && pe_registry() &&
       pe.generation.generated==pe.p.generated &&
       li2_pg_source_key_equal(&pe.publication.source,&s->key) &&
       pe.publication.header.registered_epoch==r->registration_epoch &&
       pe.publication.header.rseq_address==r->address &&
       pe.publication.header.rseq_length==r->length && pe.publication.header.rseq_signature==r->signature) {
        pe_need(ped_permitted() && !pe_bytes(),PE_PUBLICATION,10);pe.warm=1;
    } else {
        le_zero(&pe.candidate,sizeof pe.candidate);
        size_t n=0;for(size_t i=0;i<protected_count;i++)
            pe.exclusions[n++]=(struct li2_mg_range){protected[i].first,protected[i].end};
        for(unsigned i=0;i<2;i++)pe.exclusions[n++]=(struct li2_mg_range){pe.p.source[i],pe.p.source[i]+PAGE};
        pe.exclusions[n++]=(struct li2_mg_range){r->address+8,r->address+16};
        pe_need(n<=LI2_MG_RANGES,PE_STATE,6);
        pe_need(!li2_mg_table_build(pe.exclusions,n,pe.p.table,&pe.candidate.plan.table),PE_PLAN,0);
        uintptr_t pages[2]={pe.p.source[0],pe.p.source[1]};
        for(unsigned i=0;i<2;i++)copy(pe.candidate.plan.source[i],s->key.page[i].bytes,PAGE);
        pe.build_started=1;pe_decoding=1;ped_count(PGC_REF(cold_attempts));__asm__ volatile("":::"memory");
        pe.build_result=li2_pg_plan_pages(pages,pe.candidate.plan.source,s->key.entry,
            &pe.p.layout,&pe.candidate.plan.table,&pe.cold,&pe.miss);
        pe.build_returned=1;
        if(pe.build_result) {
            pe_need(li2_pg_miss_valid(&pe.cold,&pe.miss,pe.build_result) &&
                pe.miss.reason>0 && pe.miss.reason<LI2_PGD_REASON_COUNT,PE_PLAN,pe.build_result);
            ped_count(PGC_MISS_REF(pe.miss.reason));pe_decoding=0;selected_initialized();return 0;
        }
#ifdef LI2_PERSISTENT_DISPATCH
        pe_need(pe.cold.ready==1 && !pe.cold.result && pe.miss.version==LI2_PG_VERSION &&
#else
        pe_need(pe.cold.ready==1 && !pe.cold.result && pe.miss.version==1 &&
#endif
            !pe.miss.status && !pe.miss.reason && !pe.miss.site && !pe.miss.pc && !pe.miss.detail,
            PE_PLAN,pe.build_result);
        pe_need(!li2_pg_compact_build(&pe.cold,&pe.rebuild,&pe.candidate.plan),PE_PLAN,1);++pe.plan_proofs;
        pe_need(!li2_pg_compact_validate(&pe.candidate.plan,&pe.rebuild,&pe.compact_rebuild),PE_PLAN,2);++pe.plan_proofs;
        pe_need(!li2_pg_rseq_cold(&pe.token,&pe.cold,uc),PE_RSEQ,1);++pe.none_proofs;
        __asm__ volatile("":::"memory");pe_decoding=0;selected_initialized();
    }
    const struct li2_pg_compact *plan=pe.warm?&pe_payload()->plan:&pe.candidate.plan;
    pe_need(!li2_pg_source_validate(&pe.token,plan) &&
        pe.candidate_registry_count==protected_count &&
        equal(pe.candidate_registry,protected,protected_count*sizeof *protected) && pe_identity() &&
        le_quiet(&pe.ref) && !li2_pg_rseq_live(&pe.token,uc,&pe.live[0]) &&
        le_unchanged(&pe.before,si,uc),PE_SOURCE,1);
    for(unsigned i=0;i<plan->heads;i++)if(plan->head[i].kind==LI2_PE_NONE) {
        const struct li2_span_decoded *d=&plan->original[i];
        pe.gpr_written|=d->gpr_write;
        pe.flags_written|=d->flags_written|d->flags_set|d->flags_cleared|d->flags_undefined;
    }
    pe_need(!(pe.gpr_written&~UINT64_C(0xffff)) && !(pe.gpr_written&(UINT64_C(1)<<4)) &&
        !(pe.flags_written&~UINT64_C(0x8d5)),PE_PLAN,3);
    pe_need(li2_tf_chain_span_progress()->serial==pe.p.transfer_serial &&
        !li2_tf_chain_span_consume(pe.ticket,&selected_session,&pe.ref,s->key.entry,sig,si,uc),PE_EVENT,1);
    pe.transfer=*li2_tf_chain_span_progress();pe.consumed=1;pe.p.phase=LI2_PG_CONSUMED;
    pe_need(pe.transfer.phase==LI2_ST_CONSUMED && pe.transfer.consumed==1,PE_EVENT,2);return 1;
}
int li2_pg_epoch_bind(const struct li2_pg_token *t,const struct li2_pg_generation *generation) {
    if(!pe_token(t) || generation!=&pe.generation || pe.p.phase!=LI2_PG_CONSUMED ||
       !pe.consumed || pe.p.publication || !pe_busy || pe_active)return PE_STATE;
    struct li2_pg_generation *g=&pe.generation;
    if(pe.warm) {
        if(!ped_permitted() || !pe_registry() || g->generated!=pe.p.generated)return PE_STATE;
        ped_claim();
        le_zero(g->open,sizeof g->open);le_zero(g->close,sizeof g->close);le_zero(g->cleanup,sizeof g->cleanup);
        le_zero(&g->slots[1],2U*sizeof g->slots[1]);
#ifdef LI2_PERSISTENT_DISPATCH
        le_zero(&g->cell[1],2U*sizeof g->cell[1]);
#endif
        pe.p.generation=g->generation;pe.p.publication=1;pe.p.phase=LI2_PG_BOUND;ped_count(PGC_REF(hits));
        return pe_ready()?0:PE_PUBLICATION;
    }
    if(pe.plan_proofs!=2 || pe.none_proofs!=1 || pe.candidate.plan.ready!=1 ||
       pe.candidate.plan.result || pe.next_generation>=UINT64_MAX/2)return PE_STATE;
    if(g->installed) {
        ped_claim();g->ready_generation=0;__asm__ volatile("":::"memory");ped_count(PGC_REF(retirements));
    } else if(pe.next_generation || pe.permit.valid)return PE_STATE;
    const struct ped_bank *b=&pe.banks[pe.selected_bank];
    if((b->virgin?b->prot!=(PROT_READ|PROT_WRITE):b->prot!=PROT_READ) ||
       pg_queries(&b->layout,b->prot,pe.bank_before))return PE_PUBLICATION;
    int proof_prot=pe.next_generation?PROT_READ:PROT_READ|PROT_WRITE;
    if(pg_proof_query(g->proof,proof_prot,&pe.proof_before))return PE_PUBLICATION;
    uintptr_t proof=g->proof;
    if(pg_permissions(&b->layout,PROT_READ|PROT_WRITE,pe.reopen_code,0) ||
       pg_proof_permission(proof,PROT_READ|PROT_WRITE,&pe.reopen_proof))return PE_PUBLICATION;
    le_zero(g,sizeof *g);g->generated=b->generated;g->spill=b->spill;g->proof=proof;g->layout=b->layout;
    for(unsigned i=0;i<3;i++)g->code_writable[i]=pe.reopen_code[i].query;
    g->proof_writable=pe.reopen_proof.query;
    if(pe_query(g->spill,PAGE,PROT_READ|PROT_WRITE,&g->spill_query))return PE_PUBLICATION;
    g->installed=1;g->generation=++pe.next_generation;g->build_serial=pe.p.serial;
    g->member_generation[0]=2*g->generation;g->member_generation[1]=2*g->generation+1;
    g->plan_proofs=pe.plan_proofs;g->none_proofs=pe.none_proofs;
    pe.p.generation=g->generation;pe.p.phase=LI2_PG_PUBLISHING;
    pe.registry_count=pe.candidate_registry_count;copy(pe.registry,pe.candidate_registry,pe.registry_count*sizeof *pe.registry);
    if(!pe_registry())return PE_PUBLICATION;
    pe.publication=pe.candidate;struct pe_header *h=&pe.publication.header;
    const struct li2_pg_rseq_progress *r=li2_pg_rseq_progress();
    h->version=1;h->layout=g->layout;
    copy(h->member_generation,g->member_generation,sizeof g->member_generation);h->serial=g->build_serial;h->generation=g->generation;h->registry=(uintptr_t)&pe;
    h->generated=g->generated;h->spill=g->spill;h->table=pe.p.table;
    h->plan_proof=g->plan_proofs;h->none_proof=g->none_proofs;
    h->source_validations=li2_pg_source_progress()->validations;h->registered_epoch=pe.p.registration_epoch;
    h->rseq_address=r->address;h->rseq_length=r->length;h->rseq_signature=r->signature;
    copy(h->archive,pe_archive,32);copy(h->policy,pe_policy,32);pe.publication.source=li2_pg_source_view(t)->key;
    volatile unsigned char *code=(void *)g->generated,*proof_bytes=(void *)g->proof;
    for(size_t i=0;i<PE_CODE_BYTES;i++){code[i]=pg_code_byte(&pe.publication.plan,i);g->code_copied=i+1;}
    for(size_t i=0;i<PE_PROOF_BYTES;i++){proof_bytes[i]=0;g->proof_zeroed=i+1;}
    const unsigned char *src=(const void *)&pe.publication;
    for(size_t i=0;i<sizeof pe.publication;i++){proof_bytes[i]=src[i];g->proof_copied=i+1;}
    int e=pg_permissions(&g->layout,PROT_READ,g->code_sealed,0);if(e)return e;
    pe.banks[pe.selected_bank].virgin=0;pe.banks[pe.selected_bank].prot=PROT_READ;
    e=pg_proof_permission(g->proof,PROT_READ,&g->proof_sealed);if(e)return e;
    for(size_t i=0;i<PE_CODE_BYTES;i++){if(code[i]!=pg_code_byte(&pe.publication.plan,i))return PE_PUBLICATION;g->code_verified=i+1;}
    for(size_t i=0;i<PE_PROOF_BYTES;i++) {
        if(proof_bytes[i]!=(i<sizeof pe.publication?src[i]:0))return PE_PUBLICATION;
        g->proof_verified=i+1;
    }
    g->proof_complete=1;g->complete=1;pe.p.publication=1;ped_count(PGC_REF(publications));
    __asm__ volatile("":::"memory");g->ready_generation=g->generation;pe.p.phase=LI2_PG_BOUND;
    if((e=pg_link_data(0)))return e;
    return pe_ready()?0:PE_PUBLICATION;
}
int li2_pg_epoch_enter(const struct li2_pg_token *t,int sig,const siginfo_t *si,ucontext_t *uc) {
    if(!pe_token(t) || pe.p.phase!=LI2_PG_BOUND || !pe_ready() || !pe_busy || pe_active)return PE_STATE;
    const struct pe_payload *p=pe_payload();struct li2_pg_generation *g=&pe.generation;
    if(pe_bytes() || !pe_registry() || !le_unchanged(&pe.before,si,uc))return PE_PUBLICATION;
    pe.p.phase=LI2_PG_OPENING;
    int e=pg_link_data(1);if(e)return e;
    e=pg_permissions(&g->layout,PROT_READ|PROT_EXEC,g->open,&pe.p.opened_pages);if(e)return e;
    if(pe.p.opened_pages!=17 || !pg_refs(1) || !pg_slots(1))return PE_PUBLICATION;
    pe.banks[pe.selected_bank].prot=PROT_READ|PROT_EXEC;
    if((e=li2_pg_source_opened(t,&p->plan)))return e;
    if((e=li2_pg_rseq_live(t,uc,&pe.live[1])))return e;
    pe_tls(&pe.before);
    if(!pe_identity() || !le_quiet(&pe.ref) || !pe_ready() || pe_bytes() ||
       !le_unchanged(&pe.before,si,uc) || sig!=SIGTRAP)return PE_FRAME;
    /* The actual logical frame remains unchanged except its entry RIP. */
    pe.p.phase=LI2_PG_EXECUTING;pe.redirected=1;ped_count(PGC_REF(entries));
    selected_step_pending=1;selected_pending_route=SELECTED_PERSISTENT_EPOCH;pe_active=1;
    __asm__ volatile("":::"memory");uc->uc_mcontext.gregs[REG_RIP]=(greg_t)p->plan.layout.generated[0];
    return 0;
}
static int pe_exit_index(uintptr_t pc) {
    if(!pe_ready())return -1;
    const struct li2_pg_compact *p=&pe_payload()->plan;
    for(unsigned i=0;i<p->exits;i++)if(p->exit_pc[i]==pc)return (int)i;
    return -1;
}
int li2_pg_epoch_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
    /* Runs before old owners, event accounting and every returning RAW. */
    li2_pg_rseq_preentry();
    if(!pe_active && !pe_busy && selected_pending_route!=SELECTED_PERSISTENT_EPOCH)return 0;
    if(pe_busy || pe_closing || pe_decoding || handling || !pe_active || !pe.redirected || !pg_slots(1) || !pg_refs(1) ||
       pe.p.phase!=LI2_PG_EXECUTING || selected_pending_route!=SELECTED_PERSISTENT_EPOCH ||
       selected_step_pending!=1 || pe.p.first_error || !pe_ready())return PE_REENTRY;
    pe_busy=1;pe.p.phase=LI2_PG_RECOVERING;pe.recovery_started=1;__asm__ volatile("":::"memory");
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
#ifdef LI2_PERSISTENT_GROUP_COUNTERS
    (void)__atomic_fetch_add(PGC_REF(unexpected),1,__ATOMIC_ACQ_REL);
#else
    ++pe.unexpected;
#endif
    uint64_t raw[16];for(unsigned i=0;i<16;i++)raw[i]=(uint64_t)g[pe_greg[i]];
    /* Recovery owns this exact protected scratch before materialization.
       Donor recovery reads only initialized dirty spills; no blanket spill
       read or old-plan cast precedes its boundary-state validation. */
    pe.recovery_result=li2_pg_compact_recover(&pe_payload()->plan,pc,raw,(uint64_t)g[REG_EFL],
        (const uint64_t *)pe.generation.spill,&pe.recovery_scratch,&pe.recovered);
    if(!pe.recovery_result && pe.recovered.complete) {
        pe.recovery_complete=1;
        pe.guest_data_fault=sig==SIGSEGV && si->si_signo==SIGSEGV && !si->si_errno &&
            (si->si_code==SEGV_MAPERR || si->si_code==SEGV_ACCERR) && g[REG_TRAPNO]==14 &&
            !(g[REG_ERR]&16) && (uintptr_t)si->si_addr==(uintptr_t)g[REG_CR2] &&
            ((pe.recovered.kind==LI2_PG_GUARD && pe.recovered.phase==LI2_MG_STORE) ||
             (pe.recovered.kind==LI2_PG_COPIED && pe.recovered.phase==LI2_MG_BEFORE));
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
int li2_pg_epoch_drain(const struct li2_pg_token *t) {
    if(!pe_token(t) || !pe_active || !pe_busy || pe.p.phase!=LI2_PG_RECOVERING ||
       !pe.exit_seen || !pe.recovery_complete || !pe_ready())return PE_STATE;
    const struct pe_payload *p=pe_payload();struct li2_pg_generation *g=&pe.generation;
    pe.p.phase=LI2_PG_CLOSING;
    int e=pg_permissions(&g->layout,PROT_READ,g->close,&pe.p.closed_pages);if(e)return e;
    if(pe.p.closed_pages!=17 || !pg_closed(&g->layout,g->close))return PE_PUBLICATION;
    if((e=pg_link_data(2)))return e;
    pe.banks[pe.selected_bank].prot=PROT_READ;
    if(pe_bytes() || pg_proof_query(g->proof,PROT_READ,&pe.proof_exit))return PE_PUBLICATION;
    pe.p.phase=LI2_PG_RELEASING;
    pe.release_result=li2_pg_source_release(t,&p->plan);if(pe.release_result)return pe.release_result;
    pe.p.anchor_released=1;pe.final_fetch=*li2_lifecycle_fetch_progress();
    if(pe.final_fetch.held || !pe.final_fetch.complete || pe.final_fetch.first_error ||
       pe.final_fetch.sequence!=pe.ref.sequence)return PE_RELEASE;
    if((e=li2_pg_rseq_close(t,&pe.after.uc)))return e;
    pe.p.registration_rechecked=1;
    pe.p.phase=LI2_PG_CLOSED;
    return 0;
}
/* No cancelled candidate has opened code or claimed a completed generation. */
int li2_pg_epoch_cancel(const struct li2_pg_token *t,int sig,siginfo_t *si,ucontext_t *uc,
    enum li2_chain_result *result) {
    if(!pe_token(t) || pe.p.phase!=LI2_PG_HELD || !pe_busy || pe_active || !result ||
       pe.consumed || pe.redirected || pe.p.opened_pages || pe_decoding ||
       !pe.build_returned || !li2_pg_miss_valid(&pe.cold,&pe.miss,pe.build_result) ||
       !le_unchanged(&pe.before,si,uc) || li2_tf_chain_span_progress()->serial!=pe.p.transfer_serial ||
       li2_tf_chain_span_quiet(pe.ticket))return PE_STATE;
    pe.p.phase=LI2_PG_CANCELLING;
    int e=li2_pg_source_cancel(t);if(e)return e;
    pe.final_fetch=*li2_lifecycle_fetch_progress();
    if(pe.final_fetch.held || !pe.final_fetch.complete || pe.final_fetch.first_error ||
       pe.final_fetch.sequence!=pe.ref.sequence)return PE_RELEASE;
    pe.p.anchor_released=1;
    if((e=li2_pg_rseq_cancel(t,uc)))return e;
    pe.p.registration_rechecked=1;
    if(!le_unchanged(&pe.before,si,uc) || !le_quiet(0))return PE_FRAME;
    pe.resuming=1;__asm__ volatile("":::"memory");
    e=li2_tf_chain_span_resume(pe.ticket,sig,si,uc,result);if(e)return e;
    pe.transfer=*li2_tf_chain_span_progress();
    if(pe.transfer.phase!=LI2_ST_RESUMED || pe.transfer.resumed!=1 || pe.transfer.successor_installed!=1 ||
       pe.transfer.next!=(unsigned)selected_chain.active ||
       (*result!=LI2_CHAIN_RUNNING && *result!=LI2_CHAIN_NX_FALLBACK))return PE_EVENT;
    uint64_t expected=pe.flags;if(*result==LI2_CHAIN_RUNNING)expected|=SELECTED_TF;
    if((uint64_t)uc->uc_mcontext.gregs[REG_EFL]!=expected)return PE_FRAME;
    selected_step_pending=*result==LI2_CHAIN_RUNNING;
    selected_pending_route=selected_step_pending?SELECTED_GENERIC_TF:SELECTED_NO_STEP;
    pe.p.phase=LI2_PG_CANCELLED;pe.ticket=0;selected_initialized();ped_count(PGC_REF(cancelled));
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_cancelled(sig,si,uc,*result);
#endif
    __asm__ volatile("":::"memory");pe_busy=0;pe.resuming=0;
#if defined(LI2_EFFECT_PROVIDER) && defined(LI2_TF_HANDOFF) && defined(LI2_REGISTER_RUN)
    if(*result==LI2_CHAIN_NX_FALLBACK && selected_chain.slots[selected_chain.active].fallback==LI2_CHAIN_OLD_STEP)
        selected_run_trace_try(sig,si,uc,selected_logical_flags);
#endif
    return 0;
}
static _Noreturn void selected_persistent_abort(unsigned code,long detail) {
    if(!pe.p.first_error){pe.p.first_error=code;pe.p.first_detail=detail;}
    if(pe_failing){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
    pe_failing=1;pe_busy=1;pe.p.completion_permit=0;pe.generation.ready_generation=0;
    if(pe_closing || pe.resuming)li2_tf_chain_abort(&selected_chain,code,detail);
    pe.p.phase=LI2_PG_FAILED;li2_maps_phase_fail();
    if(!pe.cleanup_started && pe.code_allocated && pe.code_registered) {
        pe.cleanup_started=1;
        const struct li2_pg_layout *layout=pe.p.serial?&pe.p.layout:&pe.generation.layout;
        int e=pg_permissions(layout,PROT_READ,pe.generation.cleanup,&pe.p.closed_pages);
        if(!e && pe.generation.active_refs)e=pg_link_data(2);
        if(!e) {
            pe.p.closed_pages=17;
            if(pe.p.serial) {
                const struct li2_pg_source_progress *source=li2_pg_source_progress();
                if(source->phase==LI2_PGS_CANCELLED && source->serial==pe.p.serial &&
                   source->cancel_complete==1 && source->release_complete==1) {
                    /* The exact source is already released; the ordinary
                       successor owns any later handoff failure. */
                    pe.p.anchor_released=1;pe.cleanup_complete=1;
                } else {
                    int released=li2_pg_source_abort(&pe.token);
                    if(!released && li2_pg_source_progress()->release_complete) {
                        pe.p.anchor_released=1;pe.cleanup_complete=1;
                    }
                }
            } else if(!li2_lifecycle_fetch_interlock()) {
                pe.cleanup_complete=1;
            }
        }
    }
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();if(f)pe.final_fetch=*f;
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_terminal(1);
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_terminal(1);
#endif
    report(125,pe.p.first_error,pe.p.first_detail);
    (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static int selected_persistent_trace_try(int sig,siginfo_t *si,ucontext_t *uc) {
    if(!pe.initialized || pe_busy || pe_active || !ped_capacity() || !le_trace_coarse(sig,si,uc))return 0;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    const struct li2_rseq_state *r=li2_rseq_snapshot();
    if((pc&~(PAGE-1))<PAGE || r->registered!=1 || r->phase!=LI2_RSEQ_ACTIVE ||
       !li2_pg_source_pair_advisory(pc))return 0;
    /* Pure necessary placement before any offer, capture, reset or real
       TRACE close. A decline leaves the original dispatch path intact. */
    const unsigned bank_index=ped_bank_for(pc);
    const struct ped_bank *bank=&pe.banks[bank_index];
    const int placement=li2_pg_placement(pc,&bank->layout);
    pe_need(placement>=0 && bank->allocated==1 && bank->registered==1 &&
        bank->generated<(UINT64_C(1)<<47)-PE_ALLOC_BYTES &&
        bank->spill==bank->generated+PE_CODE_BYTES+PAGE && protected_count<=RANGES &&
        selected_run_protect_contains(0,bank->generated,PE_ALLOC_BYTES)==1,PE_STATE,31);
    if(!placement)return 0;
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_begin(sig,si,uc);
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_begin(sig,si,uc);
#endif
    ped_reset_attempt();pe.selected_bank=bank_index;
    pe_closing=1;pe_busy=1;ped_count(PGC_REF(offers));__asm__ volatile("":::"memory");
    pe_need(!le_capture(&pe.ingress,sig,si,uc),PE_FRAME,0);pe.close_started=1;
    int e=li2_tf_chain_span_close(&selected_chain,sig,si,uc,&pe.ticket);
    pe_need(!e && pe.ticket,PE_EVENT,e);pe.transfer=*li2_tf_chain_span_progress();
    pe_need(pe.transfer.phase==LI2_ST_CLOSED && pe.transfer.issued==1 &&
        pe.transfer.event==selected_chain.event_id && pe.transfer.pc==pc &&
        pe.transfer.flags==((uint64_t)pe.ingress.frame.greg[REG_EFL]&~SELECTED_TF),PE_EVENT,0);
    pe.close_complete=1;pe_closing=0;pe.flags=pe.transfer.flags;
    selected_logical_flags=pe.flags;selected_flags_known=1;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    pe_need(!le_capture(&pe.before,sig,si,uc),PE_FRAME,1);
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_closed();
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_closed();
#endif
    pe_need(!li2_pg_epoch_begin(pe.ticket,pe.transfer.serial,&selected_session,sig,si,uc,&pe.token),PE_RSEQ,2);
    le_zero(&selected_borrow,sizeof selected_borrow);le_zero(&selected_view,sizeof selected_view);
    pe.prepare_started=1;e=li2_lifecycle_fetch_prepare(pc,15,&selected_borrow);
    pe_need(!e,PE_SOURCE,e);e=li2_lifecycle_fetch_view(&selected_borrow,&selected_view);
    pe_need(!e && selected_view.pc==pc && selected_view.length==15 && selected_view.page_count==1 &&
        selected_view.identity_observed && selected_view.pid==pe.session.pid && selected_view.tid==pe.session.tid,PE_SOURCE,e);
    pe.prepare_complete=1;
    uintptr_t page=pc&~(PAGE-1),pages[2]={page,page+PAGE};
    pe_need(page>=PAGE && page<=(UINT64_C(1)<<47)-2*PAGE && pc-page<=PAGE-15,PE_SOURCE,3);
    pe_need(!li2_pg_epoch_sources(&pe.token,&selected_borrow,pages),PE_SOURCE,4);
    if(!pe_build(sig,si,uc)) {
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_miss_held();
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_miss_held();
#endif
        enum li2_chain_result result;
        pe_need(!li2_pg_epoch_cancel(&pe.token,sig,si,uc,&result),PE_EVENT,3);return 1;
    }
    pe_need(!li2_pg_epoch_bind(&pe.token,&pe.generation),PE_PUBLICATION,2);
    pe_need(!li2_pg_epoch_enter(&pe.token,sig,si,uc),PE_PUBLICATION,3);
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_entered(sig,si,uc);
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_entered(sig,si,uc);
#endif
    selected_initialized();__asm__ volatile("":::"memory");pe_busy=0;return 1;
}
static void selected_persistent_preentry(int sig,siginfo_t *si,ucontext_t *uc) {
    int e=li2_pg_epoch_preentry(sig,si,uc);
    if(e) {
        if(pe_terminal_ingress){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
        pe_terminal_ingress=1;__asm__ volatile("":::"memory");
        if(!pe.unexpected_frame.started)(void)le_capture(&pe.unexpected_frame,sig,si,uc);
        selected_persistent_abort((unsigned)e,sig);
    }
}
static void selected_persistent_exit(int sig,siginfo_t *si,ucontext_t *uc) {
    pe_need(pe_active && pe_busy && pe.exit_seen && pe.p.phase==LI2_PG_RECOVERING &&
        selected_pending_route==SELECTED_PERSISTENT_EPOCH && selected_step_pending==1 &&
        pe.after.sig==sig && le_unchanged(&pe.after,si,uc),PE_STATE,7);
    pe_tls(&pe.after);pe_need(pe.before.fs==pe.after.fs && pe.before.gs==pe.after.gs,PE_TLS,1);
    pe_preserved();pe_need(pe_identity() && pe_ready() && le_quiet(&pe.ref) &&
        !li2_pg_rseq_live(&pe.token,uc,&pe.live[2]),PE_RSEQ,3);
    pe_need(!li2_pg_epoch_drain(&pe.token) && le_unchanged(&pe.after,si,uc) &&
        le_quiet(0) && pe_registry(),PE_RELEASE,0);
    ped_count(PGC_REF(completed));pe.p.completion_permit=1;
    pe_need(!pe.permit.valid,PE_RELEASE,12);
    pe.permit=(struct ped_permit){.valid=1,.serial=pe.p.serial,.generation=pe.generation.generation,
        .ref_sequence=pe.ref.sequence,.generated=pe.generation.generated,.proof=pe.generation.proof,
        .layout=pe.generation.layout,.reset_slots=pe.generation.slots[2].seal.query,
        .proof_query=pe.proof_exit,.fetch=pe.final_fetch,
        .source=*li2_pg_source_progress(),.generation_source=pe.publication.source,
        .rseq=*li2_pg_rseq_progress()};
    copy(pe.permit.close,pe.generation.close,sizeof pe.permit.close);
    copy(pe.permit.member_generation,pe.generation.member_generation,sizeof pe.permit.member_generation);
    pe_need(ped_permitted(),PE_RELEASE,13);
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
    pgo_terminal(0);
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
    pro_terminal(0);
#endif
    selected_logical_flags=(uint64_t)pe.after.frame.greg[REG_EFL]&~SELECTED_RF;selected_flags_known=1;
    pe_active=0;selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    __asm__ volatile("":::"memory");pe_busy=0;selected_fetch(sig,si,uc);
}
static void selected_persistent_report(unsigned status,unsigned code,long detail) {
#ifdef LI2_PERSISTENT_DISPATCH
    struct writer w={.used=0};text(&w,"LI2_PERSISTENT_RESIDENT {\"version\":2");
#else
    struct writer w={.used=0};text(&w,"LI2_PERSISTENT_GROUP {\"version\":1");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"phase\":",pe.p.phase);field(&w,",\"serial\":",pe.p.serial);
    field(&w,",\"generation\":",pe.generation.generation);field(&w,",\"build_serial\":",pe.generation.build_serial);
    field(&w,",\"offers\":",PGC_VALUE(offers));field(&w,",\"cold_attempts\":",PGC_VALUE(cold_attempts));
    field(&w,",\"publications\":",PGC_VALUE(publications));field(&w,",\"hits\":",PGC_VALUE(hits));
    field(&w,",\"cancelled\":",PGC_VALUE(cancelled));field(&w,",\"retirements\":",PGC_VALUE(retirements));
    field(&w,",\"permit_claims\":",PGC_VALUE(permit_claims));field(&w,",\"entries\":",PGC_VALUE(entries));
    field(&w,",\"completed\":",PGC_VALUE(completed));field(&w,",\"unexpected\":",PGC_VALUE(unexpected));
    field(&w,",\"permit\":",pe.permit.valid);field(&w,",\"opened_pages\":",pe.p.opened_pages);
    field(&w,",\"closed_pages\":",pe.p.closed_pages);field(&w,",\"anchor_released\":",pe.p.anchor_released);
    field(&w,",\"registration_rechecked\":",pe.p.registration_rechecked);
    field(&w,",\"guest_data_fault\":",pe.guest_data_fault);field(&w,",\"recovery_complete\":",pe.recovery_complete);
    field(&w,",\"first_error\":",pe.p.first_error);field(&w,",\"active\":",pe_active);field(&w,",\"busy\":",pe_busy);
    text(&w,",\"misses\":[");for(unsigned i=0;i<LI2_PGD_REASON_COUNT;i++){if(i)text(&w,",");number(&w,PGC_MISS_VALUE(i));}
    text(&w,"]}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
_Static_assert(48*21+1200<=sizeof(((struct writer *)0)->bytes),"bounded distinct group report");
#ifdef LI2_PERSISTENT_GROUP_CAPTURE
#include "persistent_group_observe.inc"
#endif
#ifdef LI2_PERSISTENT_RESIDENT_CAPTURE
#include "persistent_resident_observe.inc"
#endif
