/* Separate direct-branch resident owner. Included after the complete old
   controller, whose two-member and two-retained-slot interfaces are unchanged. */
#include "resident_three_owner.h"
#include "resident_source_lease.h"
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/prctl.h>
#define R3_CODE_BYTES (17U*PAGE)
#define R3_PROOF_BYTES (89U*PAGE)
#define R3_STRIDE (R3_CODE_BYTES+2U*PAGE+R3_PROOF_BYTES)
#define R3_ARENA_BYTES (LI2_R3_CERTIFICATES*R3_STRIDE+LI2_JD_DOMAIN_BYTES)
enum r3_error { R3_STATE=4900,R3_FRAME,R3_SOURCE,R3_PUBLICATION,R3_EVENT,R3_RESULT,R3_RSEQ };
struct r3_header {
    uint64_t version,bytes,generation,publication_serial,index,source_epoch;
    uintptr_t root,owner;
#ifdef LI2_RESIDENT_STABLE_GENERATION
    /* Version 2 binds a stable content identity separately from the exact
       execution epoch at publication. No old version-1 wire is reused. */
    struct li2_rsl_content_ref content;
#endif
    struct li2_pg_layout layout;
    unsigned char archive[32],policy[32];
};
struct r3_payload {
    struct r3_header header;
    struct li2_pg_source_key source;
    struct li2_pg_compact plan;
};
_Static_assert(sizeof(struct r3_payload)<=R3_PROOF_BYTES,"bounded complete source/plan publication");
_Static_assert(LI2_PGD_MEMBERS==2 && LI2_PTR_SLOTS==2 && LI2_MG_RANGES==131 &&
    LI2_JD_DOMAIN_HEADS==256 && LI2_R3_CERTIFICATES==3,"old authority limits unchanged");
struct r3_certificate {
    unsigned planned,installed,active_refs,closed;
    uint64_t generation;
    uintptr_t root,proof;
    struct li2_pg_layout layout;
    struct li2_sealed_identity identity;
    struct r3_payload mirror;
    struct li2_sealed_code_query published[3],opened[3],drained[3],proof_query[2];
};
struct li2_r3_owner {
    unsigned initialized,phase,busy,active,first_error,consumed,released,exit_seen;
    long first_detail;
    uint64_t serial,publications,entries,completed,cancelled,unexpected,ingresses;
    uintptr_t arena,directory,root;
    unsigned count,planned,exit_member,exit_index,registry_count,registry_bound;
    struct li2_fork_range registry[RANGES];
    struct li2_r3_token token;
    struct li2_step_session session;
    const struct li2_tf_span_transfer *ticket;
    struct li2_span_transfer_progress transfer;
    struct li2_fetch_ref held;
    struct li2_span_fetch_observation fetch;
    struct li2_rsl_ref source;
#ifdef LI2_RESIDENT_STABLE_GENERATION
    struct li2_rsl_content_ref content;
#endif
    unsigned source_pages;
    uint64_t flags,gpr_written,flags_written;
    struct le_frame before,after;
    struct li2_link_rseq_live live[3];
    struct li2_jd_domain_directory expected_directory;
    struct li2_private_code_query directory_query;
    struct r3_certificate certificate[LI2_R3_CERTIFICATES];
#ifdef LI2_RESIDENT_RX
    unsigned rx_lifetime;
    struct li2_fetch_progress rx_release;
#endif
};
static union {
    struct li2_r3_owner owner;
    unsigned char bytes[(sizeof(struct li2_r3_owner)+PAGE-1U)&~(PAGE-1U)];
} r3_memory __attribute__((aligned(PAGE)));
#define r3 (r3_memory.owner)
static struct {
    struct li2_pg_plan cold,rebuild;
    struct li2_pg_compact compact_rebuild;
    struct li2_pg_miss miss;
    struct li2_mg_range range[LI2_MG_RANGES];
    struct li2_mg_table table;
    struct li2_pg_source_page page;
    struct li2_dd_plan direct;
#ifdef LI2_RESIDENT_RX
    struct li2_r3_rx_progress rx;
#endif
} r3_work;
#ifdef LI2_RESIDENT_RX
int li2_r3_rx_observe(unsigned operation,unsigned succeeded) {
    if(operation>=LI2_R3_RX_OPERATIONS || succeeded>1)return R3_STATE;
    struct li2_r3_rx_call *p=&r3_work.rx.call[operation];
    if(!succeeded) {if(p->attempted==UINT64_MAX)return R3_STATE;++p->attempted;}
    else {if(p->succeeded>=p->attempted)return R3_STATE;++p->succeeded;}
    return 0;
}
const struct li2_r3_rx_progress *li2_r3_rx_progress(void) {return &r3_work.rx;}
#endif
static int r3_permission(int prot) {
#ifdef LI2_RESIDENT_RX
    return LI2_R3_RX_CALL(LI2_R3_RX_OWNER_PERMISSION,
        raw(SYS_mprotect,(long)&r3_memory,sizeof r3_memory,prot,0,0,0))?R3_PUBLICATION:0;
#else
    return raw(SYS_mprotect,(long)&r3_memory,sizeof r3_memory,prot,0,0,0)?R3_PUBLICATION:0;
#endif
}
static int r3_registry(void) {
    return r3.registry_count==protected_count && protected_count<=RANGES &&
        equal(r3.registry,protected,protected_count*sizeof *protected);
}
/* The original CPUID one-shot owner appends protected landing ranges lazily.
   Bind their complete actual prefix once, at the first genuine root TRACE,
   before any plan or certificate exists. Once bound, growth is a refusal. */
static int r3_registry_unpublished(void) {
    if(r3.registry_bound || r3.active || r3.count || r3.planned ||
       r3.publications || r3.entries || r3.completed || r3.consumed || r3.held.owner ||
       !r3.arena || r3.registry_count<3 || protected_count<r3.registry_count ||
       protected_count>RANGES ||
       !equal(r3.registry,protected,r3.registry_count*sizeof *protected))return 0;
    for(unsigned i=0;i<LI2_R3_CERTIFICATES;i++)if(r3.certificate[i].planned ||
       r3.certificate[i].installed || r3.certificate[i].active_refs ||
       r3.certificate[i].identity.fd!=-1 || r3.certificate[i].identity.code_live ||
       r3.certificate[i].identity.proof_live)return 0;
    const struct li2_fork_range *tail=&r3.registry[r3.registry_count-3];
    if(tail[0].first!=(uintptr_t)&r3_memory || tail[0].end!=(uintptr_t)&r3_memory+sizeof r3_memory ||
       tail[1].first!=(uintptr_t)&r3_work || tail[1].end!=(uintptr_t)&r3_work+sizeof r3_work ||
       tail[2].first!=r3.arena || tail[2].end!=r3.arena+R3_ARENA_BYTES)return 0;
    for(size_t i=0;i<protected_count;i++)if(!protected[i].first ||
       protected[i].first>=protected[i].end)return 0;
    return 1;
}
static int r3_registry_initial(void) {
    if(r3.registry_bound)return r3_registry();
    return r3.phase==LI2_R3_IDLE && !r3.busy && !r3.serial && r3_registry_unpublished();
}
static int r3_registry_bind(void) {
    if(r3.registry_bound)return r3_registry();
    if(r3.phase!=LI2_R3_CLOSING_TRACE || r3.busy!=1 || r3.serial!=1 || !r3.ticket ||
       r3.transfer.phase!=LI2_ST_CLOSED || r3.transfer.issued!=1 || r3.transfer.consumed ||
       r3.transfer.pc!=r3.root || r3.transfer.event!=selected_chain.event_id ||
       !r3_registry_unpublished())return 0;
    for(size_t i=r3.registry_count;i<protected_count;i++)r3.registry[i]=protected[i];
    r3.registry_count=(unsigned)protected_count;r3.registry_bound=1;
    return r3_registry();
}
static int r3_identity(void) {
    const struct li2_step_session *s=&r3.session;
    return equal(s,&selected_session,sizeof *s) && s->initialized==1 && s->self_test_complete==1 &&
        s->pid>0 && s->pid==s->tid && !s->sync_register && s->sync_query>=0 && (s->sync_query&96)==96 &&
        raw(SYS_getpid,0,0,0,0,0,0)==s->pid && raw(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
unsigned li2_r3_owner_phase(const struct li2_r3_token *t) {
    return t && t->owner==&r3 && t->serial && t->serial==r3.serial &&
        r3.initialized==1?r3.phase:0;
}
static int r3_token(const struct li2_r3_token *t) {return li2_r3_owner_phase(t)!=0;}
static int r3_seed_phase(void) {
    return r3.phase>=LI2_R3_HELD && r3.phase<=LI2_R3_CLOSING && !r3.released;
}
int li2_r3_owner_seed(const struct li2_r3_token *t,struct li2_r3_seed *out) {
    struct li2_span_fetch_observation actual={0};
    if(!out || !r3_token(t) || !r3_seed_phase() || !r3.held.owner || !r3.held.sequence ||
       !r3_identity() || li2_lifecycle_span_fetch_snapshot(&actual) || actual.complete!=1 ||
       actual.progress.held!=1 || actual.progress.complete!=1 || actual.progress.first_error ||
       actual.ref.owner!=r3.held.owner || actual.ref.sequence!=r3.held.sequence ||
       actual.pc!=r3.root || actual.length!=15 || actual.page_count!=1 ||
       actual.pid!=r3.session.pid || actual.tid!=r3.session.tid ||
       !equal(actual.bytes,r3.fetch.bytes,sizeof actual.bytes) ||
       !equal(actual.pages,r3.fetch.pages,sizeof actual.pages) ||
       !equal(actual.backing,r3.fetch.backing,sizeof actual.backing))return R3_SOURCE;
    *out=(struct li2_r3_seed){.complete=1,.serial=t->serial,.held=r3.held,
        .session=&selected_session,.pid=r3.session.pid,.tid=r3.session.tid,.root=r3.root};
    return 0;
}
const struct li2_pg_compact *li2_r3_owner_plan(const struct li2_r3_token *t,unsigned index) {
    if(!r3_token(t) || index>=r3.count || index>=LI2_R3_CERTIFICATES ||
       !r3.certificate[index].planned || !r3_registry() ||
       r3.phase<LI2_R3_PLANNING || r3.phase>LI2_R3_CLOSING)return 0;
    const struct r3_certificate *c=&r3.certificate[index];const struct li2_pg_compact *p=&c->mirror.plan;
    if(p->version!=LI2_PG_COMPACT_VERSION || p->bytes!=sizeof *p || p->ready!=1 || p->result ||
       p->entry!=c->root || !equal(&p->layout,&c->layout,sizeof c->layout) ||
       p->table.address!=c->proof+offsetof(struct r3_payload,plan.table) ||
       li2_mg_table_validate(&p->table))return 0;
    /* Every actual protected range, including the whole three-region arena,
       must be represented. RSL independently checks every union source page. */
    for(unsigned i=0;i<r3.registry_count;i++) {
        unsigned found=0;
        for(unsigned j=0;j<p->table.count;j++)found+=p->table.node[j].first<=r3.registry[i].first &&
            r3.registry[i].end<=p->table.node[j].end;
        if(found!=1)return 0;
    }
    return p;
}
static int r3_query(const struct li2_sealed_identity *id,uintptr_t at,size_t bytes,int prot,
                    struct li2_sealed_code_query *q) {
    int error=li2_lifecycle_sealed_code_query(id,at,bytes,prot,q);
    return error || q->attempted!=1 || q->complete!=1 || q->result || q->first!=at ||
        q->end!=at+bytes || q->pages_checked!=bytes/PAGE || q->actual_prot!=prot || q->expected_prot!=prot ||
        q->sealed.kind!=LI2_SEALED_QUERY_KIND || q->sealed.version!=LI2_SEALED_QUERY_VERSION ||
        !equal(&q->sealed.identity,id,sizeof *id) || q->sealed.alias_complete!=1 ||
        q->sealed.alias_pages!=106 || q->sealed.seals_result!=LI2_SEALED_REQUIRED_SEALS ||
        q->sealed.stat_result?R3_PUBLICATION:0;
}
static uintptr_t r3_code_at(const struct li2_pg_layout *l,unsigned i) {return i<2?l->generated[i]:l->stubs;}
static size_t r3_code_bytes(unsigned i) {return i<2?LI2_PE_IMAGE_BYTES:PAGE;}
static int r3_code_query(unsigned index,int prot,struct li2_sealed_code_query q[3]) {
    if(index>=r3.count)return R3_STATE;
    struct r3_certificate *c=&r3.certificate[index];
    for(unsigned i=0;i<3;i++)if(r3_query(&c->identity,r3_code_at(&c->layout,i),r3_code_bytes(i),prot,&q[i]))
        return R3_PUBLICATION;
    return 0;
}
static int r3_proof_query(unsigned index,struct li2_sealed_code_query q[2]) {
    const struct r3_certificate *c=&r3.certificate[index];
    return r3_query(&c->identity,c->proof,64U*PAGE,PROT_READ,&q[0]) ||
        r3_query(&c->identity,c->proof+64U*PAGE,25U*PAGE,PROT_READ,&q[1])?R3_PUBLICATION:0;
}
static int r3_bytes(unsigned index) {
    if(index>=r3.count)return R3_STATE;
    const struct r3_certificate *c=&r3.certificate[index];const struct li2_pg_compact *p=&c->mirror.plan;
    const struct r3_header *h=&c->mirror.header;
    if(!c->installed || !c->generation || c->identity.generation!=c->generation ||
       c->identity.fd<0 || c->identity.code_live!=1 || c->identity.proof_live!=1 ||
       c->identity.code!=c->layout.generated[0] || c->identity.proof!=c->proof ||
       h->version!=LI2_R3_VERSION || h->bytes!=sizeof c->mirror || h->generation!=c->generation ||
#ifdef LI2_RESIDENT_STABLE_GENERATION
       h->publication_serial>r3.serial ||
       !r3.content.owner || !r3.content.generation || !r3.content.publication_epoch ||
       !equal(&h->content,&r3.content,sizeof r3.content) ||
       h->source_epoch!=r3.content.publication_epoch ||
#else
       h->publication_serial>r3.serial || h->source_epoch!=r3.source.epoch ||
#endif
       h->index!=index || h->root!=c->root || h->owner!=(uintptr_t)&r3 ||
       !equal(&h->layout,&c->layout,sizeof c->layout) || !equal(h->archive,pe_archive,32) ||
       !equal(h->policy,pe_policy,32) || !equal((const void *)c->proof,&c->mirror,sizeof c->mirror))return R3_PUBLICATION;
    const unsigned char *proof=(const void *)c->proof;
    for(size_t i=sizeof c->mirror;i<R3_PROOF_BYTES;i++)if(proof[i])return R3_PUBLICATION;
    if(!equal((const void *)c->layout.generated[0],p->image[0],LI2_PE_IMAGE_BYTES) ||
       !equal((const void *)c->layout.generated[1],p->image[1],LI2_PE_IMAGE_BYTES) ||
       !equal((const void *)c->layout.stubs,p->stub_image,PAGE))return R3_PUBLICATION;
    const unsigned char *slots=(const void *)c->layout.slots;
    for(unsigned i=0;i<PAGE;i++)if(slots[i])return R3_PUBLICATION;
    return 0;
}
static int r3_directory_equal(void) {
    const unsigned char *actual=(const void *)r3.directory;
    if(!r3.directory || !equal(actual,&r3.expected_directory,sizeof r3.expected_directory))return 0;
    for(size_t i=sizeof r3.expected_directory;i<LI2_JD_DOMAIN_BYTES;i++)if(actual[i])return 0;
    return 1;
}
static int r3_directory_query(void) {
    struct li2_private_code_query q={0};
    return !li2_lifecycle_private_code_query(r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,&q) &&
        q.complete==1 && q.pages_checked==3 && q.actual_prot==PROT_READ && r3_directory_equal();
}
static int r3_data_query(unsigned index) {
    if(index>=r3.count)return R3_STATE;
    const struct r3_certificate *c=&r3.certificate[index];
    struct li2_private_code_query slot={0},spill={0};
    return li2_lifecycle_private_code_query(c->layout.slots,PAGE,PROT_READ,&slot) ||
        !slot.complete || slot.pages_checked!=1 || slot.actual_prot!=PROT_READ ||
        li2_lifecycle_private_code_query(c->layout.spill,PAGE,PROT_READ|PROT_WRITE,&spill) ||
        !spill.complete || spill.pages_checked!=1 || spill.actual_prot!=(PROT_READ|PROT_WRITE)?
        R3_PUBLICATION:0;
}
static int r3_all_nx(void) {
    if(r3.count>LI2_R3_CERTIFICATES)return 0;
    for(unsigned i=0;i<r3.count;i++) {
        const struct r3_certificate *c=&r3.certificate[i];
        if(c->active_refs)return 0;
        if(c->installed) {
            struct li2_sealed_code_query q[3]={0},proof[2]={0};
            if(!c->closed || r3_code_query(i,PROT_READ,q) || r3_proof_query(i,proof) ||
               r3_data_query(i) || r3_bytes(i))return 0;
        }
    }
    return !r3.arena || !r3.publications || r3_directory_query();
}
int li2_r3_owner_closed(const struct li2_r3_token *t) {
    const struct li2_fetch_progress *f=li2_lifecycle_fetch_progress();
    return r3_token(t) && r3.phase==LI2_R3_CLOSING && r3.busy==1 && !r3.active && r3.released==1 &&
        f->complete==1 && !f->held && !f->first_error && f->sequence==r3.held.sequence &&
        !li2_lifecycle_fetch_interlock() && r3_all_nx();
}
int li2_r3_owner_quiet(void) {
    return r3.initialized==1 && !r3.busy && !r3.active && !r3.first_error &&
        (r3.phase==LI2_R3_IDLE || r3.phase==LI2_R3_DRAINED || r3.phase==LI2_R3_CANCELLED) &&
        selected_pending_route!=SELECTED_RESIDENT_THREE && !li2_r3_rseq_progress()->active &&
        (!r3.held.owner || (r3.released && !li2_lifecycle_fetch_interlock())) && r3_all_nx();
}
#ifdef LI2_RESIDENT_RX
static int r3_current(const ucontext_t *);
#include "resident_rx.inc"
#endif
#include "resident_three_storage.inc"
#include "resident_three_controller.inc"
#ifdef LI2_RESIDENT_THREE_CAPTURE
#ifdef LI2_RESIDENT_RX_CAPTURE
#include "resident_rx_observe.inc"
#elif defined(LI2_RESIDENT_GENERATION_CAPTURE)
#include "resident_generation_observe.inc"
#else
#include "resident_three_observe.inc"
#endif
#endif
