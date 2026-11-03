#include "loop_cached_direct_context.h"
static void clear(void *p,size_t n) {
    unsigned char *b=p;for(size_t i=0;i<n;i++)b[i]=0;
}
static int same(const void *p,const void *q,size_t n) {
    const unsigned char *a=p,*b=q;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;
}
static int range(uintptr_t p,size_t n) {
    return p && n && p<UINT64_C(0x800000000000) && n<=UINT64_C(0x800000000000)-p;
}
static int disjoint(uintptr_t a,size_t an,uintptr_t b,size_t bn) {
    return range(a,an) && range(b,bn) && (a+an<=b || b+bn<=a);
}
/* Exactly five original bytes, entirely in one leased page. The existing
   decoder and legal-head lookup define both ends of the transition. */
int li2_lcx_tail_value(const struct li2_pg_source_key *key,const struct li2_pg_compact *p,
    uintptr_t pc,struct li2_lcx_tail *out) {
    if(!out)return LI2_DD_ARGUMENT;
    clear(out,sizeof *out);
    if(!key || !p || !p->heads || p->heads>LI2_PG_HEADS || p->entry!=key->entry ||
       !range(pc,5))return LI2_DD_ARGUMENT;
    unsigned page=2;
    for(unsigned i=0;i<2;i++) {
        uintptr_t at=key->page[i].identity.address;
        if(!range(at,LI2_REGION_PAGE) || (at&(LI2_REGION_PAGE-1U)) || p->page[i]!=at)return LI2_DD_FORM;
        if(pc>=at && pc-at<=LI2_REGION_PAGE-5U) {
            if(page!=2)return LI2_DD_FORM;
            page=i;
        }
    }
    if(page==2 || key->page[0].identity.address>=key->page[1].identity.address)return LI2_DD_FORM;
    for(unsigned i=0;i<p->heads;i++) {
        const struct li2_decoded *d=&p->original[i].decoded;
        if(!d->length || !disjoint(pc,5,d->pc,d->length))return LI2_DD_FORM;
    }
    unsigned offset=(unsigned)(pc-key->page[page].identity.address);
    const unsigned char *bytes=key->page[page].bytes+offset;
    if(bytes[0]!=0xe9 || !same(bytes,p->source[page]+offset,5))return LI2_DD_FORM;
    struct li2_span_decoded span={0};struct li2_dd_descriptor direct={0};
    if(li2_decoder_span_describe(pc,bytes,5,&span) || li2_dd_describe(pc,bytes,5,1,&direct) ||
       !same(&span.decoded,&direct.decoded,sizeof span.decoded) || span.decoded.length!=5 ||
       direct.flow!=LI2_REGION_JMP || direct.condition!=16 || direct.external_mask!=1 ||
       li2_pgs_head_lookup(p,direct.target[0],&out->target)!=1)return LI2_DD_FORM;
    out->version=LI2_LCX_VERSION;out->source_page=page;out->source_offset=offset;
    out->original=span;return 0;
}
int li2_lcx_image_value(const struct li2_pgd_member *owner,uintptr_t pc,
    uintptr_t code,uintptr_t spill,unsigned slot,struct li2_lcx_image *out) {
    if(!out)return LI2_DD_ARGUMENT;
    clear(out,sizeof *out);
    if(!owner || !owner->plan || !owner->key || slot>=LI2_DD_AUX_SLOTS)return LI2_DD_ARGUMENT;
    int e=li2_lcx_tail_value(owner->key,owner->plan,pc,&out->tail);if(e)return e;
    const struct li2_pg_compact *p=owner->plan;
    struct li2_dd_aux_binding binding={.code=code,.spill=spill,.slot=slot};
    /* owner.head is a REAL target head, never an auxiliary ordinal. */
    if(li2_pg_dispatch_binding(p->page,&p->layout,p->table.address,p->heads,
           out->tail.target.head,&binding.owner))return LI2_DD_FORM;
    return li2_ld_aux_emit(pc,out->tail.original.decoded.bytes,5,&binding,&out->plan);
}
static int append(struct li2_lcx_directory *d,struct li2_lcx_row row) {
    if(d->count>=LI2_JD_DOMAIN_HEADS)return LI2_DD_CAPACITY;
    for(unsigned i=0;i<d->count;i++)if(d->row[i].pc==row.pc)return LI2_DD_FORM;
    d->row[d->count++]=row;return 0;
}
static int member_value(const struct li2_pgd_member *m,uintptr_t directory) {
    const struct li2_pg_compact *p=m->plan;const struct li2_pgd_ref *r=&m->identity;
    return p && m->key && r->generation && r->binding_generation && !r->node_reserved &&
        r->slot<LI2_PGD_MEMBERS && r->bank<2 && r->node<LI2_LTA_NODES && r->proof &&
        r->root==p->entry && r->root==m->key->entry && p->layout.directory==directory &&
        same(&r->layout,&p->layout,sizeof p->layout) && p->heads && p->heads<=LI2_PG_HEADS;
}
int li2_lcx_lease_value(const struct li2_pgd_view *view,const struct li2_lcx_route *routes,
    const struct li2_lcx_image *images,unsigned count,uintptr_t code,uintptr_t spill,
    const struct li2_lcx_publication_layout *publication,
    struct li2_lcx_lease *lease,struct li2_lcx_directory *directory) {
    if(!lease || !directory)return LI2_DD_ARGUMENT;
    clear(lease,sizeof *lease);clear(directory,sizeof *directory);
    if(!view || !routes || !images || !publication || !count || count>LI2_DD_AUX_SLOTS ||
       !publication->bytes || (publication->bytes&(LI2_REGION_PAGE-1U)) ||
       publication->key_offset>=publication->bytes || publication->plan_offset>=publication->bytes ||
       sizeof(struct li2_pg_source_key)>publication->bytes-publication->key_offset ||
       sizeof(struct li2_pg_compact)>publication->bytes-publication->plan_offset ||
       publication->key_offset+sizeof(struct li2_pg_source_key)>publication->plan_offset ||
       !view->token.owner || !view->token.serial || !view->count || view->count>LI2_PGD_MEMBERS ||
       view->reserved || !range(view->directory,LI2_JD_DOMAIN_BYTES) ||
       (code&(LI2_DD_AUX_CODE_BYTES-1U)) || (spill&(LI2_DD_AUX_SPILL_BYTES-1U)) ||
       !disjoint(code,LI2_DD_AUX_CODE_BYTES,spill,LI2_DD_AUX_SPILL_BYTES) ||
       !disjoint(code,LI2_DD_AUX_CODE_BYTES,view->directory,LI2_JD_DOMAIN_BYTES) ||
       !disjoint(spill,LI2_DD_AUX_SPILL_BYTES,view->directory,LI2_JD_DOMAIN_BYTES))return LI2_DD_ARGUMENT;
    unsigned heads=count,boundaries=count;
    for(unsigned i=0;i<view->count;i++) {
        const struct li2_pgd_member *m=&view->member[i];
        if(!member_value(m,view->directory))return LI2_DD_FORM;
        const struct li2_pg_compact *p=m->plan;
        const uintptr_t proof=m->identity.proof;
        if((proof&(LI2_REGION_PAGE-1U)) || !range(proof,publication->bytes) ||
           (uintptr_t)m->key!=proof+publication->key_offset ||
           (uintptr_t)p!=proof+publication->plan_offset)return LI2_DD_FORM;
        const uintptr_t at[8]={p->layout.generated[0],p->layout.generated[1],p->layout.stubs,
            p->layout.slots,p->layout.spill,p->page[0],p->page[1],proof};
        const size_t bytes[8]={LI2_PE_IMAGE_BYTES,LI2_PE_IMAGE_BYTES,LI2_PG_STUB_BYTES,
            LI2_PG_SLOT_BYTES,LI2_REGION_PAGE,LI2_REGION_PAGE,LI2_REGION_PAGE,publication->bytes};
        for(unsigned j=0;j<8;j++)if(!disjoint(code,LI2_DD_AUX_CODE_BYTES,at[j],bytes[j]) ||
            !disjoint(spill,LI2_DD_AUX_SPILL_BYTES,at[j],bytes[j]))return LI2_DD_FORM;
        if(p->heads>LI2_JD_DOMAIN_HEADS-heads || p->exits>LI2_PG_BOUNDARIES-boundaries)return LI2_DD_CAPACITY;
        heads+=p->heads;boundaries+=p->exits;
        if(p->links>LI2_PG_BOUNDARIES-boundaries)return LI2_DD_CAPACITY;
        boundaries+=p->links;
        for(unsigned j=0;j<i;j++)if(m->identity.slot==view->member[j].identity.slot ||
            m->identity.node==view->member[j].identity.node ||
            m->identity.generation==view->member[j].identity.generation ||
            m->identity.binding_generation==view->member[j].identity.binding_generation)return LI2_DD_FORM;
        for(unsigned j=0;j<p->heads;j++) {
            struct li2_pgs_target target;
            if(li2_pgs_head_lookup(p,p->original[j].decoded.pc,&target)!=1 || target.head!=j)return LI2_DD_FORM;
            int e=append(directory,(struct li2_lcx_row){target.pc,target.generated,
                m->identity.generation,m->identity.slot,j});if(e)return e;
        }
    }
    for(unsigned i=0;i<count;i++) {
        const struct li2_lcx_route *route=&routes[i];
        const struct li2_lcx_image *image=&images[i];
        if(route->from_member>=view->count || route->owner_member>=view->count ||
           route->from_member==route->owner_member || route->arm>1)return LI2_DD_FORM;
        const struct li2_pgd_member *from=&view->member[route->from_member];
        const struct li2_pgd_member *owner=&view->member[route->owner_member];
        if(route->from_head>=from->plan->heads ||
           from->plan->head[route->from_head].kind!=LI2_PG_DIRECT)return LI2_DD_FORM;
        const struct li2_dd_descriptor *direct=&from->plan->instruction[route->from_head].direct;
        struct li2_dd_descriptor expected;
        if(li2_dd_span(&from->plan->original[route->from_head],direct->external_mask,&expected) ||
           !same(&expected,direct,sizeof expected) || !(direct->external_mask&(1U<<route->arm)) ||
           route->arm>=from->plan->head[route->from_head].successor_count ||
           direct->target[route->arm]!=image->tail.original.decoded.pc)return LI2_DD_FORM;
        struct li2_lcx_image rebuilt;
        if(li2_lcx_image_value(owner,direct->target[route->arm],code,spill,i,&rebuilt) ||
           !same(&rebuilt,image,sizeof rebuilt))return LI2_DD_CORRUPT;
        /* No new head may overlap any original instruction in the UNION. */
        for(unsigned j=0;j<view->count;j++)for(unsigned h=0;h<view->member[j].plan->heads;h++) {
            const struct li2_decoded *original=&view->member[j].plan->original[h].decoded;
            if(!disjoint(image->tail.original.decoded.pc,5,original->pc,original->length))return LI2_DD_FORM;
        }
        for(unsigned j=0;j<i;j++)if(!disjoint(image->tail.original.decoded.pc,5,
            images[j].tail.original.decoded.pc,5))return LI2_DD_FORM;
        struct li2_lcx_capability *c=&lease->capability[i];
        c->route=*route;c->from=from->identity;c->owner=owner->identity;c->target=owner->identity;
        c->original=image->tail.original.decoded.pc;c->generated=image->plan.value.generated;
        c->target_generated=image->tail.target.generated;c->auxiliary=i;
        c->target_head=image->tail.target.head;c->arm=route->arm;
        int e=append(directory,(struct li2_lcx_row){c->original,c->generated,c->owner.generation,
            c->owner.slot,LI2_LCX_AUXILIARY|i});if(e)return e;
    }
    lease->token=view->token;lease->code=code;lease->spill=spill;lease->directory=view->directory;
    lease->publication=*publication;
    lease->version=LI2_LCX_VERSION;lease->count=count;lease->members=view->count;
    directory->version=LI2_LCX_DIRECTORY_VERSION;directory->serial=view->token.serial;
    return directory->count==heads?0:LI2_DD_FORM;
}
