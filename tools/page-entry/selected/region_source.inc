/* Additive full-page source extension, included after the old fetch and
   run-reuse lifecycle bodies. No permission, release or decoder call. */
#include "region_source.h"
#if !defined(LI2_SCALAR_REGION) || LI2_SCALAR_REGION != 1 || \
    !defined(LI2_RUN_CACHE_REUSE) || LI2_RUN_CACHE_REUSE != 1
#error "scalar region source requires its explicit existing lifecycle quiet interlock"
#endif

static int region_source_page_equal(const struct li2_fetch_page *a,const struct li2_fetch_page *b) {
    return a->address==b->address && a->allocation==b->allocation && a->generation==b->generation &&
        a->offset==b->offset && a->initial_extent==b->initial_extent && a->backing==b->backing &&
        a->object==b->object && a->logical==b->logical && a->closed_prot==b->closed_prot &&
        a->vma_first==b->vma_first && a->vma_end==b->vma_end && a->vma_major==b->vma_major &&
        a->vma_minor==b->vma_minor && a->vma_inode==b->vma_inode && a->vma_offset==b->vma_offset;
}
static int region_source_backing_equal(const struct li2_fetch_backing *a,const struct li2_fetch_backing *b) {
    return a->seals_observed==1 && b->seals_observed==1 &&
        a->stat_observed==1 && b->stat_observed==1 && !a->stat_result && !b->stat_result &&
        a->retained_fd>=0 && a->retained_fd==b->retained_fd &&
        a->seals>=0 && (a->seals&SEALS)==SEALS && a->seals==b->seals &&
        a->stat.st_dev==b->stat.st_dev && a->stat.st_ino==b->stat.st_ino &&
        a->stat.st_size==b->stat.st_size && a->stat.st_mode==b->stat.st_mode;
}
int li2_region_source_key_equal(const struct li2_region_source_key *a,
                                const struct li2_region_source_key *b) {
    return a && b && a->entry==b->entry && region_source_page_equal(&a->page,&b->page) &&
        region_source_backing_equal(&a->backing,&b->backing) && equal(a->bytes,b->bytes,LI2_REGION_PAGE);
}
/* Pure pre-I/O eligibility. File EOF is NOT inferred from this header: the
   actual old backing check, including its rounded last-page rule, runs below. */
static int region_source_geometry(void) {
    const struct li2_fetch_page *p=&fetch.pages[0];
    return fetch.page_count==1 && fetch.requested==15 && fetch.original[0].backing==SEALED &&
        p->backing==SEALED && p->logical==(PROT_READ|PROT_EXEC) && p->closed_prot==PROT_READ &&
        !(p->address&(PAGE-1)) && p->address<=(UINT64_C(1)<<47)-PAGE &&
        fetch.pc>=p->address && fetch.pc-p->address<=PAGE-15;
}
/* Reuse the original fallible identity/maps/EOF/seals/alias checks. The quiet
   predicate also excludes current native RX and staged transfer/custody;
   runtime step/run ownership remains the caller's explicit prerequisite. */
static int region_source_live(const struct li2_fetch_ref *ref) {
    int e=li2_lifecycle_run_reuse_quiet(ref);
    if(e)return fetch_error((unsigned)e,100);
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ)))return e;
    if((e=li2_lifecycle_run_reuse_quiet(ref)))return fetch_error((unsigned)e,101);
    const struct li2_fetch_page *p=&fetch.pages[0];
    const struct map_row *r=mapping(p->address);
    /* Keep the full original VMA observation, not just address containment.
       No canonicalization or weaker substitute for the old alias predicate. */
    if(!r || !r->private || r->prot!=PROT_READ || r->first!=p->vma_first ||
       r->end!=p->vma_end || r->major!=p->vma_major || r->minor!=p->vma_minor ||
       r->inode!=p->vma_inode || r->offset!=p->vma_offset ||
       p->address<r->first || p->address>=r->end || r->end-p->address<PAGE)
        return fetch_error(LI2_FETCH_PAGE,100);
    if(!region_source_backing_equal(&fetch.backing[0],&fetch.last_backing))
        return fetch_error(LI2_FETCH_BACKING,100);
    return 0;
}
int li2_lifecycle_region_source(const struct li2_fetch_ref *ref,struct li2_region_source *out) {
    if(!out || __atomic_load_n(&out->ready,__ATOMIC_ACQUIRE))return LI2_FETCH_ARGUMENT;
    int e=fetch_ref(ref);if(e)return e;
    if(!region_source_geometry())return 0;
    if((e=region_source_live(ref)))return e;
    out->borrow=*ref;out->key.entry=fetch.pc;
    copy(&out->key.page,&fetch.pages[0],sizeof out->key.page);
    copy(&out->key.backing,&fetch.last_backing,sizeof out->key.backing);
    const volatile unsigned char *bytes=(const void *)out->key.page.address;
    for(size_t i=0;i<LI2_REGION_PAGE;i++)out->key.bytes[i]=bytes[i];
    size_t at=fetch.pc-out->key.page.address;
    for(size_t i=0;i<15;i++)if(out->key.bytes[at+i]!=fetch.bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)(at+i));
    __atomic_store_n(&out->ready,1,__ATOMIC_RELEASE);return 0;
}
int li2_lifecycle_region_validate(const struct li2_fetch_ref *ref,
                                  const struct li2_region_source *s,
                                  const struct li2_region_plan *plan) {
    int e=fetch_ref(ref);if(e)return e;
    if(!s || __atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)!=1 ||
       s->borrow.owner!=ref->owner || s->borrow.sequence!=ref->sequence ||
       !region_source_geometry() || s->key.entry!=fetch.pc ||
       !region_source_page_equal(&s->key.page,&fetch.pages[0]))
        return fetch_error(LI2_FETCH_STALE,100);
    const struct li2_region_source_key *k=&s->key;
    if(!plan || plan->version!=LI2_REGION_PLAN_VERSION || plan->ready!=1 ||
       plan->page!=k->page.address || plan->entry!=k->entry ||
       !plan->source_bytes || plan->source_bytes>LI2_REGION_BYTES ||
       plan->source_bytes>PAGE-(plan->entry-plan->page) ||
       !plan->exits || plan->exits>LI2_REGION_EXITS ||
       !equal(plan->source,k->bytes,LI2_REGION_PAGE))
        return fetch_error(LI2_FETCH_SOURCE,100);
    uintptr_t end=plan->entry+plan->source_bytes;
    for(size_t i=0;i<LI2_REGION_EXITS;i++) {
        uintptr_t pc=plan->exit_pc[i];
        if(i>=plan->exits) {
            if(pc)return fetch_error(LI2_FETCH_SOURCE,(long)(101+i));
            continue;
        }
        if(pc<plan->page || pc-plan->page>=PAGE || (pc>=plan->entry && pc<end))
            return fetch_error(LI2_FETCH_PAGE,(long)(101+i));
        for(size_t j=0;j<i;j++)if(pc==plan->exit_pc[j])
            return fetch_error(LI2_FETCH_SOURCE,(long)(101+i));
    }
    if((e=region_source_live(ref)))return e;
    if(!region_source_backing_equal(&k->backing,&fetch.last_backing))
        return fetch_error(LI2_FETCH_BACKING,101);
    /* Every typed exit was checked in the one complete page just proved R/NX.
       The singleton unchanged borrow excludes a mutation between those checks
       and this complete read. No guest data is touched. */
    const volatile unsigned char *bytes=(const void *)k->page.address;
    for(size_t i=0;i<LI2_REGION_PAGE;i++)if(bytes[i]!=k->bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)i);
    return 0;
}
