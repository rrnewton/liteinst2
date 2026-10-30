/* Additive same-page source extension. All existing fetch15 checks run;
   neither old fetch storage nor its 15-byte public API is widened. */
#include "unrolled_source.h"
static int unrolled_source_page_equal(const struct li2_fetch_page *a,const struct li2_fetch_page *b) {
    return a->address==b->address && a->allocation==b->allocation && a->generation==b->generation &&
        a->offset==b->offset && a->initial_extent==b->initial_extent && a->backing==b->backing &&
        a->object==b->object && a->logical==b->logical && a->closed_prot==b->closed_prot &&
        a->vma_first==b->vma_first && a->vma_end==b->vma_end && a->vma_major==b->vma_major &&
        a->vma_minor==b->vma_minor && a->vma_inode==b->vma_inode && a->vma_offset==b->vma_offset;
}
int li2_lifecycle_unrolled_source(const struct li2_fetch_ref *ref,struct li2_unrolled_source *out) {
    if(!out || out->ready)return LI2_FETCH_ARGUMENT;
    int e=fetch_ref(ref);if(e)return e;
    if(fetch.page_count!=1 || fetch.requested!=15 || fetch.original[0].backing!=SEALED ||
       fetch.pc>=(UINT64_C(1)<<47) ||
       (fetch.pc&(PAGE-1))>PAGE-LI2_UNROLLED_HASH_SOURCE)return 0;
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ)))return e;
    *out=(struct li2_unrolled_source){.borrow=*ref,.pc=fetch.pc,
        .page=fetch.pages[0],.backing=fetch.last_backing};
    /* The complete page's live protection/identity/backing/alias closure was
       authenticated above. Singleton mutation exclusion holds through this
       same borrow, including its additional 24 source bytes and full guard. */
    const volatile unsigned char *bytes=(const void *)out->pc;
    for(size_t i=0;i<LI2_UNROLLED_HASH_SOURCE;i++)out->bytes[i]=bytes[i];
    for(size_t i=0;i<fetch.requested;i++)if(out->bytes[i]!=fetch.bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)i);
    __asm__ volatile("":::"memory");out->ready=1;return 0;
}
int li2_lifecycle_unrolled_validate(const struct li2_fetch_ref *ref,const struct li2_unrolled_source *s) {
    int e=fetch_ref(ref);if(e)return e;
    if(!s || s->ready!=1 || s->borrow.owner!=ref->owner || s->borrow.sequence!=ref->sequence ||
       s->pc!=fetch.pc || fetch.page_count!=1 || fetch.requested!=15 ||
       fetch.original[0].backing!=SEALED || s->pc>=(UINT64_C(1)<<47) ||
       (s->pc&(PAGE-1))>PAGE-LI2_UNROLLED_HASH_SOURCE ||
       !unrolled_source_page_equal(&s->page,&fetch.pages[0]))return fetch_error(LI2_FETCH_STALE,90);
    if((e=li2_lifecycle_fetch_validate(ref,0,PROT_READ)))return e;
    const struct li2_fetch_backing *b=&fetch.last_backing;
    if(!s->backing.seals_observed || !s->backing.stat_observed || s->backing.stat_result ||
       s->backing.retained_fd!=b->retained_fd || s->backing.seals!=b->seals ||
       s->backing.stat.st_dev!=b->stat.st_dev || s->backing.stat.st_ino!=b->stat.st_ino ||
       s->backing.stat.st_size!=b->stat.st_size || s->backing.stat.st_mode!=b->stat.st_mode)
        return fetch_error(LI2_FETCH_BACKING,90);
    const volatile unsigned char *bytes=(const void *)s->pc;
    for(size_t i=0;i<LI2_UNROLLED_HASH_SOURCE;i++)if(bytes[i]!=s->bytes[i])
        return fetch_error(LI2_FETCH_SOURCE,(long)i);
    return 0;
}
