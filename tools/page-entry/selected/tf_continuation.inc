/* Append to unchanged fetch_loader.inc inside lifecycle_loader.c. */
#include "tf_continuation.h"
static int tf_continuation_check(const struct li2_fetch_ref *ref,uintptr_t pc,
                                 struct li2_tf_continuation *out) {
    int result=fetch_ref(ref);if(result)return result;
    if((result=fetch_identity()))return result;
    for(size_t i=0;i<fetch.page_count;i++)
        if((result=li2_lifecycle_fetch_validate(ref,i,PROT_READ)))return result;
    struct check_error error={0};
    if(read_maps_checked(&error,&out->maps))return fetch_check_error(&error);
    uintptr_t address=pc&~(PAGE-1);
    const struct owned_page *p=current(address);
    const struct map_row *r=mapping(address);
    if(!p || !p->live || !p->allocation || !p->generation || p->admitted ||
       p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ ||
       (p->backing==SEALED && p->object>=object_count))return fetch_error(LI2_FETCH_PAGE,0);
    if(verify_page_checked(p,r,&error))return fetch_check_error(&error);
    if(r->prot!=PROT_READ)return fetch_error(LI2_FETCH_PAGE,0);
    if(p->backing==SEALED && alias_check_checked(p->object,p->offset,PAGE,p->logical,
                                               p->address,p->address+PAGE,&error))
        return fetch_check_error(&error);
    out->page=(struct li2_fetch_page){
        .address=p->address,.allocation=p->allocation,.generation=p->generation,
        .offset=p->offset,.initial_extent=p->initial_extent,.backing=p->backing,
        .object=p->object,.logical=p->logical,.closed_prot=p->actual,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,
        .vma_minor=r->minor,.vma_inode=r->inode,.vma_offset=r->offset
    };
    out->page_observed=1;
    return fetch_backing_check(p,&out->backing);
}
int li2_lifecycle_tf_continuation(const struct li2_fetch_ref *ref,uintptr_t pc,
                                 struct li2_tf_continuation *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->pc=pc;
    out->result=tf_continuation_check(ref,pc,out);
    if(!out->result)out->complete=1;
    return out->result;
}
