/* Included after fetch_loader.inc in the explicit linked-effect profile.
   Object indices only grow; neither object removal nor index reuse exists. */
#include "selected_source_identity.h"
#if LI2_EFFECT_PROVIDER != 1
#error "selected source descriptions require the explicit effect profile"
#endif
static int effect_private(uintptr_t first,size_t bytes) {
    if(!bytes || first>UINTPTR_MAX-bytes || !hooks.protected_range)return 0;
    for(size_t i=0;i<bytes;i++)if(hooks.protected_range(first+i,1)!=1)return 0;
    return 1;
}
int li2_lifecycle_bind_sealed_object(int fd,struct li2_effect_object_binding *out) {
    if(!out || !effect_private((uintptr_t)out,sizeof(*out)) || fd<0 ||
       !active || tx.guard || li2_lifecycle_fetch_interlock())return LI2_FETCH_ARGUMENT;
    *out=(struct li2_effect_object_binding){.registered_fd=fd,
        .actual={.retained_fd=-1}};
    size_t found=OBJECTS;
    for(size_t i=0;i<object_count;i++)
        if(fd==objects[i].original_fd || fd==objects[i].retained_fd) {
            if(found!=OBJECTS)return LI2_FETCH_IDENTITY;
            found=i;
        }
    if(found==OBJECTS)return LI2_FETCH_BACKING;
    const struct object *o=&objects[found];
    struct li2_fetch_backing *a=&out->actual;
    a->retained_fd=fd;
    a->seals=RAW(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0);a->seals_observed=1;
    if(a->seals<0 || (a->seals&SEALS)!=SEALS)return LI2_FETCH_BACKING;
    a->stat_result=RAW(SYS_fstat,fd,&a->stat,0,0,0,0);a->stat_observed=1;
    if(a->stat_result || a->stat.st_dev!=o->stat.st_dev ||
       a->stat.st_ino!=o->stat.st_ino || a->stat.st_size!=o->stat.st_size ||
       a->stat.st_mode!=o->stat.st_mode || a->stat.st_size<=0 ||
       (a->stat.st_mode&S_IFMT)!=S_IFREG)return LI2_FETCH_BACKING;
    out->object_id=found+1;
    __asm__ volatile("":::"memory");out->complete=1;
    return 0;
}
int li2_lifecycle_effect_sources(const struct li2_fetch_ref *ref,
                                struct li2_effect_source out[2],size_t *count) {
    if(!out || !count || !effect_private((uintptr_t)out,2*sizeof(*out)) ||
       !effect_private((uintptr_t)count,sizeof(*count)))return LI2_FETCH_ARGUMENT;
    *count=0;out[0]=(struct li2_effect_source){0};out[1]=(struct li2_effect_source){0};
    int error=fetch_ref(ref);if(error)return error;
    if(!fetch.page_count || fetch.page_count>2 || !fetch.requested || fetch.requested>15)
        return fetch_error(LI2_FETCH_STATE,0);
    for(size_t i=0;i<fetch.page_count;i++) {
        error=li2_lifecycle_fetch_validate(ref,i,PROT_READ);if(error)return error;
    }
    for(size_t i=0;i<fetch.page_count;i++) {
        const struct li2_fetch_page *p=&fetch.pages[i];
        uint64_t object_id=0;
        if(p->backing==SEALED) {
            if(p->object>=object_count)return fetch_error(LI2_FETCH_BACKING,(long)i);
            object_id=(uint64_t)p->object+1;
        } else if(p->backing!=ANONYMOUS)return fetch_error(LI2_FETCH_BACKING,(long)i);
        out[i]=(struct li2_effect_source){.page=p->address,.object_id=object_id,
            .allocation=p->allocation,.generation=p->generation,.offset=p->offset,
            .backing=p->backing,.reserved=0};
    }
    __asm__ volatile("":::"memory");*count=fetch.page_count;
    return 0;
}
