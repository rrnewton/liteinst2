/* Append once to lifecycle_loader.c. Existing application owners, source
   queries and all permission-changing functions remain unchanged. */
#include "private_code_query.h"
static int private_query_error(struct li2_private_code_query *out,int code,long detail) {
    if(!out->result){out->result=code;out->detail=detail;}
    return out->result;
}
int li2_lifecycle_private_code_query(uintptr_t first,size_t bytes,int prot,
                                     struct li2_private_code_query *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->first=first;out->expected_prot=prot;
    if(!active || tx.guard || !hooks.raw || !first || !bytes ||
       ((first|bytes)&(PAGE-1)) || bytes>64*PAGE || first>UINTPTR_MAX-bytes ||
       (prot!=PROT_READ && prot!=(PROT_READ|PROT_WRITE) && prot!=(PROT_READ|PROT_EXEC)))
        return private_query_error(out,LI2_FETCH_ARGUMENT,0);
    out->end=first+bytes;
    struct check_error error={0};
    if(read_maps_checked(&error,&out->maps))
        return private_query_error(out,(int)error.code,error.detail);
    for(uintptr_t at=first;at<out->end;at+=PAGE) {
        const struct map_row *r=mapping(at);
        if(!r || current(at) || !r->private || r->inode || r->major ||
           r->minor || r->offset || r->prot!=(unsigned)prot)
            return private_query_error(out,LI2_FETCH_PAGE,(long)(at-first));
        if(!out->pages_checked)out->first_vma=r->first;
        out->last_vma_end=r->end;++out->pages_checked;
    }
    out->actual_prot=prot;out->complete=1;return 0;
}
