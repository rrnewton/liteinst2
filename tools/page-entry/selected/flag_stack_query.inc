/* Exact two-page flag-tile storage query. The older 17/89-page contract
   remains unchanged. All file seals, complete alias census, mapping/source
   exclusion, real permissions and actual process-dumpability checks are the
   whole existing query, with only this separate API and exact extents. */
#include "flag_stack_storage.h"
int li2_lifecycle_flag_stack_query(const struct li2_sealed_identity *id,
    uintptr_t first,size_t bytes,int prot,struct li2_sealed_code_query *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->first=first;out->expected_prot=prot;
    if(!id || !active || tx.guard || !hooks.raw || !first || !bytes ||
       ((first|bytes)&(PAGE-1)) || bytes>64U*PAGE || first>UINTPTR_MAX-bytes ||
       (prot!=PROT_READ && prot!=(PROT_READ|PROT_EXEC)) ||
       id->fd<0 || id->fd>INT32_MAX || !id->inode || !id->generation ||
       id->code_live>1 || id->proof_live>1 || !(id->code_live|id->proof_live) ||
       id->code_bytes!=PAGE || id->proof_bytes!=PAGE ||
       id->bytes!=id->code_bytes+id->proof_bytes ||
       !id->code || !id->proof || ((id->code|id->proof)&(PAGE-1)) ||
       id->code>=(UINT64_C(1)<<47)-id->code_bytes ||
       id->proof>=(UINT64_C(1)<<47)-id->proof_bytes ||
       (id->code<id->proof+id->proof_bytes && id->proof<id->code+id->code_bytes))
        return sealed_query_error(out,LI2_FETCH_ARGUMENT,0);
    out->end=first+bytes;out->sealed.kind=LI2_SEALED_QUERY_KIND;
    out->sealed.version=LI2_SEALED_QUERY_VERSION;out->sealed.identity=*id;
    if(!sealed_offset(id,first,&out->sealed.offset))
        return sealed_query_error(out,LI2_FETCH_PAGE,0);
    out->sealed.seals_result=RAW(SYS_fcntl,id->fd,F_GET_SEALS,0,0,0,0);
    struct stat st={0};out->sealed.stat_result=RAW(SYS_fstat,id->fd,&st,0,0,0,0);
    if(out->sealed.seals_result!=LI2_SEALED_REQUIRED_SEALS || out->sealed.stat_result ||
       (uint64_t)st.st_dev!=id->device || (uint64_t)st.st_ino!=id->inode ||
       st.st_size<0 || (uint64_t)st.st_size!=id->bytes || (st.st_mode&S_IFMT)!=S_IFREG)
        return sealed_query_error(out,LI2_FETCH_IDENTITY,1);
    /* This closes ordinary same-uid external access to the new owner page.
       It does not claim isolation from a privileged tracer or host kernel. */
    if(RAW(SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0)!=0)
        return sealed_query_error(out,LI2_FETCH_IDENTITY,2);
    struct check_error error={0};
    if(read_maps_checked(&error,&out->maps))
        return sealed_query_error(out,(int)error.code,error.detail);
    uint64_t major=((id->device>>8)&UINT64_C(0xfff))|((id->device>>32)&UINT64_C(0xfffff000));
    uint64_t minor=(id->device&UINT64_C(0xff))|((id->device>>12)&UINT64_C(0xffffff00));
    /* Every alias of this inode must be an exact page of the two registered
       extents. A private/COW alias is refused even when it is read-only. */
    for(size_t i=0;i<row_count;i++) {
        const struct map_row *r=&rows[i];
        if(r->major!=major || r->minor!=minor || r->inode!=id->inode)continue;
        if(r->private || (r->prot!=PROT_READ && r->prot!=(PROT_READ|PROT_EXEC)) ||
           r->end<=r->first || ((r->first|r->end|r->offset)&(PAGE-1)))
            return sealed_query_error(out,LI2_FETCH_PAGE,3);
        ++out->sealed.alias_vmas;
        for(uintptr_t at=r->first;at<r->end;at+=PAGE) {
            uint64_t offset;
            if(!sealed_offset(id,at,&offset) || r->offset>UINT64_MAX-(at-r->first) ||
               offset!=r->offset+at-r->first ||
               (offset>=id->code_bytes && r->prot!=PROT_READ))
                return sealed_query_error(out,LI2_FETCH_PAGE,4);
            ++out->sealed.alias_pages;
        }
    }
    if(out->sealed.alias_pages!=(id->code_live*id->code_bytes+id->proof_live*id->proof_bytes)/PAGE)
        return sealed_query_error(out,LI2_FETCH_PAGE,5);
    out->sealed.alias_complete=1;
    for(uintptr_t at=first;at<out->end;at+=PAGE) {
        uint64_t offset;const struct map_row *r=mapping(at);
        if(!sealed_offset(id,at,&offset) || !r || current(at) || r->private ||
           r->major!=major || r->minor!=minor || r->inode!=id->inode ||
           r->prot!=(unsigned)prot || r->offset>UINT64_MAX-(at-r->first) ||
           offset!=r->offset+at-r->first)
            return sealed_query_error(out,LI2_FETCH_PAGE,(long)(at-first));
        if(!out->pages_checked)out->first_vma=r->first;
        out->last_vma_end=r->end;++out->pages_checked;
    }
    out->actual_prot=prot;out->complete=1;return 0;
}
