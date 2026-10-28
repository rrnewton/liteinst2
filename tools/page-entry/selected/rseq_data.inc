/* Appended only to the explicit inactive-rseq lifecycle build. */
#include "rseq_guard.h"
int li2_lifecycle_rseq_data(uintptr_t address,struct li2_rseq_data *out) {
    if(!out)return LI2_RSEQ_ARGUMENT;
    *out=(struct li2_rseq_data){.address=address,.page=address&~(PAGE-1),.attempted=1};
    if(!active || tx.guard || li2_lifecycle_fetch_interlock() ||
       (tx.phase!=IDLE && tx.phase!=REVOKED && tx.phase!=ADMITTED))
        return (int)(out->error=LI2_RSEQ_STATE);
    if((address&31) || address>UINTPTR_MAX-32)
        return (int)(out->error=LI2_RSEQ_AREA);
    out->pid=RAW(SYS_getpid,0,0,0,0,0,0);out->tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(out->pid<=0 || out->pid!=out->tid)
        return (int)(out->error=LI2_RSEQ_IDENTITY);
    struct check_error e={0};
    int error=read_maps_checked(&e,&out->maps);
    if(error){out->error=(unsigned)error;out->detail=e.detail;return error;}
    struct owned_page *p=current(out->page);const struct map_row *r=mapping(out->page);
    if(!p || p->backing!=ANONYMOUS || p->admitted ||
       p->logical!=(PROT_READ|PROT_WRITE) || p->actual!=(PROT_READ|PROT_WRITE) ||
       !r || r->prot!=(PROT_READ|PROT_WRITE))
        return (int)(out->error=LI2_RSEQ_MAPPING);
    error=verify_page_checked(p,r,&e);
    if(error){out->error=(unsigned)error;out->detail=e.detail;return error;}
    out->allocation=p->allocation;out->generation=p->generation;out->offset=p->offset;
    if(!out->allocation || !out->generation)return (int)(out->error=LI2_RSEQ_MAPPING);
    out->complete=1;return 0;
}
