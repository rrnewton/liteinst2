/* Distinct maintained observation. rseq_data.inc and all its physical callers
   remain unchanged. Included after that implementation in the lifecycle TU. */
#include "rseq_current_data.h"
static int rcd_error(struct li2_rseq_current_data *out,int code,long detail) {
    if(!out->result) {out->result=code;out->detail=detail;}
    if(!out->data.error) {out->data.error=(unsigned)code;out->data.detail=detail;}
    return out->result;
}
int li2_lifecycle_rseq_data_current(uintptr_t address,struct li2_rseq_current_data *out) {
    if(!out)return LI2_RSEQ_ARGUMENT;
    *out=(struct li2_rseq_current_data){.version=1,.attempted=1,
        .data={.address=address,.page=address&~(PAGE-1),.attempted=1}};
    struct li2_rseq_data *d=&out->data;
    if(!active || tx.guard || li2_lifecycle_fetch_interlock() ||
       (tx.phase!=IDLE && tx.phase!=REVOKED && tx.phase!=ADMITTED))
        return rcd_error(out,LI2_RSEQ_STATE,0);
    if((address&31) || address>UINTPTR_MAX-32)
        return rcd_error(out,LI2_RSEQ_AREA,0);
    struct li2_maps_stats before;
    li2_maps_stats_read(&before);
    if(before.active || before.poisoned)return rcd_error(out,LI2_RSEQ_STATE,0);
    d->pid=RAW(SYS_getpid,0,0,0,0,0,0);d->tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(d->pid<=0 || d->pid!=d->tid)return rcd_error(out,LI2_RSEQ_IDENTITY,0);
    int error=li2_maps_phase_begin();
    if(error)return rcd_error(out,error,0);
    out->phase_started=1;
    const struct li2_maps_current_view *v=0;
    error=li2_maps_current_acquire(&out->ticket,&v);
    out->acquire_result=error;
    if(v)out->view=*v;
    if(error==LI2_MAPS_CURRENT_UNAVAILABLE) {
        /* Off/retired view is a named physical fallback, never a hit. A stale,
           poisoned, busy or mismatching ticket does not reach this branch. */
        li2_maps_phase_end();out->phase_ended=1;
        if(out->ticket.owner || out->ticket.serial)
            return rcd_error(out,LI2_FETCH_STALE,0);
        out->kind=LI2_RSEQ_CURRENT_PHYSICAL_UNAVAILABLE;out->fallback_started=1;
        error=li2_lifecycle_rseq_data(address,d);
        if(error)return rcd_error(out,error,d->detail);
        if(d->complete!=1 || d->error)return rcd_error(out,LI2_RSEQ_STATE,0);
        out->fallback_complete=1;out->complete=1;return 0;
    }
    struct check_error check={0};
    if(!error) {
        error=li2_maps_current_validate(&out->ticket,v);
        if(!error) {
            out->kind=LI2_RSEQ_CURRENT_VIEW;d->maps=v->query;
            struct owned_page *p=current(d->page);const struct map_row *r=mapping(d->page);
            if(!p || p->backing!=ANONYMOUS || p->admitted ||
               p->logical!=(PROT_READ|PROT_WRITE) || p->actual!=(PROT_READ|PROT_WRITE) ||
               !r || r->prot!=(PROT_READ|PROT_WRITE))error=LI2_RSEQ_MAPPING;
            else {
                error=verify_page_checked(p,r,&check);
                if(!error) {
                    d->allocation=p->allocation;d->generation=p->generation;d->offset=p->offset;
                    if(!d->allocation || !d->generation)error=LI2_RSEQ_MAPPING;
                }
            }
            /* current(), mapping() and verify_page_checked() perform no RAW.
               Validate again after the complete old page-identity predicate. */
            if(!error)error=li2_maps_current_validate(&out->ticket,v);
        }
    }
    if(out->ticket.owner) {
        out->release_attempted=1;
        out->release_result=li2_maps_current_release(&out->ticket);
        if(!out->release_result)out->release_complete=1;
        else if(!error)error=out->release_result;
    }
    li2_maps_phase_end();out->phase_ended=1;
    if(error)return rcd_error(out,error,check.code?check.detail:(v?v->detail:0));
    if(!out->release_complete)return rcd_error(out,LI2_FETCH_STALE,0);
    d->complete=1;out->complete=1;return 0;
}
