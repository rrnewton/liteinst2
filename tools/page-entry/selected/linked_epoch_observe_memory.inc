/* Capture-only append to the actual lifecycle TU. The default TU is recovered
   byte-for-byte by removing its single guarded include. No mapping changes,
   guessed bytes, PKRU writes or application-data eligibility authority. */
#include "linked_epoch_observe_memory.h"
#if LI2_LINKED_EPOCH_CAPTURE != 1 || LI2_SCALAR_SPAN_TRACE != 1 || LI2_MAPS_MAINTAINED != 1
#error "fixed owner-memory observation requires the qualification profile"
#endif
static int leto_memory_error(struct li2_leto_memory *out,int code,long detail) {
    if(!out->result){out->result=code;out->detail=detail;}
    return out->result;
}
int li2_lifecycle_link_observe_memory(uintptr_t rsp,unsigned after_abort,struct li2_leto_memory *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->after_abort=after_abort;out->rsp=rsp;out->data_first=LETO_DATA_BASE;
    out->stack_first=LETO_STACK_RSP-128;
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range || after_abort>1 || rsp!=LETO_STACK_RSP ||
       hooks.protected_range(LETO_DATA_BASE,LETO_DATA_BYTES) ||
       hooks.protected_range(LETO_STACK_RSP-128,LETO_STACK_BYTES))
        return leto_memory_error(out,LI2_FETCH_ARGUMENT,0);
    li2_maps_stats_read(&out->before);
    /* These are two fixed call sites, not interchangeable acceptable kinds.
       Original abort ends the phase before any diagnostic observation. */
    if(out->before.active!=(after_abort?0U:1U) || out->before.poisoned)
        return leto_memory_error(out,LI2_FETCH_STATE,1);
    li2_maps_view_require_fresh();
    struct check_error error={0};
    int result=read_maps_checked(&error,&out->maps);
    li2_maps_stats_read(&out->after);
    if(result)return leto_memory_error(out,(int)error.code,error.detail);
    if(!out->maps.opened || !out->maps.close_started || !out->maps.closed ||
       out->maps.last_read || out->maps.close_result || !out->maps.bytes || !out->maps.rows ||
       out->maps.observation.kind!=(after_abort?LI2_MAPS_DIRECT:LI2_MAPS_FRESH) ||
       out->maps.observation.handler_id!=(after_abort?0:out->before.handler_id) ||
       out->maps.observation.io_performed!=1 ||
       out->before.fresh_calls==UINT64_MAX || out->before.acquisitions==UINT64_MAX ||
       out->after.fresh_calls!=out->before.fresh_calls+1 ||
       out->after.acquisitions!=out->before.acquisitions+1 ||
       out->after.active!=out->before.active || out->after.handler_id!=out->before.handler_id ||
       out->after.poisoned || !out->after.valid)
        return leto_memory_error(out,LI2_FETCH_STATE,0);
    const uintptr_t points[6]={LETO_DATA_BASE,LETO_DATA_BASE+LETO_DATA_BYTES-1,
        LETO_DATA_BASE+LETO_DATA_BYTES,LETO_STACK_BASE,LETO_STACK_RSP-128,
        LETO_STACK_BASE+PAGE+LETO_STACK_EXTENT};
    for(unsigned i=0;i<6;i++) {
        const struct map_row *r=mapping(points[i]);
        if(!r)return leto_memory_error(out,LI2_FETCH_PAGE,i);
        struct li2_leto_map_row *p=&out->rows[i];
        p->first=r->first;p->end=r->end;p->offset=r->offset;p->major=r->major;
        p->minor=r->minor;p->inode=r->inode;p->prot=r->prot;p->private=r->private;
        if(!r->private || r->inode || r->major || r->minor || r->offset)
            return leto_memory_error(out,LI2_FETCH_PAGE,i+6);
        if(i<2) {
            if(r->first!=LETO_DATA_BASE || r->end!=LETO_DATA_BASE+LETO_DATA_BYTES ||
               r->prot!=(PROT_READ|PROT_WRITE))return leto_memory_error(out,LI2_FETCH_PAGE,i+12);
        } else if(i==4) {
            if(r->first!=LETO_STACK_BASE+PAGE || r->end!=LETO_STACK_BASE+PAGE+LETO_STACK_EXTENT ||
               r->prot!=(PROT_READ|PROT_WRITE) || LETO_STACK_RSP-128+LETO_STACK_BYTES>r->end)
                return leto_memory_error(out,LI2_FETCH_PAGE,16);
        } else if(r->prot || r->end-points[i]<PAGE)
            return leto_memory_error(out,LI2_FETCH_PAGE,i+18);
        ++out->rows_checked;
    }
    /* Singleton and nonreturning nested-event policy prevent an intervening
       application mutation. Reads use actual handler rights; no PKRU bypass. */
    const volatile unsigned char *data=(void *)LETO_DATA_BASE,*stack=(void *)(LETO_STACK_RSP-128);
    for(size_t i=0;i<LETO_DATA_BYTES;i++){out->data[i]=data[i];out->data_copied=i+1;}
    for(size_t i=0;i<LETO_STACK_BYTES;i++){out->stack[i]=stack[i];out->stack_copied=i+1;}
    out->complete=1;return 0;
}
