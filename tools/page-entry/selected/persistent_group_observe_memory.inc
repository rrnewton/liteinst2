/* Capture-only append to the actual lifecycle TU. The default TU is recovered
   byte-for-byte by removing its single guarded include. No mapping changes,
   guessed bytes, PKRU writes or application-data eligibility authority. */
#include "persistent_group_observe_memory.h"
#if LI2_PERSISTENT_GROUP_CAPTURE != 1 || LI2_SCALAR_SPAN_TRACE != 1 || LI2_MAPS_MAINTAINED != 1
#error "fixed owner-memory observation requires the qualification profile"
#endif
static int pgo_memory_error(struct li2_pgo_memory *out,int code,long detail) {
    if(!out->result){out->result=code;out->detail=detail;}
    return out->result;
}
int li2_lifecycle_pg_observe_memory(uintptr_t rsp,unsigned after_abort,struct li2_pgo_memory *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->after_abort=after_abort;out->rsp=rsp;out->data_first=PGO_DATA_BASE;
    out->stack_first=PGO_STACK_RSP-128;
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range || after_abort>1 || rsp!=PGO_STACK_RSP ||
       hooks.protected_range(PGO_DATA_BASE,PGO_DATA_BYTES) ||
       hooks.protected_range(PGO_STACK_RSP-128,PGO_STACK_BYTES))
        return pgo_memory_error(out,LI2_FETCH_ARGUMENT,0);
    li2_maps_stats_read(&out->before);
    /* Actual registered seeding ends the maps phase before fresh acquisition;
       close and abort also end it. Both fixed observation sites are DIRECT. */
    if(out->before.active!=0 || out->before.poisoned)
        return pgo_memory_error(out,LI2_FETCH_STATE,1);
    li2_maps_view_require_fresh();
    struct check_error error={0};
    int result=read_maps_checked(&error,&out->maps);
    li2_maps_stats_read(&out->after);
    if(result)return pgo_memory_error(out,(int)error.code,error.detail);
    if(!out->maps.opened || !out->maps.close_started || !out->maps.closed ||
       out->maps.last_read || out->maps.close_result || !out->maps.bytes || !out->maps.rows ||
       out->maps.observation.kind!=LI2_MAPS_DIRECT ||
       out->maps.observation.handler_id!=0 ||
       out->maps.observation.io_performed!=1 ||
       out->before.fresh_calls==UINT64_MAX || out->before.acquisitions==UINT64_MAX ||
       out->after.fresh_calls!=out->before.fresh_calls+1 ||
       out->after.acquisitions!=out->before.acquisitions+1 ||
       out->after.active!=out->before.active || out->after.handler_id!=out->before.handler_id ||
       out->after.poisoned || !out->after.valid)
        return pgo_memory_error(out,LI2_FETCH_STATE,0);
    const uintptr_t points[6]={PGO_DATA_BASE,PGO_DATA_BASE+PGO_DATA_BYTES-1,
        PGO_DATA_BASE+PGO_DATA_BYTES,PGO_STACK_BASE,PGO_STACK_RSP-128,
        PGO_STACK_BASE+PAGE+PGO_STACK_EXTENT};
    for(unsigned i=0;i<6;i++) {
        const struct map_row *r=mapping(points[i]);
        if(!r)return pgo_memory_error(out,LI2_FETCH_PAGE,i);
        struct li2_pgo_map_row *p=&out->rows[i];
        p->first=r->first;p->end=r->end;p->offset=r->offset;p->major=r->major;
        p->minor=r->minor;p->inode=r->inode;p->prot=r->prot;p->private=r->private;
        if(!r->private || r->inode || r->major || r->minor || r->offset)
            return pgo_memory_error(out,LI2_FETCH_PAGE,i+6);
        if(i<2) {
            if(r->first!=PGO_DATA_BASE || r->end!=PGO_DATA_BASE+PGO_DATA_BYTES ||
               r->prot!=(PROT_READ|PROT_WRITE))return pgo_memory_error(out,LI2_FETCH_PAGE,i+12);
        } else if(i==4) {
            if(r->first!=PGO_STACK_BASE+PAGE || r->end!=PGO_STACK_BASE+PAGE+PGO_STACK_EXTENT ||
               r->prot!=(PROT_READ|PROT_WRITE) || PGO_STACK_RSP-128+PGO_STACK_BYTES>r->end)
                return pgo_memory_error(out,LI2_FETCH_PAGE,16);
        } else if(r->prot || r->end-points[i]<PAGE)
            return pgo_memory_error(out,LI2_FETCH_PAGE,i+18);
        ++out->rows_checked;
    }
    /* Singleton and nonreturning nested-event policy prevent an intervening
       application mutation. Reads use actual handler rights; no PKRU bypass. */
    const volatile unsigned char *data=(void *)PGO_DATA_BASE,*stack=(void *)(PGO_STACK_RSP-128);
    for(size_t i=0;i<PGO_DATA_BYTES;i++){out->data[i]=data[i];out->data_copied=i+1;}
    for(size_t i=0;i<PGO_STACK_BYTES;i++){out->stack[i]=stack[i];out->stack_copied=i+1;}
    out->complete=1;return 0;
}
