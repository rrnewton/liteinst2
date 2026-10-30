/* Capture-only actual lifecycle TU. No production mapping/data policy changes.
   Only terminal READBACK may restore a fixed stack page's read permission. */
#include "scalar_region_observe_memory.h"
#if LI2_SCALAR_REGION_CAPTURE != 1 || LI2_SCALAR_REGION != 1 || LI2_MAPS_MAINTAINED != 1
#error "fixed owner-memory observation requires the qualification profile"
#endif
static int sro_memory_error(struct li2_sro_memory *out,int code,long detail) {
    if(!out->result){out->result=code;out->detail=detail;}
    return out->result;
}
static void sro_memory_row(struct li2_sro_map_row *p,const struct map_row *r) {
    p->first=r->first;p->end=r->end;p->offset=r->offset;p->major=r->major;
    p->minor=r->minor;p->inode=r->inode;p->prot=r->prot;p->private=r->private;
}
static int sro_memory_maps(struct li2_sro_memory *out,struct li2_sro_maps *m,
    const struct li2_region_source_key *key,unsigned restored) {
    li2_maps_stats_read(&m->before);
    unsigned inactive=out->stage!=SRO_MEMORY_LIVE;
    if(m->before.active!=(inactive?0U:1U) || m->before.poisoned)
        return sro_memory_error(out,LI2_FETCH_STATE,1);
    li2_maps_view_require_fresh();struct check_error error={0};
    int result=read_maps_checked(&error,&m->maps);li2_maps_stats_read(&m->after);
    if(result)return sro_memory_error(out,(int)error.code,error.detail);
    if(!m->maps.opened || !m->maps.close_started || !m->maps.closed ||
       m->maps.last_read || m->maps.close_result || !m->maps.bytes || !m->maps.rows ||
       m->maps.observation.kind!=(inactive?LI2_MAPS_DIRECT:LI2_MAPS_FRESH) ||
       m->maps.observation.handler_id!=(inactive?0:m->before.handler_id) ||
       m->maps.observation.io_performed!=1 ||
       m->before.fresh_calls==UINT64_MAX || m->before.acquisitions==UINT64_MAX ||
       m->after.fresh_calls!=m->before.fresh_calls+1 ||
       m->after.acquisitions!=m->before.acquisitions+1 ||
       m->after.active!=m->before.active || m->after.handler_id!=m->before.handler_id ||
       m->after.poisoned || !m->after.valid)
        return sro_memory_error(out,LI2_FETCH_STATE,2);
    const uintptr_t points[8]={SRO_DATA_BASE,SRO_DATA_BASE+SRO_DATA_BYTES-1,
        SRO_DATA_BASE+SRO_DATA_BYTES,SRO_STACK_BASE,SRO_STACK_BASE+PAGE,
        SRO_STACK_FAULT,SRO_STACK_FAULT+PAGE,SRO_STACK_BASE+PAGE+SRO_STACK_EXTENT};
    for(unsigned i=0;i<8;i++) {
        const struct map_row *r=mapping(points[i]);
        if(!r)return sro_memory_error(out,LI2_FETCH_PAGE,i);
        sro_memory_row(&m->rows[i],r);
        if(!r->private || r->inode || r->major || r->minor || r->offset)
            return sro_memory_error(out,LI2_FETCH_PAGE,i+8);
        if(i<2) {
            if(r->first!=SRO_DATA_BASE || r->end!=SRO_DATA_BASE+SRO_DATA_BYTES ||
               r->prot!=(PROT_READ|PROT_WRITE))return sro_memory_error(out,LI2_FETCH_PAGE,i+16);
        } else if(i>=4 && i<=6) {
            uintptr_t first=SRO_STACK_BASE+PAGE,end=SRO_STACK_BASE+PAGE+SRO_STACK_EXTENT;
            unsigned prot=PROT_READ|PROT_WRITE;
            if(out->stack_kind) {
                first=i==4?first:i==5?SRO_STACK_FAULT:SRO_STACK_FAULT+PAGE;
                end=i==4?SRO_STACK_FAULT:i==5?SRO_STACK_FAULT+PAGE:end;
                if(i==5)prot=restored?PROT_READ:PROT_NONE;
            }
            if(r->first!=first || r->end!=end || r->prot!=prot)
                return sro_memory_error(out,LI2_FETCH_PAGE,i+24);
        } else if(r->prot || r->end-points[i]<PAGE)
            return sro_memory_error(out,LI2_FETCH_PAGE,i+32);
        ++m->rows_checked;
    }
    const struct map_row *r=mapping(key->page.address);const struct li2_fetch_page *p=&key->page;
    if(!r || !r->private || r->prot!=PROT_READ || r->first!=p->vma_first ||
       r->end!=p->vma_end || r->major!=p->vma_major || r->minor!=p->vma_minor ||
       r->inode!=p->vma_inode || r->offset!=p->vma_offset ||
       p->address<r->first || r->end-p->address<PAGE)
        return sro_memory_error(out,LI2_FETCH_PAGE,40);
    sro_memory_row(&m->source,r);m->source_checked=1;
    if(out->stage==SRO_MEMORY_READBACK) {
        r=mapping(out->generated);
        if(!r || !r->private || r->prot!=PROT_READ || r->inode || r->major || r->minor || r->offset ||
           out->generated<r->first || r->end-out->generated<PAGE)
            return sro_memory_error(out,LI2_FETCH_PAGE,41);
        sro_memory_row(&m->generated,r);m->generated_checked=1;
    }
    return 0;
}
int li2_lifecycle_scalar_region_observe_memory(uintptr_t rsp,unsigned stage,
    const struct li2_region_source_key *key,uintptr_t generated,struct li2_sro_memory *out) {
    if(!out || out->attempted)return LI2_FETCH_ARGUMENT;
    out->attempted=1;out->stage=stage;out->rsp=rsp;out->data_first=SRO_DATA_BASE;
    out->stack_first=rsp>=128?rsp-128:0;out->generated=generated;
    if(rsp==SRO_STACK_RSP)out->stack_kind=0;
    else if(rsp==SRO_STACK_FAULT-0x58)out->stack_kind=1;
    else if(rsp==SRO_STACK_FAULT+PAGE-0x58)out->stack_kind=2;
    else return sro_memory_error(out,LI2_FETCH_ARGUMENT,1);
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range || !key ||
       stage>SRO_MEMORY_READBACK || key->page.address%PAGE || key->page.address>UINTPTR_MAX-PAGE ||
       hooks.protected_range(SRO_DATA_BASE,SRO_DATA_BYTES) ||
       hooks.protected_range(SRO_STACK_BASE,PAGE+SRO_STACK_EXTENT+PAGE) ||
       (stage==SRO_MEMORY_READBACK && (!out->stack_kind || !generated || generated%PAGE ||
        generated>UINTPTR_MAX-PAGE || !hooks.protected_range(generated,PAGE))) ||
       (stage!=SRO_MEMORY_READBACK && generated))
        return sro_memory_error(out,LI2_FETCH_ARGUMENT,0);
    int result=sro_memory_maps(out,&out->initial,key,0);if(result)return result;
    if(stage==SRO_MEMORY_READBACK) {
        out->restore_started=1;
        out->restore_result=hooks.raw(SYS_mprotect,SRO_STACK_FAULT,PAGE,PROT_READ,0,0,0);
        out->restore_returned=1;
        if(out->restore_result)return sro_memory_error(out,LI2_FETCH_STATE,out->restore_result);
        result=sro_memory_maps(out,&out->restored,key,1);if(result)return result;
        out->restore_verified=1;
    }
    const volatile unsigned char *data=(void *)SRO_DATA_BASE,*stack=(void *)out->stack_first;
    for(size_t i=0;i<SRO_DATA_BYTES;i++){out->data[i]=data[i];out->data_copied=i+1;}
    for(size_t i=0;i<SRO_STACK_BYTES;i++) {
        uintptr_t at=out->stack_first+i;
        if(out->stack_kind && stage!=SRO_MEMORY_READBACK &&
           at>=SRO_STACK_FAULT && at<SRO_STACK_FAULT+PAGE){++out->stack_missing;continue;}
        out->stack[i]=stack[i];out->stack_observed[i]=1;++out->stack_copied;
    }
    out->stack_full=out->stack_copied==SRO_STACK_BYTES;
    if(out->stack_copied+out->stack_missing!=SRO_STACK_BYTES ||
       (stage==SRO_MEMORY_READBACK && !out->stack_full))return sro_memory_error(out,LI2_FETCH_STATE,3);
    out->complete=1;return 0;
}
