/* Observation-only lifecycle append. All actual source, backing and original
   stack observations precede volatile byte reads; no singleton fetch mutation. */
#include "persistent_ret_owner_memory.h"
#include "persistent_ret_owner_config.h"
#if LI2_PERSISTENT_RET_OWNER_CAPTURE != 1 || LI2_PRTO_VERSION != 1 || LI2_PRTO_PAGE_RVA != 0x410000 || LI2_PRTO_U_PAGE_RVA != 0x412000
#error "exact fixed RET owner fixture geometry"
#endif
static int prto_memory_error(struct li2_prto_memory *o,unsigned code,long detail) {
    if(!o->result){o->result=(int)code;o->detail=detail;}return o->result;
}
int li2_lifecycle_prto_memory(uintptr_t rsp,unsigned site,struct li2_prto_memory *o) {
    if(!o || o->attempted)return LI2_FETCH_ARGUMENT;
    o->attempted=1;o->rsp=rsp;o->site=site;
    if(site>4 || !active || tx.guard || !hooks.raw || !hooks.protected_range || rsp<PAGE+256 ||
       rsp>=(UINT64_C(1)<<47)-264 || hooks.protected_range(PRTO_DATA_BASE,PRTO_DATA_BYTES) ||
       hooks.protected_range(rsp-256,PRTO_STACK_BYTES))
        return prto_memory_error(o,LI2_FETCH_ARGUMENT,0);
    int result=li2_maps_call_stack_query(rsp-256,PRTO_STACK_BYTES,&o->stack_origin);
    if(result)return prto_memory_error(o,(unsigned)result,1);
    li2_maps_stats_read(&o->before);
    /* Entry, terminal and both LOADED poison observations are outside the
       maps phase; only the following ordinary close is inside its handler. */
    unsigned phase=site==2;
    if(o->before.active!=phase || o->before.poisoned)return prto_memory_error(o,LI2_FETCH_STATE,2);
    li2_maps_view_require_fresh();struct check_error error={0};
    result=read_maps_checked(&error,&o->maps);li2_maps_stats_read(&o->after);
    if(result)return prto_memory_error(o,error.code,error.detail);
    if(!o->maps.opened || !o->maps.close_started || !o->maps.closed || o->maps.last_read ||
       o->maps.close_result || !o->maps.bytes || !o->maps.rows ||
       o->maps.observation.kind!=(phase?LI2_MAPS_FRESH:LI2_MAPS_DIRECT) ||
       o->maps.observation.handler_id!=(phase?o->before.handler_id:0) ||
       o->maps.observation.io_performed!=1 || o->before.fresh_calls==UINT64_MAX ||
       o->before.acquisitions==UINT64_MAX || o->after.fresh_calls!=o->before.fresh_calls+1 ||
       o->after.acquisitions!=o->before.acquisitions+1 || o->after.active!=phase ||
       o->after.handler_id!=o->before.handler_id || o->after.poisoned || !o->after.valid)
        return prto_memory_error(o,LI2_FETCH_STATE,3);
    const uintptr_t points[6]={PRTO_DATA_BASE,PRTO_DATA_BASE+PRTO_DATA_BYTES-1,
        PRTO_DATA_BASE+PRTO_DATA_BYTES,rsp-256,rsp+263,o->stack_origin.anchor};
    for(unsigned i=0;i<6;i++) {
        const struct map_row *r=mapping(points[i]);
        if(!r || !r->private || r->inode || r->major || r->minor || r->offset)
            return prto_memory_error(o,LI2_FETCH_PAGE,(long)i);
        o->rows[i]=(struct li2_prto_map_row){r->first,r->end,r->offset,r->major,r->minor,r->inode,r->prot,r->private};
        if(i<2) {
            if(r->first!=PRTO_DATA_BASE || r->end!=PRTO_DATA_BASE+PRTO_DATA_BYTES ||
               r->prot!=(PROT_READ|PROT_WRITE))return prto_memory_error(o,LI2_FETCH_PAGE,6+i);
        } else if(i==2) {
            if(r->prot || r->end-points[i]<PAGE)return prto_memory_error(o,LI2_FETCH_PAGE,8);
        } else if(r->prot!=(PROT_READ|PROT_WRITE) || r->first>o->stack_origin.origin_first ||
                  r->end<o->stack_origin.origin_end)
            return prto_memory_error(o,LI2_FETCH_PAGE,9+i);
        ++o->rows_checked;
    }
    for(unsigned i=0;i<3;i++) {
        uintptr_t address=LI2_PRTO_PAGE_RVA+i*PAGE;
        const struct owned_page *p=current(address);const struct map_row *r=mapping(address);
        if(!p || !p->live || !p->allocation || !p->generation || p->admitted ||
           p->logical!=(PROT_READ|PROT_EXEC) || p->actual!=PROT_READ || p->backing!=SEALED ||
           p->object>=object_count || !r || verify_page_checked(p,r,&error) || r->prot!=PROT_READ ||
           alias_check_checked(p->object,p->offset,PAGE,p->logical,p->address,p->address+PAGE,&error))
            return prto_memory_error(o,LI2_FETCH_PAGE,20+i);
        const struct object *object=&objects[p->object];
        if(object->initial_kind!=IMAGE_MAIN || !object->initial_source || !object->initial_source_size)
            return prto_memory_error(o,LI2_FETCH_BACKING,30+i);
        o->pages[i]=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
            .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
            .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=p->actual,
            .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
            .vma_inode=r->inode,.vma_offset=r->offset};
        struct li2_fetch_backing *b=&o->backing[i];b->retained_fd=object->retained_fd;
        b->seals=RAW(SYS_fcntl,b->retained_fd,F_GET_SEALS,0,0,0,0);b->seals_observed=1;
        if(b->seals<0 || (b->seals&SEALS)!=SEALS)return prto_memory_error(o,LI2_FETCH_BACKING,40+i);
        b->stat_result=RAW(SYS_fstat,b->retained_fd,&b->stat,0,0,0,0);b->stat_observed=1;
        if(b->stat_result || b->stat.st_dev!=object->stat.st_dev || b->stat.st_ino!=object->stat.st_ino ||
           b->stat.st_size!=object->stat.st_size || b->stat.st_mode!=object->stat.st_mode ||
           b->stat.st_size<=0 || (uint64_t)b->stat.st_size>UINT64_MAX-(PAGE-1) ||
           p->offset>=(((uint64_t)b->stat.st_size+PAGE-1)&~(PAGE-1)))
            return prto_memory_error(o,LI2_FETCH_BACKING,50+i);
        ++o->pages_checked;
    }
    const volatile unsigned char *source=(void *)LI2_PRTO_PAGE_RVA,*continuation=(void *)LI2_PRTO_U_PAGE_RVA;
    const volatile unsigned char *data=(void *)PRTO_DATA_BASE,*stack=(void *)(rsp-256);
    for(size_t i=0;i<sizeof o->source;i++){o->source[i]=source[i];o->source_copied=i+1;}
    for(size_t i=0;i<sizeof o->continuation;i++){o->continuation[i]=continuation[i];o->continuation_copied=i+1;}
    for(size_t i=0;i<sizeof o->data;i++){o->data[i]=data[i];o->data_copied=i+1;}
    for(size_t i=0;i<sizeof o->stack;i++){o->stack[i]=stack[i];o->stack_copied=i+1;}
    o->complete=1;return 0;
}
