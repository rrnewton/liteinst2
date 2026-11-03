/* Capture only in the actual lifecycle TU; reuse its parser, complete sealed
   backing checks and alias policy. This does not admit or change any mapping. */
#include "loop_cache8_effects_memory.h"
#if LI2_LOOP_CACHE8_EFFECTS != 1 || LI2_LOOP_CACHE8_OBSERVE != 1 || LI2_MAPS_MAINTAINED != 1 || LI2_INITIAL_CODE_PROTECTION != 1
#error "distinct real CACHE8 effect observation requires actual maintained lifecycle"
#endif
static void lc8em_stats(uint64_t out[10]) {
    struct li2_maps_stats s;li2_maps_stats_read(&s);
    const uint64_t v[]={s.fresh_calls,s.acquisitions,s.reuses,s.invalidations,s.handler_id,
        s.mutation_epoch,s.active,s.valid,s.poisoned,s.reserved};copy(out,v,sizeof v);
}
static void lc8em_row(uint64_t out[8],const struct map_row *r) {
    const uint64_t v[]={r->first,r->end,r->offset,r->major,r->minor,r->inode,r->prot,r->private};
    copy(out,v,sizeof v);
}
static int lc8em_error(struct lc8e_memory *o,int code,long detail) {
    if(!o->h[2]){o->h[2]=(unsigned)code;o->h[3]=(uint64_t)detail;}return code;
}
int li2_lifecycle_cache8_effects_memory(struct lc8e_memory *o) {
    if(!o || o->h[0])return LI2_FETCH_ARGUMENT;
    o->h[0]=1;o->h[15]=LC8E_RSP;
    if(!active || tx.guard || !hooks.raw || !hooks.protected_range ||
       hooks.protected_range(LC8E_DATA,LC8E_DATA_BYTES) ||
       hooks.protected_range(LC8E_RSP-128,LC8E_STACK_BYTES) ||
       hooks.protected_range(LC8E_STATE,256))return lc8em_error(o,LI2_FETCH_ARGUMENT,0);
    struct li2_lifecycle_counts life;li2_lifecycle_snapshot(&life);
    _Static_assert(sizeof life==18U*sizeof(uint64_t),"whole lifecycle counter projection");
    copy(o->life,&life,sizeof life);lc8em_stats(o->before);
    li2_maps_view_require_fresh();
    struct check_error error={0};struct li2_fetch_map_progress maps={0};
    int e=read_maps_checked(&error,&maps);lc8em_stats(o->after);
    const uint64_t mv[]={(uint64_t)maps.fd,(uint64_t)maps.last_read,(uint64_t)maps.close_result,
        maps.bytes,maps.rows,maps.opened,maps.close_started,maps.closed,
        maps.observation.acquisition_id,maps.observation.handler_id,maps.observation.mutation_epoch,
        maps.observation.kind,maps.observation.io_performed};copy(o->maps,mv,sizeof mv);
    if(e)return lc8em_error(o,(int)error.code,error.detail);
    if(!maps.opened || !maps.close_started || !maps.closed || maps.last_read || maps.close_result ||
       !maps.bytes || !maps.rows || maps.observation.io_performed!=1 ||
       o->before[0]==UINT64_MAX || o->before[1]==UINT64_MAX ||
       o->after[0]!=o->before[0]+1 || o->after[1]!=o->before[1]+1 || o->after[8])
        return lc8em_error(o,LI2_FETCH_STATE,1);
    unsigned object=OBJECTS;
    for(unsigned i=0;i<6;i++) {
        uintptr_t address=LC8E_SOURCE+i*PAGE;
        const struct owned_page *p=current(address);const struct map_row *r=mapping(address);
        if(!p || !r || p->backing!=SEALED || p->object>=object_count || !initial_sealed_object[p->object] ||
           p->actual!=PROT_READ || (p->logical!=PROT_READ && p->logical!=(PROT_READ|PROT_EXEC)) ||
           r->prot!=PROT_READ || address<r->first || address>=r->end)
            return lc8em_error(o,LI2_FETCH_PAGE,10+i);
        if(!i)object=p->object;else if(p->object!=object)return lc8em_error(o,LI2_FETCH_BACKING,10+i);
        const uint64_t v[]={address,p->allocation,p->generation,p->offset,p->initial_extent,
            p->backing,p->object,p->logical,p->actual,p->live,p->admitted,
            r->first,r->end,r->offset,r->major,r->minor,r->inode,r->prot,r->private};
        copy(o->source_page[i],v,sizeof v);
        e=verify_page_checked(p,r,&error);o->source_page[i][20]=(uint64_t)e;
        if(e)return lc8em_error(o,(int)error.code,error.detail);
        e=alias_check_checked(object,p->offset,PAGE,PROT_READ|PROT_EXEC,address,address+PAGE,&error);
        o->source_page[i][19]=(uint64_t)e;
        if(e)return lc8em_error(o,(int)error.code,error.detail);
        ++o->h[4];
    }
    struct stat st={0};const struct object *b=&objects[object];
    long seals=RAW(SYS_fcntl,b->retained_fd,F_GET_SEALS,0,0,0,0);
    long result=RAW(SYS_fstat,b->retained_fd,&st,0,0,0,0);
    o->h[8]=(uint64_t)b->retained_fd;o->h[9]=(uint64_t)seals;o->h[10]=(uint64_t)result;
    o->h[11]=st.st_dev;o->h[12]=st.st_ino;o->h[13]=(uint64_t)st.st_size;o->h[14]=st.st_mode;
    if(seals<0 || (seals&SEALS)!=SEALS || result || st.st_dev!=b->stat.st_dev ||
       st.st_ino!=b->stat.st_ino || st.st_size!=b->stat.st_size || st.st_mode!=b->stat.st_mode)
        return lc8em_error(o,LI2_FETCH_BACKING,20);
    const uintptr_t first[]={LC8E_DATA,LC8E_RSP-128,LC8E_STATE};
    const size_t bytes[]={LC8E_DATA_BYTES,LC8E_STACK_BYTES,256};
    for(unsigned i=0;i<3;i++) {
        const struct map_row *r=mapping(first[i]);
        if(!r || first[i]<r->first || first[i]>=r->end || bytes[i]>r->end-first[i] ||
           r->prot!=(PROT_READ|PROT_WRITE) || !r->private || r->inode || r->major || r->minor || r->offset)
            return lc8em_error(o,LI2_FETCH_PAGE,30+i);
        lc8em_row(o->guest[i],r);
    }
    const volatile unsigned char *source=(void *)LC8E_SOURCE,*data=(void *)LC8E_DATA,*stack=(void *)(LC8E_RSP-128);
    for(unsigned i=0;i<LC8E_SOURCE_BYTES;i++){o->source[i]=source[i];o->h[5]=i+1;}
    for(unsigned i=0;i<LC8E_DATA_BYTES;i++){o->data[i]=data[i];o->h[6]=i+1;}
    for(unsigned i=0;i<LC8E_STACK_BYTES;i++){o->stack[i]=stack[i];o->h[7]=i+1;}
    const volatile uint64_t *state=(void *)LC8E_STATE;
    for(unsigned i=0;i<32;i++)o->state[i]=state[i];
    o->h[1]=1;return 0;
}
