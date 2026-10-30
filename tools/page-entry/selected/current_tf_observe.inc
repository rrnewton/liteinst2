/* Qualification only. Copy-only transfer hooks run AFTER the actual API;
   none enters the current ticket's validate/consume/CAS interval. */
#include "current_tf_observe.h"
#include "current_tf_capture_config.h"
#ifndef LI2_CURRENT_APP_HEAD_RVA
#error "actual independently retained prefix ELF symbol is required"
#endif
#ifndef LI2_CURRENT_APP_EXIT_RVA
#error "actual independently retained high exit ELF symbol is required"
#endif
#define CTO_MAGIC UINT64_C(0x315446435449324c)
#define CTO_FOOTER UINT64_C(0x314654435449324c)
#define CTO_ROWS 4U
struct cto_registry {
    unsigned complete,count;
    uintptr_t table;
    struct image bridge;
    Elf64_Phdr ph[MAX_PHDR];
    struct li2_fork_range ranges[RANGES];
    unsigned char initial_code[RANGES];
    struct li2_cto_storage storage[9];
    unsigned intersects[9],load_indices[9],range_indices[9];
};
struct cto_snapshot {
    unsigned present,point,current_route;
    int result;
    uintptr_t chain,argument,view;
    uint64_t event;
    unsigned active,pending,in_handler,first_error;
    long first_detail;
    struct li2_fetch_ref ref;
    struct li2_tf_chain_slot slot;
    struct li2_step_session session;
    struct li2_fetch_rx_view physical,current;
    struct li2_current_custody_provenance provenance;
    struct li2_current_custody_stats counts;
    struct li2_page_custody_stats custody;
    struct li2_maps_stats maps;
    struct li2_cto_view_state view_state;
    struct li2_rseq_state rseq;
};
struct cto_row {
    unsigned present,index,after_present,source_bytes,data_bytes,stack_bytes;
    uintptr_t pc;
    struct uh_frame before,after;
    struct cto_snapshot points[LI2_CTO_POINTS];
    unsigned char data[UHO_DATA_BYTES],stack[UHO_STACK_BYTES];
};
struct cto_wire {
    /* magic/version/extent/rows/head/exit/control/initialized;
       ingress_count/completed_handlers/stale_injected/terminal/status/code/detail;
       joined_hash/actual_hash_pc/prefix_end_captured; words18..31 zero. */
    uint64_t h[32];
    struct cto_registry initial_registry,terminal_registry;
    struct li2_uho_memory initial_memory;
    struct uh_frame tls_origin;
    struct cto_row rows[CTO_ROWS];
    struct cto_snapshot stale_before,stale_after;
    struct li2_tf_chain joined_chain,terminal_chain,prefix_chain;
    struct li2_current_custody_stats joined_counts,terminal_counts;
    struct li2_page_custody_stats joined_custody,terminal_custody;
    struct li2_cto_view_state joined_view,terminal_view;
    unsigned char original_source[PAGE],entry_source[PAGE],joined_source[PAGE];
    uint64_t source_offset;
};
static struct cto_wire cto_wire;
static unsigned cto_ready,cto_current=CTO_ROWS,cto_terminal,cto_written;
static uintptr_t cto_head,cto_exit;
_Static_assert(sizeof(struct uho_wire)+64+sizeof(struct cto_wire)+64<(16U<<20),
               "complete old and appended records under unchanged capture ceiling");
static void cto_registry(struct cto_registry *out) {
    checked(!out->complete && protected_count && protected_count<=RANGES,1799,1);
    const struct image *b=bridge_runtime_image();
    checked(b && b->kind==IMAGE_BRIDGE && b->ph && b->n && b->n<=MAX_PHDR &&
            !b->source && !b->source_size && b->backing_fd==-1,1799,2);
    copy(&out->bridge,b,sizeof(*b));copy(out->ph,b->ph,b->n*sizeof(*b->ph));
    out->table=(uintptr_t)protected;out->count=(unsigned)protected_count;
    copy(out->ranges,protected,protected_count*sizeof(*protected));
#ifdef LI2_INITIAL_CODE_PROTECTION
    copy(out->initial_code,initial_code_range,protected_count);
#endif
    li2_current_tf_storage(out->storage);
    for(unsigned i=0;i<9;i++) {
        const struct li2_cto_storage *s=&out->storage[i];
        checked(s->address && s->bytes && s->address<=UINTPTR_MAX-s->bytes &&
                s->alignment && !(s->alignment&(s->alignment-1)) &&
                !(s->address&(s->alignment-1)),1799,3);
        out->intersects[i]=(unsigned)private_intersects(s->address,s->bytes);
        checked(out->intersects[i]==1,1799,4);
        unsigned loads=0,ranges=0;
        for(size_t j=0;j<b->n;j++) {
            const Elf64_Phdr *p=&out->ph[j];
            if(p->p_type!=PT_LOAD || !p->p_memsz)continue;
            checked(b->bias<=UINTPTR_MAX-p->p_vaddr &&
                b->bias+p->p_vaddr<=UINTPTR_MAX-(PAGE-1) &&
                p->p_memsz<=UINTPTR_MAX-(b->bias+p->p_vaddr)-(PAGE-1),1799,26);
            uintptr_t first=b->bias+p->p_vaddr,end=first+p->p_memsz;
            if(s->address>=end || first>=s->address+s->bytes)continue;
            checked(!loads++ && p->p_flags==(PF_R|PF_W) &&
                first<=s->address && s->address+s->bytes<=end,1799,27);
            out->load_indices[i]=(unsigned)j;
            uintptr_t low=first&~(PAGE-1),high=(end+PAGE-1)&~(PAGE-1);
            for(size_t k=0;k<protected_count;k++)
                if(out->ranges[k].first==low && out->ranges[k].end==high && !out->initial_code[k]) {
                    checked(!ranges++,1799,28);out->range_indices[i]=(unsigned)k;
                }
        }
        checked(loads==1 && ranges==1,1799,29);
    }
    out->complete=1;
}
static void cto_initialize(void) {
    checked(!cto_ready && !cto_terminal && uho_ready && uho_wire.h[18],1799,5);
    checked(original_main.bias<=UINTPTR_MAX-LI2_CURRENT_APP_HEAD_RVA &&
            original_main.bias<=UINTPTR_MAX-LI2_CURRENT_APP_EXIT_RVA,1799,6);
    cto_head=original_main.bias+LI2_CURRENT_APP_HEAD_RVA;
    cto_exit=original_main.bias+LI2_CURRENT_APP_EXIT_RVA;
    checked(cto_head>=PAGE && !(cto_head&(PAGE-1)) && cto_head<=UINTPTR_MAX-PAGE,1799,7);
    unsigned found=0;
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || p->p_flags!=(PF_R|PF_X))continue;
        checked(original_main.bias<=UINTPTR_MAX-p->p_vaddr,1799,30);
        uintptr_t start=original_main.bias+p->p_vaddr;
        if(cto_head<start)continue;
        uintptr_t delta=cto_head-start;
        if(delta>p->p_filesz || PAGE>p->p_filesz-delta)continue;
        checked(!found && p->p_offset<=original_main.source_size &&
            delta<=original_main.source_size-p->p_offset &&
            PAGE<=original_main.source_size-p->p_offset-delta,1799,8);
        cto_wire.source_offset=p->p_offset+delta;
        copy(cto_wire.original_source,original_main.source+cto_wire.source_offset,PAGE);found=1;
    }
    static const unsigned char literal[12]={0x66,0x90,0x66,0x90,0x66,0x90,0xff,0x25,0,0,0,0};
    checked(found && equal(cto_wire.original_source,literal,sizeof literal) &&
            equal(cto_wire.original_source+12,&cto_exit,8),1799,9);
    for(size_t i=20;i<PAGE;i++)checked(cto_wire.original_source[i]==0xcc,1799,10);
    const char *value=fork_env("LI2_CURRENT_TF_CONTROL");
    checked(value && (value[0]=='0' || value[0]=='1') && !value[1],1799,12);
    cto_wire.h[0]=CTO_MAGIC;cto_wire.h[1]=1;cto_wire.h[2]=sizeof cto_wire;
    cto_wire.h[3]=CTO_ROWS;cto_wire.h[4]=cto_head;cto_wire.h[5]=cto_exit;
    cto_wire.h[6]=(unsigned)(value[0]-'0');
    checked(!selected_run_protect_add(0,(uintptr_t)&cto_wire,sizeof cto_wire),1799,13);
    cto_registry(&cto_wire.initial_registry);
    cto_wire.h[7]=1;cto_ready=1;
}
static void cto_snapshot(struct cto_snapshot *out,unsigned point,int result,unsigned route,
        const struct li2_tf_chain *c,const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *v) {
    checked(!out->present && c==&selected_chain && c->initialized && c->active>=0 && c->active<2,1799,14);
    out->point=point;out->result=result;out->current_route=route;out->chain=(uintptr_t)c;
    out->argument=(uintptr_t)ref;out->view=(uintptr_t)v;out->event=c->event_id;
    out->active=(unsigned)c->active;out->pending=c->pending;out->in_handler=c->in_handler;
    out->first_error=c->first_error;out->first_detail=c->first_detail;
    if(ref)copy(&out->ref,ref,sizeof(*ref));
    copy(&out->slot,&c->slots[c->active],sizeof out->slot);
    if(c->slots[c->active].owner.step.session)
        copy(&out->session,c->slots[c->active].owner.step.session,sizeof out->session);
    copy(&out->physical,li2_lifecycle_fetch_rx_progress(),sizeof out->physical);
    copy(&out->current,li2_lifecycle_fetch_rx_current_progress(),sizeof out->current);
    copy(&out->provenance,li2_current_custody_provenance(),sizeof out->provenance);
    li2_current_custody_snapshot(&out->counts);
    copy(&out->custody,li2_page_custody_snapshot(),sizeof out->custody);
    li2_maps_stats_read(&out->maps);li2_current_tf_view_state(&out->view_state);
    copy(&out->rseq,li2_rseq_snapshot(),sizeof out->rseq);out->present=1;
}
/* Called only after the old unsafe/nested guards and actual maps phase begin. */
static void cto_begin(int sig,const siginfo_t *si,const ucontext_t *uc) {
    cto_current=CTO_ROWS;if(!cto_ready || cto_terminal || !uc)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(pc==uho_head && cto_wire.h[8]==CTO_ROWS && !cto_wire.h[15]) {
        copy(&cto_wire.joined_chain,&selected_chain,sizeof selected_chain);
        li2_current_custody_snapshot(&cto_wire.joined_counts);
        copy(&cto_wire.joined_custody,li2_page_custody_snapshot(),sizeof cto_wire.joined_custody);
        li2_current_tf_view_state(&cto_wire.joined_view);
        copy(cto_wire.joined_source,(void *)cto_head,PAGE);
        cto_wire.h[15]=1;cto_wire.h[16]=pc;
    }
    if(pc<cto_head || pc>cto_head+6 || ((pc-cto_head)&1))return;
    unsigned index=(unsigned)((pc-cto_head)/2);struct cto_row *r=&cto_wire.rows[index];
    checked(!r->present && index==cto_wire.h[8] && !cto_wire.h[15],1799,15);
    checked(!uh_capture(&r->before,sig,si,uc),1799,16);
    r->index=index;r->pc=pc;r->present=1;cto_current=index;++cto_wire.h[8];
    checked((index==0 && sig==SIGSEGV) || (index && sig==SIGTRAP),1799,17);
    if(!index) {
        copy(cto_wire.entry_source,(void *)cto_head,PAGE);r->source_bytes=PAGE;
        checked(equal(cto_wire.entry_source,cto_wire.original_source,PAGE),1799,18);
        checked(!li2_lifecycle_unrolled_observe_memory((uintptr_t)uc->uc_mcontext.gregs[REG_RSP],0,
            &cto_wire.initial_memory) && cto_wire.initial_memory.complete,1799,19);
        checked(!uh_capture(&cto_wire.tls_origin,sig,si,uc),1799,20);
        uh_tls(&cto_wire.tls_origin);
    }
    checked(cto_wire.initial_memory.complete &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==UHO_STACK_RSP,1799,21);
    /* Exact prior physical proof covers these no-effect fixture NOPs. Actual
       reads, not copied expected bytes; no new query or RAW during custody. */
    copy(r->data,(void *)UHO_DATA_BASE,UHO_DATA_BYTES);r->data_bytes=UHO_DATA_BYTES;
    copy(r->stack,(void *)(UHO_STACK_RSP-128),UHO_STACK_BYTES);r->stack_bytes=UHO_STACK_BYTES;
    checked(uh_unchanged(&r->before,si,uc),1799,22);
}
void li2_current_tf_observe(unsigned point,int result,unsigned route,const struct li2_tf_chain *c,
        const struct li2_fetch_ref *ref,const struct li2_fetch_rx_view *view) {
    if(!cto_ready || cto_current==CTO_ROWS || cto_terminal)return;
    checked(point>=1 && point<=LI2_CTO_POINTS && route<=1,1799,23);
    struct cto_row *r=&cto_wire.rows[cto_current];
    cto_snapshot(&r->points[point-1],point,result,route,c,ref,view);
    if(cto_wire.h[6]==1 && cto_current==1 && point==LI2_CTO_STAGE && !result && route) {
        checked(!cto_wire.h[10],1799,24);
        cto_snapshot(&cto_wire.stale_before,point,result,route,c,ref,view);
        li2_page_custody_discard(LI2_CUSTODY_MISS); /* actual public invalidation */
        cto_snapshot(&cto_wire.stale_after,point,result,route,c,ref,view);cto_wire.h[10]=1;
    }
}
static void cto_end(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!cto_ready || cto_current==CTO_ROWS || cto_terminal)return;
    struct cto_row *r=&cto_wire.rows[cto_current];
    checked(!r->after_present && !uh_capture(&r->after,sig,si,uc),1799,25);
    /* Preserve both actual slots before the high-PAUSE successor can reuse
       the closed NOP predecessor. This is a copy, not a cleanup prediction. */
    if(cto_current==CTO_ROWS-1) {
        copy(&cto_wire.prefix_chain,&selected_chain,sizeof selected_chain);
        cto_wire.h[17]=1;
    }
    r->after_present=1;++cto_wire.h[9];cto_current=CTO_ROWS;
}
static void cto_terminal_snapshot(unsigned status,unsigned code,long detail) {
    if(!cto_ready || cto_terminal)return;
    cto_terminal=1;cto_wire.h[11]=1;cto_wire.h[12]=status;cto_wire.h[13]=code;cto_wire.h[14]=(uint64_t)detail;
    copy(&cto_wire.terminal_chain,&selected_chain,sizeof selected_chain);
    li2_current_custody_snapshot(&cto_wire.terminal_counts);
    copy(&cto_wire.terminal_custody,li2_page_custody_snapshot(),sizeof cto_wire.terminal_custody);
    li2_current_tf_view_state(&cto_wire.terminal_view);
    cto_registry(&cto_wire.terminal_registry);
}
static void cto_write(unsigned status,unsigned code) {
    if(!cto_ready || !cto_terminal || cto_written)return;
    cto_written=1;
    struct stat sink;
    long result=raw(SYS_fstat,3,(long)&sink,0,0,0,0);
    if(result || !uho_same_sink(&sink) || sink.st_size!=(off_t)(sizeof uho_wire+64))return;
    size_t at=0;uint64_t calls=0;
    while(at<sizeof cto_wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&cto_wire+at),sizeof cto_wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof cto_wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof cto_wire)return;
    const uint64_t footer[]={CTO_FOOTER,1,sizeof cto_wire,at,calls,(uint64_t)result,status,code};
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
}
