/* Included after the unchanged whole current-custody fixture and the exact
   extracted production adapter/same_data. Real kernel mappings and queries;
   no application execution, rseq registration or native-pair owner is claimed. */
static uintptr_t data_page;
static unsigned char data_before[PAGE];
static unsigned compared,identity_refusals,mapping_refusals,argument_refusals;
static unsigned fallback_checks,no_io_refusals,generation_changes;

static long data_dispatch(long n,uintptr_t p,unsigned prot) {
    const long args[6]={(long)p,PAGE,prot,
        n==SYS_mmap?MAP_PRIVATE|MAP_ANONYMOUS:0,n==SYS_mmap?-1:0,0};
    long result=0;
    need(li2_lifecycle_dispatch(n,args,&result)==1 && !kernel_error(result),1200);
    return result;
}
static void prepare_data(uintptr_t anchor) {
    setup(anchor);
    li2_page_custody_discard(LI2_CUSTODY_RELEASE);
    need(!tracked(SYS_mprotect,source_page,PAGE,PROT_READ,0,0,0) &&
         !tracked(SYS_membarrier,32,0,0,0,0,0),1201);
    need(!li2_lifecycle_fetch_release(&borrow) && !fetch.progress.held,1202);
    cleanup_released=1;li2_maps_phase_end();
    data_page=(uintptr_t)data_dispatch(SYS_mmap,0,PROT_READ|PROT_WRITE);
    need(data_page>=PAGE && !(data_page&(PAGE-1)),1203);
    for(unsigned i=0;i<PAGE;i++)((unsigned char *)data_page)[i]=(unsigned char)(i*17U+3U);
    memcpy(data_before,(const void *)data_page,PAGE);
}
static void physical_data(uintptr_t address,struct li2_rseq_data *out,int expected) {
    li2_maps_phase_end();uint64_t opens=io_opens,closes=io_closes;
    need(li2_lifecycle_rseq_data(address,out)==expected && out->error==(unsigned)expected &&
         out->maps.observation.kind==LI2_MAPS_DIRECT && out->maps.observation.io_performed==1 &&
         io_opens==opens+1 && io_closes==closes+1,1204);
    physical(&out->maps);
}
static void same_identity(const struct li2_rseq_data *physical_value,
                          const struct li2_rseq_data *actual,int expected) {
    struct li2_rseq_data wanted=*physical_value;
    /* The observation is intentionally distinct. Every other byte, including
       error/partial fields, is compared without normalization. */
    wanted.maps=actual->maps;
    need(equal(&wanted,actual,sizeof wanted) &&
         same_data(physical_value,actual)==(expected==0),1205);
    ++compared;
}
static void current_data(uintptr_t address,struct li2_rseq_data *out,int expected,
                         unsigned fallback) {
    li2_maps_phase_end();uint64_t opens=io_opens,closes=io_closes,queries=mv.queries;
    uint64_t hits=mv.hits,refreshes=mv.refreshes,comparisons=mv.comparisons;
    need(np_rseq_data(address,out)==expected && out->error==(unsigned)expected &&
         !maps_current.live && !maps_current.busy && !maps_stats.active,1206);
    unsigned kind=fallback?LI2_MAPS_DIRECT:(DIFFERENTIAL?LI2_MAPS_VERIFIED:LI2_MAPS_PROJECTED);
    unsigned io=fallback?1:DIFFERENTIAL;
    need(out->maps.observation.kind==kind && out->maps.observation.io_performed==io &&
         io_opens==opens+io && io_closes==closes+io && mv.queries==queries+1 &&
         mv.hits==hits+!fallback && mv.refreshes==refreshes+fallback &&
         mv.comparisons==comparisons+(fallback?0:DIFFERENTIAL) && !mv.mismatches,1207);
    if(fallback){physical(&out->maps);++fallback_checks;}
}
static void identity_controls(const struct li2_rseq_data *value) {
    need(same_data(value,value),1208);
#define DIFFERENT(field) do {struct li2_rseq_data changed=*value;changed.field^=1; \
    need(!same_data(value,&changed) && !same_data(&changed,value),1209);++identity_refusals;} while(0)
    DIFFERENT(address);DIFFERENT(page);DIFFERENT(allocation);DIFFERENT(generation);
    DIFFERENT(offset);DIFFERENT(pid);DIFFERENT(tid);DIFFERENT(complete);DIFFERENT(error);
#undef DIFFERENT
}
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]>='0' && argv[1][0]<='4' && !argv[1][1],1210);
    mode=(unsigned)(argv[1][0]-'0');prepare_data((uintptr_t)&argc);
    uintptr_t address=data_page+64;
    struct li2_rseq_data baseline={0},observed={0},other={0};
    physical_data(address,&baseline,0);
    if(mode==0) {
        /* Each production caller ends its phase. Stable seed/refresh/refault
           observations must reuse actual mappings with honest query kinds. */
        for(unsigned i=0;i<3;i++) {
            current_data(address,&observed,0,0);same_identity(&baseline,&observed,0);
        }
        identity_controls(&observed);
        uint64_t queries=mv.queries,opens=io_opens;
        need(np_rseq_data(address,0)==LI2_RSEQ_ARGUMENT,1211);++argument_refusals;
        need(np_rseq_data(address+1,&other)==LI2_RSEQ_AREA && other.error==LI2_RSEQ_AREA &&
             !other.complete && !other.maps.observation.io_performed &&
             mv.queries==queries && io_opens==opens,1212);++argument_refusals;
    } else if(mode==1) {
        need(data_dispatch(SYS_mprotect,data_page,PROT_READ)==0,1213);
        physical_data(address,&other,LI2_RSEQ_MAPPING);
        current_data(address,&observed,LI2_RSEQ_MAPPING,0);
        same_identity(&other,&observed,LI2_RSEQ_MAPPING);++mapping_refusals;
        need(data_dispatch(SYS_mprotect,data_page,PROT_READ|PROT_WRITE)==0,1214);
        physical_data(address,&other,0);current_data(address,&observed,0,0);
        same_identity(&other,&observed,0);
        need(observed.allocation==baseline.allocation && observed.generation>baseline.generation &&
             !same_data(&baseline,&observed),1215);++generation_changes;
    } else if(mode==2) {
        uintptr_t stack_page=(uintptr_t)&argc&~(uintptr_t)(PAGE-1);
        need(!mv_stack_retired && mv_stack_first<=stack_page && stack_page+PAGE<=mv_stack_end &&
             !tracked(SYS_mprotect,stack_page,PAGE,PROT_READ|PROT_WRITE,0,0,0) &&
             mv_stack_retired && !mv.poisoned,1216);
        current_data(address,&observed,0,1);same_identity(&baseline,&observed,0);
    } else {
        li2_maps_phase_end();
        if(mode==3)need(!li2_maps_phase_begin(),1217);
        else mv_poison(); /* One named supplied-state fail-closed control. */
        uint64_t queries=mv.queries,opens=io_opens,closes=io_closes;
        need(np_rseq_data(address,&observed)==LI2_RSEQ_STATE && observed.error==LI2_RSEQ_STATE &&
             !observed.complete && !observed.maps.observation.io_performed &&
             mv.queries==queries && io_opens==opens && io_closes==closes,1218);
        ++no_io_refusals;
    }
    need(equal((const void *)data_page,data_before,PAGE),1219);
    need(!li2_decoder_stats(&decoder_after) && equal(&decoder_before,&decoder_after,sizeof decoder_before),1220);
    li2_maps_phase_end();
    /* All real permissions/borrow were already closed before these component
       observations. Even poison uses direct terminal resource cleanup only. */
    need(!kernel(SYS_munmap,data_page,PAGE,0,0,0,0) &&
         !kernel(SYS_munmap,source_page,PAGE,0,0,0,0),1221);
    need(object_count==1 && objects[0].retained_fd>=200 && objects[0].retained_fd!=source_fd &&
         !kernel(SYS_close,objects[0].retained_fd,0,0,0,0,0) &&
         !kernel(SYS_close,source_fd,0,0,0,0,0),1222);
    need(cleanup_released==1 && io_fd==-1 && io_opens==io_closes && io_eofs==io_closes &&
         io_closes==maps_stats.fresh_calls,1223);
    need(compared==(mode==0?3U:mode==1?2U:mode==2?1U:0U) &&
         identity_refusals==(mode==0?9U:0U) && argument_refusals==(mode==0?2U:0U) &&
         mapping_refusals==(mode==1) && generation_changes==(mode==1) &&
         fallback_checks==(mode==2) && no_io_refusals==(mode>=3),1224);
    printf("{\"version\":1,\"mode\":%u,\"differential\":%u,\"component_only\":1,"
        "\"compared\":%u,\"identity_refusals\":%u,\"argument_refusals\":%u,"
        "\"mapping_refusals\":%u,\"generation_changes\":%u,\"physical_fallbacks\":%u,"
        "\"no_io_refusals\":%u,\"maps_unchanged_data\":1,\"cleanup\":[2,2,1],"
        "\"io\":[%"PRIu64",%"PRIu64",%"PRIu64"]}\n",
        mode,DIFFERENTIAL,compared,identity_refusals,argument_refusals,mapping_refusals,
        generation_changes,fallback_checks,no_io_refusals,io_opens,io_closes,io_eofs);
    return 0;
}
