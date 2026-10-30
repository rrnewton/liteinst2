/* Actual lifecycle-TU companion; the original fourteen cases remain exact.
   Session/event boundaries are supplied as in that donor, never genuine TF. */
#define main original_current_custody_main
#include "../maps_current_custody/oracle.c"
#undef main
static uint64_t witness[24];
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]>='0' && argv[1][0]<='2' && !argv[1][1],1100);
    unsigned which=(unsigned)(argv[1][0]-'0');mode=which;
    setup((uintptr_t)&argc);
    uintptr_t stack_page=(uintptr_t)&argc&~(uintptr_t)(PAGE-1);
    need(mv_stack_first<=stack_page && stack_page+PAGE<=mv_stack_end && !mv_stack_retired,1101);
    need(!tracked(SYS_mprotect,stack_page,PAGE,PROT_READ|PROT_WRITE,0,0,0),1102);
    need(mv_stack_retired && !mv.poisoned && !maps_stats.poisoned,1103);
    /* No private cache/session/epoch injection: actual stack overlap retired
       the view. The real current API must report unavailable, not a hit. */
    int result=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage);
    need(result==LI2_MAPS_CURRENT_UNAVAILABLE && !stage && !fetch.progress.first_error &&
         !li2_current_custody_owned() && custody_stats.phase==LI2_CUSTODY_EMPTY,1104);
    witness[0]=which;witness[1]=DIFFERENTIAL;witness[2]=1;witness[3]=(uint64_t)result;
    physical_stage();
    uint64_t epoch=custody_stats.epoch,acquisition=maps_stats.acquisitions;
    uint64_t opens=io_opens,closed=io_closes,queries=mv.queries,hits=mv.hits,comparisons=mv.comparisons;
    uint64_t sequence=borrow.sequence;
    need(cc_physical_refresh() && rx_view.custody.kind==LI2_CUSTODY_FRESH &&
         rx_view.maps.observation.io_performed==1,1105);
    witness[4]=epoch;witness[5]=acquisition;witness[6]=opens;witness[7]=closed;
    witness[8]=queries;witness[9]=hits;witness[10]=comparisons;witness[11]=sequence;
    if(which) {
        if(which==1)li2_page_custody_discard(LI2_CUSTODY_MISS);
        else need(tracked(SYS_getuid,0,0,0,0,0,0)>=0,1106);
        need(!cc_physical_refresh() && custody_stats.epoch>epoch &&
             custody_stats.phase==LI2_CUSTODY_EMPTY,1107);
        result=li2_lifecycle_fetch_rx_commit_custody(&borrow,stage,&owner_key,&borrow);
        need(result==LI2_FETCH_STALE && fetch.progress.first_error==LI2_FETCH_STALE &&
             borrow.sequence==sequence && io_opens==opens && io_closes==closed &&
             maps_stats.acquisitions==acquisition && mv.queries==queries,1108);
        required_refusal=1;
    } else {
        commit(0,1);
        need(custody_stats.epoch==epoch && custody_stats.phase==LI2_CUSTODY_READY &&
             borrow.sequence==sequence+1 && maps_stats.acquisitions==acquisition+1 &&
             io_opens==opens+1 && io_closes==closed+1 && mv.queries==queries+1 &&
             mv.hits==hits && mv.comparisons==comparisons && mv_stack_retired &&
             !mv_custody_io && !mv_observer_active && mv_observer_phase==3 &&
             stage->maps.observation.acquisition_id==acquisition &&
             stage->maps.observation.kind==LI2_MAPS_FRESH && stage->maps.observation.io_performed==1,1109);
        /* Actual next supplied boundary still consumes the old retained owner.
           Its API performs backing/source checks; it creates no maps receipt. */
        boundary();fallback();
        need(custody_stats.phase==LI2_CUSTODY_READY && custody_stats.epoch==epoch &&
             custody_stats.seeds==1 && custody_stats.commits==2 &&
             custody_stats.retained_stages==1 && custody_stats.retained_checks==2 &&
             borrow.sequence==sequence+2 && io_opens==opens+1 && io_closes==closed+1 &&
             mv.queries==queries+1 && mv.hits==hits && mv.comparisons==comparisons &&
             mv_stack_retired && stage->custody.kind==LI2_CUSTODY_RETAINED,1110);
        result=(int)events[event_count-1][1]; /* actual old return result */
    }
    witness[12]=(uint64_t)result;witness[13]=custody_stats.epoch;
    witness[14]=maps_stats.acquisitions;witness[15]=io_opens;witness[16]=io_closes;
    witness[17]=mv.queries;witness[18]=mv.hits;witness[19]=mv.comparisons;
    witness[20]=borrow.sequence;witness[21]=custody_stats.phase;
    witness[22]=mv_stack_retired;witness[23]=fetch.progress.first_error;
    need(!li2_decoder_stats(&decoder_after) && equal(&decoder_before,&decoder_after,sizeof decoder_before),1111);
    cleanup();
    need(io_fd==-1 && io_opens==io_closes && io_eofs==io_closes &&
         io_closes==maps_stats.fresh_calls && cleanup_maps==1 && cleanup_fds==2 &&
         cleanup_released==(which==0),1112);
    printf("{\"version\":1,\"component_only\":1,\"supplied_boundary\":1,\"values\":[");
    for(unsigned i=0;i<24;i++)printf("%s%"PRIu64,i?",":"",witness[i]);
    printf("],\"cleanup\":[%u,%u,%u],\"io\":[%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"]}\n",
        cleanup_maps,cleanup_fds,cleanup_released,io_opens,io_reads,io_eofs,io_closes,io_bytes);
    return required_refusal?125:0;
}
