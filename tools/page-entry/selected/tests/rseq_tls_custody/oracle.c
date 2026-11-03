/* Actual loader/rseq implementations and real kernel calls. The step/session
   boundary and private registry are supplied component inputs, not bridge proof. */
#include "loader.inc"
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef LI2_MAPS_CURRENT_TF
#define CURRENT 1
#else
#define CURRENT 0
#endif
#ifdef LI2_MAPS_DIFFERENTIAL
#define DIFFERENTIAL 1
#else
#define DIFFERENTIAL 0
#endif
static unsigned mode,required_refusal;
static uintptr_t source_page,denied_byte;
static unsigned deny_all,private_result=1,tls_calls,predicate_refusals;
static int source_fd=-1,io_fd=-1;
static uint64_t io_opens,io_reads,io_eofs,io_closes,io_bytes;
static struct li2_step_owner supplied_owner;
static struct li2_step_session supplied_session;
static unsigned chain_identity;
static struct li2_custody_owner owner_key;
static struct li2_fetch_ref borrow;
static const struct li2_fetch_rx_view *stage;
static unsigned char elf[2*PAGE];
static unsigned char arena[2*1024*1024] __attribute__((aligned(64)));
static struct li2_decoder_stats decoder_before,decoder_after;
static struct li2_rseq_state *actual_state;
static uint64_t wrong_output;
static void need(int,unsigned);
#include "support.inc"
static int registry(uintptr_t first,size_t bytes) {
    uintptr_t at=(uintptr_t)actual_state;
    if(!actual_state || !bytes || first>UINTPTR_MAX-bytes || first<at ||
       first+bytes>at+sizeof *actual_state || deny_all ||
       (denied_byte && first<=denied_byte && denied_byte<first+bytes))return 0;
    return (int)private_result;
}
static void no_match(long n,long a,long b,long c,long d,long e,long f) {
    need(!li2_rseq_tls_observer(n,a,b,c,d,e,f),1300);++predicate_refusals;
}
static void predicate_controls(long n,long a,long b) {
    need(li2_rseq_tls_observer(n,a,b,0,0,0,0),1301);
    no_match(SYS_getpid,a,b,0,0,0,0);
    no_match(n,ARCH_GET_GS,b,0,0,0,0);
    no_match(n,a,(long)&actual_state->gs_base,0,0,0,0);
    no_match(n,a,b+1,0,0,0,0);
    no_match(n,a,b,1,0,0,0);no_match(n,a,b,0,1,0,0);
    no_match(n,a,b,0,0,1,0);no_match(n,a,b,0,0,0,1);
    for(unsigned i=0;i<8;i++){denied_byte=(uintptr_t)b+i;no_match(n,a,b,0,0,0,0);denied_byte=0;}
    unsigned saved=actual_state->initialized;actual_state->initialized=0;
    no_match(n,a,b,0,0,0,0);actual_state->initialized=saved;
    saved=actual_state->first_error;actual_state->first_error=LI2_RSEQ_STATE;
    no_match(n,a,b,0,0,0,0);actual_state->first_error=saved;
    deny_all=1;no_match(n,a,b,0,0,0,0);deny_all=0;
    private_result=2;no_match(n,a,b,0,0,0,0);private_result=1;
    need(li2_rseq_tls_observer(n,a,b,0,0,0,0),1302);
}
long raw(long n,long a,long b,long c,long d,long e,long f) {
    if(n==SYS_arch_prctl && (a==ARCH_GET_FS || a==ARCH_GET_GS)) {
        need(tls_calls<2 && a==(tls_calls?ARCH_GET_GS:ARCH_GET_FS) &&
             b==(long)(tls_calls?&actual_state->gs_base:&actual_state->fs_base) &&
             !c&&!d&&!e&&!f,1303);
        if(!tls_calls && mode==0)predicate_controls(n,a,b);
        if(!tls_calls) {
            if(mode==3)b=(long)&wrong_output;
            if(mode==4)denied_byte=(uintptr_t)b+7;
            if(mode==5)c=1;
            if(mode==8)b=0;
            if(mode==9)a=ARCH_GET_GS;
        }
        int matched=li2_rseq_tls_observer(n,a,b,c,d,e,f);
        need(matched==!(tls_calls==0 && (mode==3||mode==4||mode==5||mode==8||mode==9)),1304);
        ++tls_calls;
        long result=tracked(n,a,b,c,d,e,f);denied_byte=0;
        need(result==(mode==8&&tls_calls==1?-EFAULT:0),1305);
        return result;
    }
    return tracked(n,a,b,c,d,e,f);
}
static void stage_actual(uintptr_t pc) {
    int e;
#ifdef LI2_MAPS_CURRENT_TF
    e=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,pc,&owner_key,&stage);
    need(!e && stage==&rx_current.stage && stage->custody.kind==LI2_CUSTODY_CURRENT_SEED &&
         cc.proof.complete && cc.proof.consumed && !maps_current.live,1306);
#else
    e=li2_lifecycle_fetch_rx_stage_custody(&borrow,pc,&owner_key,&stage);
    need(!e && stage==&rx_view && stage->custody.kind==LI2_CUSTODY_FRESH,1307);
#endif
    need(stage->phase==LI2_RX_STAGED && stage->complete && !stage->result &&
         stage->before_sequence==borrow.sequence && custody_stats.phase==LI2_CUSTODY_STAGED &&
         stage->length==(mode==1?13U:15U),1308);
}
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]>='0'&&argv[1][0]<='9'&&!argv[1][1],1309);
    mode=(unsigned)(argv[1][0]-'0');actual_state=(struct li2_rseq_state *)li2_rseq_snapshot();
    setup((uintptr_t)&argc);
    need(!li2_rseq_initialize(registry) && actual_state->initialized==1 &&
         !actual_state->registered && !actual_state->first_error,1310);
    stage_actual(source_page+(mode==1?PAGE-13:1));
    uint64_t epoch=custody_stats.epoch,sequence=borrow.sequence;
    struct li2_decoded next={0};ucontext_t uc={0};
    need(!li2_decoder_decode(stage->pc,stage->bytes,stage->length,&next) &&
         next.decode_status==LI2_VALID && next.length==1 && next.bytes[0]==0x90,1311);
    uc.uc_mcontext.gregs[REG_RIP]=(greg_t)stage->pc;
    /* The actual invalidator advances the epoch and retires the staged
       authority; retain its failed prefix instead of repairing test state. */
    if(mode==6)li2_page_custody_discard(LI2_CUSTODY_EVENT);
    int guard=li2_rseq_check_instruction(&next,&uc);
    need(tls_calls==2 && guard==(mode==8?LI2_RSEQ_TLS:0) &&
         actual_state->instruction_checks==1 && actual_state->tls_attempted==1 &&
         actual_state->tls_complete==(mode!=8) && actual_state->fs_result==(mode==8?-EFAULT:0) &&
         !actual_state->gs_result,1312);
    if(mode==0) {
        no_match(SYS_arch_prctl,ARCH_GET_FS,(long)&actual_state->fs_base,0,0,0,0);
        no_match(SYS_arch_prctl,ARCH_GET_GS,(long)&actual_state->gs_base,0,0,0,0);
    }
    if(mode==2)need(!tracked(SYS_arch_prctl,ARCH_GET_FS,(long)&actual_state->fs_base,0,0,0,0),1313);
    if(mode==7)need(!tracked(SYS_mprotect,source_page,PAGE,PROT_READ|PROT_EXEC,0,0,0),1314);
    int commit=-1;
    if(mode!=8) {
#ifdef LI2_MAPS_CURRENT_TF
        commit=li2_lifecycle_fetch_rx_commit_current_custody(&borrow,stage,&owner_key,&borrow);
#else
        commit=li2_lifecycle_fetch_rx_commit_custody(&borrow,stage,&owner_key,&borrow);
#endif
        need(commit==(mode<=1?0:LI2_FETCH_STALE),1315);
    }
    if(mode<=1) {
        need(custody_stats.epoch==epoch && custody_stats.phase==LI2_CUSTODY_COMMITTED &&
             borrow.sequence==sequence+1 && fetch.progress.held && !fetch.progress.first_error &&
             stage->after_sequence==borrow.sequence,1316);
        supplied_owner.request.decoded=next;supplied_owner.in_handler=0;
#ifdef LI2_MAPS_CURRENT_TF
        need(!li2_lifecycle_fetch_rx_publish_current_custody(&borrow,stage,&owner_key) &&
             !li2_current_custody_return(&chain_identity),1317);
#else
        need(!li2_lifecycle_fetch_rx_publish_custody(&borrow,stage,&owner_key) &&
             !li2_page_custody_return(&chain_identity),1318);
#endif
        need(custody_stats.phase==LI2_CUSTODY_READY,1319);
    } else {
        required_refusal=1;
        need(custody_stats.epoch>epoch && custody_stats.phase==LI2_CUSTODY_EMPTY &&
             borrow.sequence==sequence && fetch.progress.held &&
             fetch.progress.first_error==(mode==8?0U:LI2_FETCH_STALE),1320);
    }
    need(predicate_refusals==(mode==0?22U:0U) &&
         !li2_decoder_stats(&decoder_after) && equal(&decoder_before,&decoder_after,sizeof decoder_before),1321);
    li2_page_custody_discard(LI2_CUSTODY_RELEASE);
    need(!tracked(SYS_mprotect,source_page,PAGE,PROT_READ,0,0,0) &&
         !tracked(SYS_membarrier,32,0,0,0,0,0) && equal((void *)source_page,elf+PAGE,PAGE),1322);
    if(!required_refusal)need(!li2_lifecycle_fetch_release(&borrow)&&!fetch.progress.held,1323);
    li2_maps_phase_end();
    need(!kernel(SYS_munmap,source_page,PAGE,0,0,0,0) && object_count==1 &&
         !kernel(SYS_close,objects[0].retained_fd,0,0,0,0,0) &&
         !kernel(SYS_close,source_fd,0,0,0,0,0) && io_fd==-1 &&
         io_opens==io_closes&&io_eofs==io_closes&&io_closes==maps_stats.fresh_calls,1324);
    printf("{\"version\":1,\"mode\":%u,\"current\":%u,\"differential\":%u,\"component_only\":1,"
        "\"supplied_boundary\":1,\"tls_calls\":%u,\"predicate_refusals\":%u,\"guard\":%d,"
        "\"commit\":%d,\"required_refusal\":%u,\"cleanup\":[1,2,%u]}\n",
        mode,CURRENT,DIFFERENTIAL,tls_calls,predicate_refusals,guard,commit,required_refusal,!required_refusal);
    return required_refusal?125:0;
}
