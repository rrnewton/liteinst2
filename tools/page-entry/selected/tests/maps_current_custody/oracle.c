/* Actual lifecycle TU and real kernel mappings/I/O. The step boundary and
   session are explicitly supplied: this component executes no application
   instruction and supplies no actual TF, full-frame or runtime-range credit. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if LI2_MAPS_CURRENT_TF != 1
#error "explicit current-custody profile required"
#endif
#ifdef LI2_MAPS_DIFFERENTIAL
#define DIFFERENTIAL 1
#else
#define DIFFERENTIAL 0
#endif
enum { MAX_EVENTS=40, WORDS=80 };
enum { SETUP=1, STAGE_CURRENT, STAGE_PHYSICAL, COMMIT_CURRENT, COMMIT_PHYSICAL,
       PUBLISH_CURRENT, PUBLISH_PHYSICAL, RETURN_CURRENT, RETURN_PHYSICAL,
       BOUNDARY, DISCARD, FALLBACK, INJECT_EPOCH, INJECT_ENTRY, INJECT_MAX,
       WRONG_OLD_COMMIT, WRONG_OLD_CANCEL, WRONG_OLD_PUBLISH,
       WRONG_CURRENT_COMMIT, WRONG_CURRENT_CANCEL, WRONG_CURRENT_PUBLISH,
       WRONG_CURRENT_RETURN, WRONG_OLD_RETURN, STALE_STAGE, POISON_STAGE,
       TERMINAL };
static uint64_t events[MAX_EVENTS][WORDS];
static unsigned mode,event_count,state_injections,required_refusal,ticket_refusals;
static uintptr_t source_page;
static int source_fd=-1,io_fd=-1;
static uint64_t io_opens,io_reads,io_eofs,io_closes,io_bytes;
static unsigned cleanup_maps,cleanup_fds,cleanup_released;
static struct li2_step_owner supplied_owner;
static struct li2_step_session supplied_session;
static unsigned chain_identity;
static struct li2_custody_owner owner_key;
static struct li2_fetch_ref borrow;
static const struct li2_fetch_rx_view *stage;
static unsigned char elf[2*PAGE];
static unsigned char arena[2*1024*1024] __attribute__((aligned(64)));
static struct li2_decoder_stats decoder_before,decoder_after;
static void need(int,unsigned);
static long kernel(long n,long a,long b,long c,long d,long e,long f) {
    errno=0;long result=syscall(n,a,b,c,d,e,f);if(result==-1)result=-errno;
    if(n==SYS_openat) {
        need(result>=0 && io_fd==-1 && a==AT_FDCWD && b &&
             !memcmp((const void *)b,"/proc/self/maps",sizeof "/proc/self/maps") &&
             c==(O_RDONLY|O_CLOEXEC) && !d && !e && !f,900);
        io_fd=(int)result;++io_opens;
    } else if(n==SYS_read && a==io_fd && io_fd>=0) {
        need(result>=0,901);++io_reads;if(!result)++io_eofs;else io_bytes+=(uint64_t)result;
    } else if(n==SYS_close && a==io_fd && io_fd>=0) {
        need(!result,902);io_fd=-1;++io_closes;
    }
    return result;
}
static long tracked(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(kernel,n,a,b,c,d,e,f);
}
static void need(int yes,unsigned code) {
    if(!yes) {
        /* Failure retains the process outcome; only terminal best-effort
           resource closure follows, never another custody attempt. */
        if(source_page)(void)syscall(SYS_mprotect,source_page,PAGE,PROT_READ);
        fprintf(stderr,"current-custody fixture error %u mode %u\n",code,mode);
        _Exit(124);
    }
}
static _Noreturn void fatal(unsigned code,long detail) {
    (void)detail;need(0,10000+code);__builtin_unreachable();
}
_Noreturn void li2_decoder_abort(uint32_t reason) { fatal(20000+reason,0); }
int equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;
}
static int protected_none(uintptr_t p,size_t n) { (void)p;(void)n;return 0; }
static int authenticate(void *context,const struct li2_step_page *p,int prot) {
    need(context==&borrow && p->address==source_page,903);
    return li2_lifecycle_fetch_validate(&borrow,0,prot);
}
static void owner_failure(void *context,const struct li2_step_owner *p) {
    (void)context;(void)p;fatal(904,0);
}
static void map_words(uint64_t **out,const struct li2_fetch_map_progress *p) {
    uint64_t *v=*out;
    *v++=p->observation.acquisition_id;*v++=p->observation.handler_id;
    *v++=p->observation.mutation_epoch;*v++=p->observation.kind;
    *v++=p->observation.io_performed;*v++=p->opened;*v++=p->close_started;
    *v++=p->closed;*v++=p->bytes;*v++=p->rows;
    *out=v;
}
static void observe(unsigned op,int result) {
    need(event_count<MAX_EVENTS && result>=0,905);
    uint64_t *v=events[event_count++],*first=v;
#define PUT(x) *v++=(uint64_t)(x)
    PUT(op);PUT(result);PUT(custody_stats.phase);PUT(custody_stats.epoch);
    PUT(li2_current_custody_owned());PUT(cc.bound);
    PUT(fetch.progress.sequence);PUT(fetch.progress.held);PUT(fetch.progress.first_error);
    PUT(rx_current.stage.phase);PUT(rx_current.stage.serial);PUT(rx_current.stage.before_sequence);
    PUT(rx_current.stage.after_sequence);PUT(rx_current.stage.custody.kind);
    PUT(rx_view.phase);PUT(rx_view.serial);PUT(rx_view.before_sequence);PUT(rx_view.after_sequence);PUT(rx_view.custody.kind);
    PUT(cc.proof.epoch);PUT(cc.proof.kind);PUT(cc.proof.complete);PUT(cc.proof.consumed);PUT(cc.proof.origin_sequence);
    PUT(cc_stats.attempts);PUT(cc_stats.current_stages);PUT(cc_stats.current_seeds);PUT(cc_stats.physical_fallbacks);
    PUT(cc_stats.retained_stages);PUT(cc_stats.retained_checks);PUT(cc_stats.commits);PUT(cc_stats.cancels);PUT(cc_stats.first_error);
    PUT(custody_stats.seeds);PUT(custody_stats.retained_stages);PUT(custody_stats.retained_checks);PUT(custody_stats.commits);
    PUT(maps_stats.acquisitions);PUT(maps_stats.fresh_calls);PUT(maps_stats.handler_id);PUT(maps_stats.mutation_epoch);
    PUT(maps_stats.active);PUT(maps_stats.valid);PUT(maps_stats.poisoned);
    PUT(mv.queries);PUT(mv.hits);PUT(mv.refreshes);PUT(mv.comparisons);PUT(mv.mismatches);PUT(mv.poisoned);
    map_words(&v,&cc.proof.origin.physical);map_words(&v,&cc.proof.origin.query);
    map_words(&v,&custody.origin);
    need(v-first==WORDS,906);
#undef PUT
}
static void physical(const struct li2_fetch_map_progress *p) {
    need(p->opened==1 && p->close_started==1 && p->closed==1 && p->fd>=0 &&
         !p->last_read && !p->close_result && p->bytes && p->rows &&
         p->observation.acquisition_id && p->observation.io_performed==1 &&
         (p->observation.kind==LI2_MAPS_FRESH || p->observation.kind==LI2_MAPS_DIRECT),907);
    need(io_fd==-1 && io_opens==io_closes && io_eofs==io_closes && io_reads>=io_eofs &&
         io_closes==maps_stats.fresh_calls && io_bytes>=p->bytes,908);
}
static void decoded(uintptr_t pc) {
    need(!li2_decoder_decode(pc,(const void *)pc,15,&supplied_owner.request.decoded),909);
    const struct li2_decoded *d=&supplied_owner.request.decoded;
    need(d->abi_version==1 && d->decode_status==LI2_VALID && !d->reserved &&
         d->pc==pc && d->next_pc==pc+1 && d->length==1 && d->available==15 &&
         d->kind==LI2_NONE && d->destination==16 && d->width_bits==0 &&
         d->step_disposition==LI2_STEP_CANDIDATE && d->bytes[0]==0x90,910);
    for(unsigned i=0;i<15;i++)need(d->bytes[i]==0x90,911);
}
static void current_stage(void) {
    int r=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage);
    observe(STAGE_CURRENT,r);need(!r && stage==&rx_current.stage &&
        cc.proof.version==1 && cc.proof.complete==1 && cc.proof.consumed==1 &&
        !maps_current.live && custody_stats.phase==LI2_CUSTODY_STAGED && li2_current_custody_owned(),912);
    physical(&cc.proof.origin.physical);
    need(cc.proof.origin.query.observation.kind==(DIFFERENTIAL?LI2_MAPS_VERIFIED:LI2_MAPS_PROJECTED) &&
         cc.proof.origin.query.observation.io_performed==DIFFERENTIAL &&
         cc.proof.origin.query.observation.acquisition_id==cc.proof.origin.physical.observation.acquisition_id,913);
}
static void physical_stage(void) {
    int r=li2_lifecycle_fetch_rx_stage_custody(&borrow,fetch.pc+1,&owner_key,&stage);
    observe(STAGE_PHYSICAL,r);need(!r && stage==&rx_view &&
        (stage->custody.kind==LI2_CUSTODY_FRESH || stage->custody.kind==LI2_CUSTODY_RETAINED),914);
    physical(&custody.origin);need(custody.origin.observation.kind==LI2_MAPS_FRESH,915);
}
static void commit(unsigned current_kind,unsigned returned) {
    uint64_t before=borrow.sequence;
    int r=current_kind?li2_lifecycle_fetch_rx_commit_current_custody(&borrow,stage,&owner_key,&borrow):
        li2_lifecycle_fetch_rx_commit_custody(&borrow,stage,&owner_key,&borrow);
    observe(current_kind?COMMIT_CURRENT:COMMIT_PHYSICAL,r);
    need(!r && borrow.sequence==before+1 && fetch.progress.held==1 &&
         stage->phase==LI2_RX_COMMITTED && stage->after_sequence==borrow.sequence,916);
    decoded(stage->pc);supplied_owner.in_handler=0;
    r=current_kind?li2_lifecycle_fetch_rx_publish_current_custody(&borrow,stage,&owner_key):
        li2_lifecycle_fetch_rx_publish_custody(&borrow,stage,&owner_key);
    observe(current_kind?PUBLISH_CURRENT:PUBLISH_PHYSICAL,r);need(!r && custody_stats.phase==LI2_CUSTODY_RETURN,917);
    if(!returned)return;
    r=current_kind?li2_current_custody_return(&chain_identity):li2_page_custody_return(&chain_identity);
    observe(current_kind?RETURN_CURRENT:RETURN_PHYSICAL,r);need(!r && custody_stats.phase==LI2_CUSTODY_READY,918);
}
static void boundary(void) {
    li2_maps_phase_end();li2_maps_event_boundary();need(!li2_maps_phase_begin(),919);
    supplied_owner.in_handler=1;++owner_key.event;
    observe(BOUNDARY,0);need(custody_stats.phase==LI2_CUSTODY_ENTRY,920);
}
static void discard(void) {
    uint64_t before=custody_stats.epoch;li2_page_custody_discard(LI2_CUSTODY_MISS);
    observe(DISCARD,0);need(custody_stats.phase==LI2_CUSTODY_EMPTY &&
         custody_stats.epoch==before+1 && !li2_current_custody_owned(),921);
    need(!li2_page_custody_return(&chain_identity),922);
    supplied_owner.in_handler=1;++owner_key.event;
}
static void fallback(void) {
    int r=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage);
    observe(FALLBACK,r);need(r==LI2_MAPS_CURRENT_UNAVAILABLE && !stage && !fetch.progress.first_error &&
         custody_stats.phase==LI2_CUSTODY_ENTRY && !li2_current_custody_owned(),923);
    physical_stage();commit(0,1);
}
static void refused(unsigned op,int result,int expected) {
    observe(op,result);need(result==expected && !required_refusal,924);required_refusal=1;
}
static void ticket_controls(void) {
    struct li2_maps_current_ref ref={0};const struct li2_maps_current_view *v=0;
    need(!li2_maps_current_acquire(&ref,&v) && !li2_maps_current_validate(&ref,v),925);
    struct li2_maps_current_ref wrong=ref;wrong.serial^=1;
    need(li2_maps_current_validate(&wrong,v)==LI2_FETCH_STALE,926);++ticket_refusals;
    wrong=ref;wrong.owner=0;need(li2_maps_current_validate(&wrong,v)==LI2_FETCH_STALE,927);++ticket_refusals;
    struct li2_maps_current_view copy=*v;
    need(li2_maps_current_validate(&ref,&copy)==LI2_FETCH_STALE,928);++ticket_refusals;
    /* Named supplied-state mutations restore only their own descriptive field. */
#define CORRUPT(field) do { __typeof__(maps_current.view.field) saved=maps_current.view.field; \
    maps_current.view.field^=1;need(li2_maps_current_validate(&ref,v)==LI2_FETCH_STALE,929); \
    maps_current.view.field=saved;++ticket_refusals;++state_injections; } while(0)
    CORRUPT(version);CORRUPT(complete);CORRUPT(result);CORRUPT(detail);CORRUPT(serial);
    CORRUPT(query_serial);CORRUPT(table);CORRUPT(rows);CORRUPT(stack_first);CORRUPT(stack_end);
    CORRUPT(query.observation.acquisition_id);CORRUPT(query.observation.handler_id);
    CORRUPT(query.observation.mutation_epoch);CORRUPT(query.observation.io_performed);
    CORRUPT(query.rows);CORRUPT(physical.opened);CORRUPT(physical.closed);
    CORRUPT(physical.close_started);CORRUPT(physical.last_read);CORRUPT(physical.close_result);
    CORRUPT(physical.observation.acquisition_id);CORRUPT(physical.observation.io_performed);
#undef CORRUPT
    need(!li2_maps_current_release(&ref) && li2_maps_current_release(&ref)==LI2_FETCH_STALE,930);++ticket_refusals;
    need(!li2_maps_current_acquire(&ref,&v),931);
    need(tracked(SYS_getpid,0,0,0,0,0,0)==supplied_session.pid &&
         li2_maps_current_validate(&ref,v)==LI2_FETCH_STALE &&
         li2_maps_current_release(&ref)==LI2_FETCH_STALE,932);++ticket_refusals;
    need(!li2_maps_current_acquire(&ref,&v),933);
    struct check_error e={0};struct li2_fetch_map_progress p;
    need(!read_maps_checked(&e,&p) && li2_maps_current_validate(&ref,v)==LI2_FETCH_STALE &&
         li2_maps_current_release(&ref)==LI2_FETCH_STALE,934);++ticket_refusals;
    need(!li2_maps_current_acquire(&ref,&v),935);li2_maps_phase_end();
    need(li2_maps_current_validate(&ref,v)==LI2_FETCH_STALE &&
         li2_maps_current_release(&ref)==LI2_FETCH_STALE && !li2_maps_phase_begin(),936);++ticket_refusals;
}
static void setup(uintptr_t anchor) {
    Elf64_Ehdr *h=(void *)elf;memcpy(h->e_ident,"\177ELF\2\1\1",7);
    h->e_type=ET_DYN;h->e_machine=EM_X86_64;h->e_version=1;h->e_ehsize=sizeof *h;
    h->e_phoff=sizeof *h;h->e_phentsize=sizeof(Elf64_Phdr);h->e_phnum=2;
    Elf64_Phdr *ph=(void *)(elf+h->e_phoff);
    ph[0]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R,.p_filesz=PAGE,.p_memsz=PAGE,.p_align=PAGE};
    ph[1]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_offset=PAGE,.p_vaddr=PAGE,
        .p_filesz=PAGE,.p_memsz=PAGE,.p_align=PAGE};
    memset(elf+PAGE,0x90,PAGE);
    source_fd=(int)tracked(SYS_memfd_create,(long)"li2-current-custody",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    need(source_fd>=0,937);
    size_t at=0;while(at<sizeof elf) {
        long n=tracked(SYS_write,source_fd,(long)elf+at,sizeof elf-at,0,0,0);
        need(n>0 && (size_t)n<=sizeof elf-at,938);at+=(size_t)n;
    }
    need(!tracked(SYS_fcntl,source_fd,F_ADD_SEALS,SEALS,0,0,0),939);
    const struct li2_lifecycle_hooks actual_hooks={tracked,fatal,protected_none};
    li2_lifecycle_initialize(&source_fd,1,&actual_hooks);
    const long args[6]={0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,source_fd,PAGE};long result=0;
    need(li2_lifecycle_dispatch(SYS_mmap,args,&result)==1 && result>0,940);source_page=(uintptr_t)result;
    li2_maps_view_stack(anchor);need(!li2_maps_view_enable(),941);
    li2_maps_event_boundary();need(!li2_maps_phase_begin(),942);
    need(!li2_lifecycle_fetch_prepare(source_page,15,&borrow),943);
    need(!li2_decoder_initialize(arena,sizeof arena,&decoder_before) &&
         decoder_before.abi_version==1 && decoder_before.phase==2 &&
         !decoder_before.first_fatal_reason && !decoder_before.reserved,944);
    /* These owner/session boundary values are supplied, not genuine TF. */
    supplied_session=(struct li2_step_session){.pid=fetch.pid,.tid=fetch.tid,.initialized=1,.self_test_complete=1};
    need(!tracked(SYS_rt_sigprocmask,0,0,(long)&supplied_session.application_mask,8,0,0),945);
    supplied_owner.phase=LI2_STEP_RUNNING;supplied_owner.in_handler=1;
    supplied_owner.session=&supplied_session;supplied_owner.hooks=(struct li2_step_hooks){&borrow,authenticate,owner_failure};
    supplied_owner.request.page_count=1;supplied_owner.request.pages[0]=(struct li2_step_page){
        source_page,fetch.original[0].allocation,fetch.original[0].generation,fetch.original[0].offset,PROT_READ,PROT_READ|PROT_EXEC};
    decoded(source_page);supplied_owner.open_started[0]=1;
    supplied_owner.open_result[0]=tracked(SYS_mprotect,source_page,PAGE,PROT_READ|PROT_EXEC,0,0,0);
    need(!supplied_owner.open_result[0],946);supplied_owner.opened[0]=1;
    supplied_owner.open_sync=tracked(SYS_membarrier,32,0,0,0,0,0);need(!supplied_owner.open_sync,947);
    owner_key=(struct li2_custody_owner){&chain_identity,&supplied_owner,0,1,1};
    observe(SETUP,0);need(!custody_owner_live(&owner_key,&borrow,1),948);
}
static void exercise(void) {
    if(mode==0) {ticket_controls();current_stage();commit(1,1);boundary();current_stage();commit(1,1);return;}
    if(mode==1) {
        current_stage();commit(1,1);discard();physical_stage();commit(0,1);
        boundary();fallback();discard();current_stage();commit(1,1);return;
    }
    if(mode==2) {physical_stage();commit(0,1);boundary();fallback();return;}
    if(mode==3) {
        current_stage();commit(1,1);boundary();++custody_stats.epoch;++state_injections;observe(INJECT_EPOCH,0);
        int r=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage);
        refused(STALE_STAGE,r,LI2_FETCH_STATE);return;
    }
    if(mode==4) {
        custody_stats.phase=LI2_CUSTODY_ENTRY;++state_injections;observe(INJECT_ENTRY,0);
        int r=li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage);
        refused(STALE_STAGE,r,LI2_FETCH_STATE);return;
    }
    if(mode>=5 && mode<=7) {
        current_stage();int r;
        if(mode==5)r=li2_lifecycle_fetch_rx_commit_custody(&borrow,stage,&owner_key,&borrow);
        else if(mode==6)r=li2_lifecycle_fetch_rx_cancel(&borrow,stage);
        else {supplied_owner.in_handler=0;r=li2_lifecycle_fetch_rx_publish_custody(&borrow,stage,&owner_key);}
        refused(WRONG_OLD_COMMIT+mode-5,r,LI2_FETCH_STALE);return;
    }
    if(mode>=8 && mode<=10) {
        physical_stage();int r;
        if(mode==8)r=li2_lifecycle_fetch_rx_commit_current_custody(&borrow,stage,&owner_key,&borrow);
        else if(mode==9)r=li2_lifecycle_fetch_rx_cancel_current_custody(&borrow,stage);
        else {supplied_owner.in_handler=0;r=li2_lifecycle_fetch_rx_publish_current_custody(&borrow,stage,&owner_key);}
        refused(WRONG_CURRENT_COMMIT+mode-8,r,LI2_FETCH_STALE);return;
    }
    if(mode==11) {physical_stage();commit(0,0);refused(WRONG_CURRENT_RETURN,li2_current_custody_return(&chain_identity),LI2_FETCH_STATE);return;}
    if(mode==12) {current_stage();commit(1,0);refused(WRONG_OLD_RETURN,li2_page_custody_return(&chain_identity),LI2_FETCH_STATE);return;}
    need(mode==13,949);current_stage();commit(1,1);
    custody_stats.epoch=UINT64_MAX;++state_injections;observe(INJECT_MAX,0);
    li2_page_custody_discard(LI2_CUSTODY_MISS);observe(DISCARD,0);
    need(custody_stats.phase==LI2_CUSTODY_POISONED && custody_stats.epoch==UINT64_MAX,950);
    supplied_owner.in_handler=1;++owner_key.event;
    refused(POISON_STAGE,li2_lifecycle_fetch_rx_stage_current_custody(&borrow,fetch.pc+1,&owner_key,&stage),LI2_FETCH_STATE);
}
static void cleanup(void) {
    li2_page_custody_discard(LI2_CUSTODY_RELEASE);
    need(!tracked(SYS_mprotect,source_page,PAGE,PROT_READ,0,0,0) &&
         !tracked(SYS_membarrier,32,0,0,0,0,0),951);
    need(equal((const void *)source_page,elf+PAGE,PAGE),952);
    if(!required_refusal) {
        need(!li2_lifecycle_fetch_release(&borrow) && !fetch.progress.held,953);cleanup_released=1;
    }
    /* A failed fetch remains failed/held in its retained prefix. Actual RX is
       revoked and resources close terminally; no fake release is recorded. */
    li2_maps_phase_end();
    need(!kernel(SYS_munmap,source_page,PAGE,0,0,0,0),954);source_page=0;++cleanup_maps;
    need(object_count==1 && objects[0].retained_fd>=200 && objects[0].retained_fd!=source_fd,955);
    need(!kernel(SYS_close,objects[0].retained_fd,0,0,0,0,0),956);++cleanup_fds;
    need(!kernel(SYS_close,source_fd,0,0,0,0,0),957);source_fd=-1;++cleanup_fds;
}
int main(int argc,char **argv) {
    need(argc==2 && argv[1][0]>='0' && argv[1][0]<='9',958);
    unsigned n=0;for(unsigned i=0;argv[1][i];i++) {need(i<2 && argv[1][i]>='0' && argv[1][i]<='9',959);n=n*10+(unsigned)(argv[1][i]-'0');}
    need(n<14 && (n>=10 || !argv[1][1]),960);mode=n;
    setup((uintptr_t)&argc);exercise();observe(TERMINAL,0);
    need(required_refusal==(mode>=3),961);
    need(!li2_decoder_stats(&decoder_after) && equal(&decoder_before,&decoder_after,sizeof decoder_before),962);
    uint64_t actual_fresh=maps_stats.fresh_calls;need(actual_fresh==io_closes && io_opens==io_closes && io_eofs==io_closes,963);
    cleanup();
    need(io_fd==-1 && io_opens==io_closes && io_eofs==io_closes && io_closes==maps_stats.fresh_calls,964);
    printf("{\"version\":1,\"mode\":%u,\"differential\":%u,\"component_only\":1,\"supplied_boundary\":1,\"required_refusal\":%u,\"state_injections\":%u,\"ticket_refusals\":%u,\"cleanup\":[%u,%u,%u,%"PRIu64"],\"decoder\":[%u,%u,%u,%u,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"],\"io\":[%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"],\"events\":[",
        mode,DIFFERENTIAL,required_refusal,state_injections,ticket_refusals,cleanup_maps,cleanup_fds,cleanup_released,maps_stats.fresh_calls,
        decoder_after.abi_version,decoder_after.phase,decoder_after.first_fatal_reason,decoder_after.reserved,
        decoder_after.arena_bytes,decoder_after.retained_high_water,decoder_after.allocation_calls,decoder_after.deallocation_calls,
        io_opens,io_reads,io_eofs,io_closes,io_bytes);
    for(unsigned i=0;i<event_count;i++) {printf("%s[",i?",":"");for(unsigned j=0;j<WORDS;j++)printf("%s%"PRIu64,j?",":"",events[i][j]);printf("]");}
    printf("]}\n");return required_refusal?125:0;
}
