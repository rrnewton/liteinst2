/* Additive retained-REP native oracle. No supplied frame grants positive credit. */
#define _GNU_SOURCE
#include "repeat_lease.h"
#include "repeat_custody.h"
#include "register_run_publish.h"
static int rl_dump(void);
static int rl_sealed_elf(void);
long raw(long,long,long,long,long,long,long);
#define fixture_main unchanged_generic_fixture_main
#include "repeat_lease_support.inc"
#undef fixture_main
#include <sys/stat.h>
#define RL_CASES 3
#define RL_EVENTS 24
#define RL_DATA (4*PAGE)
#define RL_MODES 46
struct rl_snapshot {
    struct state state;
    uintptr_t uc_address,si_address;
    unsigned char uc[sizeof(ucontext_t)],si[sizeof(siginfo_t)];
    unsigned char extra[RL_DATA-DATA_BYTES];
    uint16_t selectors[6];
    int signal,code,error;
    uintptr_t address;
};
struct rl_bases { uint64_t attempted,complete,fs,gs; long fs_result,gs_result; struct li2_fetch_progress fetch; };
struct rl_view {
    uintptr_t pc,bytes_address,pages_address,backing_address,last_backing_address;
    size_t length,page_count;long pid,tid;unsigned identity_observed;
    unsigned char bytes[15];struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2],last_backing;
    struct li2_fetch_ref ref;struct li2_fetch_progress progress;
};
struct rl_observation {
    struct li2_repeat_owner repeat;
    struct li2_repeat_lease_registration registration;
    struct li2_fetch_ref borrow;
    unsigned borrow_held,return_pending,handler_returned,close_started,close_complete;
    unsigned release_started,release_complete;
    int custody_result,rseq_result,release_result;
    uint64_t attempts,completed,total_traces,total_retained,total_closes,total_releases;
    uint64_t retained_transfers,rseq_checks,write_checks,write_first,write_bytes;
    unsigned write_query_attempted;int write_result;
};
struct rl_event {
    struct rl_snapshot before,after,returned;
    struct rl_observation owner;
    struct li2_repeat_custody_observation custody_before,custody_after,custody_returned;
    struct li2_tf_continuation continuation;
    struct li2_fetch_progress fetch;
    uint64_t continuation_calls;
    int continuation_result;
    uint64_t case_index,remaining,progress,final,checked,old_route;
};
struct rl_permission {
    unsigned attempted,complete;long result;
    unsigned validate_attempted;int validate_result;
    unsigned sync_attempted;long sync_result;
};
struct rl_case {
    uintptr_t mapping,pc,next_pc;
    uint64_t width,direction,count,flags,seed[16],native_completed,native_fault,endpoint_seen;
    uint64_t started,checked,first_event,event_count,phase,geometry,view_length,eligible;
    struct li2_decoded decoded;
    struct li2_tf_classification refused;
    unsigned fallback_rseq_attempted;int fallback_rseq_result;
    struct li2_rseq_state fallback_rseq_before,fallback_rseq_after;
    struct rl_view view[2];
    struct li2_fetch_progress released[2];
    struct rl_bases bases[2][2];
    struct rl_snapshot before[2],after[2],cold,cold_returned;
    struct li2_repeat_custody_observation custody_begin,custody_ready,custody_finished;
    struct live live[4];
    unsigned char fp[4][FP_CAPACITY] __attribute__((aligned(64)));
    struct rl_permission open[2],close[2];
    struct li2_repeat_lease_owner begun,finished;
    struct li2_repeat_owner old_begun,old_finished;
};
struct rl_record {
    uint64_t magic,version,bytes,mode,pid,tid,uid,xcr0,xsave_bytes;
    uint64_t cases,completed,native_completed,native_faults,events,old_refusals,startup_pairs;
    uint64_t first_error,owner_error,owner_detail_abs,owner_detail_negative,verified_failure;
    uint64_t real_signals,supplied_mutations,injection_attempted,injection_issued,injection_returned;
    long injection_actual,injection_result;
    uint64_t nested_site,nested_owner_phase,nested_custody_phase,nested_outer_observed;
    uint64_t private_queries,private_first,private_bytes,private_result,span_supplied,injected_word;
    uintptr_t subject_address,data_address,rseq_address,marker;
    uint64_t registered,unregistered;
    struct li2_rseq_state registration_before,registration_after;
    unsigned char header[PAGE],literal[CODE_BYTES];
    struct rl_case row[RL_CASES];
    struct rl_event event[RL_EVENTS];
    struct rl_snapshot delivered,outer,mutated;
    struct li2_repeat_lease_owner terminal,clone;
    struct li2_repeat_custody_observation custody;
    struct li2_fetch_progress fetch;
    struct li2_maps_stats maps;
    struct li2_decoder_stats decoder;
    struct stat stat_actual,stat_supplied;
    uint64_t source_equal,source_closed,expected_source_pages,complete;
};
static struct rl_record rl;
static struct li2_repeat_lease_owner rl_owner;
static struct li2_repeat_owner rl_old;
static struct sample rl_source;
static struct rl_case *rl_case;
static struct rl_event *rl_event;
static unsigned rl_mode,rl_lane,rl_index,rl_gateway,rl_active,rl_phase,rl_old_route,rl_injection_armed,rl_decoder_ready;
static volatile sig_atomic_t rl_handling,rl_injected;
static int rl_fd;
static uintptr_t rl_mapping;
static unsigned char rl_header[PAGE],rl_literal[CODE_BYTES];
static siginfo_t *rl_si;static ucontext_t *rl_uc;
static int rl_contains(void *unused,uintptr_t first,size_t n) {
    (void)unused;if(!n||first>UINTPTR_MAX-n)return 0;
    for(size_t i=0;i<protected_count;i++)if(protected[i].first<=first&&first+n<=protected[i].end)return 1;
    return 0;
}
static int rl_protect(void *unused,uintptr_t first,size_t n) {
    if(rl_contains(unused,first,n))return 0;
    if(!n||first>UINTPTR_MAX-n||protected_count==128)return 1;
    protected[protected_count].first=first;protected[protected_count++].end=first+n;return 0;
}
static const struct li2_run_protection rl_protection={0,rl_protect,rl_contains};
int li2_repeat_lease_private_intersects(uintptr_t first,size_t n) {
    ++rl.private_queries;rl.private_first=first;rl.private_bytes=n;
    int answer=protected_range(first,n);rl.private_result=(unsigned)answer;return answer;
}
static int rl_is_fault(void) {return rl_mode==12||rl_mode==13;}
static int rl_is_nested(void) {return rl_mode>=14&&rl_mode<=17;}
static int rl_is_failure(void) {return rl_mode>=12;}
static int rl_is_unregistered(void) {return rl_mode==11||(rl_mode>=30&&((rl_mode-30)/8));}
static void rl_observe(struct rl_observation *x) {
    const struct li2_repeat_lease_owner *o=&rl_owner;
    x->repeat=rl_old_route?rl_old:o->repeat;x->registration=o->registration;x->borrow=o->borrow;
#define RL_COPY(f) x->f=o->f
    RL_COPY(borrow_held);RL_COPY(return_pending);RL_COPY(handler_returned);RL_COPY(close_started);RL_COPY(close_complete);
    RL_COPY(release_started);RL_COPY(release_complete);RL_COPY(custody_result);RL_COPY(rseq_result);RL_COPY(release_result);
    RL_COPY(attempts);RL_COPY(completed);RL_COPY(total_traces);RL_COPY(total_retained);RL_COPY(total_closes);RL_COPY(total_releases);
    RL_COPY(retained_transfers);RL_COPY(rseq_checks);RL_COPY(write_checks);RL_COPY(write_first);RL_COPY(write_bytes);
    RL_COPY(write_query_attempted);RL_COPY(write_result);
#undef RL_COPY
}
static void rl_snapshot(struct rl_snapshot *s,int sig,const siginfo_t *si,const ucontext_t *uc) {
    need(si&&uc,600);s->uc_address=(uintptr_t)uc;s->si_address=(uintptr_t)si;
    memcpy(s->uc,uc,sizeof(s->uc));memcpy(s->si,si,sizeof(s->si));
    s->signal=sig;s->code=si->si_code;s->error=si->si_errno;s->address=(uintptr_t)si->si_addr;
    struct li2_step_frame *f=&s->state.frame;
    memcpy(f->greg,uc->uc_mcontext.gregs,sizeof(f->greg));memcpy(&f->mask,&uc->uc_sigmask,8);
    f->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    need(f->fp_address&&!(f->fp_address&15),601);const unsigned char *p=(void *)f->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        need(n>=580&&n<=FP_CAPACITY&&x>=576&&x<=n-4&&u32(p+n-4)==UINT32_C(0x46505845),602);
    }
    f->fp_bytes=n;for(size_t i=0;i<n;i++){f->fp[i]=p[i];f->initialized=i+1;}
    memcpy(s->state.stack,(void *)subject,SUBJECT_BYTES);memcpy(s->state.data,(void *)data_page,DATA_BYTES);
    memcpy(s->extra,(void *)(data_page+DATA_BYTES),sizeof(s->extra));
    __asm__ volatile("mov %%cs,%0":"=r"(s->selectors[0]));__asm__ volatile("mov %%ss,%0":"=r"(s->selectors[1]));
    __asm__ volatile("mov %%ds,%0":"=r"(s->selectors[2]));__asm__ volatile("mov %%es,%0":"=r"(s->selectors[3]));
    __asm__ volatile("mov %%fs,%0":"=r"(s->selectors[4]));__asm__ volatile("mov %%gs,%0":"=r"(s->selectors[5]));
    /* fs/gs remain zero: no base observation is invented inside this event. */
}
static void rl_unchanged(const struct rl_snapshot *s,const siginfo_t *si,const ucontext_t *uc,uint64_t flags) {
    ucontext_t expected;memcpy(&expected,s->uc,sizeof(expected));expected.uc_mcontext.gregs[REG_EFL]=(greg_t)flags;
    need((uintptr_t)uc==s->uc_address&&(uintptr_t)si==s->si_address&&
        !memcmp(&expected,uc,sizeof(expected))&&!memcmp(si,s->si,sizeof(s->si))&&
        (uintptr_t)uc->uc_mcontext.fpregs==s->state.frame.fp_address&&
        !memcmp(uc->uc_mcontext.fpregs,s->state.frame.fp,s->state.frame.fp_bytes)&&
        !memcmp((void *)subject,s->state.stack,SUBJECT_BYTES)&&!memcmp((void *)data_page,s->state.data,DATA_BYTES)&&
        !memcmp((void *)(data_page+DATA_BYTES),s->extra,sizeof(s->extra)),603);
}
static void rl_bases(struct rl_bases *b) {
    need(!li2_lifecycle_fetch_interlock()&&!b->attempted,604);b->fetch=*li2_lifecycle_fetch_progress();b->attempted=1;
    b->fs_result=RAW(SYS_arch_prctl,ARCH_GET_FS,&b->fs,0,0,0,0);
    b->gs_result=RAW(SYS_arch_prctl,ARCH_GET_GS,&b->gs,0,0,0,0);
    need(!b->fs_result&&!b->gs_result&&!li2_lifecycle_fetch_interlock(),605);b->complete=1;
}
static unsigned char rl_byte(const struct rl_snapshot *s,size_t i) {
    return i<DATA_BYTES?s->state.data[i]:s->extra[i-DATA_BYTES];
}
static void rl_effects(const struct rl_case *r,const struct rl_snapshot *s,const struct rl_snapshot *b,uint64_t progress) {
    need(progress<=r->count,606);
    for(unsigned i=0;i<16;i++) {
        uint64_t want=r->seed[i];if(i==1)want=r->count-progress;
        if(i==7)want=r->direction?want-r->width*progress:want+r->width*progress;
        need((uint64_t)s->state.frame.greg[regs[i]]==want,607);
    }
    need(!memcmp(s->state.stack,b->state.stack,SUBJECT_BYTES),608);
    for(size_t i=0;i<RL_DATA;i++) {
        unsigned char want=rl_byte(b,i);
        for(uint64_t j=0;j<progress;j++) {
            uintptr_t address=r->direction?r->seed[7]-r->width*j:r->seed[7]+r->width*j;
            need(address>=data_page&&address<=data_page+RL_DATA-r->width,609);
            size_t at=address-data_page;if(i>=at&&i<at+r->width)want=(unsigned char)(r->seed[0]>>(8*(i-at)));
        }
        need(rl_byte(s,i)==want,610);
    }
    need(s->state.frame.fp_bytes==b->state.frame.fp_bytes&&s->state.frame.initialized==s->state.frame.fp_bytes&&
        !memcmp(s->state.frame.fp,b->state.frame.fp,s->state.frame.fp_bytes)&&s->state.frame.mask==mask&&
        s->state.frame.greg[REG_CSGSFS]==b->state.frame.greg[REG_CSGSFS]&&
        !memcmp(s->selectors,b->selectors,sizeof(s->selectors))&&!s->state.fs&&!s->state.gs,611);
}
static int rl_dump(void) {
    rl.magic=UINT64_C(0x31455341454c3252);rl.version=1;rl.bytes=sizeof(rl);rl.mode=rl_mode;
    rl.xcr0=fixture_xcr0;rl.xsave_bytes=xsave_bytes;rl.first_error=result.fixture_failure;
    rl.terminal=rl_owner;rl.custody=*li2_repeat_custody_progress();rl.fetch=*li2_lifecycle_fetch_progress();
    rl.registration_after=*li2_rseq_snapshot();li2_maps_stats_read(&rl.maps);
    if(rl_decoder_ready)(void)li2_decoder_stats(&rl.decoder);
    return write_all(3,&rl,sizeof(rl))&&write_all(3,&samples[0],sizeof(samples[0]));
}
static unsigned rl_expected(void) {
    if(rl_is_fault())return LI2_STEP_FOREIGN_EVENT;
    if(rl_is_nested())return rl_mode==15?LI2_STEP_FOREIGN_EVENT:LI2_STEP_REENTRY;
    static const unsigned values[12]={LI2_REPEAT_LEASE_STATE,LI2_REPEAT_LEASE_CUSTODY,
        LI2_REPEAT_LEASE_CUSTODY,LI2_REPEAT_LEASE_CUSTODY,LI2_REPEAT_LEASE_REGISTRATION,
        LI2_REPEAT_LEASE_REGISTRATION,LI2_REPEAT_LEASE_REGISTRATION,LI2_REPEAT_LEASE_OVERFLOW,
        LI2_STEP_REVOKE,LI2_STEP_SYNC_REVOKE,LI2_REPEAT_CONTINUATION,LI2_REPEAT_LEASE_STATE};
    return rl_mode<30?values[rl_mode-18]:((rl_mode-30)&1?LI2_REPEAT_LEASE_OVERFLOW:LI2_REPEAT_LEASE_WRITE);
}
static void rl_failure(void *context,const struct li2_step_owner *o) {
    need(context==&rl_source&&o==&rl_owner.repeat.step,612);
    rl.owner_error=o->first_error;rl.owner_detail_abs=o->first_detail<0?0ULL-(uint64_t)o->first_detail:(uint64_t)o->first_detail;
    rl.owner_detail_negative=o->first_detail<0;
    rl.source_equal=!memcmp((void *)rl_mapping,rl_literal,CODE_BYTES);rl.source_closed=1;
    for(unsigned i=0;i<3;i++)if(actual_protection(rl_mapping+i*PAGE,0)!=PROT_READ)rl.source_closed=0;
    rl.expected_source_pages=o->request.page_count;
    if(rl_is_failure()&&!result.fixture_failure&&o->phase==LI2_STEP_FAILED&&o->first_error==rl_expected()) {
        rl.verified_failure=1;need(rl_dump(),613);output("LI2_REPEAT_LEASE_EXPECTED_FAILURE\n");
    } else {(void)rl_dump();output("LI2_REPEAT_LEASE_UNEXPECTED_FAILURE\n");}
}
static void rl_nested(unsigned site) {
    if(rl.real_signals)return;
    rl.nested_site=site;rl.nested_owner_phase=rl_owner.repeat.step.phase;
    rl.nested_custody_phase=li2_repeat_custody_progress()->phase;
    need(rl_uc&&rl_si,614);rl_snapshot(&rl.outer,rl_si->si_signo,rl_si,rl_uc);rl.nested_outer_observed=1;
    ++rl.real_signals;
    (void)RAW(SYS_tgkill,session.pid,session.tid,SIGTRAP,0,0,0);need(0,615);
}
void rl_seed_observe(struct li2_repeat_lease_owner *o) {
    need(o==&rl_owner&&o->repeat.step.phase==LI2_STEP_RUNNING&&o->repeat.step.in_handler&&
        li2_repeat_custody_progress()->phase==LI2_REP_CUSTODY_SEEDING,616);
    if(rl_mode==14)rl_nested(1);
}
void rl_revoke_observe(struct li2_step_owner *o) {
    if(rl_active&&o==&rl_owner.repeat.step&&rl_mode==17&&!rl_owner.failure_started) {
        need(o->phase==LI2_STEP_REVOKING&&o->in_handler&&rl_owner.repeat.final,617);rl_nested(4);
    }
}
static struct {uint32_t version,flags;uint64_t start_ip,post_commit_offset,abort_ip;} rl_cs;
void rl_guard_observe(struct li2_repeat_lease_owner *o,const ucontext_t *context) {
    if(!rl_active||o!=&rl_owner||rl_injected)return;
    ucontext_t *uc=(ucontext_t *)(uintptr_t)context;
    if(rl_mode==22&&!o->repeat.traces) {
        rl_injected=1;++rl.supplied_mutations;rl_cs.abort_ip=(uintptr_t)fixture_capture_return;
        *(volatile uint64_t *)(rl.rseq_address+8)=(uintptr_t)&rl_cs;
        rl.injected_word=*(volatile uint64_t *)(rl.rseq_address+8);
    } else if(rl_mode==25&&o->repeat.traces==1) {
        rl_injected=1;++rl.supplied_mutations;uc->uc_mcontext.gregs[REG_RCX]=(greg_t)UINT64_MAX;
        rl_snapshot(&rl.mutated,SIGTRAP,rl_si,uc);
    }
}
int rl_release_observe(const struct li2_fetch_ref *ref) {
    if(rl_active&&rl_mode==29&&!rl_injected) {
        rl_injected=1;rl.injection_attempted=1;rl.injection_result=LI2_FETCH_STATE;
        ++rl.supplied_mutations;return LI2_FETCH_STATE;
    }
    return li2_lifecycle_fetch_release(ref);
}
long raw(long n,long a,long b,long c,long d,long e,long f) {
    if(rl_gateway)li2_maps_before_raw(n,a,b,c,d,e,f);
    int inject=rl_active&&!rl_injected&&rl_owner.repeat.step.phase==LI2_STEP_REVOKING&&
        ((rl_mode==26&&n==SYS_mprotect&&c==PROT_READ)||(rl_mode==27&&n==SYS_membarrier&&a==32));
    long answer;
    if(inject) {
        rl_injected=1;rl.injection_attempted=1;rl.injection_result=-22;++rl.supplied_mutations;answer=-22;
    } else {
        answer=fixture_kernel_raw(n,a,b,c,d,e,f);
        if(rl_active&&rl_injection_armed&&rl_mode==21&&!rl_injected&&n==SYS_fstat&&answer==0&&rl_owner.attempts) {
            rl_injected=1;++rl.supplied_mutations;rl.injection_attempted=rl.injection_issued=rl.injection_returned=1;
            rl.injection_actual=answer;rl.injection_result=answer;rl.stat_actual=*(struct stat *)b;
            ((struct stat *)b)->st_ino^=1;rl.stat_supplied=*(struct stat *)b;
        }
    }
    if(rl_gateway)li2_maps_after_raw(n,a,b,c,d,e,f,answer);
    return answer;
}
static int rl_sealed_elf(void) {
    int old=sealed_elf();need(!RAW(SYS_close,old,0,0,0,0,0),618);
    memcpy(rl_header,elf_bytes,PAGE);memset(rl_literal,0xcc,CODE_BYTES);
    Elf64_Ehdr *eh=(void *)rl_header;eh->e_phnum=2;
    Elf64_Phdr *p=(void *)(rl_header+sizeof(*eh));
    p[1]=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R|PF_X,.p_offset=PAGE,.p_vaddr=PAGE,
        .p_filesz=CODE_BYTES,.p_memsz=CODE_BYTES,.p_align=PAGE};
    /* Both widths in distinct source pages, each with an exact NX successor.
       Crossing mode uses the same one literal width per process/pair. */
    const unsigned char d[]={0xf3,0xab},q[]={0xf3,0x48,0xab};
    memcpy(rl_literal+PAGE-2,d,sizeof(d));memcpy(rl_literal+2*PAGE-3,q,sizeof(q));
    if(rl_mode==9) {
        /* One D or Q source is mapped at a time, from distinct sealed files is
           unnecessary: D and Q crossing literals occupy disjoint page edges. */
        memset(rl_literal,0xcc,CODE_BYTES);
        memcpy(rl_literal+PAGE-1,d,sizeof(d));memcpy(rl_literal+2*PAGE-2,q,sizeof(q));
    }
    long fd=RAW(SYS_memfd_create,"li2-repeat-lease-literal",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);
    need(fd>=0&&write_all((int)fd,rl_header,PAGE)&&write_all((int)fd,rl_literal,CODE_BYTES)&&
        !RAW(SYS_fcntl,fd,F_ADD_SEALS,SEALS,0,0,0),619);
    rl_fd=(int)fd;return rl_fd;
}
static void rl_prepare_source(void) {
    long area=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(area>0,620);
    rl_mapping=(uintptr_t)area+PAGE;
    if(rl_mode==8) {
        need(!dispatch(SYS_mprotect,rl_mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),621);
        memcpy((void *)rl_mapping,rl_literal,CODE_BYTES);
        need(!dispatch(SYS_mprotect,rl_mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),622);
    } else {
        need(!dispatch(SYS_munmap,rl_mapping,CODE_BYTES,0,0,0,0),623);
        long mapped=dispatch(SYS_mmap,rl_mapping,CODE_BYTES,PROT_READ|PROT_EXEC,
            MAP_PRIVATE|MAP_FIXED_NOREPLACE,rl_fd,PAGE);need(mapped==(long)rl_mapping,624);
    }
    memcpy(rl.header,rl_header,PAGE);memcpy(rl.literal,rl_literal,CODE_BYTES);
    for(unsigned i=0;i<3;i++)need(actual_protection(rl_mapping+i*PAGE,0)==PROT_READ,625);
}
static void rl_permissions(struct rl_permission *p,int prot) {
    need(!p->attempted&&rl_case,626);p->attempted=1;
    uintptr_t page=rl_case->pc&~(PAGE-1);size_t count=rl_source.count;
    p->result=RAW(SYS_mprotect,page,count*PAGE,prot,0,0,0);need(!p->result,627);
    p->validate_attempted=1;
    for(size_t i=0;i<count;i++) {
        p->validate_result=li2_lifecycle_fetch_validate(&rl_source.ref,i,prot);need(!p->validate_result,628);
    }
    p->sync_attempted=1;p->sync_result=RAW(SYS_membarrier,32,0,0,0,0,0);
    need(!p->sync_result,629);p->complete=1;
}
static int rl_continue(void *context,uintptr_t pc) {
    need(context==&rl_source&&rl_event&&!rl_event->continuation_calls,630);
    ++rl_event->continuation_calls;
    if(rl_mode==28&&!rl_injected) {
        rl_injected=1;++rl.supplied_mutations;rl.injection_attempted=1;rl.injection_result=LI2_FETCH_PAGE;
        rl_event->continuation_result=LI2_FETCH_PAGE;return LI2_FETCH_PAGE;
    }
    rl_event->continuation_result=li2_lifecycle_tf_continuation(&rl_source.ref,pc,&rl_event->continuation);
    return rl_event->continuation_result;
}
static void rl_fetch(void) {
    struct rl_case *r=rl_case;struct sample *s=&rl_source;
    size_t n=PAGE-(r->pc&(PAGE-1));if(n>15)n=15;if(rl_mode==10)n=15;
    struct li2_fetch_view actual;struct li2_fetch_view *v=&actual;
    need(!li2_lifecycle_fetch_prepare(r->pc,n,&s->ref)&&!li2_lifecycle_fetch_view(&s->ref,v),631);
    struct li2_decoded decoded;
    need(!li2_decoder_decode(r->pc,v->bytes,v->length,&decoded),632);
    if(decoded.decode_status==LI2_TRUNCATED&&n<15) {
        need(!li2_lifecycle_fetch_release(&s->ref)&&!li2_lifecycle_fetch_prepare(r->pc,15,&s->ref)&&
            !li2_lifecycle_fetch_view(&s->ref,v)&&!li2_decoder_decode(r->pc,v->bytes,v->length,&decoded),633);
    }
    need(decoded.decode_status==LI2_VALID&&decoded.kind==LI2_NONE&&
        decoded.code==(r->width==4?345:346)&&decoded.length==(r->width==4?2:3)&&decoded.next_pc==r->next_pc,634);
    if(!rl_lane)r->decoded=decoded;else need(!memcmp(&r->decoded,&decoded,sizeof(decoded)),635);
    r->view_length=v->length;s->pc=r->pc;s->mapping=r->mapping;s->length=decoded.length;s->decoded=decoded;
    s->count=((r->next_pc-1)&~(PAGE-1))==(r->pc&~(PAGE-1))?1:2;
    need(v->bytes&&v->pages&&v->backing&&v->length>=1&&v->length<=15&&
        v->page_count>=1&&v->page_count<=2,701);
    for(size_t i=0;i<s->count;i++)s->pages[i]=v->pages[i];
    memcpy(s->source,rl_literal,CODE_BYTES);
    need(v->identity_observed&&v->pid==session.pid&&v->tid==session.tid&&
        !memcmp(v->bytes,rl_literal+r->pc-r->mapping,v->length),636);
    struct rl_view *saved=&r->view[rl_lane];
    saved->pc=v->pc;saved->length=v->length;saved->page_count=v->page_count;
    saved->pid=v->pid;saved->tid=v->tid;saved->identity_observed=v->identity_observed;
    saved->bytes_address=(uintptr_t)v->bytes;saved->pages_address=(uintptr_t)v->pages;
    saved->backing_address=(uintptr_t)v->backing;saved->last_backing_address=(uintptr_t)v->last_backing;
    memcpy(saved->bytes,v->bytes,v->length);
    for(size_t i=0;i<v->page_count;i++){saved->pages[i]=v->pages[i];saved->backing[i]=v->backing[i];}
    saved->ref=s->ref;saved->progress=*li2_lifecycle_fetch_progress();
    need(!!v->last_backing==!!saved->progress.last_backing_observed,702);
    if(v->last_backing)saved->last_backing=*v->last_backing;
}
static void rl_arm(void) {
    struct rl_case *r=rl_case;struct sample *s=&rl_source;
    struct li2_step_request q={.decoded=r->decoded,.page_count=s->count,.original_flags=r->flags};
    for(size_t i=0;i<s->count;i++)q.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    int eligible=-1;need(!li2_repeat_custody_eligible(&s->ref,&q,&eligible),637);
    need(eligible==(rl_mode<8||rl_mode>=11),638);r->eligible=(unsigned)eligible;rl_old_route=!eligible;
    struct li2_tf_hooks h={{s,authenticate,rl_failure},rl_continue};
    int e;
    if(rl_old_route) {memset(&rl_old,0,sizeof(rl_old));e=li2_repeat_arm(&rl_old,&session,&h,&q);}
    else e=li2_repeat_lease_arm(&rl_owner,&session,&h,&q,&s->ref);
    need(!e,639);
    if(rl_mode==20){++rl_owner.repeat.step.request.pages[0].generation;++rl.supplied_mutations;}
    if(rl_mode==23){++rl_owner.registration.epoch;++rl.supplied_mutations;}
}
static void rl_fault_event(int sig,const siginfo_t *si,const ucontext_t *uc) {
    const greg_t *g=uc->uc_mcontext.gregs;const struct rl_case *r=rl_case;
    uintptr_t address=r->direction?r->seed[7]-3*r->width:r->seed[7]+3*r->width;
    need(sig==SIGSEGV&&si->si_signo==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
        (uintptr_t)si->si_addr==address&&(uintptr_t)g[REG_RIP]==r->pc&&g[REG_TRAPNO]==14&&
        g[REG_ERR]==7&&(uintptr_t)g[REG_CR2]==address&&(uint64_t)g[REG_RCX]==21,640);
}
static void rl_handler(int sig,siginfo_t *si,void *context) {
    ucontext_t *uc=context;need(rl_case&&si&&uc,641);
    /* Exact production order: consume the prior return ticket before rows. */
    li2_repeat_custody_boundary();li2_maps_event_boundary();
    if(rl_handling) {
        rl_snapshot(&rl.delivered,sig,si,uc);
        li2_repeat_lease_unexpected(&rl_owner,sig,si,uc);
    }
    if(rl_lane&&!rl_old_route&&rl_owner.repeat.step.phase==LI2_STEP_RUNNING&&rl_mode==15&&!rl.real_signals) {
        /* Source-proven nested delivery before owner.in_handler. Its owner's
           unexpected/nested label is retained as actually produced. */
        rl_si=si;rl_uc=uc;rl_handling=1;rl_nested(2);
    }
    rl_handling=1;rl_si=si;rl_uc=uc;
    need(!li2_maps_phase_begin(),642);
    struct rl_case *r=rl_case;greg_t *g=uc->uc_mcontext.gregs;
    uint64_t actual_mask=0;memcpy(&actual_mask,&uc->uc_sigmask,8);
    need(actual_mask==mask&&RAW(SYS_getpid,0,0,0,0,0,0)==session.pid&&
        RAW(SYS_gettid,0,0,0,0,0,0)==session.tid&&((uint64_t)g[REG_CSGSFS]&0xffff)==0x33,643);
    if(!rl_phase) {
        need(nx(sig,si,g,r->pc)&&(uint64_t)g[REG_EFL]==(r->flags|LI2_STEP_RF)&&fixture_flags==r->flags,644);
        rl_snapshot(&r->before[rl_lane],sig,si,uc);
        if(rl_lane){rl_arm();rl_injection_armed=1;}
        if(!rl_lane)rl_permissions(&r->open[0],PROT_READ|PROT_EXEC);
        else if(rl_old_route) {
            r->fallback_rseq_before=*li2_rseq_snapshot();r->fallback_rseq_attempted=1;
            r->fallback_rseq_result=li2_rseq_check_instruction(&r->decoded,uc);
            r->fallback_rseq_after=*li2_rseq_snapshot();need(!r->fallback_rseq_result,703);
            li2_repeat_begin(&rl_old,sig,si,uc);r->old_begun=rl_old;
        } else {
            if(rl_mode==24)++rl.supplied_mutations; /* Explicit violating initial seed. */
            if(rl_mode>=30) {
                unsigned k=(rl_mode-30)%8;
                if(!(k&1))g[REG_RDI]=(greg_t)(r->direction?rl.marker+2:rl.marker-2);
                else if(r->direction)g[REG_RDI]=1;else g[REG_RDI]=(greg_t)(UINTPTR_MAX-1);
                ++rl.supplied_mutations;rl.span_supplied=1;rl_snapshot(&rl.mutated,sig,si,uc);
            }
            if(rl_mode==18) {
                rl.clone=rl_owner;++rl.supplied_mutations;li2_repeat_lease_begin(&rl.clone,sig,si,uc);need(0,645);
            }
            li2_repeat_lease_begin(&rl_owner,sig,si,uc);r->begun=rl_owner;
            r->custody_begin=*li2_repeat_custody_progress();
            need(rl_owner.borrow_held&&rl_owner.return_pending&&rl_owner.begin_checked&&rl_owner.cold_seeded&&
                rl_owner.rseq_checks==2&&rl_owner.write_checks==2,646);
        }
        if(rl_lane)rl_snapshot(&r->cold,sig,si,uc);
        fixture_vector_clobber();rl_unchanged(&r->before[rl_lane],si,uc,r->flags|LI2_STEP_RF|(rl_lane?LI2_STEP_TF:0));
        rl_phase=1;
    } else if(!rl_lane&&rl_phase==1) {
        if(rl_is_fault()) {
            rl_fault_event(sig,si,uc);rl_snapshot(&r->after[0],sig,si,uc);
            need((uint64_t)g[REG_EFL]==(r->flags|LI2_STEP_RF),647);
            rl_effects(r,&r->after[0],&r->before[0],3);r->native_fault=1;++rl.native_faults;
        } else {
            if(r->geometry==2)need(sig==SIGTRAP&&si->si_signo==SIGTRAP&&si->si_code==SI_KERNEL&&!si->si_errno&&
                !si->si_addr&&g[REG_TRAPNO]==3&&!g[REG_ERR]&&(uintptr_t)g[REG_RIP]==r->next_pc+1&&
                (uintptr_t)g[REG_CR2]==r->pc&&(uint64_t)g[REG_EFL]==r->flags,648);
            else need(nx(sig,si,g,r->next_pc)&&(uintptr_t)g[REG_CR2]==r->next_pc&&
                (uint64_t)g[REG_EFL]==(r->flags|LI2_STEP_RF),649);
            rl_snapshot(&r->after[0],sig,si,uc);rl_effects(r,&r->after[0],&r->before[0],r->count);
            r->native_completed=1;++rl.native_completed;
        }
        rl_permissions(&r->close[0],PROT_READ);rl_phase=3;
        fixture_vector_clobber();rl_unchanged(&r->after[0],si,uc,(uint64_t)r->after[0].state.frame.greg[REG_EFL]);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else if(rl_lane&&rl_phase==1) {
        if(rl_is_fault()&&sig==SIGSEGV) {
            rl_fault_event(sig,si,uc);need(r->event_count&&rl_owner.retained_transfers,650);
            rl_snapshot(&rl.delivered,sig,si,uc);rl_effects(r,&rl.delivered,&r->before[1],3);
            li2_repeat_lease_unexpected(&rl_owner,sig,si,uc);
        }
        need(sig==SIGTRAP&&si->si_signo==SIGTRAP&&si->si_code==TRAP_TRACE&&!si->si_errno&&
            g[REG_TRAPNO]==1&&!g[REG_ERR]&&(uintptr_t)si->si_addr==(uintptr_t)g[REG_RIP],651);
        need(rl.events<RL_EVENTS,652);rl_event=&rl.event[rl.events++];++r->event_count;
        struct rl_event *ev=rl_event;ev->case_index=rl_index;ev->old_route=rl_old_route;
        ev->custody_before=*li2_repeat_custody_progress();rl_snapshot(&ev->before,sig,si,uc);
        ev->remaining=(uint64_t)g[REG_RCX];need(ev->remaining<=r->count,653);
        ev->progress=r->count-ev->remaining;ev->final=!ev->remaining;
        uint64_t prior=r->event_count==1?0:rl.event[rl.events-2].progress;
        need((!r->count&&r->event_count==1&&!ev->progress)||(r->count&&ev->progress>prior),654);
        need((uintptr_t)g[REG_RIP]==(ev->final?r->next_pc:r->pc)&&
            (uint64_t)g[REG_EFL]==(r->flags|LI2_STEP_TF|(ev->final?0:LI2_STEP_RF)),655);
        rl_effects(r,&ev->before,&r->before[1],ev->progress);
        if(rl_mode==19&&!rl_injected){rl_injected=1;++rl.supplied_mutations;li2_repeat_custody_boundary();}
        if(rl_old_route)li2_repeat_trace(&rl_old,sig,si,uc);else li2_repeat_lease_trace(&rl_owner,sig,si,uc);
        rl_observe(&ev->owner);ev->custody_after=*li2_repeat_custody_progress();ev->fetch=*li2_lifecycle_fetch_progress();
        rl_snapshot(&ev->after,sig,si,uc);rl_unchanged(&ev->before,si,uc,
            ev->final?r->flags:r->flags|LI2_STEP_TF|LI2_STEP_RF);
        const struct li2_repeat_owner *o=&ev->owner.repeat;
        need(!o->step.first_error&&!o->step.in_handler&&o->traces==r->event_count&&o->remaining==ev->remaining&&
            o->final==ev->final&&!memcmp(o->step.after.greg,ev->before.state.frame.greg,sizeof(o->step.after.greg))&&
            o->step.after.fp_address==ev->before.state.frame.fp_address&&
            o->step.after.fp_bytes==ev->before.state.frame.fp_bytes&&
            !memcmp(o->step.after.fp,ev->before.state.frame.fp,o->step.after.fp_bytes),656);
        if(rl_old_route)need(o->closed_cycles==r->event_count&&o->reopened_cycles==r->event_count-ev->final&&
            ev->continuation_calls==1&&!ev->continuation_result&&ev->continuation.complete,657);
        else need(o->closed_cycles==ev->final&&!o->reopened_cycles&&
            rl_owner.rseq_checks==r->event_count+2&&rl_owner.write_checks==r->event_count+2&&
            ev->continuation_calls==ev->final&&(!ev->final||(!ev->continuation_result&&ev->continuation.complete)),658);
        if(ev->final) {
            need(o->step.phase==LI2_STEP_COMPLETE,659);rl_phase=2;
            if(!rl_old_route)need(li2_repeat_lease_closed(&rl_owner)&&!rl_owner.borrow_held&&!li2_lifecycle_fetch_interlock(),660);
        } else need(o->step.phase==LI2_STEP_RUNNING&&li2_lifecycle_fetch_interlock(),661);
        fixture_vector_clobber();rl_unchanged(&ev->after,si,uc,(uint64_t)ev->after.state.frame.greg[REG_EFL]);ev->checked=1;
    } else if(rl_lane&&rl_phase==2) {
        need(nx(sig,si,g,r->next_pc)&&(uintptr_t)g[REG_CR2]==r->next_pc&&
            (uint64_t)g[REG_EFL]==(r->flags|LI2_STEP_RF),662);
        rl_snapshot(&r->after[1],sig,si,uc);rl_effects(r,&r->after[1],&r->before[1],r->count);
        r->endpoint_seen=1;rl_phase=3;
        fixture_vector_clobber();rl_unchanged(&r->after[1],si,uc,r->flags|LI2_STEP_RF);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else need(0,663);
    if(rl_lane&&!rl_old_route&&rl_owner.return_pending) {
        if(rl_mode==16&&!rl.real_signals)rl_nested(3);
        li2_repeat_lease_handler_end(&rl_owner,uc);
        if(rl_event) {
            rl_snapshot(&rl_event->returned,sig,si,uc);rl_event->custody_returned=*li2_repeat_custody_progress();
            rl_unchanged(&rl_event->after,si,uc,(uint64_t)rl_event->after.state.frame.greg[REG_EFL]);
        } else {rl_snapshot(&r->cold_returned,sig,si,uc);
            rl_unchanged(&r->cold,si,uc,r->flags|LI2_STEP_RF|LI2_STEP_TF);
            r->custody_ready=*li2_repeat_custody_progress();}
    }
    li2_maps_phase_end();rl_handling=0;rl_si=0;rl_uc=0;rl_event=0;
}
static void rl_inputs(struct rl_case *r) {
    inputs(&rl_source);
    for(size_t i=DATA_BYTES;i<RL_DATA;i++)((unsigned char *)data_page)[i]=(unsigned char)(i*17+3);
    fixture_seed[0]=UINT64_C(0x0123456789abcdef);fixture_seed[1]=r->count;
    fixture_seed[6]=data_page+1024;fixture_seed[7]=data_page+512;
    if(rl_is_fault())fixture_seed[7]=r->direction?data_page+PAGE+2*r->width:data_page+PAGE-3*r->width;
    if(rl_mode==24)fixture_seed[7]=rl.rseq_address+8;
    fixture_input_flags=UINT64_C(0x247)|(r->direction?UINT64_C(0x400):0);
    r->flags=fixture_input_flags;memcpy(r->seed,fixture_seed,sizeof(r->seed));fixture_target=r->pc;
}
static void rl_compare(struct rl_case *r) {
    need(r->native_completed&&r->endpoint_seen&&rl_phase==3&&r->event_count&&
        r->event_count<=(r->count?r->count:1),664);
    for(unsigned k=0;k<2;k++) {
        const struct rl_snapshot *a=k?&r->after[0]:&r->before[0],*b=k?&r->after[1]:&r->before[1];
        for(unsigned i=0;i<NGREG;i++) {
            if(r->geometry==2&&k&&(i==REG_RIP||i==REG_EFL||i==REG_ERR||i==REG_TRAPNO||i==REG_CR2))continue;
            need(a->state.frame.greg[i]==b->state.frame.greg[i],665);
        }
        if(r->geometry==2&&k) {
            /* Every exception-field difference is exact, not ignored. */
            need(a->signal==5&&a->code==128&&!a->error&&!a->address&&
                a->state.frame.greg[REG_RIP]==(greg_t)(r->next_pc+1)&&
                a->state.frame.greg[REG_EFL]==(greg_t)r->flags&&a->state.frame.greg[REG_ERR]==0&&
                a->state.frame.greg[REG_TRAPNO]==3&&a->state.frame.greg[REG_CR2]==(greg_t)r->pc&&
                b->signal==11&&b->code==2&&!b->error&&b->address==r->next_pc&&
                b->state.frame.greg[REG_RIP]==(greg_t)r->next_pc&&
                b->state.frame.greg[REG_EFL]==(greg_t)(r->flags|LI2_STEP_RF)&&b->state.frame.greg[REG_ERR]==21&&
                b->state.frame.greg[REG_TRAPNO]==14&&b->state.frame.greg[REG_CR2]==(greg_t)r->next_pc,666);
        }
        need(!memcmp(a->state.stack,b->state.stack,SUBJECT_BYTES)&&!memcmp(a->state.data,b->state.data,DATA_BYTES)&&
            !memcmp(a->extra,b->extra,sizeof(a->extra))&&a->state.frame.fp_bytes==b->state.frame.fp_bytes&&
            !memcmp(a->state.frame.fp,b->state.frame.fp,a->state.frame.fp_bytes)&&
            a->state.frame.mask==b->state.frame.mask&&!memcmp(a->selectors,b->selectors,sizeof(a->selectors)),667);
    }
    const struct rl_snapshot *states[]={&r->before[0],&r->after[0],&r->before[1],&r->after[1]};
    for(unsigned k=0;k<4;k++) {
        const struct live *v=&r->live[k];const struct rl_snapshot *s=states[k];
        need(v->started==1&&v->complete==1&&!v->reserved&&v->rflags==r->flags,668);
        for(unsigned i=0;i<16;i++)need(v->gpr[i]==(uint64_t)s->state.frame.greg[regs[i]],669);
        need(!memcmp(v->selectors,r->live[0].selectors,sizeof(v->selectors))&&
            !memcmp(r->fp[0],r->fp[k],xsave_bytes),670);
        need(r->bases[k/2][k%2].attempted==1&&r->bases[k/2][k%2].complete==1&&
            r->bases[k/2][k%2].fs==r->bases[0][0].fs&&r->bases[k/2][k%2].gs==r->bases[0][0].gs,671);
    }
    need(!memcmp(&r->view[0].pages,&r->view[1].pages,sizeof(r->view[0].pages))&&
        r->released[0].complete&&!r->released[0].held&&r->released[1].complete&&!r->released[1].held,672);
    if(r->eligible)need(li2_repeat_lease_closed(&r->finished)&&r->finished.repeat.traces==r->event_count&&
        r->finished.retained_transfers+1==r->event_count&&r->finished.repeat.closed_cycles==1&&
        !r->finished.repeat.reopened_cycles&&(r->count!=24||r->finished.retained_transfers>0),673);
    else need(r->old_finished.traces==r->event_count&&r->old_finished.closed_cycles==r->event_count&&
        r->old_finished.reopened_cycles+1==r->event_count&&!rl_owner.attempts&&
        !li2_repeat_custody_progress()->bound&&!li2_repeat_custody_progress()->ticket,674);
    r->checked=1;++rl.completed;
}
static void rl_case_prepare(unsigned index) {
    struct rl_case *r=&rl.row[index];rl_case=r;rl_index=index;r->mapping=rl_mapping;
    if(rl_mode<8) {
        unsigned combination=rl_mode/2;r->width=combination<2?4:8;r->direction=combination%2;
        static const unsigned counts[]={0,1,3};r->count=rl_mode&1?24:counts[index];
    } else if(rl_mode<12){r->width=index?8:4;r->direction=index;r->count=3;}
    else if(rl_is_fault()){r->width=rl_mode==12?4:8;r->direction=rl_mode==13;r->count=24;}
    else if(rl_mode>=30) {unsigned k=(rl_mode-30)%8;r->width=k<4?4:8;r->direction=(k/2)%2;r->count=3;}
    else {r->width=8;r->direction=0;r->count=3;}
    r->geometry=rl_mode==9?2:rl_mode==10?3:rl_mode==8?1:0;
    size_t n=r->width==4?2:3,edge=r->width==4?PAGE:2*PAGE;
    r->pc=rl_mapping+edge-(r->geometry==2?n-1:n);r->next_pc=r->pc+n;
    r->first_event=rl.events;
    need(!li2_decoder_tf_classify(r->pc,(void *)r->pc,n,&r->refused)&&r->refused.abi_version==1&&
        r->refused.pc==r->pc&&!r->refused.policy&&!r->refused.family&&!r->refused.flow,675);
}
static void rl_pair(unsigned index) {
    rl_case_prepare(index);struct rl_case *r=rl_case;r->started=1;current=&rl_source;
    unsigned first=rl_mode>=14?1:0;
    for(rl_lane=first;rl_lane<2;rl_lane++) {
        rl_active=0;rl_injection_armed=0;rl_old_route=rl_mode>=8&&rl_mode<=10;rl_phase=0;rl_event=0;
        if(rl_is_fault())need(!dispatch(SYS_mprotect,data_page,2*PAGE,PROT_READ|PROT_WRITE,0,0,0),676);
        rl_inputs(r);
        if(rl_is_fault())need(!dispatch(SYS_mprotect,r->direction?data_page:data_page+PAGE,PAGE,PROT_READ,0,0,0),677);
        rl_bases(&r->bases[rl_lane][0]);rl_fetch();rl_active=1;
        fixture_enter();rl_active=0;need(rl_phase==3,678);
        unsigned k=rl_lane*2;r->live[k]=fixture_live_before;r->live[k+1]=fixture_live_after;
        memcpy(r->fp[k],fixture_fp_before,xsave_bytes);memcpy(r->fp[k+1],fixture_fp_after,xsave_bytes);
        if(!rl_lane||rl_old_route)need(!li2_lifecycle_fetch_release(&rl_source.ref),679);
        else need(!li2_lifecycle_fetch_interlock()&&li2_repeat_lease_closed(&rl_owner),680);
        r->released[rl_lane]=*li2_lifecycle_fetch_progress();rl_bases(&r->bases[rl_lane][1]);
        if(rl_lane) {r->finished=rl_owner;r->old_finished=rl_old;r->custody_finished=*li2_repeat_custody_progress();}
    }
    need(!rl_is_failure(),681);rl_compare(r);
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(rl)+sizeof(samples[0])<16*1024*1024,"complete retained lease record within original bound");
    need(stack[0]==1,682);const char *const *argv=(void *)(stack+1),*const *env=argv+2;
    const char key[]="LI2_REPEAT_LEASE_MODE=";unsigned seen=0;
    for(size_t i=0;env[i];i++) {
        need(i<1024,683);size_t at=0;while(at<sizeof(key)-1&&env[i][at]==key[at])++at;
        if(at==sizeof(key)-1) {
            need(!seen++,684);const char *p=env[i]+at;unsigned v=0,n=0;
            while(*p>='0'&&*p<='9'){need(n++<2,685);v=v*10+(unsigned)(*p++-'0');}
            need(n&&! *p&&v<RL_MODES&&(n==1||env[i][at]!='0'),686);rl_mode=v;
        }
    }
    need(seen==1,687);result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PAIRS;
    setup(stack);rl_decoder_ready=1;size_t done=0,failed=0;uint32_t decoder_result=0;
    need(!li2_tf_refusal_controls(&done,&failed,&decoder_result,&refused_last)&&done==47&&failed==SIZE_MAX&&!decoder_result,688);
    rl.old_refusals=done;prepare_case(&samples[0],0);run_pair(&samples[0]);
    need(session.self_test_complete&&!li2_lifecycle_fetch_interlock(),689);rl.startup_pairs=1;
    rl.pid=(uint64_t)session.pid;rl.tid=(uint64_t)session.tid;rl.uid=(uint64_t)RAW(SYS_getuid,0,0,0,0,0,0);
    rl.subject_address=subject;rl_prepare_source();
    long area=dispatch(SYS_mmap,0,RL_DATA,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(area>0,690);data_page=(uintptr_t)area;rl.data_address=data_page;
    rl.marker=data_page+3*PAGE;need(!rl_protect(0,rl.marker,PAGE),691);
    long reg=dispatch(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reg>0,692);rl.rseq_address=(uintptr_t)reg;
    need(!li2_rseq_initialize(protected_range),693);
    long args[6]={(long)reg,32,0,UINT32_C(0x53053053),0,0},returned=-1;
    need(!li2_rseq_dispatch(args,&returned)&&!returned,694);rl.registered=1;
    if(rl_is_unregistered()) {args[2]=1;need(!li2_rseq_dispatch(args,&returned)&&!returned,695);rl.unregistered=1;}
    rl.registration_before=*li2_rseq_snapshot();
    need(!li2_repeat_custody_initialize(&rl_owner,&session,&rl_protection),696);
    rl_gateway=1;
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} a={
        rl_handler,SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL,step_restorer,mask};
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&a,0,8,0,0)&&
        !RAW(SYS_rt_sigaction,SIGSYS,&a,0,8,0,0),697);
    rl.cases=rl_mode<8?(rl_mode&1?1:3):rl_mode<12?2:1;
    for(unsigned i=0;i<rl.cases;i++)rl_pair(i);
    need(!rl_is_failure()&&rl.completed==rl.cases&&!li2_lifecycle_fetch_interlock(),698);
    rl.source_equal=!memcmp((void *)rl_mapping,rl_literal,CODE_BYTES);rl.source_closed=1;
    for(unsigned i=0;i<3;i++)if(actual_protection(rl_mapping+i*PAGE,0)!=PROT_READ)rl.source_closed=0;
    need(rl.source_equal&&rl.source_closed,699);rl.complete=1;
    need(rl_dump(),700);output("LI2_REPEAT_LEASE_PASS\n");return 0;
}
