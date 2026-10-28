/* Finite three-lane original-address programs. The native lane opens a fixed
   literal source palette; reference/chain use actual lifecycle instruction
   borrows. This fixture does not establish arbitrary code-entry authority. */
static int chain_dump(void);
static int chain_sealed_elf(void);
long raw(long,long,long,long,long,long,long);
#define fixture_main unchanged_generic_fixture_main
#include "chain_support.inc"
#undef fixture_main
#include "tf_chain.h"
#include "maps_phase.h"
#include "cases.h"
#include <errno.h>

struct chain_event {
    struct state actual;
    struct li2_decoded decoded;
    struct li2_fetch_progress fetch;
    struct li2_tf_continuation query;
    uint64_t ordinal,pc,flags;
    int signal,code,error;
    uintptr_t address;
    unsigned origin,owner_phase,owner_error,open,opened,revoke,revoked;
    unsigned trace,release_started,release_complete,result;
};
struct chain_lane {
    struct state before,after;
    struct live live[2];
    unsigned char fp[2][FP_CAPACITY] __attribute__((aligned(64)));
    struct chain_event events[CHAIN_EVENTS];
    unsigned event_count,started,complete,fault,checked,nx,traces,selected,old;
    unsigned returns,completed_instructions,call_return_checked;
    uint64_t flags,attempts_before,steps_before,entries_before,fallbacks_before;
};
struct chain_record {
    uint64_t magic,version,header_bytes,record_bytes,case_id,mode;
    uint64_t xcr0,xsave_bytes,refusals,route_controls,completed_lanes;
    uint64_t fixture_failure,owner_failure,detail_abs,detail_negative,verified_failure;
    uintptr_t mapping,pc,stop,callee;
    unsigned char source[CODE_BYTES];
    struct chain_lane lanes[3];
    struct li2_tf_chain chain;
    struct li2_tf_owner reference;
    struct li2_step_owner old_owner;
    struct li2_tf_continuation reference_query;
    struct li2_fetch_progress final_fetch;
    struct li2_decoder_stats initial_stats,final_stats;
};
static struct chain_record li2_chain_record;
static struct sample ref_source;
static struct li2_fetch_ref active_ref;
static struct li2_fetch_view active_view;
static struct li2_decoded active_decoded;
static struct chain_event *event;
static unsigned case_id,mode,which,reference_pending,old_pending;
static volatile sig_atomic_t chain_handling;
static int program_fd=-1;
static unsigned char program_image[CODE_BYTES];
static siginfo_t *active_info;
static ucontext_t *active_context;
static uint64_t logical_flags;
int li2_trace_route_controls(size_t *);
static _Noreturn void chain_expected(unsigned,long);
static long chain_control_raw(long,long,long,long,long,long,long);
static void chain_control_before_entry(void);
static void chain_control_event(int,siginfo_t *,ucontext_t *);
static void chain_control_inputs(void);
static int chain_control_dump(void);

long raw(long n,long a,long b,long c,long d,long e,long f) {
    return chain_control_raw(n,a,b,c,d,e,f);
}
static struct chain_lane *active_lane(void) {return &li2_chain_record.lanes[which];}
static int chain_dump(void) {
    li2_chain_record.magic=UINT64_C(0x314e48434649324c);li2_chain_record.version=1;
    li2_chain_record.header_bytes=offsetof(struct chain_record,source);li2_chain_record.record_bytes=sizeof li2_chain_record;
    li2_chain_record.xcr0=fixture_xcr0;li2_chain_record.xsave_bytes=xsave_bytes;li2_chain_record.fixture_failure=result.fixture_failure;
    li2_chain_record.owner_failure=result.owner_failure;li2_chain_record.detail_abs=result.owner_detail_abs;li2_chain_record.detail_negative=result.owner_detail_negative;
    li2_chain_record.final_fetch=*li2_lifecycle_fetch_progress();
    return write_all(3,&li2_chain_record,sizeof li2_chain_record)&&write_all(3,&samples[0],sizeof samples[0])&&chain_control_dump();
}
static void chain_failure(const struct li2_tf_chain *c) {
    result.owner_failure=c->first_error;result.owner_detail_abs=c->first_detail<0?0ULL-(uint64_t)c->first_detail:(uint64_t)c->first_detail;
    result.owner_detail_negative=c->first_detail<0;
    if(mode)chain_expected(c->first_error,c->first_detail);
    (void)chain_dump();output("LI2_CHAIN_UNEXPECTED_FAILURE\n");
}
static void reference_failure(void *context,const struct li2_step_owner *o) {
    (void)context;result.owner_failure=o->first_error;
    result.owner_detail_abs=o->first_detail<0?0ULL-(uint64_t)o->first_detail:(uint64_t)o->first_detail;
    result.owner_detail_negative=o->first_detail<0;
    if(mode)chain_expected(o->first_error,o->first_detail);
    (void)chain_dump();output("LI2_CHAIN_UNEXPECTED_REFERENCE_FAILURE\n");
}
static int reference_continue(void *context,uintptr_t pc) {
    (void)context;return li2_lifecycle_tf_continuation(&active_ref,pc,&li2_chain_record.reference_query);
}
static int reference_authenticate(void *context,const struct li2_step_page *p,int prot) {
    (void)context;
    for(size_t i=0;i<active_view.page_count;i++) {
        const struct li2_fetch_page *q=&active_view.pages[i];
        if(p->address==q->address&&p->object==q->allocation&&p->generation==q->generation&&p->offset==q->offset)
            return li2_lifecycle_fetch_validate(&active_ref,i,prot);
    }
    return LI2_FETCH_STALE;
}
static void release_actual(void) {
    need(!li2_lifecycle_fetch_release(&active_ref),302);
    need(!li2_lifecycle_fetch_progress()->held&&!li2_lifecycle_fetch_progress()->first_error,303);
}
static void source_closed(void) {
    need(!memcmp((void *)li2_chain_record.mapping,li2_chain_record.source,CODE_BYTES),304);
    for(unsigned i=0;i<3;i++)need(actual_protection(li2_chain_record.mapping+i*PAGE,0)==PROT_READ,305);
}
static void native_permissions(int prot) {
    unsigned bits=chain_cases[case_id].open_mask;
    for(unsigned i=0;i<3;i++)if(bits&(1U<<i))
        need(!RAW(SYS_mprotect,li2_chain_record.mapping+i*PAGE,PAGE,prot,0,0,0),306);
    need(!RAW(SYS_membarrier,32,0,0,0,0,0),307);
}
static void fetch_actual(uintptr_t pc) {
    size_t count=PAGE-(pc&(PAGE-1));if(count>15)count=15;
    need(!li2_lifecycle_fetch_prepare(pc,count,&active_ref),308);
    need(!li2_lifecycle_fetch_view(&active_ref,&active_view),309);
    need(!li2_decoder_decode(pc,active_view.bytes,active_view.length,&active_decoded),310);
    if(active_decoded.decode_status==LI2_TRUNCATED&&count<15) {
        release_actual();need(!li2_lifecycle_fetch_prepare(pc,15,&active_ref),311);
        need(!li2_lifecycle_fetch_view(&active_ref,&active_view),312);
        need(!li2_decoder_decode(pc,active_view.bytes,active_view.length,&active_decoded),313);
    }
    need(active_decoded.decode_status==LI2_VALID&&active_decoded.length&&active_decoded.length<=active_view.length,314);
}
static struct li2_step_request request_actual(void) {
    struct li2_step_request r={.decoded=active_decoded,.original_flags=logical_flags};
    r.page_count=((active_decoded.pc^(active_decoded.next_pc-1))&~(PAGE-1))?2:1;
    need(r.page_count<=active_view.page_count,315);
    for(size_t i=0;i<r.page_count;i++) {
        const struct li2_fetch_page *p=&active_view.pages[i];
        r.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    return r;
}
static void event_owner(const struct li2_tf_owner *o,const struct li2_tf_continuation *q,
                        unsigned released) {
    event->decoded=o->step.request.decoded;event->query=*q;
    event->owner_phase=o->step.phase;event->owner_error=o->step.first_error;
    event->open=o->step.open_started[0]|(o->step.open_started[1]<<1);
    event->opened=o->step.opened[0]|(o->step.opened[1]<<1);
    event->revoke=o->step.revoke_started[0]|(o->step.revoke_started[1]<<1);
    event->revoked=o->step.revoked[0]|(o->step.revoked[1]<<1);
    event->trace=o->step.trace_seen;event->release_started=released;event->release_complete=released;
    event->fetch=*li2_lifecycle_fetch_progress();
}
static void cpuid_actual(ucontext_t *uc) {
    greg_t *g=uc->uc_mcontext.gregs;unsigned a=(unsigned)g[REG_RAX],c=(unsigned)g[REG_RCX],b,d;
    need(active_decoded.kind==LI2_CPUID&&active_decoded.length==2&&
         (uint64_t)g[REG_EFL]==(logical_flags|LI2_STEP_RF),316);
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
    g[REG_RAX]=a;g[REG_RBX]=b;g[REG_RCX]=c;g[REG_RDX]=d;
    g[REG_RIP]=(greg_t)active_decoded.next_pc;g[REG_EFL]=(greg_t)logical_flags;
    ++active_lane()->selected;release_actual();
}
static void call_prefix(ucontext_t *uc) {
    if(case_id!=7||(uintptr_t)uc->uc_mcontext.gregs[REG_RIP]!=li2_chain_record.callee)return;
    need((uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==fixture_seed[4]-8&&
         word((const unsigned char *)(fixture_seed[4]-8))==li2_chain_record.pc+5&&
         li2_chain_record.stop==li2_chain_record.pc+5&&actual_protection(li2_chain_record.stop,0)==PROT_READ,317);
    ++active_lane()->call_return_checked;
}
static void chain_handler(int sig,siginfo_t *si,void *frame_) {
    li2_maps_event_boundary();li2_tf_chain_event_boundary(&li2_chain_record.chain);
    if(chain_handling) {
        chain_control_event(sig,si,frame_);
        if(which==2)li2_tf_chain_unexpected(&li2_chain_record.chain,sig,si,frame_);
        die(318);
    }
    chain_handling=1;need(si&&frame_&&which<3,319);
    need(!li2_maps_phase_begin(),320);active_info=si;active_context=frame_;
    ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;struct chain_lane *l=active_lane();
    need(l->event_count<CHAIN_EVENTS,321);event=&l->events[l->event_count++];
    event->ordinal=l->event_count;event->signal=sig;event->code=si->si_code;event->error=si->si_errno;
    event->address=(uintptr_t)si->si_addr;event->pc=(uintptr_t)g[REG_RIP];event->flags=(uint64_t)g[REG_EFL];
    capture(&event->actual,uc);
    if(nx(sig,si,g,event->pc))++l->nx;
    if(sig==SIGTRAP&&si->si_code==TRAP_TRACE)++l->traces;
    if(!l->started) {
        need(nx(sig,si,g,li2_chain_record.pc)&&(uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),322);
        capture(&l->before,uc);l->started=1;logical_flags=fixture_flags;
    }
    if(which==0) {
        if(l->event_count==1)native_permissions(PROT_READ|PROT_EXEC);
        else {
            /* Genuine native program endpoint remains NX. No injected TF. */
            if(mode)chain_control_event(sig,si,uc);
            if(!l->fault)need(nx(sig,si,g,li2_chain_record.stop),323);
            capture(&l->after,uc);
            l->flags=(uint64_t)g[REG_EFL]&~LI2_STEP_RF;l->complete=!l->fault;
            native_permissions(PROT_READ);g[REG_EFL]=(greg_t)l->flags;
            g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        }
    } else if(which==2&&li2_chain_record.chain.pending) {
        if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_tf_chain_unexpected(&li2_chain_record.chain,sig,si,uc);
        call_prefix(uc);unsigned previous=li2_chain_record.chain.active;
        enum li2_chain_result r=li2_tf_chain_trace(&li2_chain_record.chain,sig,si,uc);
        const struct li2_tf_chain_slot *p=&li2_chain_record.chain.slots[previous];
        event_owner(&p->owner,&p->query,p->release.complete);event->fetch=p->fetch.progress;event->origin=p->origin;event->result=r;
        ++l->completed_instructions;logical_flags=p->owner.actual_post_flags&~LI2_STEP_TF;
    } else if(reference_pending) {
        if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_tf_unexpected(&li2_chain_record.reference,sig,si,uc);
        call_prefix(uc);li2_tf_trace(&li2_chain_record.reference,sig,si,uc);release_actual();
        event_owner(&li2_chain_record.reference,&li2_chain_record.reference_query,1);event->origin=1;
        logical_flags=li2_chain_record.reference.actual_post_flags&~LI2_STEP_TF;
        ++l->completed_instructions;reference_pending=0;
    } else if(old_pending) {
        if(sig!=SIGTRAP||si->si_code!=TRAP_TRACE)li2_step_abort(&li2_chain_record.old_owner,LI2_STEP_FOREIGN_EVENT,sig);
        li2_step_trace(&li2_chain_record.old_owner,sig,si,uc);release_actual();
        logical_flags=(uint64_t)g[REG_EFL];++l->old;old_pending=0;
    } else {
        need(nx(sig,si,g,event->pc)&&(uint64_t)g[REG_EFL]==(logical_flags|LI2_STEP_RF),324);
        if(event->pc==li2_chain_record.stop) {
            capture(&l->after,uc);l->flags=logical_flags;l->complete=1;source_closed();
            g[REG_EFL]=(greg_t)logical_flags;g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        } else {
            fetch_actual(event->pc);event->decoded=active_decoded;event->fetch=*li2_lifecycle_fetch_progress();
            if(active_decoded.kind==LI2_CPUID)cpuid_actual(uc);
            else if(which==2&&active_decoded.step_disposition==LI2_STEP_CANDIDATE) {
                struct li2_step_request req=request_actual();li2_chain_record.old_owner=(struct li2_step_owner){0};
                const struct li2_step_hooks hooks={0,reference_authenticate,reference_failure};
                old_pending=1;need(!li2_step_arm(&li2_chain_record.old_owner,&session,&hooks,&req,0),325);
                li2_step_begin(&li2_chain_record.old_owner,sig,si,uc);
            } else if(which==1) {
                struct li2_step_request req=request_actual();li2_chain_record.reference=(struct li2_tf_owner){0};
                li2_chain_record.reference_query=(struct li2_tf_continuation){0};
                const struct li2_tf_hooks hooks={{0,reference_authenticate,reference_failure},reference_continue};
                reference_pending=1;need(!li2_tf_arm(&li2_chain_record.reference,&session,&hooks,&req),326);
                li2_tf_begin_observed_shstk(&li2_chain_record.reference,sig,si,uc);
            } else {
                chain_control_before_entry();
                li2_tf_chain_begin_nx(&li2_chain_record.chain,&active_ref,&active_decoded,logical_flags,sig,si,uc);
            }
        }
    }
    fixture_vector_clobber();++l->returns;
    li2_tf_chain_handler_end(&li2_chain_record.chain);li2_maps_phase_end();chain_handling=0;
    active_info=0;active_context=0;
}
static void install_chain_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} a;
    a.handler=chain_handler;a.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    a.restorer=step_restorer;a.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&a,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&a,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&a,0,8,0,0),327);
}
static int chain_sealed_elf(void) {
    int seed=sealed_elf();need(!RAW(SYS_close,seed,0,0,0,0,0),328);
    memcpy(program_image,elf_bytes,PAGE);memset(program_image+PAGE,0xcc,CODE_BYTES-PAGE);
    Elf64_Phdr *ph=(void *)(program_image+sizeof(Elf64_Ehdr));
    ph->p_flags=PF_R|PF_X;ph->p_filesz=CODE_BYTES;ph->p_memsz=CODE_BYTES;
    const struct chain_case *v=&chain_cases[case_id];
    memcpy(program_image+v->offset,v->bytes,v->length);
    if(mode==1) {
        /* Failure is the second instruction, reached through a real TRACE
           handoff. Native executes the identical ADD then faulty load. */
        const unsigned char prefix[]={0x48,0x01,0xd8,0x48,0x8b,0x06};
        memcpy(program_image+v->offset,prefix,sizeof prefix);
    }
    unsigned stop=case_id==7?PAGE:2*PAGE;
    program_image[stop]=0x0f;program_image[stop+1]=0x0b; /* observed guard, never executes */
    if(v->tail_offset!=255)emit_i32(program_image+v->offset+v->tail_offset+1,
        (int64_t)stop-(int64_t)(v->offset+v->tail_offset+5));
    if(case_id==7) {
        emit_i32(program_image+v->offset+1,(int64_t)(2*PAGE+64)-(int64_t)(v->offset+5));
        const unsigned char callee[]={0x48,0x01,0xd8,0xc3};
        memcpy(program_image+2*PAGE+64,callee,sizeof callee);
    }
    long fd=RAW(SYS_memfd_create,"li2-chain-literal",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);
    need(fd>=0&&write_all((int)fd,program_image,sizeof program_image),329);
    need(!RAW(SYS_fcntl,fd,F_ADD_SEALS,SEALS,0,0,0),330);program_fd=(int)fd;return program_fd;
}
static void program_prepare(void) {
    long area=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(area>0,331);
    li2_chain_record.mapping=(uintptr_t)area+PAGE;
    long mapped=dispatch(SYS_mmap,li2_chain_record.mapping,CODE_BYTES,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_FIXED,program_fd,0);
    need(mapped==(long)li2_chain_record.mapping,332);
    li2_chain_record.pc=li2_chain_record.mapping+chain_cases[case_id].offset;
    li2_chain_record.stop=li2_chain_record.mapping+(case_id==7?PAGE:2*PAGE);li2_chain_record.callee=li2_chain_record.mapping+2*PAGE+64;
    memcpy(li2_chain_record.source,program_image,CODE_BYTES);source_closed();
    if(case_id==9) {
        struct li2_decoded containing={0},embedded={0};
        need(!li2_decoder_decode(li2_chain_record.pc+2,(const void *)(li2_chain_record.pc+2),10,&containing)&&
             containing.decode_status==LI2_VALID&&containing.length==10&&containing.kind==LI2_NONE&&
             containing.step_disposition==LI2_STEP_CANDIDATE&&
             !li2_decoder_decode(li2_chain_record.pc+4,(const void *)(li2_chain_record.pc+4),2,&embedded)&&
             embedded.decode_status==LI2_VALID&&embedded.kind==LI2_CPUID&&embedded.length==2,364);
    }
}
static void program_inputs(void) {
    ref_source.id=200+case_id;inputs(&ref_source);
    if(case_id==5)fixture_seed[1]=3;
    if(case_id==6)fixture_seed[2]=li2_chain_record.stop;
    if(case_id==8||case_id==9){fixture_seed[0]=0;fixture_seed[1]=0;}
    if(case_id==11)fixture_seed[1]=0;
    chain_control_inputs();fixture_target=li2_chain_record.pc;
}
static void lane_run(unsigned n) {
    which=n;program_inputs();struct chain_lane *l=active_lane();
    l->attempts_before=li2_chain_record.chain.attempts;l->steps_before=li2_chain_record.chain.steps;
    l->entries_before=li2_chain_record.chain.trace_entries;l->fallbacks_before=li2_chain_record.chain.fallbacks;
    fixture_enter();need(l->complete&&!l->fault,333);
    l->live[0]=fixture_live_before;l->live[1]=fixture_live_after;
    memcpy(l->fp[0],fixture_fp_before,xsave_bytes);memcpy(l->fp[1],fixture_fp_after,xsave_bytes);
    source_closed();need(!li2_lifecycle_fetch_interlock()&&!reference_pending&&!old_pending&&!li2_chain_record.chain.pending,334);
    ++li2_chain_record.completed_lanes;
}
/* Multi-instruction endpoint comparison uses real states in each lane. No
   synthesized single-instruction owner or expected machine frame exists. */
static void compare_program(void) {
    const struct chain_lane *native=&li2_chain_record.lanes[0];
    for(unsigned n=0;n<3;n++) {
        struct chain_lane *l=&li2_chain_record.lanes[n];need(l->complete&&!l->fault&&l->event_count<=CHAIN_EVENTS,335);
        need(l->before.frame.greg[REG_RIP]==(greg_t)li2_chain_record.pc&&l->after.frame.greg[REG_RIP]==(greg_t)li2_chain_record.stop,336);
        need((uint64_t)l->before.frame.greg[REG_EFL]==(fixture_flags|LI2_STEP_RF)&&
             (uint64_t)l->after.frame.greg[REG_EFL]==(l->flags|LI2_STEP_RF)&&l->flags==native->flags,337);
        for(unsigned i=0;i<16;i++)need(l->before.frame.greg[regs[i]]==native->before.frame.greg[regs[i]]&&
             l->after.frame.greg[regs[i]]==native->after.frame.greg[regs[i]],338);
        compare_memory(&l->before,&native->before,339);compare_memory(&l->after,&native->after,340);
        for(unsigned e=0;e<2;e++) {
            const struct state *s=e?&l->after:&l->before,*r=e?&native->after:&native->before;
            const struct li2_step_frame *f=&s->frame;const struct live *v=&l->live[e];
            need(s->fs==native->before.fs&&s->gs==native->before.gs&&f->mask==mask&&
                 f->initialized==f->fp_bytes&&f->fp_bytes==r->frame.fp_bytes&&
                 f->greg[REG_CSGSFS]==r->frame.greg[REG_CSGSFS]&&!memcmp(f->fp,r->frame.fp,f->fp_bytes),341);
            need(v->started==1&&v->complete==1&&!v->reserved&&v->rflags==(e?l->flags:fixture_flags),342);
            for(unsigned i=0;i<16;i++)need(v->gpr[i]==(uint64_t)f->greg[regs[i]],343);
            for(unsigned i=0;i<6;i++)need(v->selectors[i]==native->live[0].selectors[i],344);
            need(v->selectors[0]==((uint64_t)f->greg[REG_CSGSFS]&0xffff)&&
                 v->selectors[1]==((uint64_t)f->greg[REG_CSGSFS]>>48)&&
                 !memcmp(l->fp[e],native->fp[e],xsave_bytes),345);
        }
        if(n)need(l->selected==chain_cases[case_id].selected&&
             l->completed_instructions+l->old==chain_cases[case_id].instructions+chain_cases[case_id].old,346);
        if(n==1)need(l->nx==l->completed_instructions+l->selected+1&&!l->old,347);
        if(n==2)need(l->completed_instructions==li2_chain_record.chain.steps-l->steps_before&&
            li2_chain_record.chain.trace_entries>l->entries_before&&li2_chain_record.chain.fallbacks>l->fallbacks_before,348);
        need(l->returns==l->event_count,349);
        if(n==0)need(l->event_count==2&&l->nx==2&&!l->traces&&!l->selected&&!l->old,361);
        if(n)need(l->traces==chain_cases[case_id].instructions+chain_cases[case_id].old,362);
        if(n==2) {
            unsigned separate=(case_id==9||case_id==10||case_id==11),nx_expected=2;
            if(case_id==8||case_id==11)nx_expected=3;
            if(case_id==9||case_id==10)nx_expected=4;
            need(l->nx==nx_expected&&l->old==chain_cases[case_id].old&&
                li2_chain_record.chain.nx_entries==1+separate&&li2_chain_record.chain.fallbacks==1+separate&&
                li2_chain_record.chain.trace_entries==chain_cases[case_id].instructions-(1+separate),363);
        }
        l->checked=1;
    }
    uint64_t a=(uint64_t)native->before.frame.greg[REG_RAX],b=(uint64_t)native->before.frame.greg[REG_RBX];
    if(case_id<2)need((uint64_t)native->after.frame.greg[REG_RAX]==((a+b)^1),350);
    if(case_id==2||case_id==3)for(unsigned i=0;i<16;i++) {
        unsigned char x=native->fp[0][160+i],y=native->fp[0][160+7*16+i];
        need(native->fp[1][160+i]==(((x^y)==y)?255:0),351);
    }
    if(case_id==4)need((uint64_t)native->after.frame.greg[REG_RAX]==word(native->before.data)+b&&
        word(native->after.data+8)==word(native->before.data)+b,352);
    if(case_id==5)need(!native->after.frame.greg[REG_RCX]&&(native->flags&0x40),353);
    if(case_id==7) {
        need((uint64_t)native->after.frame.greg[REG_RSP]==fixture_seed[4]&&
             word(native->after.stack+SUBJECT_BYTES/2-8)==li2_chain_record.pc+5,354);
        need(li2_chain_record.lanes[1].call_return_checked==1&&li2_chain_record.lanes[2].call_return_checked==1&&
             actual_protection(li2_chain_record.stop,0)==PROT_READ,355);
    }
}
#include "controls.inc"
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(li2_chain_record)+sizeof(samples[0])+sizeof(ctl)<16*1024*1024,"unchanged bounded private li2_chain_record");
    /* Environment selects this independent fixture; generic argv stays argc1. */
    chain_parse_environment(stack);li2_chain_record.case_id=case_id;li2_chain_record.mode=mode;
    setup(stack);size_t complete=0,failed=0;uint32_t rc=0;
    need(!li2_tf_refusal_controls(&complete,&failed,&rc,&refused_last)&&complete==47&&failed==SIZE_MAX&&!rc,356);
    li2_chain_record.refusals=complete;size_t route_failed=0;need(li2_trace_route_controls(&route_failed)&&route_failed==SIZE_MAX,357);li2_chain_record.route_controls=15;
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,358);
    need(!li2_decoder_stats(&li2_chain_record.initial_stats)&&!li2_tf_chain_init(&li2_chain_record.chain,&session,chain_failure),359);
    program_prepare();install_chain_handler();
    if(mode)chain_control_run();
    for(unsigned n=0;n<3;n++)lane_run(n);
    compare_program();need(li2_chain_record.completed_lanes==3&&!li2_decoder_stats(&li2_chain_record.final_stats)&&
        !memcmp(&li2_chain_record.initial_stats,&li2_chain_record.final_stats,sizeof li2_chain_record.initial_stats)&&chain_dump(),360);
    output("LI2_CHAIN_PROGRAM_PASS ");output(chain_cases[case_id].name);output("\n");return 0;
}
