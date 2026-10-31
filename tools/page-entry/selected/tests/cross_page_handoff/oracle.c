/* Pure source-owned predicate controls. TRACE, identity and physical lifecycle
   observations below are explicitly supplied, not native execution evidence. */
#define _GNU_SOURCE
#define LI2_PERSISTENT_CROSS_PAIR 1
#define LI2_SCALAR_SPAN_TRACE 1
#define LI2_SCALAR_SPAN 1
#define LI2_RUN_CACHE_REUSE 1
#define LI2_LINKED_EPOCH 1
#define LI2_EFFECT_PROVIDER 1
#define LI2_TF_HANDOFF 1
#define LI2_REGISTER_RUN 1
#include "tf_span_transfer.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct li2_tf_chain chain,foreign_chain;
static struct li2_tf_chain *chain_registered;
static struct li2_step_session session,foreign_session;
static struct li2_span_fetch_observation observed;
static struct li2_fetch_page target_page;
static siginfo_t signal_info;
static ucontext_t context;
static unsigned char fp[512] __attribute__((aligned(64)));
static jmp_buf failure;
static unsigned fault,aborted,trace_calls,release_calls,snapshot_calls;
static unsigned close_injection;
static int identity_ok,quiet_error;
static const struct li2_tf_span_transfer *ticket;
static unsigned eligibility_cases,refusal_cases,close_cases,fresh_cases,consume_cases;
static const unsigned registers[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,
    REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};

static void check(int yes,const char *name) {
    if(!yes){fprintf(stderr,"cross-page-handoff: %s\n",name);exit(1);}
}
static void copy(void *to,const void *from,size_t n){memcpy(to,from,n);}
static int equal(const void *a,const void *b,size_t n){return !memcmp(a,b,n);}
static int identity(const struct li2_step_session *s){return identity_ok && s==&session;}
_Noreturn void li2_tf_chain_abort(struct li2_tf_chain *c,unsigned code,long detail) {
    (void)detail;check(c==&chain,"scripted failure owner");aborted=code;longjmp(failure,1);
}
int li2_tf_chain_run_reuse_quiet(const struct li2_tf_chain *c,
                                const struct li2_tf_run_entry *entry) {
    check(c==&chain && !entry,"scripted quiet arguments");return quiet_error;
}
const struct li2_fetch_progress *li2_lifecycle_fetch_progress(void){return &observed.progress;}
void li2_lifecycle_fetch_partial_view(struct li2_fetch_view *v) {
    *v=(struct li2_fetch_view){.pc=observed.pc,.bytes=observed.bytes,
        .length=observed.length,.page_count=observed.page_count,.pid=observed.pid,.tid=observed.tid,
        .identity_observed=1,.pages=observed.pages,.backing=observed.backing,
        .last_backing=&observed.last_backing};
}
int li2_lifecycle_fetch_release(const struct li2_fetch_ref *ref) {
    ++release_calls;
    check(ref->owner==observed.ref.owner && ref->sequence==observed.ref.sequence,
          "scripted release retains exact original ref");
    if(fault==8)return LI2_FETCH_STALE;
    if(fault!=9)observed.progress.held=0;
    return 0;
}
int li2_lifecycle_span_fetch_snapshot(struct li2_span_fetch_observation *out) {
    ++snapshot_calls;*out=observed;
    if(fault==10)return LI2_FETCH_STALE;
    if(fault==11)out->complete=0;
    if(fault==12)out->ref.sequence++;
    return 0;
}
static void save_frame(struct li2_step_frame *out,const ucontext_t *uc) {
    memset(out,0,sizeof *out);copy(out->greg,uc->uc_mcontext.gregs,sizeof out->greg);
    copy(&out->mask,&uc->uc_sigmask,sizeof out->mask);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;out->fp_bytes=sizeof fp;
    out->initialized=sizeof fp;copy(out->fp,uc->uc_mcontext.fpregs,sizeof fp);
}
void li2_tf_trace(struct li2_tf_owner *owner,int sig,siginfo_t *si,ucontext_t *uc) {
    /* Script a real-close-shaped observation, then inject one causal error.
       The extracted close predicates, release ordering and ticket logic decide. */
    check(owner==&chain.slots[0].owner && sig==SIGTRAP && si==&signal_info && uc==&context,
          "scripted TRACE arguments");
    ++trace_calls;struct li2_step_owner *p=&owner->step;
    p->trace_seen=1;p->revoke_sync_started=1;p->revoke_sync=0;
    p->open_started[0]=p->opened[0]=p->revoke_started[0]=p->revoked[0]=1;
    owner->actual_post_pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    owner->actual_post_flags=(uint64_t)uc->uc_mcontext.gregs[REG_EFL];
    save_frame(&p->after,uc);
    owner->continuation_started=owner->continuation_complete=1;
    chain.slots[0].query=(struct li2_tf_continuation){.pc=owner->actual_post_pc,
        .attempted=1,.page_observed=1,.complete=1,.page=target_page};
    uc->uc_mcontext.gregs[REG_EFL]&=~LI2_STEP_TF;
    p->phase=LI2_STEP_COMPLETE;p->in_handler=0;
    if(fault==1)owner->continuation_complete=0;
    if(fault==2)chain.slots[0].query.pc++;
    if(fault==3)p->revoked[0]=0;
    if(fault==4)uc->uc_mcontext.gregs[REG_R15]^=1;
    if(fault==5)fp[511]^=1;
    if(fault==6)si->si_errno=1;
    if(fault==7)uc->uc_flags^=1;
}

/* ACTUAL_SOURCE */

static struct li2_tf_chain_slot *slot(void){return &chain.slots[0];}
static struct li2_decoded *decoded(void){return &slot()->owner.step.request.decoded;}
static void sync_decoded(void){slot()->decoded=*decoded();}
static void seed(unsigned reg,unsigned source_end,unsigned target_offset,int same_page) {
    memset(&chain,0,sizeof chain);memset(&foreign_chain,0,sizeof foreign_chain);
    memset(&span_transfer,0,sizeof span_transfer);span_transfer_serial=19;
    memset(&observed,0,sizeof observed);memset(&context,0,sizeof context);
    memset(&signal_info,0,sizeof signal_info);memset(fp,0x6d,sizeof fp);
    session=(struct li2_step_session){.pid=101,.tid=101,.initialized=1,.self_test_complete=1};
    foreign_session=session;chain_registered=&chain;chain.session=&session;
    chain.initialized=1;chain.pending=1;chain.event_id=12;
    struct li2_tf_chain_slot *s=slot();s->chain=&chain;s->phase=LI2_CHAIN_EXECUTING;
    s->generation=7;s->event_id=11;s->owner.step.phase=LI2_STEP_RUNNING;
    s->owner.step.session=&session;s->owner.step.request.page_count=1;
    s->owner.step.request.pages[0].address=0x400000;
    s->owner.step.request.original_flags=0x202;
    unsigned length=reg>=8?3:2;
    uint64_t original=0x400000+(source_end?4096-length:0);
    uint64_t target=(same_page?0x400000:0x600000)+target_offset;
    *decoded()=(struct li2_decoded){.pc=original,.next_pc=original+length,
        .abi_version=1,.code=765,.destination=16,.available=length,.length=length};
    unsigned prefix=reg>=8;decoded()->bytes[0]=prefix?0x41:0xff;
    decoded()->bytes[prefix]=0xff;decoded()->bytes[prefix+1]=(unsigned char)(0xe0+(reg&7));
    sync_decoded();
    s->owner.classification=(struct li2_tf_classification){.pc=original,.next_pc=original+length,
        .abi_version=1,.policy=1,.code=765,.length=length,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_BRANCH};
    for(unsigned i=0;i<16;i++)context.uc_mcontext.gregs[registers[i]]=0x700000+i*16;
    context.uc_mcontext.gregs[registers[reg]]=(greg_t)target;
    context.uc_mcontext.gregs[REG_RIP]=(greg_t)target;
    context.uc_mcontext.gregs[REG_EFL]=0x302;
    context.uc_mcontext.gregs[REG_TRAPNO]=1;
    context.uc_mcontext.gregs[REG_CSGSFS]=0x33;
    context.uc_mcontext.fpregs=(void *)fp;
    save_frame(&s->owner.step.before,&context);
    s->owner.step.before.greg[REG_RIP]=(greg_t)original;
    s->owner.step.before.greg[REG_EFL]=0x202;
    signal_info.si_signo=SIGTRAP;signal_info.si_code=TRAP_TRACE;
    signal_info.si_addr=(void *)(uintptr_t)target;
    observed.complete=1;observed.ref.owner=(const struct li2_fetch *)(uintptr_t)0x123400;
    observed.ref.sequence=31;observed.progress.held=observed.progress.complete=1;
    observed.progress.sequence=31;observed.progress.validation_calls=2;
    observed.progress.last_backing_observed=1;observed.pc=original;
    observed.length=length;observed.page_count=1;observed.pid=session.pid;observed.tid=session.tid;
    observed.pages[0]=(struct li2_fetch_page){.address=0x400000,.allocation=8,.generation=9,
        .offset=4096,.initial_extent=2,.backing=1,.object=3,.logical=5,.closed_prot=1,
        .vma_first=0x400000,.vma_end=0x401000,.vma_major=1,.vma_minor=2,.vma_inode=300,.vma_offset=4096};
    s->fetch.ref=observed.ref;chain_observe(&s->fetch);
    target_page=observed.pages[0];target_page.address=target&~UINT64_C(4095);
    if(!same_page){target_page.allocation=18;target_page.generation=19;}
    target_page.vma_first=target_page.address;target_page.vma_end=target_page.address+4096;
    fault=aborted=trace_calls=release_calls=snapshot_calls=0;identity_ok=1;quiet_error=0;ticket=0;
}
static int eligible(void){return li2_tf_chain_span_cross_page_eligible(&chain,SIGTRAP,&signal_info,&context);}
static void target_at(uint64_t target) {
    context.uc_mcontext.gregs[REG_RIP]=context.uc_mcontext.gregs[REG_RDX]=(greg_t)target;
    slot()->owner.step.before.greg[REG_RDX]=(greg_t)target;
    signal_info.si_addr=(void *)(uintptr_t)target;
}
static void eligibility(void) {
    for(unsigned reg=0;reg<16;reg++)for(unsigned end=0;end<2;end++)for(unsigned t=0;t<2;t++) {
        seed(reg,end,t?4081:0,0);check(eligible(),"all canonical registers and exact endpoints");
        check(!trace_calls && !release_calls && !snapshot_calls && !span_transfer.valid,
              "eligibility has no close/query/issue effect");++eligibility_cases;
    }
#define REFUSE(name,change) do {seed(2,0,32,0);change;check(!eligible(),name); \
    check(!trace_calls && !release_calls && !snapshot_calls && !span_transfer.progress.issued, \
          "refusal performs no observation/issue");++refusal_cases;} while(0)
    REFUSE("target offset4082",target_at(0x600ff2));
    REFUSE("zero target",target_at(0));
    REFUSE("null page target",target_at(15));
    REFUSE("upper canonical target",target_at(UINT64_C(0xffff800000000020)));
    REFUSE("noncanonical target",target_at(UINT64_C(1)<<47));
    REFUSE("same page",target_at(0x400020));
    REFUSE("source zero",slot()->owner.step.request.pages[0].address=0);
    REFUSE("source unaligned",slot()->owner.step.request.pages[0].address++);
    REFUSE("source high",slot()->owner.step.request.pages[0].address=UINT64_C(1)<<47);
    REFUSE("source fetch mismatch",slot()->fetch.pages[0].address+=4096);
    REFUSE("source before page",decoded()->pc=0x3fffff;sync_decoded());
    REFUSE("source straddle",decoded()->pc=0x400fff;decoded()->next_pc=0x401001;sync_decoded());
    REFUSE("descriptor copy",slot()->decoded.code++);
    REFUSE("target register",context.uc_mcontext.gregs[REG_RDX]++);
    REFUSE("other register",context.uc_mcontext.gregs[REG_R15]++);
    REFUSE("prestate target register",slot()->owner.step.before.greg[REG_RDX]++);
    REFUSE("flags changed",context.uc_mcontext.gregs[REG_EFL]^=1);
    REFUSE("RF set",context.uc_mcontext.gregs[REG_EFL]|=LI2_STEP_RF);
    REFUSE("TF absent",context.uc_mcontext.gregs[REG_EFL]&=~LI2_STEP_TF);
    REFUSE("stale event",chain.event_id=slot()->event_id);
    REFUSE("nonexecuting chain",slot()->phase=LI2_CHAIN_CLOSED);
    REFUSE("nonrunning owner",slot()->owner.step.phase=LI2_STEP_COMPLETE);
    REFUSE("pending absent",chain.pending=0);
    REFUSE("handler active",chain.in_handler=1);
    REFUSE("owner handler active",slot()->owner.step.in_handler=1);
    REFUSE("chain error",chain.first_error=1);
    REFUSE("wrong registered chain",chain_registered=&foreign_chain);
    REFUSE("uninitialized chain",chain.initialized=0);
    REFUSE("bad active index",chain.active=2);
    REFUSE("missing ref owner",slot()->fetch.ref.owner=0);
    REFUSE("missing ref serial",slot()->fetch.ref.sequence=0);
    REFUSE("wrong request count",slot()->owner.step.request.page_count=2);
    REFUSE("wrong fetch count",slot()->fetch.page_count=2);
    REFUSE("existing valid ticket",span_transfer.valid=1);
    REFUSE("closing ticket",span_transfer.progress.phase=LI2_ST_CLOSING);
    REFUSE("serial overflow",span_transfer_serial=UINT64_MAX);
    REFUSE("wrong signal",signal_info.si_signo=SIGSEGV);
    REFUSE("wrong trap",signal_info.si_code=SI_USER);
    REFUSE("signal errno",signal_info.si_errno=1);
    REFUSE("trap number",context.uc_mcontext.gregs[REG_TRAPNO]=14);
    REFUSE("trap error",context.uc_mcontext.gregs[REG_ERR]=1);
    REFUSE("signal target",signal_info.si_addr=(void *)0x600021);
    REFUSE("decoder ABI",decoded()->abi_version=2;sync_decoded());
    REFUSE("invalid decode",decoded()->decode_status=LI2_INVALID;sync_decoded());
    REFUSE("selected kind",decoded()->kind=LI2_CPUID;sync_decoded());
    REFUSE("destination",decoded()->destination=0;sync_decoded());
    REFUSE("width",decoded()->width_bits=64;sync_decoded());
    REFUSE("reserved",decoded()->reserved=1;sync_decoded());
    REFUSE("supported disposition",decoded()->step_disposition=LI2_STEP_CANDIDATE;sync_decoded());
    REFUSE("short bytes",decoded()->available=1;sync_decoded());
    REFUSE("oversize bytes",decoded()->available=16;sync_decoded());
    REFUSE("wrong next",decoded()->next_pc++;sync_decoded());
    REFUSE("wrong length",decoded()->length=3;sync_decoded());
    REFUSE("REX W prefix",decoded()->bytes[0]=0x48;sync_decoded());
    REFUSE("memory JMP",decoded()->bytes[1]=0x22;sync_decoded());
    REFUSE("direct JMP",decoded()->bytes[0]=0xe9;decoded()->code=696;sync_decoded());
    REFUSE("CALL",decoded()->bytes[1]=0xd2;decoded()->code=759;sync_decoded());
    REFUSE("RET",decoded()->bytes[0]=0xc3;decoded()->code=396;sync_decoded());
    REFUSE("Jcc",decoded()->bytes[0]=0x75;decoded()->code=1766;sync_decoded());
    REFUSE("classifier ABI",slot()->owner.classification.abi_version=2);
    REFUSE("classifier refusal",slot()->owner.classification.policy=0);
    REFUSE("classifier PC",slot()->owner.classification.pc++);
    REFUSE("classifier next",slot()->owner.classification.next_pc++);
    REFUSE("classifier code",slot()->owner.classification.code++);
    REFUSE("classifier length",slot()->owner.classification.length++);
    REFUSE("classifier flow",slot()->owner.classification.flow=LI2_TF_FALLTHROUGH);
    REFUSE("classifier family",slot()->owner.classification.family=LI2_TF_CALL);
#undef REFUSE
    seed(2,0,32,0);check(!li2_tf_chain_span_cross_page_eligible(0,SIGTRAP,&signal_info,&context),"null chain");++refusal_cases;
    check(!li2_tf_chain_span_cross_page_eligible(&chain,SIGTRAP,0,&context),"null signal");++refusal_cases;
    check(!li2_tf_chain_span_cross_page_eligible(&chain,SIGTRAP,&signal_info,0),"null frame");++refusal_cases;
    check(!li2_tf_chain_span_cross_page_eligible(&chain,SIGSEGV,&signal_info,&context),"foreign delivered signal");++refusal_cases;
}

static void close_good(int cross) {
    check(!(cross?li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket):
        li2_tf_chain_span_close(&chain,SIGTRAP,&signal_info,&context,&ticket)),"actual close success");
    check(ticket==&span_transfer && span_transfer.valid==1 && span_transfer.progress.issued==1 &&
        span_transfer.progress.serial==20 && span_transfer.progress.previous_borrow==31 &&
        span_transfer.progress.phase==LI2_ST_CLOSED && !span_origin(ticket),"issued exact closed ticket");
    check(trace_calls==1 && release_calls==1 && snapshot_calls==1 && chain.steps==1 &&
        chain.releases==1 && !chain.pending && !chain.in_handler && chain_closed(slot()),"whole close sequence");
    check(span_transfer.progress.pc==(uintptr_t)context.uc_mcontext.gregs[REG_RIP] &&
        context.uc_mcontext.gregs[REG_EFL]==0x202 && span_frame_equal(SIGTRAP,&signal_info,&context),
        "only TF changes in full actual predicate frame");
}
static void closes(void) {
    for(unsigned reg=0;reg<16;reg++) {
        seed(reg,1,4081,0);close_good(1);++close_cases;
    }
    seed(2,0,32,1);close_good(0);++close_cases;
    seed(2,0,32,0);check(li2_tf_chain_span_close(&chain,SIGTRAP,&signal_info,&context,&ticket)==LI2_ST_ORIGIN &&
        !ticket && !trace_calls && !release_calls && span_transfer_serial==19,"old close cross-page remains refusal");++close_cases;
    seed(2,0,32,1);check(li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket)==LI2_ST_ORIGIN &&
        !ticket && !trace_calls && !release_calls && span_transfer_serial==19,"new close same-page refuses");++close_cases;
    seed(2,0,32,0);check(li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,0)==LI2_ST_ARGUMENT,
        "null output preserved");++close_cases;
    seed(2,0,32,0);chain.pending=0;
    check(li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket)==LI2_ST_STATE && !trace_calls,
        "state refusal before mutation");++close_cases;
    seed(2,0,32,0);span_transfer_serial=UINT64_MAX;
    check(li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket)==LI2_ST_OVERFLOW && !trace_calls,
        "overflow refusal before mutation");++close_cases;
    /* Every injected partial physical/TRACE observation must terminate before
       issuing a ticket. Codes and release prefix distinguish the failed seam. */
    for(close_injection=1;close_injection<=12;close_injection++) {
        seed(2,0,32,0);fault=close_injection;
        if(!setjmp(failure)) {
            (void)li2_tf_chain_span_close_cross_page(&chain,SIGTRAP,&signal_info,&context,&ticket);
            check(0,"partial close must terminate");
        }
        unsigned want=fault<=5 || fault==9?LI2_CHAIN_FRAME:fault<=7?LI2_ST_FRAME:fault==8?LI2_CHAIN_RELEASE:LI2_ST_FETCH;
        check(aborted==want && !ticket && !span_transfer.valid && !span_transfer.progress.issued &&
            span_transfer.progress.phase==LI2_ST_CLOSING && trace_calls==1,"failure prefix and exact code");
        check(release_calls==(fault<=5?0U:1U),"failure occurs at exact release frontier");++close_cases;
    }
}
static void fresh_seed(void) {
    seed(2,0,32,0);close_good(1);
    observed.pc=span_transfer.progress.pc;observed.length=15;observed.page_count=1;
    observed.progress.held=1;observed.ref.sequence=32;observed.progress.sequence=32;
    observed.pages[0]=target_page;
}
static void fresh_controls(void) {
    struct li2_span_fetch_observation out;
    fresh_seed();check(!span_fresh(1,&out),"new held target-bound borrow");++fresh_cases;
    observed.progress.held=0;check(!span_fresh(0,&out),"new released target-bound borrow");++fresh_cases;
#define FRESH_BAD(name,change) do {fresh_seed();change; \
    check(span_fresh(1,&out)==LI2_ST_FETCH,name);++fresh_cases;} while(0)
    FRESH_BAD("incomplete snapshot",observed.complete=0);
    FRESH_BAD("not held",observed.progress.held=0);
    FRESH_BAD("length",observed.length=14);
    FRESH_BAD("page count",observed.page_count=2);
    FRESH_BAD("actual PC",observed.pc++);
    FRESH_BAD("PID",observed.pid++);
    FRESH_BAD("TID",observed.tid++);
    FRESH_BAD("borrow owner",observed.ref.owner=0);
    FRESH_BAD("stale borrow",observed.ref.sequence=31);
    FRESH_BAD("old predecessor page",observed.pages[0]=slot()->fetch.pages[0]);
    FRESH_BAD("page address",observed.pages[0].address+=4096);
    FRESH_BAD("allocation",observed.pages[0].allocation++);
    FRESH_BAD("generation",observed.pages[0].generation++);
    FRESH_BAD("offset",observed.pages[0].offset++);
    FRESH_BAD("initial extent",observed.pages[0].initial_extent++);
    FRESH_BAD("backing",observed.pages[0].backing++);
    FRESH_BAD("object",observed.pages[0].object++);
    FRESH_BAD("logical protection",observed.pages[0].logical^=2);
    FRESH_BAD("closed protection",observed.pages[0].closed_prot^=2);
    FRESH_BAD("VMA first",observed.pages[0].vma_first++);
    FRESH_BAD("VMA end",observed.pages[0].vma_end++);
    FRESH_BAD("major",observed.pages[0].vma_major++);
    FRESH_BAD("minor",observed.pages[0].vma_minor++);
    FRESH_BAD("inode",observed.pages[0].vma_inode++);
    FRESH_BAD("VMA offset",observed.pages[0].vma_offset++);
#undef FRESH_BAD
    fresh_seed();observed.progress.held=0;observed.progress.validation_calls=0;
    check(span_fresh(0,&out)==LI2_ST_FETCH,"released requires validation");++fresh_cases;
    fresh_seed();observed.progress.held=0;observed.progress.last_backing_observed=0;
    check(span_fresh(0,&out)==LI2_ST_FETCH,"released requires backing observation");++fresh_cases;
}
static int consume(void) {
    return li2_tf_chain_span_consume(ticket,&session,&observed.ref,
        (uintptr_t)context.uc_mcontext.gregs[REG_RIP],SIGTRAP,&signal_info,&context);
}
static void consumes(void) {
    fresh_seed();check(!consume() && !span_transfer.valid && span_transfer.progress.consumed==1 &&
        span_transfer.progress.consume_attempted==1 && span_transfer.progress.phase==LI2_ST_CONSUMED &&
        span_transfer.progress.fresh_borrow==32,"consume exactly once");++consume_cases;
    check(consume()==LI2_ST_ORIGIN,"second consume refuses");++consume_cases;
#define CONSUME_BAD(name,change,want) do {fresh_seed();change;check(consume()==(want),name); \
    check(!span_transfer.progress.consumed,"refusal is not consumption");++consume_cases;} while(0)
    CONSUME_BAD("stale event",chain.event_id++,LI2_ST_ORIGIN);
    CONSUME_BAD("stale transfer serial",span_transfer_serial++,LI2_ST_ORIGIN);
    CONSUME_BAD("stale generation",slot()->generation++,LI2_ST_ORIGIN);
    CONSUME_BAD("stale original borrow",slot()->fetch.ref.sequence++,LI2_ST_ORIGIN);
    CONSUME_BAD("foreign session",chain.session=&foreign_session,LI2_ST_ORIGIN);
    CONSUME_BAD("changed session identity",session.pid++,LI2_ST_ORIGIN);
    CONSUME_BAD("new pending instruction",chain.pending=1,LI2_ST_ORIGIN);
    CONSUME_BAD("unreleased original",slot()->fetch.progress.held=1,LI2_ST_ORIGIN);
    CONSUME_BAD("altered closed frame",slot()->owner.step.after.greg[REG_R12]++,LI2_ST_ORIGIN);
    CONSUME_BAD("changed supplied GPR",context.uc_mcontext.gregs[REG_R12]++,LI2_ST_FRAME);
    CONSUME_BAD("changed supplied flags",context.uc_mcontext.gregs[REG_EFL]^=1,LI2_ST_FRAME);
    CONSUME_BAD("changed supplied FP",fp[511]^=1,LI2_ST_FRAME);
    CONSUME_BAD("changed supplied signal",signal_info.si_errno=1,LI2_ST_FRAME);
    CONSUME_BAD("actual identity refusal",identity_ok=0,LI2_ST_FRAME);
    CONSUME_BAD("stale new borrow",observed.ref.sequence=31,LI2_ST_FETCH);
    CONSUME_BAD("target query mismatch",slot()->query.page.generation++,LI2_ST_FETCH);
#undef CONSUME_BAD
}
int main(void) {
    eligibility();closes();fresh_controls();consumes();
    check(eligibility_cases==64 && refusal_cases==71 && close_cases==34 &&
        fresh_cases==29 && consume_cases==18,"literal complete control populations");
    puts("cross_page_handoff eligibility=64 refusals=71 close=34 fresh=29 consume=18 supplied_observations=1 native_credit=0");
    return 0;
}
