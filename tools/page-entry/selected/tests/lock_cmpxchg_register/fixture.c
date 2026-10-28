/* Canonical LOCK CMPXCHG dword [base],r32, all 256 source/base combinations. CPU success/failure and complete
   original-PC state remain independently observed, never emulated. */
#define fixture_main li2_unchanged_generic_fixture_main
#include "tests/generic/fixture.c"
#undef fixture_main
#include "cases.inc"
#include "write_footprint.h"
#define LOCK_EXPECTED_CODE 2075
#define LOCK_CONTROL_KEY "LI2_LOCK_CMPXCHG_REGISTER_CONTROL="
static unsigned lock_group;
_Static_assert(PAIRS==21,"unchanged complete generic capture layout");
#define LOCK_COUNT 16U
#define LOCK_PAIRS (LOCK_COUNT+1)
#define LOCK_MASK UINT64_C(0x8d5)
#define LOCK_OFFSET 256U
#define LOCK_ARENA UINT64_C(0x100010000)
#define LOCK_DATA UINT64_C(0x100011000)
#define LOCK_FAULT UINT64_C(0x100012000)
static unsigned lock_fault_kind,lock_control_index;
/* Actual pre-instruction query inputs/results. Queries are descriptive and
   performed on retained NX before-state, never substituted for owner authority. */
struct lock_query { uint64_t attempted,result,sample_id,base; struct li2_write_registers before; struct li2_write_footprint value; };
struct lock_query_record { uint64_t magic,version,bytes,group,acceptances,native_queries,step_queries,reserved; struct lock_query rows[PAIRS+1][2]; };
static struct lock_query_record lock_queries;
_Static_assert(sizeof(struct lock_query)==224 && sizeof(lock_queries)==9920,"closed query trailer");
static void lock_query_before(struct sample *s,unsigned which) {
    need(which<2&&!s->selftest,980);
    const struct lock_case *v=s==&negative_sample?&lock_fault_cases[lock_control_index]:
        &lock_cases[s->id-2000-16*lock_group];
    size_t index=s==&negative_sample?PAIRS:(size_t)(s-samples);
    need(index<=PAIRS,981);struct lock_query *q=&lock_queries.rows[index][which];
    need(!q->attempted,982);q->attempted=1;q->sample_id=s->id;q->base=v->base;
    const struct state *before=which?&s->step_before:&s->native_before;
    for(unsigned r=0;r<16;r++){q->before.gpr[r]=(uint64_t)before->frame.greg[regs[r]];
        need(q->before.gpr[r]==fixture_seed[r],983);}
    q->before.fs_base=before->fs;q->before.gs_base=before->gs;
    need(q->before.gpr[v->base]==s->target,984);
    q->result=li2_decoder_write_footprint(s->pc,s->decoded.bytes,s->length,&q->before,&q->value);
    need(!q->result&&q->value.abi_version==1&&q->value.policy==LI2_WRITE_RANGE&&
         q->value.code==LOCK_EXPECTED_CODE&&q->value.length==s->length&&
         q->value.pc==s->pc&&q->value.next_pc==s->pc+s->length&&
         q->value.first==s->target&&q->value.end==s->target+4,985);
    if(which)++lock_queries.step_queries;else ++lock_queries.native_queries;
}
static void lock_arena(void) {
    long mapped=dispatch(SYS_mmap,LOCK_ARENA,4*PAGE,PROT_NONE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    need(mapped==(long)LOCK_ARENA,986); /* Collision is setup failure; no replacement/fallback. */
    need(!dispatch(SYS_mprotect,LOCK_DATA,PAGE,PROT_READ|PROT_WRITE,0,0,0),987);
    data_page=LOCK_DATA;data_fault=LOCK_FAULT+LOCK_OFFSET;
}
/* Separate genuine failed-operand page: no capture reads an inaccessible page.
   Its four actual snapshots supplement the unchanged full generic record. */
struct lock_fault_record {
    uint64_t magic,version,bytes,control,operand,page,requested_protection,input;
    uint64_t before_protection[2],after_protection[2],captured[2],native_error,step_error;
    unsigned char memory[4][PAGE];
};
static struct lock_fault_record lock_fault;
_Static_assert(sizeof(struct lock_fault_record)==128+4*PAGE,"fixed fault trailer");
static const struct lock_case *lock_case(const struct sample *s) {
    if(s==&negative_sample){need(lock_control_index<32,900);return &lock_fault_cases[lock_control_index];}
    need(s->id>=2000+16*lock_group&&s->id<2016+16*lock_group,900);
    return &lock_cases[s->id-2000-16*lock_group];
}
static void lock_fault_after(unsigned lane_index) {
    need(control==1&&lane_index<2&&data_fault==lock_fault.operand,901);
    uintptr_t page=data_fault&~(PAGE-1);int prot=lock_fault_kind?PROT_READ:PROT_NONE;
    need(actual_protection(data_fault,0)==prot,902);
    need(!RAW(SYS_mprotect,page,PAGE,PROT_READ,0,0,0),903);
    memcpy(lock_fault.memory[2*lane_index+1],(const void *)page,PAGE);
    need(!memcmp(lock_fault.memory[2*lane_index],lock_fault.memory[2*lane_index+1],PAGE),904);
    need(!RAW(SYS_mprotect,page,PAGE,prot,0,0,0),905);
    lock_fault.after_protection[lane_index]=(uint64_t)actual_protection(data_fault,0);
    need(lock_fault.after_protection[lane_index]==(uint64_t)prot,906);
    lock_fault.captured[lane_index]=1;
}
static void lock_inputs(struct sample *s) {
    inputs(s);const struct lock_case *v=lock_case(s);
    /* All GPR values are independent input seeds, not predicted outputs. */
    fixture_seed[0]=v->rax;fixture_seed[v->source]=v->source_value;fixture_seed[v->base]=s->target;
    need(fixture_seed[0]==v->rax&&fixture_seed[v->source]==v->source_value&&
         fixture_seed[v->base]==s->target,988);
    if(s!=&negative_sample)memcpy((void *)(data_page+LOCK_OFFSET),&v->input,4);
    if(s==&negative_sample&&control==1) {
        uintptr_t page=data_fault&~(PAGE-1);unsigned l=s->native_fault?1:0;
        need(!RAW(SYS_mprotect,page,PAGE,PROT_READ|PROT_WRITE,0,0,0),907);
        for(size_t i=0;i<PAGE;i++)((unsigned char *)page)[i]=(unsigned char)(i*13+0x5b);
        memcpy((void *)data_fault,&v->input,4);
        memcpy(lock_fault.memory[2*l],(const void *)page,PAGE);
        if(l)need(!memcmp(lock_fault.memory[0],lock_fault.memory[2],PAGE),908);
        int prot=lock_fault_kind?PROT_READ:PROT_NONE;
        need(!RAW(SYS_mprotect,page,PAGE,prot,0,0,0),909);
        lock_fault.control=1;lock_fault.operand=data_fault;lock_fault.page=page;
        lock_fault.requested_protection=prot;lock_fault.input=v->input;
        lock_fault.before_protection[l]=(uint64_t)actual_protection(data_fault,0);
        need(lock_fault.before_protection[l]==(uint64_t)prot,910);
    }
}
static void lock_prepare(struct sample *s,unsigned index) {
    need(index<LOCK_COUNT,911);s->id=s==&negative_sample?3000+lock_control_index:2000+16*lock_group+index;
    const struct lock_case *v=lock_case(s);s->length=v->length;
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0&&(uintptr_t)reserved<=UINTPTR_MAX-5*PAGE,912);s->mapping=(uintptr_t)reserved+PAGE;
    need(data_page==LOCK_DATA&&data_fault==LOCK_FAULT+LOCK_OFFSET,913);
    s->target=(s==&negative_sample?LOCK_FAULT:LOCK_DATA)+LOCK_OFFSET;
    need((s->target&63)+4<=64&&(s->target&(PAGE-1))+4<=PAGE,914);
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),915);
    need(v->tail>=1&&v->tail<=v->length&&v->base<16&&v->source<16,916);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=PAGE-v->tail;
    s->pc=s->mapping+offset;s->expected_post=s->pc+v->length;
    s->endpoint_int3=v->tail<v->length;s->count=s->endpoint_int3?2:1;
    need(v->length==lock_forms[16*v->source+v->base].length&&!memcmp(v->bytes,lock_forms[16*v->source+v->base].bytes,v->length),917);
    memcpy(s->source+offset,v->bytes,v->length);
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),918);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.code==LOCK_EXPECTED_CODE&&
         s->decoded.length==v->length&&!memcmp(s->decoded.bytes,s->source+offset,v->length),919);
}
static void lock_effects(struct sample *s) {
    const struct lock_case *v=lock_case(s);const struct li2_step_owner *o=&s->owner.step;
    need(s->owner.classification.policy==1&&s->owner.classification.code==LOCK_EXPECTED_CODE&&
         s->owner.classification.flow==LI2_TF_FALLTHROUGH&&s->owner.classification.family==LI2_TF_INTEGER&&
         s->expected_post==s->pc+v->length&&!memcmp(s->decoded.bytes,v->bytes,v->length),920);
    need(fixture_seed[v->base]==s->target&&s->target==data_page+LOCK_OFFSET,921);
    for(unsigned l=0;l<2;l++) {
        const struct state *before=l?&s->step_before:&s->native_before;
        const struct state *after=l?&s->step_endpoint:&s->native_after;
        for(unsigned r=0;r<16;r++) {
            uint64_t expected=r==0?v->rax_after:fixture_seed[r];
            need((uint64_t)before->frame.greg[regs[r]]==fixture_seed[r]&&
                 (uint64_t)after->frame.greg[regs[r]]==expected&&
                 s->live[2*l].gpr[r]==fixture_seed[r]&&s->live[2*l+1].gpr[r]==expected,922);
        }
        need(u32(before->data+LOCK_OFFSET)==v->input&&u32(after->data+LOCK_OFFSET)==v->output,923);
        need(!memcmp(before->stack,after->stack,SUBJECT_BYTES),924);
        for(size_t i=0;i<DATA_BYTES;i++) {
            unsigned char expected=before->data[i];
            if(i>=LOCK_OFFSET&&i<LOCK_OFFSET+4)expected=(unsigned char)(v->output>>(8*(i-LOCK_OFFSET)));
            need(after->data[i]==expected,925);
        }
        need(before->frame.fp_bytes==after->frame.fp_bytes&&
             !memcmp(before->frame.fp,after->frame.fp,before->frame.fp_bytes)&&
             !memcmp(s->actual_fp[2*l],s->actual_fp[2*l+1],xsave_bytes),926);
        need((s->live[2*l+1].rflags&LOCK_MASK)==v->flags&&
             (s->live[2*l].rflags&~LOCK_MASK)==(s->live[2*l+1].rflags&~LOCK_MASK),927);
    }
    need((s->post_flags&LOCK_MASK)==v->flags&&
         (s->initial_flags&~LOCK_MASK)==(s->post_flags&~LOCK_MASK)&&
         !memcmp(o->before.fp,o->after.fp,o->before.fp_bytes),928);
    for(size_t i=0;i<s->count;i++)need(actual_protection(s->pages[i].address,0)==PROT_READ,929);
    need(s->continuation.complete&&actual_protection(s->expected_post,0)==PROT_READ,930);
}
/* The original native handler accepts load ERR4 only. This separate wrapper
   observes actual write/RMW faults: populated PROT_NONE ERR6 or read-only ERR7.
   The original handler, failed-frame comparator and owner remain unchanged. */
static void lock_handler(int sig,siginfo_t *si,void *frame_) {
    if(control==1&&current==&negative_sample&&!lane&&native_phase==1) {
        need(!handling&&si&&frame_,931);handling=1;
        struct sample *s=current;ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;
        need(sig==SIGSEGV&&si->si_signo==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
             (uintptr_t)si->si_addr==data_fault&&(uintptr_t)g[REG_RIP]==s->pc&&
             g[REG_TRAPNO]==14&&g[REG_ERR]==(lock_fault_kind?7:6)&&(uintptr_t)g[REG_CR2]==data_fault,932);
        s->native_fault=1;capture(&s->native_after,uc);permissions(s,PROT_READ);native_phase=2;
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        fixture_vector_clobber();handling=0;return;
    }
    handler(sig,si,frame_);
}
static void lock_install_handler(void) {
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action;
    action.handler=lock_handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;
    action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),933);
}
static void lock_failure(void *context,const struct li2_step_owner *o) {
    struct sample *s=context;
    if(control==1&&s==&negative_sample) {
        need(s->native_fault&&!s->native_complete&&!s->step_endpoint_seen,934);
        need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->pc&&
             s->native_after.frame.greg[REG_TRAPNO]==14&&s->native_after.frame.greg[REG_ERR]==(lock_fault_kind?7:6)&&
             (uintptr_t)s->native_after.frame.greg[REG_CR2]==data_fault&&
             o->after.greg[REG_TRAPNO]==14&&(uintptr_t)o->after.greg[REG_CR2]==data_fault,935);
        for(unsigned i=0;i<16;i++)need(s->native_before.frame.greg[regs[i]]==s->native_after.frame.greg[regs[i]],936);
        need(s->native_before.frame.greg[REG_EFL]==s->native_after.frame.greg[REG_EFL]&&
             s->native_before.frame.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(s->native_before.frame.fp,s->native_after.frame.fp,s->native_before.frame.fp_bytes)&&
             !memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes),937);
        compare_memory(&s->native_before,&s->native_after,938);
        lock_query_before(s,1);
        lock_fault_after(1);
        lock_fault.native_error=(uint64_t)s->native_after.frame.greg[REG_ERR];
        lock_fault.step_error=(uint64_t)o->after.greg[REG_ERR];
        need(lock_fault.captured[0]&&lock_fault.captured[1]&&
             !memcmp(lock_fault.memory[0],lock_fault.memory[3],PAGE),939);
        need(s->native_before.fs==s->native_after.fs&&s->native_before.gs==s->native_after.gs&&
             s->native_before.frame.mask==mask&&s->native_after.frame.mask==mask&&
             s->native_before.frame.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS]&&
             o->after.greg[REG_CSGSFS]==s->native_after.frame.greg[REG_CSGSFS],940);
        need(s->live[0].started==1&&s->live[0].complete==1&&!s->live[0].reserved&&
             s->live[1].started==1&&s->live[1].complete==1&&!s->live[1].reserved&&
             s->live[0].rflags==s->live[1].rflags&&
             !memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[0].selectors,s->live[1].selectors,sizeof(s->live[0].selectors)),941);
    }
    failure(context,o); /* Unchanged actual frame/revoke/sync/held-borrow predicates and dump. */
    need(write_all(3,&lock_fault,sizeof(lock_fault))&&write_all(3,&lock_queries,sizeof(lock_queries)),942);
}
static void lock_pair(struct sample *s) {
    current=s;fixture_target=s->pc;lock_inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    lock_query_before(s,0);
    if(s==&negative_sample&&control==1)lock_fault_after(0);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3||(s==&negative_sample&&control==1))s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    lock_inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,lock_failure},continue_closed};
    int error=li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    lock_query_before(s,1);compare(s);lock_effects(s);
    need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void lock_refusals(void) {
    static const struct {unsigned n;unsigned char b[12];} cases[]={
        {8,{0xf0,0x0f,0xb1,0x0d,0x00,0x00,0x00,0x00}}, /* other_source */
        {5,{0xf0,0x0f,0xb1,0x50,0x00}}, /* base_rax */
        {5,{0xf0,0x0f,0xb1,0x53,0x00}}, /* base_rbx */
        {9,{0xf0,0x0f,0xb1,0x14,0x25,0x00,0x00,0x00,0x00}}, /* sib */
        {9,{0xf0,0x48,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* qword */
        {9,{0x66,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* word */
        {8,{0xf0,0x0f,0xb0,0x15,0x00,0x00,0x00,0x00}}, /* byte */
        {9,{0x67,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* address32 */
        {9,{0x64,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* fs */
        {9,{0x65,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* gs */
        {9,{0x2e,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* cs */
        {9,{0xf0,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* repeat_lock */
        {9,{0xf2,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* xacquire */
        {9,{0xf3,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* xrelease */
        {9,{0xf0,0x44,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* rex_r */
        {9,{0xf0,0x42,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* rex_x */
        {9,{0xf0,0x41,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* rex_b */
        {9,{0xf0,0x40,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* rex_ignored */
        {4,{0xf0,0x0f,0xb1,0xd0}}, /* register */
        {7,{0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00}}, /* missing_dispbyte */
        {9,{0x40,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* prefix_after_rex */
        {10,{0x66,0x66,0xf0,0x0f,0xb1,0x15,0x00,0x00,0x00,0x00}}, /* repeat_operand */
        {2,{0xf0,0x0f}}, /* truncated_opcode */
        {4,{0xf0,0x0f,0xb1,0x15}}, /* truncated_disp */
        {5,{0xf0,0x40,0x0f,0xb1,0x10}}, /* unnecessary_rex */
        {6,{0xf0,0x41,0x0f,0xb1,0x50,0x00}}, /* unnecessary_high_disp8 */
        {5,{0xf0,0x0f,0xb1,0x55,0x01}}, /* rbp_nonzero_disp8 */
        {6,{0xf0,0x41,0x0f,0xb1,0x55,0x01}}, /* r13_nonzero_disp8 */
        {5,{0xf0,0x0f,0xb1,0x14,0x64}}, /* ignored_sib_scale */
        {5,{0xf0,0x0f,0xb1,0x14,0x04}}, /* actual_index_rax */
        {6,{0xf0,0x43,0x0f,0xb1,0x14,0x24}}, /* actual_index_r12 */
        {4,{0xf0,0x0f,0xb1,0x14}}, /* missing_sib */
        {5,{0xf0,0x41,0x0f,0xb1,0x14}}, /* missing_high_sib */
        {5,{0xf0,0x41,0x0f,0xb1,0x55}}, /* missing_mandatory_disp */
        {5,{0xf0,0x0f,0xb1,0x14,0x23}}, /* unnecessary_sib_rbx */
        {5,{0xf0,0x0f,0xb1,0x14,0x20}}, /* unnecessary_sib_rax */
    };
    _Static_assert(sizeof(cases)/sizeof(cases[0])==36,"closed exact CMPXCHG neighbors");
    for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        result.failed_refusal=47+i;
        result.decoder_result=li2_decoder_tf_classify(0x1000,cases[i].b,cases[i].n,&refused_last);
        need(!result.decoder_result&&refused_last.abi_version==1&&refused_last.pc==0x1000&&
             !refused_last.policy&&!refused_last.flow&&!refused_last.family,950+(unsigned)i);
        ++result.refusals;
    }
    result.failed_refusal=SIZE_MAX;
    for(unsigned i=0;i<256;i++) {
        const struct lock_form *f=&lock_forms[i];struct li2_tf_classification c={0};
        need(f->source==i/16&&f->base==i%16&&!li2_decoder_tf_classify(0x1000,f->bytes,f->length,&c)&&
             c.abi_version==1&&c.pc==0x1000&&c.next_pc==0x1000+f->length&&
             c.code==LOCK_EXPECTED_CODE&&c.length==f->length&&c.policy==1&&
             c.flow==LI2_TF_FALLTHROUGH&&c.family==LI2_TF_INTEGER,989);
        ++lock_queries.acceptances;
    }
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)+sizeof(lock_fault)+sizeof(lock_queries)<16*1024*1024,
                   "unchanged complete private record bound including queries");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=LOCK_PAIRS;
    lock_fault.magic=UINT64_C(0x314b434f4c32494c);lock_fault.version=1;lock_fault.bytes=sizeof(lock_fault);
    lock_queries.magic=UINT64_C(0x315942514c32494c);lock_queries.version=1;lock_queries.bytes=sizeof(lock_queries);
    need(stack[0]==1,970);setup(stack);lock_install_handler();
    const char *const *env=(const void *)(stack+3);const char key[]=LOCK_CONTROL_KEY;
    const char group_key[]="LI2_LOCK_CMPXCHG_REGISTER_GROUP=";unsigned group_seen=0;
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(group_key)-1&&!memcmp(env[i],group_key,sizeof(group_key)-1)) {
        need(!group_seen,993);unsigned found=0;
        for(unsigned j=0;j<32;j++)if(same(env[i]+sizeof(group_key)-1,lock_group_names[j])){lock_group=j;found++;}
        need(found==1,994);group_seen=1;
    }
    need(group_seen==1,995);lock_literals(lock_group);lock_queries.group=lock_group;
    for(size_t i=0;env[i];i++)if(length(env[i])>=sizeof(key)-1&&!memcmp(env[i],key,sizeof(key)-1)) {
        need(!control&&lock_group==0,971);unsigned found=0;
        for(unsigned j=0;j<32;j++)if(same(env[i]+sizeof(key)-1,lock_fault_cases[j].name)) {
            lock_control_index=j;lock_fault_kind=j&1;found++;
        }
        need(found==1,972);control=1;
    }
    result.control=control;
    size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    lock_refusals();need(result.refusals==83&&lock_queries.acceptances==256,973);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    lock_arena();
    if(control){lock_prepare(&negative_sample,0);lock_pair(&negative_sample);die(974);}
    for(unsigned i=0;i<LOCK_COUNT;i++){lock_prepare(&samples[i+1],i);lock_pair(&samples[i+1]);}
    need(result.completed==LOCK_PAIRS&&lock_queries.native_queries==LOCK_COUNT&&lock_queries.step_queries==LOCK_COUNT&&
         dump()&&write_all(3,&lock_fault,sizeof(lock_fault))&&write_all(3,&lock_queries,sizeof(lock_queries)),975);
    output("LI2_LOCK_CMPXCHG_REGISTER_TF_PASS group=");number(lock_group);
    output("pairs=17 lock_cmpxchg=16 selftest=1 old_refusal_bytes=47 new_refusal_bytes=36 typed_acceptances=256 footprint_queries=32 full_state=17 full_memory=17 live_endpoints=17\n");
    return 0;
}
