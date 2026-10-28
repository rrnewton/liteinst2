/* Named failures use actual effects or explicitly nonissued negative returns.
   No supplied success result, fabricated #PF/TRACE, or retry is permitted. */
enum { CTL_OPERAND=1,CTL_UNOWNED,CTL_SOURCE,CTL_ALIAS,CTL_GENERATION,
       CTL_OPEN,CTL_SYNC,CTL_REVOKE,CTL_NESTED,CTL_INT3,CTL_REPLAY,CTL_COUNT=11 };
static const char *const control_names[]={"none","operand-fault","unowned-continuation",
 "source-cow-change","writable-alias","generation-reuse","open-error","sync-error",
 "revoke-error","nested-tgkill","wrong-trace-int3","consumed-proof-replay"};
struct chain_control {
    uint64_t bytes,mode,issued_effects,injected_returns,signal_count,replay_attempts,verified;
    unsigned entered,injected,pending_raw,raw_issued,raw_complete;
    long number,args[6],actual_result,returned_result,effects[5];
    long sender_pid,sender_uid,expected_pid,expected_uid;int signal,code,error;
    uintptr_t alias,unowned;
    int alias_prot,cleanup_prot[2];
    unsigned char changed_source[15];
    struct li2_fetch_ref before_ref,after_ref;
    struct li2_fetch_page before_page,after_page;
    struct li2_tf_trace_entry replayed;
    struct state delivered;
};
static struct chain_control ctl;
/* Defined only by the exact wrapper translation unit in this fixture build.
   Re-enters the private consumer with the retained actual TRACE event after
   its original consumption. It does not manufacture a valid capability. */
void li2_chain_test_consume_actual(struct li2_tf_chain *,int,siginfo_t *,ucontext_t *);
static long kernel(long n,long a,long b,long c,long d,long e,long f) {
    li2_maps_before_raw(n,a,b,c,d,e,f);
    long r=fixture_kernel_raw(n,a,b,c,d,e,f);
    li2_maps_after_raw(n,a,b,c,d,e,f,r);return r;
}
static long chain_control_raw(long n,long a,long b,long c,long d,long e,long f) {
    if(!mode||which!=2||!li2_chain_record.chain.pending||ctl.injected)return kernel(n,a,b,c,d,e,f);
    struct li2_tf_chain_slot *s=&li2_chain_record.chain.slots[li2_chain_record.chain.active];
    struct li2_step_owner *o=&s->owner.step;
    int opening=n==SYS_mprotect&&b==PAGE&&c==(PROT_READ|PROT_EXEC)&&o->phase==LI2_STEP_OPENING;
    int open_sync=n==SYS_membarrier&&a==32&&o->phase==LI2_STEP_OPENING&&o->opened[0];
    int revoking=n==SYS_mprotect&&b==PAGE&&c==PROT_READ&&o->phase==LI2_STEP_REVOKING;
    if((mode==CTL_OPEN&&opening)||(mode==CTL_SYNC&&open_sync)||(mode==CTL_REVOKE&&revoking)) {
        ctl.injected=1;ctl.pending_raw=1;ctl.number=n;long args[6]={a,b,c,d,e,f};memcpy(ctl.args,args,sizeof args);
        ++ctl.injected_returns;ctl.returned_result=mode==CTL_OPEN?-EACCES:-EIO;
        /* The normal invalidation gateway still sees a failed attempt. */
        li2_maps_before_raw(n,a,b,c,d,e,f);li2_maps_after_raw(n,a,b,c,d,e,f,ctl.returned_result);
        ctl.raw_complete=1;return ctl.returned_result;
    }
    if((mode==CTL_NESTED||mode==CTL_INT3)&&opening) {
        ctl.injected=1;ctl.pending_raw=1;ctl.number=n;long args[6]={a,b,c,d,e,f};memcpy(ctl.args,args,sizeof args);
        if(mode==CTL_NESTED) {
            ++ctl.signal_count;ctl.actual_result=kernel(SYS_tgkill,session.pid,session.tid,SIGTRAP,0,0,0);
        } else {
            ++ctl.signal_count;__asm__ volatile("int3":::"memory");
        }
        die(380); /* The original mprotect was never issued. */
    }
    if(mode==CTL_REPLAY&&n==SYS_getpid&&s->origin==2&&o->phase==LI2_STEP_ARMED&&
       o->in_handler&&li2_chain_record.chain.entry.sequence&&!li2_chain_record.chain.entry.valid) {
        ctl.injected=1;++ctl.replay_attempts;ctl.replayed=li2_chain_record.chain.entry;
        need(active_info&&active_context&&active_info->si_code==TRAP_TRACE,381);
        li2_chain_test_consume_actual(&li2_chain_record.chain,SIGTRAP,active_info,active_context);die(382);
    }
    return kernel(n,a,b,c,d,e,f);
}
static void chain_control_before_entry(void) {
    if(!mode||ctl.entered)return;
    ctl.entered=1;ctl.before_ref=active_ref;ctl.before_page=active_view.pages[0];
    if(mode==CTL_SOURCE) {
        uintptr_t page=li2_chain_record.pc&~(PAGE-1);
        ctl.effects[0]=kernel(SYS_mprotect,page,PAGE,PROT_READ|PROT_WRITE,0,0,0);need(!ctl.effects[0],383);
        *(volatile unsigned char *)li2_chain_record.pc^=1;++ctl.issued_effects;
        ctl.effects[1]=kernel(SYS_mprotect,page,PAGE,PROT_READ,0,0,0);need(!ctl.effects[1],384);
        memcpy(ctl.changed_source,(const void *)li2_chain_record.pc,sizeof ctl.changed_source);
    } else if(mode==CTL_ALIAS) {
        ctl.effects[0]=kernel(SYS_mmap,0,CODE_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE,program_fd,PAGE);
        need(ctl.effects[0]>0,385);ctl.alias=(uintptr_t)ctl.effects[0];++ctl.issued_effects;
        ctl.alias_prot=actual_protection(ctl.alias,0);need(ctl.alias_prot==(PROT_READ|PROT_WRITE),386);
    } else if(mode==CTL_GENERATION) {
        release_actual();ctl.effects[0]=dispatch(SYS_munmap,li2_chain_record.mapping,CODE_BYTES,0,0,0,0);need(!ctl.effects[0],387);
        ctl.effects[1]=dispatch(SYS_mmap,li2_chain_record.mapping,CODE_BYTES,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_FIXED_NOREPLACE,program_fd,PAGE);
        need(ctl.effects[1]==(long)li2_chain_record.mapping,388);++ctl.issued_effects;
        fetch_actual(li2_chain_record.pc);ctl.after_ref=active_ref;ctl.after_page=active_view.pages[0];
        need(ctl.after_ref.sequence!=ctl.before_ref.sequence&&
             ctl.after_page.generation!=ctl.before_page.generation,389);
        active_ref=ctl.before_ref; /* Exact retained old reference, not edited tuple. */
    }
}
static void chain_control_event(int sig,siginfo_t *si,ucontext_t *uc) {
    need(si&&uc,390);
    if(which==0) {
        if(mode==CTL_OPERAND)need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
            (uintptr_t)si->si_addr==data_fault&&(uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==li2_chain_record.pc+3&&
            uc->uc_mcontext.gregs[REG_TRAPNO]==14&&uc->uc_mcontext.gregs[REG_ERR]==4,391);
        else if(mode==CTL_UNOWNED)need(sig==SIGTRAP&&si->si_code==SI_KERNEL&&!si->si_errno&&
            uc->uc_mcontext.gregs[REG_TRAPNO]==3&&!uc->uc_mcontext.gregs[REG_ERR]&&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==ctl.unowned+1,392);
        else return;
        active_lane()->fault=1;return;
    }
    ctl.signal=sig;ctl.code=si->si_code;ctl.error=si->si_errno;capture(&ctl.delivered,uc);
    if(mode==CTL_NESTED) {
        need(ctl.signal_count==1&&sig==SIGTRAP&&si->si_signo==SIGTRAP&&si->si_code==SI_TKILL&&
             !si->si_errno&&si->si_pid==ctl.expected_pid&&si->si_uid==(unsigned)ctl.expected_uid&&
             ctl.expected_pid==session.pid&&ctl.expected_uid==kernel(SYS_getuid,0,0,0,0,0,0),393);
        ctl.sender_pid=si->si_pid;ctl.sender_uid=si->si_uid;
    } else if(mode==CTL_INT3)need(ctl.signal_count==1&&sig==SIGTRAP&&si->si_signo==SIGTRAP&&
        si->si_code==SI_KERNEL&&!si->si_errno&&uc->uc_mcontext.gregs[REG_TRAPNO]==3&&!uc->uc_mcontext.gregs[REG_ERR],394);
}
static _Noreturn void chain_expected(unsigned code,long detail) {
    static const unsigned expected[]={0,LI2_STEP_FOREIGN_EVENT,LI2_TF_CONTINUATION,
        LI2_STEP_PAGE_BINDING,LI2_STEP_PAGE_BINDING,LI2_CHAIN_PREPARE,
        LI2_STEP_OPEN,LI2_STEP_SYNC_OPEN,LI2_STEP_REVOKE,LI2_STEP_FOREIGN_EVENT,
        LI2_STEP_FOREIGN_EVENT,LI2_CHAIN_ORIGIN};
    need(mode&&mode<=CTL_COUNT&&code==expected[mode]&&!result.fixture_failure,395);
    struct li2_tf_chain_slot *s=&li2_chain_record.chain.slots[li2_chain_record.chain.active];
    const struct li2_step_owner *o=&s->owner.step;
    need(li2_chain_record.completed_lanes<=1&&!li2_chain_record.lanes[2].complete&&li2_chain_record.chain.first_error==code,396);
    if(mode==CTL_OPERAND||mode==CTL_UNOWNED) {
        const struct li2_step_frame *f=mode==CTL_OPERAND?&s->unexpected:&o->after;
        const struct state *n=&li2_chain_record.lanes[0].after;
        need(li2_chain_record.lanes[0].fault&&f->initialized==f->fp_bytes&&f->fp_bytes==n->frame.fp_bytes,397);
        for(unsigned i=0;i<16;i++)need(f->greg[regs[i]]==n->frame.greg[regs[i]],398);
        uint64_t flags=(uint64_t)f->greg[REG_EFL];
        need((flags&~LI2_STEP_TF)==(uint64_t)n->frame.greg[REG_EFL],399);
        need(!memcmp(f->fp,n->frame.fp,f->fp_bytes)&&!memcmp((void *)subject,n->stack,SUBJECT_BYTES)&&
             !memcmp((void *)data_page,n->data,DATA_BYTES),400);
        if(mode==CTL_OPERAND)need(s->unexpected_frame_observed&&!o->trace_seen&&
            (uintptr_t)f->greg[REG_RIP]==li2_chain_record.pc+3&&f->greg[REG_ERR]==4&&
            s->origin==2&&li2_chain_record.chain.steps==1,401);
        else need(o->trace_seen&&s->owner.actual_post_pc==ctl.unowned&&s->query.attempted&&
            !s->query.complete&&s->query.result==LI2_FETCH_PAGE,402);
    }
    if(mode==CTL_SOURCE)need(ctl.issued_effects==1&&s->fetch.progress.first_error==LI2_FETCH_SOURCE,403);
    if(mode==CTL_ALIAS)need(ctl.issued_effects==1&&ctl.alias&&s->fetch.progress.first_error&&
        actual_protection(ctl.alias,0)==(PROT_READ|PROT_WRITE),404);
    if(mode==CTL_GENERATION)need(ctl.issued_effects==1&&ctl.after_ref.sequence!=ctl.before_ref.sequence&&
        ctl.after_page.generation!=ctl.before_page.generation&&!o->open_started[0],405);
    if(mode>=CTL_OPEN&&mode<=CTL_REVOKE)need(ctl.injected_returns==1&&!ctl.raw_issued&&ctl.raw_complete&&
        ctl.returned_result==(mode==CTL_OPEN?-EACCES:-EIO)&&detail==ctl.returned_result,406);
    if(mode==CTL_NESTED||mode==CTL_INT3)need(ctl.signal_count==1&&ctl.pending_raw&&!ctl.raw_issued&&
        !ctl.raw_complete&&s->unexpected_frame_observed,407);
    if(mode==CTL_REPLAY)need(ctl.replay_attempts==1&&!ctl.replayed.valid&&
        li2_chain_record.chain.steps==1&&!o->open_started[0]&&li2_chain_record.chain.slots[li2_chain_record.chain.active^1].release.complete,408);
    for(size_t i=0;i<o->request.page_count;i++)if(o->open_started[i]) {
        need(o->revoke_started[i]&&o->revoke_sync_started,409);
        ctl.cleanup_prot[i]=actual_protection(o->request.pages[i].address,0);
        if(mode==CTL_REVOKE)need(o->revoke_result[i]==-EIO&&!o->revoked[i]&&
             ctl.cleanup_prot[i]==(PROT_READ|PROT_EXEC),410);
        else need(!o->revoke_result[i]&&o->revoked[i]&&ctl.cleanup_prot[i]==PROT_READ,411);
    }
    need(!li2_decoder_stats(&li2_chain_record.final_stats)&&!memcmp(&li2_chain_record.initial_stats,&li2_chain_record.final_stats,sizeof li2_chain_record.initial_stats),412);
    li2_chain_record.verified_failure=1;ctl.verified=1;ctl.bytes=sizeof ctl;
    need(chain_dump(),413);
    output("LI2_CHAIN_EXPECTED_FAILURE ");output(control_names[mode]);output("\n");
    (void)kernel(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static unsigned decimal(const char *s) {
    unsigned n=0;need(*s!=0,414);
    while(*s){need(*s>='0'&&*s<='9'&&n<=100,415);n=n*10+(unsigned)(*s++-'0');}return n;
}
static void chain_parse_environment(unsigned long *stack) {
    const char *const *env=(const void *)(stack+stack[0]+2);unsigned seen=0;
    for(size_t i=0;env[i];i++) {
        if(length(env[i])>=15&&!memcmp(env[i],"LI2_CHAIN_CASE=",15)){need(!(seen&1),416);seen|=1;case_id=decimal(env[i]+15);}
        if(length(env[i])>=18&&!memcmp(env[i],"LI2_CHAIN_CONTROL=",18)){need(!(seen&2),417);seen|=2;mode=decimal(env[i]+18);}
    }
    need(case_id<CHAIN_CASES&&mode<=CTL_COUNT,418);
    if(mode==CTL_OPERAND)case_id=4;
    else if(mode==CTL_UNOWNED)case_id=6;
    else if(mode)case_id=0;
}
static void chain_control_run(void) {
    ctl.mode=mode;ctl.expected_pid=kernel(SYS_getpid,0,0,0,0,0,0);
    ctl.expected_uid=kernel(SYS_getuid,0,0,0,0,0,0);
    need(ctl.expected_pid==session.pid&&ctl.expected_uid>=0,423);
    if(mode==CTL_UNOWNED) {
        long page=kernel(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(page>0,419);
        *(unsigned char *)(uintptr_t)page=0xcc;
        need(!kernel(SYS_mprotect,page,PAGE,PROT_READ|PROT_EXEC,0,0,0),420);ctl.unowned=(uintptr_t)page;
    }
    if(mode==CTL_OPERAND||mode==CTL_UNOWNED) {
        which=0;program_inputs();fixture_enter();struct chain_lane *l=active_lane();
        need(l->fault&&!l->complete,421);l->live[0]=fixture_live_before;l->live[1]=fixture_live_after;
        memcpy(l->fp[0],fixture_fp_before,xsave_bytes);memcpy(l->fp[1],fixture_fp_after,xsave_bytes);
    }
    which=2;program_inputs();fixture_enter();die(422);
}

static void chain_control_inputs(void) {
    if(mode==CTL_OPERAND)fixture_seed[6]=data_fault;
    if(mode==CTL_UNOWNED)fixture_seed[2]=ctl.unowned;
}

static int chain_control_dump(void) { ctl.bytes=sizeof ctl;return write_all(3,&ctl,sizeof ctl); }
