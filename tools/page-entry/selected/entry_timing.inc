/* Explicit observed effect build only. Boot, initialization and selftest finish
   before start. Two RAW timestamps bracket pre-restore entry and the first
   genuinely closed execution unit; no TF, permission or frame edits occur here. */
enum entry_time_route { ET_STEP=4 };
_Static_assert(sizeof(struct li2_lifecycle_page_view)==40,"complete page identity without padding");
_Static_assert(sizeof(struct li2_maps_stats)==64,"complete clock maps observation without padding");
/* Current effect prefix is twelve rows plus optional REP. Old site/sample
   limits remain exact; new origins and entry row fit the existing16MiB capture. */
_Static_assert(13*4096+64*352+11*352+11*352+2*4096<16*1024*1024,
    "complete effect timing reports fit the unchanged capture bound");
static struct {
    unsigned initialized,mode,start_called,started,ingress,armed,complete,first_error;
    unsigned clock_attempted,clock_complete,route,instructions_known;
    long first_detail,clock_result[2];
    uint64_t identity[9],closure[5],ns[2],instructions,repeat_iterations,native_pages,native_refaults;
    struct li2_lifecycle_page_view source;
    struct li2_maps_stats before[2],after[2];
    uint64_t origins[LI2_TIME_SAMPLES][7],origin_count;
} selected_entry_time;
static void entry_need(int ok,unsigned code,long detail) {
    if(!ok) {
        if(!selected_entry_time.first_error) {
            selected_entry_time.first_error=code;selected_entry_time.first_detail=detail;
        }
        li2_run_timing_fail(&selected_run_timing,code,detail);
        fail(code,detail);
    }
}
static int entry_pending(void) {
    return selected_entry_time.mode==LI2_TIME_MEASURE && selected_entry_time.started &&
        !selected_entry_time.complete;
}
static void entry_clock(unsigned index,unsigned active) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    struct li2_run_timing *t=&selected_run_timing;
    entry_need(index<2 && e->clock_attempted==index && e->clock_complete==index &&
        t->initialized && !t->first_error && !t->finalized &&
        !li2_lifecycle_fetch_interlock() && !li2_lifecycle_oneshot_interlock() &&
        li2_rseq_publication_snapshot()->phase==LI2_RP_IDLE &&
        !li2_rseq_publication_snapshot()->first_error &&
        li2_rseq_native_snapshot()->phase==LI2_RN_IDLE &&
        !li2_rseq_native_snapshot()->first_error &&
        li2_rseq_snapshot()->initialized && !li2_rseq_snapshot()->first_error &&
        li2_lifecycle_native_counts()->admissions==li2_lifecycle_native_counts()->closed,
        LI2_TIME_ORDER,16+index);
    e->clock_attempted=index+1;
    li2_maps_stats_read(&e->before[index]);
    entry_need(e->before[index].active==active && !e->before[index].poisoned &&
        !e->before[index].reserved,LI2_TIME_CLOCK,16+index);
    /* Same already-registered exact16B buffer; no additional maps allowance. */
    t->clock_buffer=(struct li2_time_clock){-1,-1};
    e->clock_result[index]=raw(SYS_clock_gettime,4,(long)&t->clock_buffer,0,0,0,0);
    li2_maps_stats_read(&e->after[index]);
    entry_need(!e->clock_result[index],LI2_TIME_CLOCK,e->clock_result[index]);
    entry_need(equal(&e->before[index],&e->after[index],sizeof(e->before[index])),LI2_TIME_CLOCK,18);
    int64_t sec=t->clock_buffer.sec,nsec=t->clock_buffer.nsec;
    entry_need(sec>=0 && nsec>=0 && nsec<1000000000 &&
        (uint64_t)sec<=(UINT64_MAX-(uint64_t)nsec)/UINT64_C(1000000000),LI2_TIME_CLOCK,19);
    uint64_t now=(uint64_t)sec*UINT64_C(1000000000)+(uint64_t)nsec;
    entry_need(!index || now>=e->ns[0],LI2_TIME_ORDER,18);
    e->ns[index]=now;__asm__ volatile("":::"memory");e->clock_complete=index+1;
}
void li2_entry_time_initialize(void) {
    entry_need(!selected_entry_time.initialized && selected_run_timing.initialized &&
        !selected_run_protect_add(0,(uintptr_t)&selected_entry_time,sizeof selected_entry_time) &&
        selected_run_protect_contains(0,(uintptr_t)&selected_entry_time,sizeof selected_entry_time)==1,
        LI2_TIME_IDENTITY,16);
    selected_entry_time.mode=selected_run_timing.config.mode;selected_entry_time.initialized=1;
}
void li2_entry_time_start(uintptr_t target) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    entry_need(e->initialized && !e->start_called && !e->started && !e->first_error,LI2_TIME_REUSE,16);
    e->start_called=1;
    if(e->mode==LI2_TIME_DISCOVERY)return;
    entry_need(e->mode==LI2_TIME_MEASURE && target==original_interpreter.entry && target &&
        target>=original_interpreter.bias && target-original_interpreter.bias==0x1f010 &&
        selected_session.initialized &&
        selected_session.self_test_complete && !selected_selftesting && !handling &&
        selected_flags_known && !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        selected_run_owner.phase==LI2_RUN_EMPTY && !selected_chain.pending &&
        !selected_oneshot_active && !selected_effect_runtime.busy &&
        li2_native_epoch_progress()->phase==LI2_NATIVE_IDLE &&
        li2_lifecycle_query(target,&e->source)==1 && e->source.allocation && e->source.generation &&
        e->source.backing==1 && e->source.logical==(PROT_READ|PROT_EXEC) &&
        e->source.actual==PROT_READ && !e->source.admitted,LI2_TIME_IDENTITY,17);
    const uint64_t identity[]={target,target-original_interpreter.bias,target&~(PAGE-1),
        e->source.allocation,e->source.generation,e->source.offset,e->source.backing,0,0};
    copy(e->identity,identity,sizeof identity);
    e->started=1;entry_clock(0,0);
}
void li2_entry_time_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    if(!entry_pending() || e->ingress)return;
    uint64_t mask=0;struct li2_lifecycle_page_view source={0};
    entry_need(si && uc,LI2_TIME_IDENTITY,18);copy(&mask,&uc->uc_sigmask,8);
    const greg_t *g=uc->uc_mcontext.gregs;
    entry_need(handling && !selected_selftesting && selected_session.self_test_complete &&
        sig==SIGSEGV && si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
        (uintptr_t)g[REG_RIP]==e->identity[0] && (uintptr_t)si->si_addr==e->identity[0] &&
        (uintptr_t)g[REG_CR2]==e->identity[0] && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
        ((uint64_t)g[REG_CSGSFS]&0xffff)==0x33 && mask==SELECTED_MASK && selected_flags_known &&
        (uint64_t)g[REG_EFL]==(selected_logical_flags|SELECTED_RF) &&
        li2_lifecycle_query(e->identity[0],&source)==1 && equal(&source,&e->source,sizeof source),
        LI2_TIME_IDENTITY,19);
    struct li2_maps_stats maps;li2_maps_stats_read(&maps);
    entry_need(maps.active && !maps.poisoned && selected_chain.event_id,LI2_TIME_IDENTITY,20);
    e->identity[7]=maps.handler_id;e->identity[8]=selected_chain.event_id;e->ingress=1;
}
/* The initial measured profile is only the source-bound ld.so entry MOV.
   The following CALL stays outside this first closed unit. No alternate first
   route receives a clock endpoint or qualification. */
void li2_entry_time_arm(void) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    if(!entry_pending() || e->armed)return;
    static const unsigned char source[8]={0x48,0x89,0xe7,0xe8,0x68,0x0d,0x00,0x00};
    const struct li2_decoded *d=&selected_step.request.decoded;
    entry_need(e->ingress && handling && !selected_selftesting &&
        selected_pending_route==SELECTED_OLD_STEP && selected_step_pending &&
        selected_step.phase==LI2_STEP_RUNNING && !selected_step.first_error &&
        d->pc==e->identity[0] && d->length==3 && d->next_pc==d->pc+3 &&
        equal(d->bytes,source,3) && selected_view.length>=sizeof source &&
        equal(selected_view.bytes,source,sizeof source) && selected_borrow.sequence,
        LI2_TIME_IDENTITY,21);
    e->route=ET_STEP;e->closure[0]=selected_borrow.sequence;e->armed=1;
}
void li2_entry_time_step(void) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    if(!entry_pending() || selected_selftesting)return;
    const struct li2_step_owner *o=&selected_step;
    entry_need(e->ingress && e->armed && e->route==ET_STEP && handling && !e->first_error &&
        selected_pending_route==SELECTED_OLD_STEP && !selected_step_pending &&
        o->phase==LI2_STEP_COMPLETE && o->trace_seen && !o->in_handler && !o->first_error &&
        o->request.decoded.pc==e->identity[0] && o->request.decoded.length==3 &&
        (uintptr_t)o->after.greg[REG_RIP]==e->identity[0]+3 &&
        selected_borrow.sequence==e->closure[0] && !li2_lifecycle_fetch_interlock() &&
        selected_chain.event_id>e->identity[8],LI2_TIME_RESET,16);
    e->instructions_known=1;e->instructions=1;
    e->closure[1]=selected_borrow.sequence;e->closure[2]=(uintptr_t)o->after.greg[REG_RIP];
    e->closure[3]=selected_chain.event_id;
    entry_clock(1,1);__asm__ volatile("":::"memory");e->complete=1;
}
void li2_entry_time_run(void) {
    __typeof__(selected_entry_time) *e=&selected_entry_time;
    const struct li2_run_owner *o=&selected_run_history.last_complete;
    /* Preserve all old timing samples; origins are observations of the same
       retained completion, joined without changing its old sample layout. */
    uint64_t n=selected_run_timing.samples_complete;
    if(n!=e->origin_count) {
        entry_need(n==e->origin_count+1 && n<=LI2_TIME_SAMPLES,LI2_TIME_ORDER,19);
        const struct li2_time_sample *s=&selected_run_timing.samples[n-1];
        entry_need(o->entry_event.observed && o->borrow.sequence==s->borrow &&
            ((o->entry_event.number==SIGSEGV && o->entry_event.code==SEGV_ACCERR) ||
             (o->entry_event.number==SIGTRAP && o->entry_event.code==TRAP_TRACE)),LI2_TIME_IDENTITY,25);
        const uint64_t row[]={1,n-1,s->ordinal,s->borrow,s->slot,
            (unsigned)o->entry_event.number,(unsigned)o->entry_event.code};
        copy(e->origins[n-1],row,sizeof row);e->origin_count=n;
    }
}
static void entry_maps_row(struct writer *w,const char *key,const struct li2_maps_stats *m) {
    const uint64_t a[]={m->fresh_calls,m->acquisitions,m->reuses,m->invalidations,m->handler_id,
        m->mutation_epoch,m->active,m->valid,m->poisoned,m->reserved};
    selected_repeat_array(w,key,a,10);
}
void li2_entry_time_origins_report(void) {
    for(size_t i=0;i<selected_entry_time.origin_count && i<LI2_TIME_SAMPLES;i++)
        selected_time_row("LI2_RUN_TIME_ORIGIN ",selected_entry_time.origins[i],7);
}
void li2_entry_time_report(unsigned status,unsigned code,long detail) {
    const __typeof__(selected_entry_time) *e=&selected_entry_time;
    unsigned qualified=!status && !code && e->initialized && !e->first_error &&
        selected_run_timing.qualified && (e->mode==LI2_TIME_DISCOVERY ? !e->started && !e->clock_attempted :
        e->started && e->ingress && e->armed && e->complete && e->clock_attempted==2 && e->clock_complete==2);
    struct writer w={.used=0};text(&w,"LI2_ENTRY_TIME {\"version\":1");
#define ET_FIELD(name,value) field(&w,",\"" name "\":",(uint64_t)(value))
    ET_FIELD("status",status);ET_FIELD("failure_code",code);ET_FIELD("detail_abs",selected_repeat_abs(detail));
    ET_FIELD("detail_negative",detail<0);ET_FIELD("mode",e->mode);ET_FIELD("initialized",e->initialized);
    ET_FIELD("started",e->started);ET_FIELD("ingress",e->ingress);ET_FIELD("armed",e->armed);
    ET_FIELD("complete",e->complete);ET_FIELD("qualified",qualified);ET_FIELD("observer_error",e->first_error);
    ET_FIELD("observer_detail_abs",selected_repeat_abs(e->first_detail));ET_FIELD("observer_detail_negative",e->first_detail<0);
    ET_FIELD("clock_attempted",e->clock_attempted);ET_FIELD("clock_complete",e->clock_complete);ET_FIELD("clock_id",4);
    ET_FIELD("route",e->route);ET_FIELD("instructions_known",e->instructions_known);ET_FIELD("instructions",e->instructions);
    ET_FIELD("repeat_iterations",e->repeat_iterations);ET_FIELD("native_pages",e->native_pages);ET_FIELD("native_refaults",e->native_refaults);
#undef ET_FIELD
    selected_repeat_array(&w,",\"identity\":",e->identity,9);selected_repeat_array(&w,",\"closure\":",e->closure,5);
    selected_repeat_array(&w,",\"ns\":",e->ns,2);
    const uint64_t results[]={selected_repeat_abs(e->clock_result[0]),e->clock_result[0]<0,
        selected_repeat_abs(e->clock_result[1]),e->clock_result[1]<0};
    selected_repeat_array(&w,",\"clock_results\":",results,4);
    entry_maps_row(&w,",\"maps_start_before\":",&e->before[0]);entry_maps_row(&w,",\"maps_start_after\":",&e->after[0]);
    entry_maps_row(&w,",\"maps_end_before\":",&e->before[1]);entry_maps_row(&w,",\"maps_end_after\":",&e->after[1]);
    text(&w,"}\n");selected_time_line(&w);
}
