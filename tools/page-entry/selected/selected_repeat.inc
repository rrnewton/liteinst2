/* Canonical F3 48 AB only. The unchanged owner executes original bytes and
   validates every actual TRACE; no ordinary classifier permission is added. */
static int selected_repeat_continue(void *context,uintptr_t pc) {
    (void)context;
    if(selected_repeat_queries==UINT64_MAX)return LI2_REPEAT_OVERFLOW;
    if(selected_repeat_query.attempted) {
        if(!selected_repeat_query.complete || !selected_repeat_query.page_observed ||
           selected_repeat_query.result)return LI2_FETCH_STATE;
        /* Keep the preceding successful output before resetting its current
           slot. li2_lifecycle_tf_continuation rejects an attempted output. */
        selected_repeat_previous_query=selected_repeat_query;
        selected_repeat_query=(struct li2_tf_continuation){0};
    }
    ++selected_repeat_queries;
    return li2_lifecycle_tf_continuation(&selected_repeat_borrow,pc,&selected_repeat_query);
}
static void selected_repeat_begin(int sig,siginfo_t *si,ucontext_t *context,uint64_t flags) {
    checked(!selected_selftesting && !selected_step_pending &&
            selected_pending_route==SELECTED_NO_STEP &&
            li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,660,0);
    checked((selected_repeat.step.phase==LI2_STEP_EMPTY && !selected_repeat.step.session) ||
            (selected_repeat.step.phase==LI2_STEP_COMPLETE && !selected_repeat.step.first_error &&
             selected_repeat.final && selected_repeat.continuation_complete &&
             selected_repeat_query.complete && !selected_repeat_query.result &&
             selected_repeat_release_complete),661,0);
    checked(selected_repeat_attempts!=UINT64_MAX,662,0);
    selected_repeat=(struct li2_repeat_owner){0};
    selected_repeat_request=(struct li2_step_request){.decoded=selected_decoded,.original_flags=flags};
    selected_repeat_borrow=selected_borrow;
    selected_repeat_borrow_held=li2_lifecycle_fetch_progress()->held;
    selected_repeat_query=(struct li2_tf_continuation){0};
    selected_repeat_previous_query=(struct li2_tf_continuation){0};
    selected_repeat_queries=0;
    selected_repeat_release_started=0;selected_repeat_release_complete=0;selected_repeat_release_result=0;
    ++selected_repeat_attempts;
    uintptr_t first=selected_decoded.pc&~(PAGE-1),last=(selected_decoded.next_pc-1)&~(PAGE-1);
    selected_repeat_request.page_count=first==last?1:2;
    checked(selected_repeat_request.page_count<=selected_view.page_count,663,0);
    for(size_t i=0;i<selected_repeat_request.page_count;i++) {
        const struct li2_fetch_page *p=&selected_view.pages[i];
        selected_repeat_request.pages[i]=(struct li2_step_page){p->address,p->allocation,p->generation,p->offset,PROT_READ,PROT_READ|PROT_EXEC};
    }
    const struct li2_tf_hooks hooks={{0,selected_authenticate,selected_step_failure},selected_repeat_continue};
    selected_pending_route=SELECTED_REPEAT;selected_step_pending=1;
    int error=li2_repeat_arm(&selected_repeat,&selected_session,&hooks,&selected_repeat_request);
    if(error)li2_repeat_abort(&selected_repeat,(unsigned)error,0);
    selected_initialized();
    li2_repeat_begin(&selected_repeat,sig,si,context);
}
static void selected_repeat_trace(int sig,siginfo_t *si,ucontext_t *context) {
    li2_repeat_trace(&selected_repeat,sig,si,context);
    const struct li2_repeat_owner *o=&selected_repeat;
    const struct li2_step_owner *p=&o->step;
    checked(!p->first_error && p->trace_seen && o->traces &&
            o->closed_cycles==o->traces && o->continuation_started &&
            o->continuation_complete && !o->continuation_result &&
            selected_repeat_queries==o->traces && selected_repeat_query.attempted &&
            selected_repeat_query.page_observed && selected_repeat_query.complete &&
            !selected_repeat_query.result && selected_repeat_query.pc==o->actual_post_pc &&
            (uintptr_t)context->uc_mcontext.gregs[REG_RIP]==o->actual_post_pc,664,0);
    checked(selected_repeat_traces!=UINT64_MAX,665,0);++selected_repeat_traces;
    if(p->phase==LI2_STEP_RUNNING) {
        checked(!o->final && o->remaining && o->reopened_cycles==o->traces &&
                !selected_repeat_release_started && !selected_repeat_release_complete &&
                li2_lifecycle_fetch_interlock()==LI2_FETCH_BUSY,666,0);
        for(size_t i=0;i<p->request.page_count;i++)
            checked(p->open_started[i] && p->opened[i] && !p->open_result[i] &&
                    !p->revoke_started[i] && !p->revoked[i],667,i);
        checked(!p->open_sync && !p->revoke_sync_started &&
                (uint64_t)context->uc_mcontext.gregs[REG_EFL]==o->actual_post_flags,668,0);
        return;
    }
    checked(p->phase==LI2_STEP_COMPLETE && o->final && !o->remaining &&
            o->reopened_cycles==o->traces-1 && p->revoke_sync_started && !p->revoke_sync,669,0);
    for(size_t i=0;i<p->request.page_count;i++)
        checked(p->open_started[i] && p->opened[i] && !p->open_result[i] &&
                p->revoke_started[i] && p->revoked[i] && !p->revoke_result[i],670,i);
    checked(selected_repeat_steps!=UINT64_MAX,671,0);
    selected_repeat_release_started=1;
    selected_repeat_release_result=li2_lifecycle_fetch_release(&selected_repeat_borrow);
    selected_repeat_borrow_held=li2_lifecycle_fetch_progress()->held;
    checked(!selected_repeat_release_result,672,selected_repeat_release_result);
    checked(!selected_repeat_borrow_held,674,0);
    selected_repeat_release_complete=1;
    selected_logical_flags=(uint64_t)context->uc_mcontext.gregs[REG_EFL];
    checked(!(selected_logical_flags&(SELECTED_TF|SELECTED_RF)) &&
            selected_logical_flags==(o->actual_post_flags&~SELECTED_TF) &&
            selected_logical_flags==p->request.original_flags,673,0);
    selected_flags_known=1;++selected_repeat_steps;
    selected_step_pending=0;selected_pending_route=SELECTED_NO_STEP;
    /* Last owner, both query outputs and release outcome remain installed
       until the next independently admitted REP attempt can prove reuse. */
}

/* A separate closed numeric schema; the old LI2_LOADER writer and every old
   field stay unchanged. Signed observations use adjacent magnitude/sign words.
   REPORT.json binds the exact array field positions and worst-case byte bound. */
_Static_assert(3926<=sizeof(((struct writer *)0)->bytes),"bounded REP report");
static uint64_t selected_repeat_abs(long n) {
    return n<0?0ULL-(uint64_t)n:(uint64_t)n;
}
static void selected_repeat_array(struct writer *w,const char *key,const uint64_t *v,size_t n) {
    text(w,key);text(w,"[");
    for(size_t i=0;i<n;i++){if(i)text(w,",");number(w,v[i]);}
    text(w,"]");
}
static void selected_repeat_query_report(struct writer *w,const char *key,const struct li2_tf_continuation *q) {
    const uint64_t v[]={q->pc,q->attempted,q->page_observed,q->complete,
        selected_repeat_abs(q->result),q->result<0,
        selected_repeat_abs(q->maps.fd),q->maps.fd<0,
        selected_repeat_abs(q->maps.last_read),q->maps.last_read<0,
        selected_repeat_abs(q->maps.close_result),q->maps.close_result<0,
        q->maps.bytes,q->maps.rows,q->maps.opened,q->maps.close_started,q->maps.closed,
        q->page.address,q->page.allocation,q->page.generation,q->page.offset,q->page.logical,q->page.closed_prot,
        selected_repeat_abs(q->backing.retained_fd),q->backing.retained_fd<0,
        selected_repeat_abs(q->backing.seals),q->backing.seals<0,
        selected_repeat_abs(q->backing.stat_result),q->backing.stat_result<0,
        q->backing.seals_observed,q->backing.stat_observed};
    selected_repeat_array(w,key,v,sizeof(v)/sizeof(v[0]));
}
static void selected_repeat_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};
    const struct li2_repeat_owner *o=&selected_repeat;
    const struct li2_step_owner *p=&o->step;
    const struct li2_step_request *r=&selected_repeat_request;
    const struct li2_repeat_permissions *last=&o->last_closed;
    text(&w,"LI2_REPEAT {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"attempts\":",selected_repeat_attempts);field(&w,",\"completed\":",selected_repeat_steps);
    field(&w,",\"traces\":",selected_repeat_traces);field(&w,",\"queries\":",selected_repeat_queries);
    field(&w,",\"route\":",selected_pending_route);field(&w,",\"pending\":",selected_step_pending);
    const uint64_t request[]={r->decoded.pc,r->decoded.next_pc,r->decoded.code,r->decoded.length,r->decoded.available,
        (uint64_t)r->decoded.bytes[0]|((uint64_t)r->decoded.bytes[1]<<8)|((uint64_t)r->decoded.bytes[2]<<16),
        r->original_flags,r->page_count};
    selected_repeat_array(&w,",\"request\":",request,sizeof(request)/sizeof(request[0]));
    const uint64_t source0[]={r->pages[0].address,r->pages[0].object,r->pages[0].generation,r->pages[0].offset,
        (unsigned)r->pages[0].closed_prot,(unsigned)r->pages[0].open_prot};
    const uint64_t source1[]={r->pages[1].address,r->pages[1].object,r->pages[1].generation,r->pages[1].offset,
        (unsigned)r->pages[1].closed_prot,(unsigned)r->pages[1].open_prot};
    selected_repeat_array(&w,",\"source0\":",source0,sizeof(source0)/sizeof(source0[0]));
    selected_repeat_array(&w,",\"source1\":",source1,sizeof(source1)/sizeof(source1[0]));
    const uint64_t owner[]={p->phase,p->first_error,selected_repeat_abs(p->first_detail),p->first_detail<0,
        p->in_handler,p->trace_seen,o->unexpected_frame_observed};
    selected_repeat_array(&w,",\"owner\":",owner,sizeof(owner)/sizeof(owner[0]));
    const uint64_t event[]={selected_repeat_abs(p->signal_number),p->signal_number<0,
        selected_repeat_abs(p->signal_code),p->signal_code<0,selected_repeat_abs(p->signal_errno),p->signal_errno<0,p->signal_address};
    selected_repeat_array(&w,",\"event\":",event,sizeof(event)/sizeof(event[0]));
    const uint64_t progress[]={o->initial_count,o->remaining,o->traces,o->closed_cycles,o->reopened_cycles,o->final,
        o->actual_post_pc,o->actual_post_flags,o->continuation_started,o->continuation_complete,
        selected_repeat_abs(o->continuation_result),o->continuation_result<0};
    selected_repeat_array(&w,",\"progress\":",progress,sizeof(progress)/sizeof(progress[0]));
    const uint64_t frames[]={p->before.greg[REG_RIP],p->before.greg[REG_EFL],p->before.greg[REG_RCX],p->before.greg[REG_RDI],
        p->before.greg[REG_RSP],p->before.fp_bytes,p->before.initialized,
        p->after.greg[REG_RIP],p->after.greg[REG_EFL],p->after.greg[REG_RCX],p->after.greg[REG_RDI],
        p->after.greg[REG_RSP],p->after.fp_bytes,p->after.initialized};
    selected_repeat_array(&w,",\"frames\":",frames,sizeof(frames)/sizeof(frames[0]));
    const uint64_t io[]={p->open_started[0]|(p->open_started[1]<<1),p->opened[0]|(p->opened[1]<<1),
        p->revoke_started[0]|(p->revoke_started[1]<<1),p->revoked[0]|(p->revoked[1]<<1),
        selected_repeat_abs(p->open_sync),p->open_sync<0,p->revoke_sync_started,
        selected_repeat_abs(p->revoke_sync),p->revoke_sync<0,
        selected_repeat_abs(p->open_result[0]),p->open_result[0]<0,selected_repeat_abs(p->open_result[1]),p->open_result[1]<0,
        selected_repeat_abs(p->revoke_result[0]),p->revoke_result[0]<0,selected_repeat_abs(p->revoke_result[1]),p->revoke_result[1]<0};
    selected_repeat_array(&w,",\"io\":",io,sizeof(io)/sizeof(io[0]));
    const uint64_t closed[]={last->open_started[0]|(last->open_started[1]<<1),last->opened[0]|(last->opened[1]<<1),
        last->revoke_started[0]|(last->revoke_started[1]<<1),last->revoked[0]|(last->revoked[1]<<1),
        selected_repeat_abs(last->open_sync),last->open_sync<0,last->revoke_sync_started,
        selected_repeat_abs(last->revoke_sync),last->revoke_sync<0,
        selected_repeat_abs(last->open_result[0]),last->open_result[0]<0,selected_repeat_abs(last->open_result[1]),last->open_result[1]<0,
        selected_repeat_abs(last->revoke_result[0]),last->revoke_result[0]<0,selected_repeat_abs(last->revoke_result[1]),last->revoke_result[1]<0};
    selected_repeat_array(&w,",\"last_closed\":",closed,sizeof(closed)/sizeof(closed[0]));
    selected_repeat_query_report(&w,",\"query\":",&selected_repeat_query);
    selected_repeat_query_report(&w,",\"previous_query\":",&selected_repeat_previous_query);
    const uint64_t release[]={selected_repeat_release_started,selected_repeat_release_complete,
        selected_repeat_abs(selected_repeat_release_result),selected_repeat_release_result<0};
    selected_repeat_array(&w,",\"release\":",release,sizeof(release)/sizeof(release[0]));
    const uint64_t held[]={selected_repeat_borrow.sequence,selected_repeat_borrow_held};
    selected_repeat_array(&w,",\"borrow\":",held,sizeof(held)/sizeof(held[0]));
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
