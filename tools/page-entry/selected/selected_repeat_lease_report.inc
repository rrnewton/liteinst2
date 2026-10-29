/* Separate ordered numeric row: retained transfers never count as closes. */
_Static_assert(4095<=sizeof(((struct writer *)0)->bytes),"bounded REP lease report");
static void selected_repeat_lease_report(unsigned status,unsigned code,long detail) {
    struct writer w={.used=0};
    const struct li2_repeat_lease_owner *o=&selected_repeat_lease;
    const struct li2_repeat_owner *r=&o->repeat;
    const struct li2_step_owner *p=&r->step;
    const struct li2_step_request *q=&p->request;
    const struct li2_repeat_custody_observation *c=li2_repeat_custody_progress();
    const struct li2_fetch_backing *b=&c->last_backing;
    const struct li2_repeat_lease_registration *reg=&o->registration;
    text(&w,"LI2_REPEAT_LEASE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"attempts\":",o->attempts);field(&w,",\"completed\":",o->completed);
    field(&w,",\"traces\":",o->total_traces);field(&w,",\"retained\":",o->total_retained);
    field(&w,",\"closes\":",o->total_closes);field(&w,",\"releases\":",o->total_releases);
    field(&w,",\"queries\":",selected_repeat_lease_queries);
    field(&w,",\"route\":",selected_pending_route);field(&w,",\"pending\":",selected_step_pending);
    const uint64_t request[]={q->decoded.pc,q->decoded.next_pc,q->decoded.code,q->decoded.length,q->decoded.available,
        (uint64_t)q->decoded.bytes[0]|((uint64_t)q->decoded.bytes[1]<<8)|((uint64_t)q->decoded.bytes[2]<<16),
        q->original_flags,q->page_count};
    selected_repeat_array(&w,",\"request\":",request,sizeof request/sizeof request[0]);
    const uint64_t source[]={q->pages[0].address,q->pages[0].object,q->pages[0].generation,q->pages[0].offset,
        (unsigned)q->pages[0].closed_prot,(unsigned)q->pages[0].open_prot};
    selected_repeat_array(&w,",\"source\":",source,sizeof source/sizeof source[0]);
    const uint64_t owner[]={p->phase,p->first_error,selected_repeat_abs(p->first_detail),p->first_detail<0,
        p->in_handler,p->trace_seen,o->unexpected_observed,o->nested_observed,o->failure_started,
        o->return_pending,o->handler_returned,o->begin_checked,o->cold_seeded,selected_repeat_lease_initialized};
    selected_repeat_array(&w,",\"owner\":",owner,sizeof owner/sizeof owner[0]);
    /* A real fault/nested capture is distinct from the last accepted event.
       Never label a partially initialized siginfo as a complete observation. */
    unsigned event_kind=o->nested_observed?2:o->unexpected_observed?1:0;
    unsigned event_complete=event_kind==2?o->nested_info_complete:
        event_kind==1?o->unexpected_info_complete:p->signal_number!=0;
    const siginfo_t *info=event_kind==2?&o->nested_info:&o->unexpected_info;
    long signal_number=event_kind?(event_complete?info->si_signo:0):p->signal_number;
    long signal_code=event_kind?(event_complete?info->si_code:0):p->signal_code;
    long signal_errno=event_kind?(event_complete?info->si_errno:0):p->signal_errno;
    uintptr_t signal_address=event_kind?(event_complete?(uintptr_t)info->si_addr:0):p->signal_address;
    const uint64_t event[]={selected_repeat_abs(signal_number),signal_number<0,
        selected_repeat_abs(signal_code),signal_code<0,selected_repeat_abs(signal_errno),signal_errno<0,
        signal_address,event_kind,event_complete};
    selected_repeat_array(&w,",\"event\":",event,sizeof event/sizeof event[0]);
    const uint64_t progress[]={r->initial_count,r->remaining,r->traces,o->retained_transfers,r->final,
        r->actual_post_pc,r->actual_post_flags,r->continuation_started,r->continuation_complete,
        selected_repeat_abs(r->continuation_result),r->continuation_result<0,o->rseq_checks};
    selected_repeat_array(&w,",\"progress\":",progress,sizeof progress/sizeof progress[0]);
    const uint64_t frames[]={p->before.greg[REG_RIP],p->before.greg[REG_EFL],p->before.greg[REG_RCX],p->before.greg[REG_RDI],
        p->before.greg[REG_RSP],p->before.fp_bytes,p->before.initialized,
        p->after.greg[REG_RIP],p->after.greg[REG_EFL],p->after.greg[REG_RCX],p->after.greg[REG_RDI],
        p->after.greg[REG_RSP],p->after.fp_bytes,p->after.initialized};
    selected_repeat_array(&w,",\"frames\":",frames,sizeof frames/sizeof frames[0]);
    const uint64_t io[]={p->open_started[0]|(p->open_started[1]<<1),p->opened[0]|(p->opened[1]<<1),
        p->revoke_started[0]|(p->revoke_started[1]<<1),p->revoked[0]|(p->revoked[1]<<1),
        selected_repeat_abs(p->open_sync),p->open_sync<0,p->revoke_sync_started,
        selected_repeat_abs(p->revoke_sync),p->revoke_sync<0,
        selected_repeat_abs(p->open_result[0]),p->open_result[0]<0,selected_repeat_abs(p->open_result[1]),p->open_result[1]<0,
        selected_repeat_abs(p->revoke_result[0]),p->revoke_result[0]<0,selected_repeat_abs(p->revoke_result[1]),p->revoke_result[1]<0};
    selected_repeat_array(&w,",\"io\":",io,sizeof io/sizeof io[0]);
    selected_repeat_query_report(&w,",\"query\":",&selected_repeat_lease_query);
    const uint64_t release[]={o->release_started,o->release_complete,selected_repeat_abs(o->release_result),o->release_result<0};
    selected_repeat_array(&w,",\"release\":",release,sizeof release/sizeof release[0]);
    const uint64_t writes[]={o->write_checks,selected_repeat_abs(o->write_result),o->write_result<0};
    selected_repeat_array(&w,",\"writes\":",writes,sizeof writes/sizeof writes[0]);
    const uint64_t borrow[]={o->borrow.sequence,o->borrow_held};
    selected_repeat_array(&w,",\"borrow\":",borrow,sizeof borrow/sizeof borrow[0]);
    const uint64_t custody[]={c->initialized,c->phase,c->bound,c->reset_ready,c->ticket,c->first_error,
        selected_repeat_abs(c->first_detail),c->first_detail<0,c->epoch,c->attempt,c->event,c->seeds,c->entries,
        c->validations,c->returns,c->closed,c->invalidations,c->last_reason,c->borrow_sequence,
        selected_repeat_abs(o->custody_result),o->custody_result<0};
    selected_repeat_array(&w,",\"custody\":",custody,sizeof custody/sizeof custody[0]);
    const uint64_t backing[]={selected_repeat_abs(b->retained_fd),b->retained_fd<0,
        selected_repeat_abs(b->seals),b->seals<0,selected_repeat_abs(b->stat_result),b->stat_result<0,
        b->seals_observed,b->stat_observed,selected_repeat_abs(b->stat.st_size),b->stat.st_size<0,b->stat.st_mode};
    selected_repeat_array(&w,",\"backing\":",backing,sizeof backing/sizeof backing[0]);
    const uint64_t registration[]={reg->initialized,reg->registered,reg->held,(unsigned)reg->phase,
        (uint64_t)reg->pid,(uint64_t)reg->tid,reg->address,reg->page,reg->length,reg->signature,
        reg->epoch,reg->fs_base,reg->gs_base,reg->tls_complete};
    selected_repeat_array(&w,",\"registration\":",registration,sizeof registration/sizeof registration[0]);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
