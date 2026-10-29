/* Included only by the explicit timing build. Its generated configuration is
   a pinned build input, never an application-controlled environment value. */
#include "register_timing_config.h"
static uint64_t selected_time_word(const unsigned char *p) {
    uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static void selected_run_time_initialize(void) {
    uintptr_t first=UINTPTR_MAX,end=0;
    for(size_t i=0;i<original_interpreter.n;i++) {
        const Elf64_Phdr *p=&original_interpreter.ph[i];
        if(p->p_type!=PT_LOAD || !(p->p_flags&PF_X) || !p->p_memsz)continue;
        checked(p->p_vaddr<=UINTPTR_MAX-original_interpreter.bias &&
                p->p_memsz<=UINTPTR_MAX-original_interpreter.bias-p->p_vaddr,800,0);
        uintptr_t a=original_interpreter.bias+p->p_vaddr,b=a+p->p_memsz;
        if(a<first)first=a;
        if(b>end)end=b;
    }
    int r=li2_run_timing_init(&selected_run_timing,&li2_time_configuration,
        first,end,original_interpreter.bias,original_interpreter.source_hash,&selected_run_protection);
    checked(!r,(unsigned)(r?r:LI2_TIME_ARGUMENT),selected_run_timing.first_detail);
#ifdef LI2_ENTRY_TIMING
    li2_entry_time_initialize();
#endif
}
static void selected_time_line(struct writer *w) {
    long r=raw(SYS_write,report_fd<0?2:report_fd,(long)w->bytes,w->used,0,0,0);
    if(r!=(long)w->used)li2_fail("timing report write");
}
/* A row has at most 16 u64 values: 352 bytes including its prefix. 64 site
   rows +11 samples +summary +the three old4096-byte lines stay below64KiB. */
_Static_assert(64*352+11*352+4096+3*4096<65536,"bounded complete timing reports");
static void selected_time_row(const char *prefix,const uint64_t *x,size_t n) {
    struct writer w={.used=0};text(&w,prefix);text(&w,"[");
    for(size_t i=0;i<n;i++){if(i)text(&w,",");number(&w,x[i]);}
    text(&w,"]\n");selected_time_line(&w);
}
static void selected_run_time_report(unsigned status,unsigned code,long detail) {
    struct li2_run_timing *t=&selected_run_timing;li2_run_timing_finish(t,status);
    size_t sites=0;
    for(size_t i=0;i<64;i++)if(t->sites[i].installed) {
        const struct li2_time_site *s=&t->sites[i];const struct li2_time_key *k=&s->key;
        uint64_t row[]={1,i,k->offset,k->source_length,k->run_length,k->instructions,
            k->guard_length,k->guard_code,selected_time_word(k->source),
            selected_time_word(k->source+8),s->publication_generation,s->completed,s->hits};
        selected_time_row("LI2_RUN_TIME_SITE ",row,sizeof row/sizeof row[0]);++sites;
    }
    for(size_t i=0;i<t->samples_complete && i<LI2_TIME_SAMPLES;i++) {
        const struct li2_time_sample *s=&t->samples[i];
        uint64_t row[]={1,i,s->ordinal,s->borrow,s->slot,s->hit,s->started,s->published,
            s->complete,s->clock_attempted,s->clock_complete,(uint64_t)s->clock_id,
            s->ns[0],s->ns[1],s->ns[2]};
        selected_time_row("LI2_RUN_TIME_SAMPLE ",row,sizeof row/sizeof row[0]);
    }
#ifdef LI2_ENTRY_TIMING
    li2_entry_time_origins_report();
#endif
    struct writer w={.used=0};text(&w,"LI2_RUN_TIME {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",selected_repeat_abs(detail));field(&w,",\"detail_negative\":",detail<0);
    field(&w,",\"mode\":",t->config.mode);field(&w,",\"initialized\":",t->initialized);
    field(&w,",\"finalized\":",t->finalized);field(&w,",\"qualified\":",t->qualified);
    field(&w,",\"observer_error\":",t->first_error);
    field(&w,",\"observer_detail_abs\":",selected_repeat_abs(t->first_detail));
    field(&w,",\"observer_detail_negative\":",t->first_detail<0);
    field(&w,",\"completed\":",t->completed);field(&w,",\"publications\":",t->publications);
    field(&w,",\"hits\":",t->hits);field(&w,",\"full_misses\":",t->full_misses);
    field(&w,",\"clock_calls\":",t->clock_calls);field(&w,",\"clock_id\":",4);
    field(&w,",\"sites\":",sites);field(&w,",\"samples\":",t->samples_complete);
    const uint64_t hash[]={selected_time_word(t->config.image_hash),selected_time_word(t->config.image_hash+8),
        selected_time_word(t->config.image_hash+16),selected_time_word(t->config.image_hash+24)};
    selected_repeat_array(&w,",\"image_hash\":",hash,4);
    const uint64_t resolution[]={selected_repeat_abs(t->resolution_result),t->resolution_result<0,
        (uint64_t)t->resolution.sec,(uint64_t)t->resolution.nsec};
    selected_repeat_array(&w,",\"resolution\":",resolution,4);
    const struct li2_time_pending *p=&t->pending;
    const uint64_t pending[]={p->active,p->matched,p->sampled,p->published,p->borrow,p->ordinal,p->slot,p->hit};
    selected_repeat_array(&w,",\"pending\":",pending,8);
    const struct li2_time_sample *s=&t->sample;
    const uint64_t current[]={s->started,s->published,s->complete,s->clock_attempted,s->clock_complete,
        selected_repeat_abs(s->clock_result),s->clock_result<0,(uint64_t)s->clock_id,
        s->ordinal,s->borrow,s->slot,s->hit,s->ns[0],s->ns[1],s->ns[2]};
    selected_repeat_array(&w,",\"current\":",current,15);
    text(&w,"}\n");selected_time_line(&w);
}
