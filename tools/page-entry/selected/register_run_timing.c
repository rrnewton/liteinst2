#include "register_run_timing.h"
#include "maps_phase.h"
#include <sys/syscall.h>
#include <time.h>
_Static_assert(sizeof(struct li2_time_clock)==16,"native x86-64 timespec");
_Static_assert(sizeof(long)==8,"native x86-64 syscall ABI");
_Static_assert(sizeof(struct li2_time_key)==64,"no key padding in exact identity");
_Static_assert(sizeof(struct li2_fetch_page)==104,"complete no-padding page tuple");
_Static_assert(__atomic_always_lock_free(4,0),"signal-visible pending state");
_Static_assert(__atomic_always_lock_free(8,0),"signal-visible sample count");
#define RAW(n,a,b,c,d,e,f) li2_maps_raw(li2_step_raw,n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;
}
static int zero(const void *a,size_t n) {
    const unsigned char *x=a;for(size_t i=0;i<n;i++)if(x[i])return 0;return 1;
}
static int error(struct li2_run_timing *t,unsigned code,long detail) {
    if(t && !t->first_error){t->first_error=code;t->first_detail=detail;}
    if(t)t->qualified=0;
    return (int)code;
}
void li2_run_timing_fail(struct li2_run_timing *t,unsigned code,long detail) {
    if(t && t->initialized)(void)error(t,code,detail);
}
static int increment(struct li2_run_timing *t,uint64_t *x) {
    if(*x==UINT64_MAX)return error(t,LI2_TIME_OVERFLOW,0);
    ++*x;return 0;
}
static int key_ok(const struct li2_time_key *k) {
    if(!k->source_length || k->source_length>15 || k->run_length<2 ||
       k->run_length>=k->source_length || k->instructions<2 || k->instructions>14 ||
       !k->guard_length || k->guard_length>15 ||
       k->run_length+k->guard_length>k->source_length || !k->guard_code)return 0;
    for(size_t i=(size_t)k->source_length;i<16;i++)if(k->source[i])return 0;
    return 1;
}
int li2_run_timing_init(struct li2_run_timing *t,const struct li2_time_config *c,
    uintptr_t first,uintptr_t end,uintptr_t bias,const unsigned char hash[32],
    const struct li2_run_protection *protect) {
    if(!t || !c || !hash || !protect || !protect->add || !protect->contains ||
       first>=end || first<bias || !zero(t,sizeof(*t)) ||
       (c->mode!=LI2_TIME_DISCOVERY && c->mode!=LI2_TIME_MEASURE) ||
       !same(hash,c->image_hash,32) || zero(hash,32) ||
       (c->mode==LI2_TIME_DISCOVERY?!zero(&c->key,sizeof(c->key)):!key_ok(&c->key)))
        return LI2_TIME_ARGUMENT;
    t->config=*c;t->image_first=first;t->image_end=end;t->image_bias=bias;
    if(protect->add(protect->context,(uintptr_t)t,sizeof(*t)) ||
       protect->contains(protect->context,(uintptr_t)t,sizeof(*t))!=1)
        return error(t,LI2_TIME_IDENTITY,0);
    t->clock_buffer=(struct li2_time_clock){-1,-1};t->resolution=t->clock_buffer;
    int r=li2_maps_clock_observer_register(&t->clock_buffer,sizeof(t->clock_buffer));
    if(r)return error(t,LI2_TIME_IDENTITY,r);
    t->resolution_result=RAW(SYS_clock_getres,CLOCK_MONOTONIC_RAW,&t->resolution,0,0,0,0);
    if(t->resolution_result || t->resolution.sec<0 || t->resolution.nsec<0 ||
       t->resolution.nsec>=1000000000 || (!t->resolution.sec && !t->resolution.nsec))
        return error(t,LI2_TIME_CLOCK,t->resolution_result);
    t->initialized=1;return 0;
}
#ifdef LI2_RUN_TIMING_TEST
static struct li2_run_timing *bad_clock;
int li2_run_timing_test_bad_clock(struct li2_run_timing *t) {
    if(!t || !t->initialized || t->pending.active || t->clock_calls || bad_clock)
        return LI2_TIME_ARGUMENT;
    bad_clock=t;return 0;
}
#endif
static int clock_read(struct li2_run_timing *t,unsigned index) {
    struct li2_time_sample *s=&t->sample;
    if(index>2 || s->clock_attempted!=index || s->clock_complete!=index)
        return error(t,LI2_TIME_ORDER,index);
    if(increment(t,&t->clock_calls))return (int)t->first_error;
    long id=CLOCK_MONOTONIC_RAW;
#ifdef LI2_RUN_TIMING_TEST
    /* Genuine invalid-clock syscall, not a fabricated return code. */
    if(bad_clock==t){id=INT32_MAX;bad_clock=0;}
#endif
    s->clock_id=id;s->clock_attempted=index+1;
    li2_maps_stats_read(&s->maps_before[index]);
    if(!s->maps_before[index].active || s->maps_before[index].poisoned)
        return error(t,LI2_TIME_CLOCK,2);
    t->clock_buffer=(struct li2_time_clock){-1,-1};
    s->clock_result=RAW(SYS_clock_gettime,id,&t->clock_buffer,0,0,0,0);
    li2_maps_stats_read(&s->maps_after[index]);
    if(s->clock_result)return error(t,LI2_TIME_CLOCK,s->clock_result);
    if(!same(&s->maps_before[index],&s->maps_after[index],sizeof(s->maps_before[index])))
        return error(t,LI2_TIME_CLOCK,3);
    int64_t sec=t->clock_buffer.sec,nsec=t->clock_buffer.nsec;
    if(sec<0 || nsec<0 || nsec>=1000000000 ||
       (uint64_t)sec>(UINT64_MAX-(uint64_t)nsec)/UINT64_C(1000000000))
        return error(t,LI2_TIME_CLOCK,1);
    uint64_t now=(uint64_t)sec*UINT64_C(1000000000)+(uint64_t)nsec;
    if((index && now<s->ns[index-1]) ||
       (!index && t->samples_complete && now<t->samples[t->samples_complete-1].ns[2]))
        return error(t,LI2_TIME_ORDER,index);
    s->ns[index]=now;
    __atomic_store_n(&s->clock_complete,index+1,__ATOMIC_RELEASE);return 0;
}
int li2_run_timing_begin(struct li2_run_timing *t,const struct li2_run_plan *plan,
    const struct li2_fetch_ref *ref,const struct li2_fetch_view *v) {
    if(!t || !t->initialized || t->first_error || t->finalized || t->pending.active)
        return LI2_TIME_REUSE;
    if(!plan || !ref || !ref->owner || !ref->sequence || !v || !v->bytes || !v->pages ||
       !v->identity_observed || v->pid<=0 || v->pid!=v->tid || v->pc!=plan->pc ||
       v->length!=plan->source_length || !v->length || v->length>15 ||
       v->page_count<1 || v->page_count>2 || !same(v->bytes,plan->source,v->length))
        return error(t,LI2_TIME_ARGUMENT,0);
    if(plan->pc<t->image_first || plan->pc>=t->image_end)return 0;
    if(plan->source_length>t->image_end-plan->pc || plan->pc<t->image_bias)
        return error(t,LI2_TIME_IDENTITY,1);
    struct li2_time_key key={.offset=plan->pc-t->image_bias,.source_length=plan->source_length,
        .run_length=plan->run_length,.instructions=plan->instruction_count,
        .guard_length=plan->guard.length,.guard_code=plan->guard.code};
    for(size_t i=0;i<plan->source_length;i++)key.source[i]=plan->source[i];
    if(!key_ok(&key))return error(t,LI2_TIME_ARGUMENT,1);
    if(t->config.mode==LI2_TIME_MEASURE && key.offset!=t->config.key.offset)return 0;
    if(t->config.mode==LI2_TIME_MEASURE && !same(&key,&t->config.key,sizeof key))
        return error(t,LI2_TIME_IDENTITY,2);
    t->sample=(struct li2_time_sample){.started=1,.borrow=ref->sequence};
    t->pending=(struct li2_time_pending){.matched=1,.key=key,.pc=plan->pc,.stop=plan->stop,
        .page_count=v->page_count,.borrow=ref->sequence,
        .sampled=t->config.mode==LI2_TIME_MEASURE && t->samples_complete<LI2_TIME_SAMPLES};
    for(size_t i=0;i<v->page_count;i++)t->pending.pages[i]=v->pages[i];
    /* Install every pointer/identity before a signal can observe active. */
    __atomic_store_n(&t->pending.active,1,__ATOMIC_RELEASE);
    if(t->pending.sampled)return clock_read(t,0);
    return 0;
}
int li2_run_timing_published(struct li2_run_timing *t,int result,
    const struct li2_run_cache_diagnostic *d,const struct li2_run_publication_progress *pub) {
    if(!t || !t->initialized || t->first_error || t->finalized)return LI2_TIME_REUSE;
    if(!t->pending.active)return 0;
    struct li2_time_pending *p=&t->pending;
    if(p->published || !d || d->phase!=LI2_CACHE_READY || d->first_error ||
       !d->last_attempt.installed || !d->last_attempt.complete ||
       !d->last_attempt.source_complete || !d->last_attempt.plan_complete ||
       d->last_attempt.first_error || d->last_attempt.borrow_sequence!=p->borrow)
        return error(t,LI2_TIME_PUBLICATION,result);
    const struct li2_run_publish_attempt *a=&d->last_attempt;
    if(result==LI2_RUN_SLOW) {
        if(pub || !a->miss_before_publication || a->hit || a->slot!=64 ||
           d->slots_used!=64 || d->complete_slots!=64)
            return error(t,LI2_TIME_PUBLICATION,result);
        if(increment(t,&t->full_misses))return (int)t->first_error;
        __atomic_store_n(&p->active,0,__ATOMIC_RELEASE);return 0;
    }
    if(result || !pub || a->slot>=64 || a->hit>1 || a->miss_before_publication ||
       pub->phase!=LI2_PUBLICATION_COMPLETE || pub->first_error ||
       pub->generation!=a->slot+1 || !pub->rx_complete || !pub->sync_complete ||
       pub->verified_bytes!=4096)return error(t,LI2_TIME_PUBLICATION,result);
    struct li2_time_site *site=&t->sites[a->slot];
    if(a->hit) {
        if(!site->installed || !site->completed || !same(&site->key,&p->key,sizeof p->key) ||
           site->pc!=p->pc || site->stop!=p->stop || site->page_count!=p->page_count ||
           site->publication_generation!=pub->generation ||
           !same(site->pages,p->pages,p->page_count*sizeof(p->pages[0])))
            return error(t,LI2_TIME_IDENTITY,3);
    } else {
        if(site->installed)return error(t,LI2_TIME_REUSE,2);
        site->key=p->key;site->pc=p->pc;site->stop=p->stop;site->page_count=p->page_count;
        for(size_t i=0;i<p->page_count;i++)site->pages[i]=p->pages[i];
        site->publication_generation=pub->generation;
        __atomic_store_n(&site->installed,1,__ATOMIC_RELEASE);
    }
    p->ordinal=a->ordinal;p->slot=a->slot;p->hit=a->hit;
    t->sample.ordinal=a->ordinal;t->sample.slot=a->slot;t->sample.hit=a->hit;
    __atomic_store_n(&p->published,1,__ATOMIC_RELEASE);
    __atomic_store_n(&t->sample.published,1,__ATOMIC_RELEASE);
    if(p->sampled)return clock_read(t,1);
    return 0;
}
int li2_run_timing_complete(struct li2_run_timing *t,const struct li2_run_completion_history *h) {
    if(!t || !t->initialized || t->first_error || t->finalized)return LI2_TIME_REUSE;
    if(!t->pending.active)return 0;
    struct li2_time_pending *p=&t->pending;
    if(!p->published || p->slot>=64 || !h || !h->reset_started || !h->reset_complete || h->first_error)
        return error(t,LI2_TIME_RESET,0);
    const struct li2_run_owner *o=&h->last_complete;
    if(o->phase!=LI2_RUN_COMPLETE || o->first_error || o->in_handler || !o->exit_seen ||
       !o->release_complete || o->release_result || !o->exit_query.complete ||
       o->borrow.sequence!=p->borrow || o->plan.pc!=p->pc || o->plan.stop!=p->stop ||
       o->page_count!=p->page_count || !same(o->pages,p->pages,p->page_count*sizeof(p->pages[0])))
        return error(t,LI2_TIME_RESET,1);
    if(p->sampled && clock_read(t,2))return (int)t->first_error;
    struct li2_time_site *site=&t->sites[p->slot];
    if(t->completed==UINT64_MAX || site->completed==UINT64_MAX ||
       (p->hit?(t->hits==UINT64_MAX || site->hits==UINT64_MAX):t->publications==UINT64_MAX))
        return error(t,LI2_TIME_OVERFLOW,1);
    if(p->sampled) {
        if(t->samples_complete>=LI2_TIME_SAMPLES ||
           p->hit!=(t->samples_complete!=0) || t->sample.clock_complete!=3)
            return error(t,LI2_TIME_ORDER,3);
        t->sample.complete=1;t->samples[t->samples_complete]=t->sample;
        __atomic_store_n(&t->samples_complete,t->samples_complete+1,__ATOMIC_RELEASE);
    }
    ++t->completed;++site->completed;
    if(p->hit){++t->hits;++site->hits;}else ++t->publications;
    __atomic_store_n(&p->active,0,__ATOMIC_RELEASE);return 0;
}
void li2_run_timing_finish(struct li2_run_timing *t,unsigned status) {
    if(!t || !t->initialized || t->finalized)return;
    t->finalized=1;t->qualified=0;
    if(status || t->first_error || t->pending.active)return;
    if(t->config.mode==LI2_TIME_DISCOVERY) {t->qualified=1;return;}
    if(t->publications!=1 || t->hits<LI2_TIME_HITS || t->full_misses ||
       t->samples_complete!=LI2_TIME_SAMPLES || t->clock_calls!=3*LI2_TIME_SAMPLES)return;
    t->qualified=1;
}
