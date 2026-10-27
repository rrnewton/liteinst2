#include "register_run_publish.h"
#include <linux/membarrier.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
_Static_assert(LI2_RUN_CACHE_PAGES==64 && LI2_RUN_CACHE_BYTES==262144,"fixed arena");
_Static_assert(LI2_RUN_CODE_BYTES<LI2_STEP_PAGE,"one immutable publication per page");
struct li2_run_publication {
    struct li2_run_publication_progress progress;
    struct li2_run_plan plan;
    struct li2_fetch_page source_pages[2];
    size_t source_page_count;
    struct li2_fetch_backing source_backing[2];
    struct li2_private_code_query last_inspection;
    uint64_t inspections;
    size_t last_verified_bytes;
};
struct li2_run_cache {
    struct li2_run_cache_diagnostic diagnostic;
    struct li2_step_session *session;
    struct li2_run_protection protection;
    volatile sig_atomic_t busy;
    struct li2_fetch_ref last_borrow;
    struct li2_run_plan rebuilt;
    struct li2_fetch_page pages[2];
    struct li2_fetch_backing backing[2];
    size_t page_count;
    struct li2_run_publication slots[LI2_RUN_CACHE_PAGES];
};
static struct li2_run_cache cache;
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static int kernel_error(long x) {return x<0 && x>=-4095;}
static int error(struct li2_run_cache *c,unsigned code,long detail) {
    if(!c->diagnostic.first_error){c->diagnostic.first_error=code;c->diagnostic.first_detail=detail;}
    c->diagnostic.phase=LI2_CACHE_FAILED;return (int)c->diagnostic.first_error;
}
static int attempt_error(struct li2_run_cache *c,unsigned code,long detail) {
    struct li2_run_publish_attempt *a=&c->diagnostic.last_attempt;
    if(!a->first_error){a->first_error=code;a->first_detail=detail;}
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(p && p->sequence==a->borrow_sequence)a->fetch=*p;
    return error(c,code,detail);
}
static int identity(const struct li2_run_cache *c,int selftest) {
    const struct li2_step_session *s=c->session;
    return s && s->initialized && (!selftest || s->self_test_complete) &&
        s->pid>0 && s->pid==s->tid && s->sync_query>=0 && (s->sync_query&96)==96 &&
        !s->sync_register && RAW(SYS_getpid,0,0,0,0,0,0)==s->pid &&
        RAW(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
static int protected(const struct li2_run_cache *c) {
    return c->protection.add && c->protection.contains &&
        c->protection.contains(c->protection.context,(uintptr_t)c,sizeof(*c))==1 &&
        c->protection.contains(c->protection.context,c->diagnostic.initialization.arena,
                               LI2_RUN_CACHE_BYTES)==1;
}
static int usable(struct li2_run_cache *c) {
    if(c!=&cache)return LI2_CACHE_ARGUMENT;
    if(c->diagnostic.phase!=LI2_CACHE_READY || c->diagnostic.first_error)
        return c->diagnostic.first_error?(int)c->diagnostic.first_error:LI2_CACHE_REUSE;
    if(!identity(c,1))return error(c,LI2_CACHE_IDENTITY,0);
    if(!protected(c))return error(c,LI2_CACHE_PROTECTION,0);
    return 0;
}
int li2_run_cache_initialize(struct li2_step_session *s,const struct li2_run_protection *h,
                             struct li2_run_cache **out) {
    if(!out)return LI2_CACHE_ARGUMENT;
    *out=&cache;
    if(cache.diagnostic.phase!=LI2_CACHE_EMPTY)return LI2_CACHE_REUSE;
    cache.diagnostic.phase=LI2_CACHE_INITIALIZING;cache.session=s;
    struct li2_run_cache_initialization *p=&cache.diagnostic.initialization;
    p->metadata_bytes=sizeof(cache);p->arena_bytes=LI2_RUN_CACHE_BYTES;
    if(!h || !h->add || !h->contains)return error(&cache,LI2_CACHE_PROTECTION,0);
    cache.protection=*h;
    if(!identity(&cache,0))return error(&cache,LI2_CACHE_IDENTITY,0);
    p->metadata_started=1;
    p->metadata_result=h->add(h->context,(uintptr_t)&cache,sizeof(cache));
    if(p->metadata_result || h->contains(h->context,(uintptr_t)&cache,sizeof(cache))!=1)
        return error(&cache,LI2_CACHE_PROTECTION,p->metadata_result);
    p->metadata_complete=1;p->allocation_started=1;
    p->allocation_result=RAW(SYS_mmap,0,LI2_RUN_CACHE_BYTES,PROT_READ|PROT_WRITE,
                             MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(kernel_error(p->allocation_result))return error(&cache,LI2_CACHE_ALLOCATION,p->allocation_result);
    p->allocated=1;p->arena=(uintptr_t)p->allocation_result;
    if(!p->arena || (p->arena&(LI2_STEP_PAGE-1)) || p->arena>UINTPTR_MAX-LI2_RUN_CACHE_BYTES)
        return error(&cache,LI2_CACHE_ALLOCATION,p->allocation_result);
    p->arena_protection_started=1;
    p->arena_protection_result=h->add(h->context,p->arena,LI2_RUN_CACHE_BYTES);
    if(p->arena_protection_result || !protected(&cache))
        return error(&cache,LI2_CACHE_PROTECTION,p->arena_protection_result);
    p->arena_protection_complete=1;
    int r=li2_lifecycle_private_code_query(p->arena,LI2_RUN_CACHE_BYTES,
                                           PROT_READ|PROT_WRITE,&p->mapping);
    if(r || !p->mapping.complete || p->mapping.pages_checked!=LI2_RUN_CACHE_PAGES)
        return error(&cache,LI2_CACHE_QUERY,r);
    p->complete=1;cache.diagnostic.phase=LI2_CACHE_READY;return 0;
}
static int page_same(const struct li2_fetch_page *a,const struct li2_fetch_page *b) {
    return a->address==b->address && a->allocation==b->allocation && a->generation==b->generation &&
        a->offset==b->offset && a->initial_extent==b->initial_extent && a->backing==b->backing &&
        a->object==b->object && a->logical==b->logical && a->closed_prot==b->closed_prot &&
        a->vma_first==b->vma_first && a->vma_end==b->vma_end && a->vma_major==b->vma_major &&
        a->vma_minor==b->vma_minor && a->vma_inode==b->vma_inode && a->vma_offset==b->vma_offset;
}
static int source(struct li2_run_cache *c,const struct li2_fetch_ref *borrow,
                   const struct li2_run_plan *supplied) {
    struct li2_run_publish_attempt *a=&c->diagnostic.last_attempt;
    struct li2_fetch_view v={0};
    a->view_result=li2_lifecycle_fetch_view(borrow,&v);
    if(a->view_result || !v.bytes || !v.pages || !v.backing || !v.length || v.length>15 ||
       v.pc>UINTPTR_MAX-v.length || !v.identity_observed || v.pid!=c->session->pid ||
       v.tid!=c->session->tid)return attempt_error(c,LI2_CACHE_SOURCE,a->view_result);
    uintptr_t first=v.pc&~(LI2_STEP_PAGE-1),last=(v.pc+v.length-1)&~(LI2_STEP_PAGE-1);
    c->page_count=first==last?1:2;
    if(v.page_count!=c->page_count)return attempt_error(c,LI2_CACHE_SOURCE,0);
    for(size_t i=0;i<c->page_count;i++) {
        const struct li2_fetch_page *p=&v.pages[i];
        if(p->address!=first+i*LI2_STEP_PAGE || !p->allocation || !p->generation ||
           p->logical!=(PROT_READ|PROT_EXEC) || p->closed_prot!=PROT_READ)
            return attempt_error(c,LI2_CACHE_SOURCE,(long)i);
        c->pages[i]=*p;c->backing[i]=v.backing[i];
        a->validation_result=li2_lifecycle_fetch_validate(borrow,i,PROT_READ);
        if(a->validation_result)return attempt_error(c,LI2_CACHE_SOURCE,a->validation_result);
        ++a->pages_validated;
    }
    const struct li2_fetch_progress *p=li2_lifecycle_fetch_progress();
    if(!p || !p->held || !p->complete || p->first_error || p->sequence!=borrow->sequence)
        return attempt_error(c,LI2_CACHE_SOURCE,0);
    a->fetch=*p;a->source_complete=1;
    a->plan_result=li2_run_plan_bytes(v.pc,v.bytes,v.length,&c->rebuilt);
    if(a->plan_result || !same(supplied,&c->rebuilt,sizeof(c->rebuilt)))
        return attempt_error(c,LI2_CACHE_PLAN,a->plan_result);
    /* Both copied run AND the whole final guard stay in the sole held view. */
    if(c->rebuilt.stop<v.pc || c->rebuilt.stop>=v.pc+v.length ||
       c->rebuilt.guard.next_pc>v.pc+v.length || c->rebuilt.guard.next_pc<=c->rebuilt.stop ||
       !c->rebuilt.generated_length || c->rebuilt.generated_length>LI2_RUN_CODE_BYTES)
        return attempt_error(c,LI2_CACHE_PLAN,0);
    a->plan_complete=1;return 0;
}
static struct li2_run_publication *registered(const struct li2_run_cache *c,
                                               const struct li2_run_publication *p) {
    uintptr_t at=(uintptr_t)p,first=(uintptr_t)&c->slots[0],end=(uintptr_t)&c->slots[LI2_RUN_CACHE_PAGES];
    if(at<first || at>=end || (at-first)%sizeof(*p))return 0;
    size_t index=(at-first)/sizeof(*p);
    if(index>=c->diagnostic.slots_used)return 0;
    return (struct li2_run_publication *)&c->slots[index];
}
static int receipt(const struct li2_run_cache *c,const struct li2_run_publication *p) {
    size_t index=(size_t)(p-c->slots);
    const struct li2_run_publication_progress *r=&p->progress;
    return r->phase==LI2_PUBLICATION_COMPLETE && !r->first_error && !r->first_detail &&
        r->allocation==1 && r->generation==index+1 &&
        r->entry==c->diagnostic.initialization.arena+index*LI2_STEP_PAGE &&
        r->fill_bytes==LI2_STEP_PAGE && r->code_bytes==p->plan.generated_length &&
        r->verified_bytes==LI2_STEP_PAGE && r->rw_checked==1 &&
        r->rx_started==1 && r->rx_complete==1 && !r->rx_result &&
        r->sync_started==1 && r->sync_complete==1 && !r->sync_result &&
        r->before.complete==1 && !r->before.result && r->after.complete==1 &&
        !r->after.result && !r->cleanup_started;
}
static int verify_bytes(struct li2_run_publication *p,size_t *observed) {
    const volatile unsigned char *bytes=(const void *)p->progress.entry;
    for(size_t i=0;i<LI2_STEP_PAGE;i++) {
        unsigned char expected=i<p->plan.generated_length?p->plan.generated[i]:0xcc;
        if(bytes[i]!=expected)return LI2_CACHE_BYTES;
        *observed=i+1;
    }
    return 0;
}
static int inspect(struct li2_run_cache *c,struct li2_run_publication *p) {
    if(!receipt(c,p))return error(c,LI2_CACHE_QUERY,0);
    if(p->inspections==UINT64_MAX)return error(c,LI2_CACHE_REUSE,0);
    ++p->inspections;p->last_inspection=(struct li2_private_code_query){0};p->last_verified_bytes=0;
    int r=li2_lifecycle_private_code_query(p->progress.entry,LI2_STEP_PAGE,
                                           PROT_READ|PROT_EXEC,&p->last_inspection);
    if(r || !p->last_inspection.complete || p->last_inspection.pages_checked!=1)
        return error(c,LI2_CACHE_QUERY,r);
    r=verify_bytes(p,&p->last_verified_bytes);
    return r?error(c,(unsigned)r,0):0;
}
static int publication_error(struct li2_run_cache *c,struct li2_run_publication *p,
                               unsigned code,long detail) {
    struct li2_run_publication_progress *r=&p->progress;
    if(!r->first_error){r->first_error=code;r->first_detail=detail;}
    r->phase=LI2_PUBLICATION_FAILED;
    (void)attempt_error(c,code,detail);
    /* Owner installed before any write. Never recycle it, refund a slot or
       replace the first error. Revoke an uncertain RX result independently. */
    if(r->cleanup_started)return (int)c->diagnostic.first_error;
    r->cleanup_started=1;
    r->cleanup_result=RAW(SYS_mprotect,r->entry,LI2_STEP_PAGE,PROT_READ,0,0,0);
    r->cleanup_sync_started=1;
    r->cleanup_sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    int q=li2_lifecycle_private_code_query(r->entry,LI2_STEP_PAGE,PROT_READ,&r->cleanup);
    if(!r->cleanup_result && !r->cleanup_sync_result && !q && r->cleanup.complete &&
       r->cleanup.pages_checked==1)r->cleanup_complete=1;
    return (int)c->diagnostic.first_error;
}
int li2_run_cache_interrupt(struct li2_run_cache *c,unsigned code,long detail) {
    if(c!=&cache)return LI2_CACHE_ARGUMENT;
    if(!code)code=LI2_CACHE_REENTRY;
    if(!c->diagnostic.interrupted) {
        c->diagnostic.interrupted=1;c->diagnostic.interrupted_code=code;
        c->diagnostic.interrupted_detail=detail;
    } else c->diagnostic.interrupted_again=1;
    (void)error(c,code,detail);
    const struct li2_run_publish_attempt *a=&c->diagnostic.last_attempt;
    if(a->installed && a->slot<c->diagnostic.slots_used) {
        struct li2_run_publication *p=&c->slots[a->slot];
        if(p->progress.phase==LI2_PUBLICATION_WRITING ||
           (p->progress.phase==LI2_PUBLICATION_FAILED && !p->progress.cleanup_started))
            return publication_error(c,p,code,detail);
    }
    return (int)c->diagnostic.first_error;
}
int li2_run_cache_publish(struct li2_run_cache *c,const struct li2_fetch_ref *borrow,
                          const struct li2_run_plan *plan,const struct li2_run_publication **out) {
    if(!out)return LI2_CACHE_ARGUMENT;
    *out=0;
    int r=usable(c);if(r)return r;
    if(c->busy)return error(c,LI2_CACHE_REENTRY,0);
    if(!borrow || !plan || !borrow->sequence || borrow->sequence<=c->last_borrow.sequence ||
       c->diagnostic.attempts==UINT64_MAX)return error(c,LI2_CACHE_REUSE,0);
    c->busy=1;c->last_borrow=*borrow;
    struct li2_run_publish_attempt *a=&c->diagnostic.last_attempt;
    *a=(struct li2_run_publish_attempt){.ordinal=++c->diagnostic.attempts,
        .borrow_sequence=borrow->sequence,.installed=1,.slot=LI2_RUN_CACHE_PAGES};
    r=source(c,borrow,plan);if(r)return r;
    for(size_t i=0;i<c->diagnostic.slots_used;i++) {
        struct li2_run_publication *p=&c->slots[i];
        if(!same(&p->plan,&c->rebuilt,sizeof(p->plan)) || p->source_page_count!=c->page_count)continue;
        int equal=1;
        for(size_t j=0;j<c->page_count;j++)if(!page_same(&p->source_pages[j],&c->pages[j]))equal=0;
        if(!equal)continue;
        a->slot=i;a->hit=1;
        r=inspect(c,p);if(r)return attempt_error(c,(unsigned)r,c->diagnostic.first_detail);
        if(c->diagnostic.hits==UINT64_MAX)return attempt_error(c,LI2_CACHE_REUSE,0);
        ++c->diagnostic.hits;a->complete=1;*out=p;c->busy=0;return 0;
    }
    if(c->diagnostic.slots_used==LI2_RUN_CACHE_PAGES) {
        if(c->diagnostic.full_misses==UINT64_MAX)return attempt_error(c,LI2_CACHE_REUSE,0);
        ++c->diagnostic.full_misses;a->miss_before_publication=1;a->complete=1;c->busy=0;
        return LI2_RUN_SLOW;
    }
    a->slot=c->diagnostic.slots_used++;
    struct li2_run_publication *p=&c->slots[a->slot];
    struct li2_run_publication_progress *q=&p->progress;
    q->allocation=1;q->generation=a->slot+1;
    q->entry=c->diagnostic.initialization.arena+a->slot*LI2_STEP_PAGE;
    q->borrow_sequence=borrow->sequence;p->plan=c->rebuilt;p->source_page_count=c->page_count;
    for(size_t i=0;i<c->page_count;i++){p->source_pages[i]=c->pages[i];p->source_backing[i]=c->backing[i];}
    *out=p; /* Retain the installed, possibly failed owner; not a permit. */
    /* A signal observer may use WRITING to begin cleanup. Its exact owned
       address and every immutable binding must already be visible, including
       when interrupted before the first page query or byte write. */
    __asm__ volatile("" ::: "memory");
    q->phase=LI2_PUBLICATION_WRITING;
    __asm__ volatile("" ::: "memory");
    r=li2_lifecycle_private_code_query(q->entry,LI2_STEP_PAGE,PROT_READ|PROT_WRITE,&q->before);
    if(r || !q->before.complete || q->before.pages_checked!=1)
        return publication_error(c,p,LI2_CACHE_QUERY,r);
    q->rw_checked=1;
    volatile unsigned char *to=(void *)q->entry;
    for(size_t i=0;i<LI2_STEP_PAGE;i++){to[i]=0xcc;q->fill_bytes=i+1;}
    for(size_t i=0;i<p->plan.generated_length;i++){to[i]=p->plan.generated[i];q->code_bytes=i+1;}
    q->rx_started=1;q->rx_result=RAW(SYS_mprotect,q->entry,LI2_STEP_PAGE,PROT_READ|PROT_EXEC,0,0,0);
    if(q->rx_result)return publication_error(c,p,LI2_CACHE_RX,q->rx_result);
    q->rx_complete=1;q->sync_started=1;
    q->sync_result=RAW(SYS_membarrier,MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,0,0,0,0,0);
    if(q->sync_result)return publication_error(c,p,LI2_CACHE_SYNC,q->sync_result);
    q->sync_complete=1;
    r=li2_lifecycle_private_code_query(q->entry,LI2_STEP_PAGE,PROT_READ|PROT_EXEC,&q->after);
    if(r || !q->after.complete || q->after.pages_checked!=1)
        return publication_error(c,p,LI2_CACHE_QUERY,r);
    r=verify_bytes(p,&q->verified_bytes);
    if(r)return publication_error(c,p,(unsigned)r,0);
    q->phase=LI2_PUBLICATION_COMPLETE;++c->diagnostic.complete_slots;
    a->complete=1;c->busy=0;return 0;
}
int li2_run_publication_observe(void *context,const struct li2_run_publication *publication,
                               const struct li2_run_plan *plan,struct li2_run_slot_observation *out) {
    if(!out || out->attempted)return LI2_CACHE_ARGUMENT;
    out->attempted=1;
    struct li2_run_cache *c=context;
    int r=usable(c);if(r){out->result=r;return r;}
    if(c->busy){out->result=error(c,LI2_CACHE_REENTRY,0);return out->result;}
    c->busy=1;
    struct li2_run_publication *p=registered(c,publication);
    if(!p || !plan || !same(plan,&p->plan,sizeof(*plan)) || !receipt(c,p)) {
        out->result=error(c,LI2_CACHE_QUERY,0);return out->result;
    }
    out->owner_observed=1;out->entry=p->progress.entry;
    out->mapping_first=out->entry;out->mapping_end=out->entry+LI2_STEP_PAGE;
    out->allocation=p->progress.allocation;out->generation=p->progress.generation;
    out->length=p->plan.generated_length;
    r=inspect(c,p);
    if(p->last_inspection.complete){out->mapping_observed=1;out->actual_prot=p->last_inspection.actual_prot;}
    if(r){out->result=r;return r;}
    /* Exclusive anonymous mmap + lifetime no-remap/fork/protected mutation
       custody excludes writable aliases. The maps query alone does not. */
    out->writable_aliases=0;
    const volatile unsigned char *bytes=(const void *)out->entry;
    for(size_t i=0;i<out->length;i++)out->bytes[i]=bytes[i];
    out->bytes_observed=1;out->complete=1;c->busy=0;return 0;
}
static int overlaps(uintptr_t a,uintptr_t b,uintptr_t c,size_t n) {return a<b && a<c+n && c<b;}
int li2_run_cache_before_syscall(struct li2_run_cache *c,long n,const long args[6]) {
    int r=usable(c);if(r)return r;
    if(c->busy)return error(c,LI2_CACHE_REENTRY,n);
    if(!args)return error(c,LI2_CACHE_ARGUMENT,n);
    if(n!=SYS_brk || !args[0])return 0;
    c->busy=1;
    struct li2_run_brk_observation *b=&c->diagnostic.last_brk;
    *b=(struct li2_run_brk_observation){.attempted=1,.requested=(uintptr_t)args[0]};
    b->query_result=RAW(SYS_brk,0,0,0,0,0,0);b->observed=(uintptr_t)b->query_result;
    if(kernel_error(b->query_result) || b->observed>UINTPTR_MAX-(LI2_STEP_PAGE-1)) {
        b->result=error(c,LI2_CACHE_BRK,b->query_result);return b->result;
    }
    if(b->requested<b->observed) {
        b->first=(b->requested+LI2_STEP_PAGE-1)&~(LI2_STEP_PAGE-1);
        b->end=(b->observed+LI2_STEP_PAGE-1)&~(LI2_STEP_PAGE-1);
        if(overlaps(b->first,b->end,c->diagnostic.initialization.arena,LI2_RUN_CACHE_BYTES) ||
           overlaps(b->first,b->end,(uintptr_t)c,sizeof(*c))) {
            b->result=error(c,LI2_CACHE_BRK,n);return b->result;
        }
    }
    b->complete=1;c->busy=0;return 0;
}
const struct li2_run_cache_diagnostic *li2_run_cache_diagnostic(const struct li2_run_cache *c) {
    return c==&cache?&c->diagnostic:0;
}
const struct li2_run_publication_progress *li2_run_publication_progress(
    const struct li2_run_cache *c,const struct li2_run_publication *publication) {
    if(c!=&cache)return 0;
    struct li2_run_publication *p=registered(c,publication);
    return p?&p->progress:0;
}
const struct li2_private_code_query *li2_run_publication_last_query(
    const struct li2_run_cache *c,const struct li2_run_publication *publication) {
    if(c!=&cache)return 0;
    struct li2_run_publication *p=registered(c,publication);
    return p?&p->last_inspection:0;
}
