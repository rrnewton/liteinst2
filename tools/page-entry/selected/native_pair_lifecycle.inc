/* Explicit two-page owner; included after the unchanged native close core.
   Existing one-page admission and its counters are not used as pair permits. */
#include "native_pair.h"
#ifdef LI2_LINKED_NATIVE_HINT
#include "linked_native_hint.h"
static void link_native_hint_published(unsigned);
#endif
static struct li2_native_pair_lifecycle np_life;
static struct owned_page np_original[LI2_NATIVE_PAIR_SLOTS];
static unsigned char np_disk[LI2_NATIVE_PAIR_WINDOW];
static uint64_t np_started;
#ifdef LI2_COST_PROFILE
static struct li2_native_pair_cost np_cost;
static void np_cost_add(uint64_t ns) {
    if(!np_cost.initialized || np_cost.overflow)return;
    np_cost.busy=1;__asm__ volatile("":::"memory");
    if(np_cost.count==UINT64_MAX || ns>UINT64_MAX-np_cost.sum_ns) {
        /* Keep the last representable tuple; never wrap or change the route. */
        np_cost.overflow=1;
    } else {
        if(!np_cost.count || ns<np_cost.min_ns)np_cost.min_ns=ns;
        if(ns>np_cost.max_ns)np_cost.max_ns=ns;
        np_cost.sum_ns+=ns;++np_cost.count;
    }
    __asm__ volatile("":::"memory");np_cost.busy=0;
}
void li2_lifecycle_pair_cost_snapshot(struct li2_native_pair_cost *out) {
    if(!out)return;
    *out=np_cost;
    out->valid=out->initialized && np_life.initialized && !out->busy && !out->overflow &&
        out->count==np_life.published && out->count==native_counts.admissions;
}
#endif
const struct li2_native_pair_lifecycle *li2_lifecycle_pair_progress(void) { return &np_life; }
static int np_life_bad(unsigned code,long detail) {
    if(!np_life.first_error){np_life.first_error=code;np_life.first_detail=detail;}
    return (int)np_life.first_error;
}
static int np_life_check(const struct check_error *e) { return np_life_bad(e->code,e->detail); }
static int np_life_owner(const struct li2_native_pair_owner *o,unsigned phase) {
    return np_life.initialized && o && o==np_life.owner && !np_life.first_error &&
        li2_native_pair_owner_check(o,phase);
}
static int np_life_epoch(void) {
    return active && !tx.guard && used==np_life.records_epoch &&
        allocation_id==np_life.allocation_epoch && generation==np_life.generation_epoch &&
        counts.transactions==np_life.transactions_epoch;
}
/* Original lifecycle admission is callable only by this exact staged owner
   once the opt-in owner is initialized. Bootstrap/self-test stays unchanged. */
static int np_life_admission_guard(uintptr_t pc) {
    if(!np_life.initialized)return li2_native_pair_quiet();
    unsigned phase=np_life.live?LI2_NP_EXTENDING:LI2_NP_SEEDING;
    return np_life_owner(np_life.owner,phase) && np_life.busy==1 && np_life.opening==1 &&
        np_life.live<LI2_NATIVE_PAIR_SLOTS && np_life.candidate==pc &&
        np_life.candidate_eligible==1 && np_life_epoch();
}
int li2_lifecycle_pair_initialize(const struct li2_native_pair_owner *o) {
    if(np_life.initialized || np_life.owner || !o ||
       !li2_native_pair_owner_check(o,LI2_NP_INITIALIZING) || !active || tx.guard ||
       li2_lifecycle_fetch_interlock() || native_counts.admissions!=native_counts.closed)
        return np_life_bad(LI2_NP_STATE,0);
    for(size_t i=0;i<used;i++)if(records[i].live && records[i].admitted)
        return np_life_bad(LI2_NP_STATE,1);
#ifdef LI2_COST_PROFILE
    np_cost.initialized=1;
#endif
    np_life.owner=o;np_life.initialized=1;return 0;
}
/* The entire actual admitted set must equal the owner's retained identities.
   Neither a count nor a copied publication record grants permission. */
static int np_life_set(void) {
    if(!np_life_epoch() || np_life.live>LI2_NATIVE_PAIR_SLOTS)
        return np_life_bad(LI2_NP_STALE,0);
    size_t count=0;
    for(size_t i=0;i<used;i++)if(records[i].live && records[i].admitted) {
        unsigned found=0;
        for(unsigned j=0;j<np_life.live;j++)if(&records[i]==current(np_original[j].address) &&
            fetch_owned_equal(&records[i],&np_original[j]) && np_life.slots[j].published==1)++found;
        if(found!=1)return np_life_bad(LI2_NP_STALE,1);
        ++count;
    }
    if(count!=np_life.live || native_counts.admissions<native_counts.closed ||
       native_counts.admissions-native_counts.closed!=count)
        return np_life_bad(LI2_NP_STATE,2);
    return 0;
}
static int np_life_page(struct li2_native_pair_slot *out,const struct owned_page *p) {
    const struct map_row *r=mapping(p->address);struct check_error e={0};
    if(verify_page_checked(p,r,&e))return np_life_check(&e);
    unsigned admitted=0;
    for(unsigned i=0;i<np_life.live;i++)if(fetch_owned_equal(p,&np_original[i]))++admitted;
    if(p->backing!=SEALED || p->object>=object_count || p->logical!=(PROT_READ|PROT_EXEC) ||
       admitted>1 || p->admitted!=admitted || p->actual!=(admitted?(PROT_READ|PROT_EXEC):PROT_READ) ||
       r->prot!=p->actual)return np_life_bad(LI2_NP_MAPPING,0);
    if(alias_check_checked(p->object,p->offset,PAGE,p->logical,p->address,p->address+PAGE,&e))
        return np_life_check(&e);
    out->page=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=PROT_READ,
        .vma_first=r->first,.vma_end=r->end,.vma_major=r->major,.vma_minor=r->minor,
        .vma_inode=r->inode,.vma_offset=r->offset};
    return 0;
}
static int np_life_copy(struct li2_native_pair_slot *out,const struct owned_page *p,
                        uintptr_t first,size_t bytes,size_t destination,int retain) {
    if(!p || first<p->address || bytes>PAGE-(first-p->address) ||
       bytes>sizeof(out->window) || destination>sizeof(out->window)-bytes)
        return np_life_bad(LI2_NP_SOURCE,0);
    struct li2_native_pair_slot observed={0};
    if(np_life_page(&observed,p))return (int)np_life.first_error;
    struct li2_fetch_backing *b=&observed.backing;const struct object *o=&objects[p->object];
    b->retained_fd=o->retained_fd;
    b->seals=RAW(SYS_fcntl,o->retained_fd,F_GET_SEALS,0,0,0,0);b->seals_observed=1;
    if(b->seals<0 || (b->seals&SEALS)!=SEALS)return np_life_bad(LI2_NP_BACKING,b->seals);
    b->stat_result=RAW(SYS_fstat,o->retained_fd,&b->stat,0,0,0,0);b->stat_observed=1;
    if(b->stat_result || b->stat.st_dev!=o->stat.st_dev || b->stat.st_ino!=o->stat.st_ino ||
       b->stat.st_size!=o->stat.st_size || b->stat.st_mode!=o->stat.st_mode)
        return np_life_bad(LI2_NP_BACKING,b->stat_result);
    uint64_t offset=p->offset+(first-p->address);
    if(offset<p->offset || b->stat.st_size<0 || offset>(uint64_t)b->stat.st_size ||
       bytes>(uint64_t)b->stat.st_size-offset)return np_life_bad(LI2_NP_BACKING,1);
    long got=RAW(SYS_pread64,o->retained_fd,np_disk+destination,bytes,offset,0,0);
    if(got!=(long)bytes)return np_life_bad(LI2_NP_SOURCE,got);
    const volatile unsigned char *source=(const void *)first;
    for(size_t i=0;i<bytes;i++) {
        unsigned char value=source[i];
        if(value!=np_disk[destination+i])return np_life_bad(LI2_NP_SOURCE,(long)i);
        out->window[destination+i]=value;out->window_initialized=destination+i+1;
    }
    if(retain){out->page=observed.page;out->backing=observed.backing;}
    return 0;
}
static int np_life_validate_live(void) {
    for(unsigned i=0;i<np_life.live;i++) {
        struct li2_native_pair_slot observed={0};const struct owned_page *p=current(np_original[i].address);
        if(!fetch_owned_equal(p,&np_original[i]) || np_life_copy(&observed,p,p->address,PAGE,0,1))
            return np_life.first_error?(int)np_life.first_error:np_life_bad(LI2_NP_STALE,2);
        const struct li2_native_pair_slot *s=&np_life.slots[i];
        if(observed.backing.retained_fd!=s->backing.retained_fd ||
           observed.backing.seals!=s->backing.seals ||
           observed.backing.seals_observed!=s->backing.seals_observed ||
           observed.backing.stat_observed!=s->backing.stat_observed ||
           observed.backing.stat_result!=s->backing.stat_result ||
           observed.backing.stat.st_dev!=s->backing.stat.st_dev ||
           observed.backing.stat.st_ino!=s->backing.stat.st_ino ||
           observed.backing.stat.st_size!=s->backing.stat.st_size ||
           observed.backing.stat.st_mode!=s->backing.stat.st_mode ||
           !equal(observed.window,s->window+s->window_before,PAGE))
            return np_life_bad(LI2_NP_STALE,3);
    }
    return 0;
}
int li2_lifecycle_pair_prepare(const struct li2_native_pair_owner *o,uintptr_t pc,int *eligible) {
#ifdef LI2_LINKED_EPOCH
    if(li2_lifecycle_link_interlock())DIE(LI2_FETCH_BUSY,441);
#endif
#ifdef LI2_EVENT_PROFILE
    LI2_EVENT_SCOPE(event_prepare,LI2_EV_PREPARE);
#endif
    unsigned phase=np_life.live?LI2_NP_EXTENDING:LI2_NP_SEEDING;
    if(!eligible || !np_life_owner(o,phase) || np_life.busy || np_life.live>=2 ||
       !active || tx.guard || li2_lifecycle_fetch_interlock())return np_life_bad(LI2_NP_STATE,3);
    *eligible=0;
    if(np_life.sequence==UINT64_MAX || np_life.attempts==UINT64_MAX ||
       native_counts.attempts==UINT64_MAX)return np_life_bad(LI2_NP_OVERFLOW,0);
    if(!np_life.live) {
        np_life.allocation_epoch=allocation_id;np_life.generation_epoch=generation;
        np_life.transactions_epoch=counts.transactions;np_life.records_epoch=used;
        np_life.slots[0]=(struct li2_native_pair_slot){0};
        np_life.slots[1]=(struct li2_native_pair_slot){0};
    }
    ++np_life.sequence;++np_life.attempts;++native_counts.attempts;
    np_life.busy=1;np_life.candidate=pc;np_life.candidate_eligible=0;
    np_life.candidate_policy=0;np_life.opening=0;np_life.post_verified=0;
    __asm__ volatile("":::"memory");
    if(np_life_set())return (int)np_life.first_error;
    np_started=native_clock();
    np_life.pid=RAW(SYS_getpid,0,0,0,0,0,0);np_life.tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(np_life.pid<=0 || np_life.pid!=np_life.tid)return np_life_bad(LI2_NP_IDENTITY,0);
    uintptr_t address=pc&~(PAGE-1);
    if(address<NATIVE_LOW_LIMIT || address>UINTPTR_MAX-2*PAGE) {
        native_increment(&native_counts.low_address_refusals);np_life.busy=0;return 0;
    }
    const struct owned_page *p=current(address);
    if(!p || p->backing!=SEALED || p->logical!=(PROT_READ|PROT_EXEC)) {np_life.busy=0;return 0;}
    if(p->actual!=PROT_READ || p->admitted)return np_life_bad(LI2_NP_MAPPING,1);
    li2_maps_phase_end();struct check_error e={0};
    if(read_maps_checked(&e,&np_life.before))return np_life_check(&e);
    if(np_life_validate_live())return (int)np_life.first_error;
    for(size_t i=0;i<row_count;i++)if(rows[i].first<NATIVE_LOW_LIMIT && (rows[i].prot&PROT_EXEC)) {
        native_increment(&native_counts.low_address_refusals);np_life.busy=0;return 0;
    }
    int before=native_neighbor(address-PAGE),after=native_neighbor(address+PAGE);
    struct li2_native_pair_slot *s=&np_life.slots[np_life.live];
    *s=(struct li2_native_pair_slot){.slot=np_life.live,.pc=pc,.window_before=before?14:0,
        .window_after=after?14:0,.window_bytes=(before?14:0)+PAGE+(after?14:0)};
    if(before && np_life_copy(s,current(address-PAGE),address-14,14,0,0))return (int)np_life.first_error;
    if(np_life_copy(s,p,address,PAGE,s->window_before,1))return (int)np_life.first_error;
    if(after && np_life_copy(s,current(address+PAGE),address+PAGE,14,s->window_before+PAGE,0))
        return (int)np_life.first_error;
#ifdef LI2_EVENT_PROFILE
    s->policy=LI2_EVENT_VALUE(LI2_EV_POLICY,li2_native_policy(s->window,s->window_bytes));
#else
    s->policy=li2_native_policy(s->window,s->window_bytes);
#endif
    np_life.candidate_policy=s->policy;native_counts.last_block=s->policy;
    if(s->policy){native_increment(&native_counts.blocked);np_life.busy=0;return 0;}
    if(!np_life_epoch())return np_life_bad(LI2_NP_STALE,4);
    np_original[np_life.live]=*p;s->prepared=1;np_life.candidate_eligible=1;*eligible=1;return 0;
}
int li2_lifecycle_pair_publish(const struct li2_native_pair_owner *o,uintptr_t pc) {
#ifdef LI2_LINKED_EPOCH
    if(li2_lifecycle_link_interlock())DIE(LI2_FETCH_BUSY,441);
#endif
#ifdef LI2_EVENT_PROFILE
    LI2_EVENT_SCOPE(event_publish,LI2_EV_PUBLISH);
#endif
    unsigned phase=np_life.live?LI2_NP_EXTENDING:LI2_NP_SEEDING;
    if(!np_life_owner(o,phase) || np_life.busy!=1 || np_life.opening ||
       np_life.candidate!=pc || np_life.candidate_eligible!=1 || np_life.live>=2 ||
       !np_life_epoch() || np_life.published==UINT64_MAX || native_counts.admissions==UINT64_MAX ||
       counts.transactions==UINT64_MAX || counts.admissions==UINT64_MAX || counts.sync_core==UINT64_MAX)
        return np_life_bad(LI2_NP_STATE,4);
    unsigned index=np_life.live;struct li2_native_pair_slot *s=&np_life.slots[index];
    if(s->prepared!=1 || s->published || s->policy || s->window_initialized!=s->window_bytes ||
       !fetch_owned_equal(current(s->page.address),&np_original[index]))return np_life_bad(LI2_NP_STALE,5);
    np_life.opening=1;__asm__ volatile("":::"memory");
    if(!li2_lifecycle_admit(pc,pc))return np_life_bad(LI2_NP_MAPPING,2);
    if(counts.transactions!=np_life.transactions_epoch+1 || allocation_id!=np_life.allocation_epoch ||
       generation!=np_life.generation_epoch || used!=np_life.records_epoch || tx.guard || tx.phase!=ADMITTED)
        return np_life_bad(LI2_NP_STALE,6);
    np_life.transactions_epoch=counts.transactions;
    const struct owned_page *p=current(s->page.address);
    struct owned_page expected=np_original[index];expected.actual=PROT_READ|PROT_EXEC;expected.admitted=1;
    if(!fetch_owned_equal(p,&expected))return np_life_bad(LI2_NP_STALE,7);
    np_original[index]=*p;s->published=1;++np_life.live;++np_life.published;++native_counts.admissions;
    li2_maps_phase_end();struct check_error e={0};
    if(read_maps_checked(&e,&np_life.after))return np_life_check(&e);
    if(np_life_set() || np_life_validate_live())return (int)np_life.first_error;
    uint64_t ended=native_clock();if(ended<np_started)return np_life_bad(LI2_NP_STATE,5);
#ifdef LI2_COST_PROFILE
    np_cost_add(ended-np_started);
#endif
    if(native_counts.admissions==1) {
        native_counts.first_admission_ns=ended-np_started;native_counts.first_source_offset=p->offset;
        native_timed_page=p->address;native_timed_allocation=p->allocation;native_timed_generation=p->generation;
    } else if(p->address==native_timed_page && p->allocation==native_timed_allocation &&
              p->generation==native_timed_generation && native_counts.revisit_count<16)
        native_counts.revisit_ns[native_counts.revisit_count++]=ended-np_started;
#ifdef LI2_LINKED_NATIVE_HINT
    np_life.post_verified=1;link_native_hint_published(index);
    np_life.opening=0;np_life.busy=0;return 0;
#else
    np_life.post_verified=1;np_life.opening=0;np_life.busy=0;return 0;
#endif
}
int li2_lifecycle_pair_close(const struct li2_native_pair_owner *o) {
#ifdef LI2_EVENT_PROFILE
    LI2_EVENT_SCOPE(event_close,LI2_EV_NATIVE_CLOSE);
#endif
    if((!np_life_owner(o,LI2_NP_CLOSING) && !np_life_owner(o,LI2_NP_REFAULTING)) ||
       np_life.busy || np_life.opening || np_life.close_calls==UINT64_MAX ||
       np_life.closed_pages>UINT64_MAX-np_life.live)return np_life_bad(LI2_NP_STATE,6);
    if(np_life_set())return (int)np_life.first_error;
    np_life.busy=1;++np_life.close_calls;__asm__ volatile("":::"memory");
    int result=native_close_all();np_life.close=native_close;
    if(result)return np_life_bad((unsigned)result,native_close.first_detail);
    if(!native_close.complete || native_close.busy || native_close.first_error ||
       native_close.pages!=np_life.live || native_close.verified!=np_life.live ||
       native_close.pid!=np_life.pid || native_close.tid!=np_life.tid || !np_life_epoch())
        return np_life_bad(LI2_NP_CLOSE,0);
    for(unsigned i=0;i<np_life.live;i++) {
        struct owned_page expected=np_original[i];expected.actual=PROT_READ;expected.admitted=0;
        if(!fetch_owned_equal(current(expected.address),&expected))return np_life_bad(LI2_NP_STALE,8);
    }
    np_life.closed_pages+=np_life.live;np_life.live=0;np_life.busy=0;
    np_life.candidate_eligible=0;return 0;
}
int li2_lifecycle_pair_quiet(const struct li2_native_pair_owner *o) {
    return np_life_owner(o,LI2_NP_IDLE) && !np_life.busy && !np_life.opening && !np_life.live &&
        np_life.published==np_life.closed_pages && native_counts.admissions==native_counts.closed;
}
