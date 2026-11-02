#ifndef LI2_PERSISTENT_LOOP_NEGATIVE_HINT_H
#define LI2_PERSISTENT_LOOP_NEGATIVE_HINT_H
#include <stddef.h>
#include <stdint.h>

/* An optional-offer hint, never a plan, source lease or execution permit.
   The lifecycle adapter supplies exact, live owned-record identities. */
#define LI2_PLNH_ENTRIES 8U
struct li2_plnh_page {
    uint64_t record,address,allocation,generation,offset,initial_extent;
    unsigned backing,object,logical;
};
struct li2_plnh_key { uintptr_t pc;struct li2_plnh_page page[2]; };
struct li2_plnh_cache { unsigned count,next;struct li2_plnh_key key[LI2_PLNH_ENTRIES]; };

static inline int li2_plnh_key_valid(const struct li2_plnh_key *k) {
    const uint64_t page=4096,limit=UINT64_C(1)<<47;
    if(!k || k->page[0].address<page || k->page[0].address>limit-2*page ||
       (k->page[0].address&(page-1)) || k->page[1].address!=k->page[0].address+page ||
       k->pc<k->page[0].address || k->pc-k->page[0].address>page-15 ||
       k->page[0].record==k->page[1].record)return 0;
    for(unsigned i=0;i<2;i++) {
        const struct li2_plnh_page *p=&k->page[i];
        if(!p->record || !p->allocation || !p->generation || p->logical!=5 ||
           (p->backing!=1 && p->backing!=2))return 0;
    }
    return 1;
}
static inline int li2_plnh_page_equal(const struct li2_plnh_page *a,const struct li2_plnh_page *b) {
    return a->record==b->record && a->address==b->address && a->allocation==b->allocation &&
        a->generation==b->generation && a->offset==b->offset && a->initial_extent==b->initial_extent &&
        a->backing==b->backing && a->object==b->object && a->logical==b->logical;
}
static inline int li2_plnh_key_equal(const struct li2_plnh_key *a,const struct li2_plnh_key *b) {
    return li2_plnh_key_valid(a) && li2_plnh_key_valid(b) && a->pc==b->pc &&
        li2_plnh_page_equal(&a->page[0],&b->page[0]) && li2_plnh_page_equal(&a->page[1],&b->page[1]);
}
static inline int li2_plnh_cache_valid(const struct li2_plnh_cache *c) {
    return c && c->count<=LI2_PLNH_ENTRIES && c->next<LI2_PLNH_ENTRIES &&
        (c->count==LI2_PLNH_ENTRIES || c->next==c->count);
}
static inline void li2_plnh_put(struct li2_plnh_cache *c,const struct li2_plnh_key *k) {
    if(!li2_plnh_cache_valid(c) || !li2_plnh_key_valid(k))return;
    for(unsigned i=0;i<c->count;i++)if(li2_plnh_key_equal(&c->key[i],k))return;
    c->key[c->next]=*k;
    if(c->count<LI2_PLNH_ENTRIES)++c->count;
    c->next=(c->next+1U)%LI2_PLNH_ENTRIES;
}
#endif
