/* Pure policy checks only. The three production bodies below are exact
 * source copies authenticated by SOURCE.json. Stubs model already-authenticated
 * eligible residents; they do not test or replace any runtime authority check. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#define LI2_LINKED_PREEDGE 1
#define LI2_PREEDGE_HEADS 64U
#define LE_PAGES 64U
#define LE_STATE 1
struct plan { unsigned heads; };
struct le_slot { struct plan plan; };
struct ler_retirement { unsigned started,consumed,target_ready,replaced;size_t slot;uint64_t new_generation; };
static struct { size_t used;uint64_t completed;struct le_slot slots[LE_PAGES]; } selected_linked_epoch;
static struct { unsigned pending,retiring;size_t cursor,slot;uint64_t generation,retirements;
    struct { unsigned valid;uint64_t completion; } permits[LE_PAGES];
    struct ler_retirement retirement;
} ler;
static int selected_borrow;
static unsigned permitted_calls,plan_calls;
static void check(int ok) { if(!ok)abort(); }
static void le_need(int ok,int code,long detail) { (void)code;(void)detail;check(ok); }
static int le_quiet(const void *p) { return p==&selected_borrow; }
static void le_count(uint64_t *p) { check(*p!=UINT64_MAX);++*p; }
static int ler_identity(size_t slot,uint64_t generation) { return slot<LE_PAGES && generation==ler.generation; }
static int ler_permitted(size_t slot) {
    ++permitted_calls;
    check(slot<LE_PAGES && ler.permits[slot].valid<=1);
    if(!ler.permits[slot].valid)return 0;
    check(ler.permits[slot].completion && ler.permits[slot].completion<=selected_linked_epoch.completed);
    return 1;
}
static const struct plan *le_plan(const struct le_slot *s) { ++plan_calls;return &s->plan; }

static int ler_age_greater(uint64_t age,unsigned heads,uint64_t previous_age,unsigned previous_heads) {
    uint64_t quotient=age/heads,previous_quotient=previous_age/previous_heads;
    if(quotient!=previous_quotient)return quotient>previous_quotient;
    return (age%heads)*previous_heads>(previous_age%previous_heads)*heads;
}

static size_t ler_choose(void) {
    le_need(selected_linked_epoch.used==LE_PAGES && !ler.pending && !ler.retiring &&
        le_quiet(&selected_borrow),LE_STATE,305);
    size_t chosen=LE_PAGES;uint64_t chosen_age=0;unsigned chosen_heads=0;
    for(size_t n=0;n<LE_PAGES;n++) {
        size_t slot=(ler.cursor+n)%LE_PAGES;
        if(ler_permitted(slot)) {
            /* Every timestamp is the actual most recent successful completion
               of this permitted generation, including genuine cache hits. */
            unsigned heads=le_plan(&selected_linked_epoch.slots[slot])->heads;
            le_need(heads && heads<=LI2_PREEDGE_HEADS,LE_STATE,317);
            uint64_t age=selected_linked_epoch.completed-ler.permits[slot].completion+1;
            if(chosen==LE_PAGES || ler_age_greater(age,heads,chosen_age,chosen_heads)) {
                chosen=slot;chosen_age=age;chosen_heads=heads;
            }
        }
    }
    return chosen; /* Equal ratios retain cyclic scan-hand order; no permit is MISS. */
}

static void ler_published(size_t slot) {
    le_need(ler.pending && ler.slot==slot && ler_identity(slot,ler.generation),LE_STATE,309);
    if(ler.retiring) {
        struct ler_retirement *t=&ler.retirement;
        le_need(t->started && t->consumed && t->target_ready && !t->replaced &&
            t->slot==slot && t->new_generation==ler.generation,LE_STATE,310);
#ifdef LI2_LINKED_PREEDGE
        /* The aging-policy hand advances once per completed retirement; it is
           only a tie-order origin, not the selected victim's successor. */
        t->replaced=1;le_count(&ler.retirements);ler.cursor=(ler.cursor+1)%LE_PAGES;ler.retiring=0;
#else
        t->replaced=1;le_count(&ler.retirements);ler.cursor=(slot+1)%LE_PAGES;ler.retiring=0;
#endif
    }
}

/* Independent rational reference uses a wider exact cross product, unlike
 * the production quotient/remainder comparison. No floating-point oracle. */
static int reference_greater(uint64_t age,unsigned heads,uint64_t prior,unsigned prior_heads) {
    return (unsigned __int128)age*prior_heads>(unsigned __int128)prior*heads;
}
static void reset(uint64_t completed,size_t hand) {
    selected_linked_epoch.used=LE_PAGES;selected_linked_epoch.completed=completed;
    ler.pending=ler.retiring=0;ler.cursor=hand;permitted_calls=plan_calls=0;
    for(size_t i=0;i<LE_PAGES;i++) {
        ler.permits[i].valid=0;ler.permits[i].completion=0;
        selected_linked_epoch.slots[i].plan.heads=0;
    }
}
static void resident(size_t slot,unsigned heads,uint64_t age) {
    check(slot<LE_PAGES && heads && heads<=LI2_PREEDGE_HEADS && age && age<=selected_linked_epoch.completed);
    ler.permits[slot].valid=1;ler.permits[slot].completion=selected_linked_epoch.completed-age+1;
    selected_linked_epoch.slots[slot].plan.heads=heads;
}
static size_t reference(void) {
    size_t best=LE_PAGES;
    for(size_t n=0;n<LE_PAGES;n++) {
        size_t slot=(ler.cursor+n)%LE_PAGES;
        if(!ler.permits[slot].valid)continue;
        uint64_t age=selected_linked_epoch.completed-ler.permits[slot].completion+1;
        unsigned heads=selected_linked_epoch.slots[slot].plan.heads;
        if(best==LE_PAGES || reference_greater(age,heads,
            selected_linked_epoch.completed-ler.permits[best].completion+1,
            selected_linked_epoch.slots[best].plan.heads))best=slot;
    }
    return best;
}
static void selection(size_t expected) {
    unsigned valid=0;for(size_t i=0;i<LE_PAGES;i++)valid+=ler.permits[i].valid;
    check(ler_choose()==expected && expected==reference());
    check(permitted_calls==LE_PAGES && plan_calls==valid);
}
int main(void) {
    uint64_t ratio_cases=0,selection_cases=0,aging_cases=0,hand_cases=0;
    const uint64_t ages[]={1,2,3,7,31,64,65,4095,UINT64_MAX/2,UINT64_MAX-1,UINT64_MAX};
    for(unsigned h=1;h<=LI2_PREEDGE_HEADS;h++)for(unsigned p=1;p<=LI2_PREEDGE_HEADS;p++)
        for(size_t a=0;a<sizeof ages/sizeof ages[0];a++)for(size_t b=0;b<sizeof ages/sizeof ages[0];b++) {
            check(ler_age_greater(ages[a],h,ages[b],p)==reference_greater(ages[a],h,ages[b],p));
            ++ratio_cases;
        }
    for(size_t hand=0;hand<LE_PAGES;hand++) {
        reset(UINT64_MAX,hand);selection(LE_PAGES);++selection_cases;
        for(size_t slot=0;slot<LE_PAGES;slot++) {
            reset(UINT64_MAX,hand);resident(slot,(unsigned)slot+1,UINT64_MAX);
            selection(slot);++selection_cases;
        }
        /* Different heads and ages can have exactly equal benefit ratios. */
        reset(UINT64_MAX,hand);
        for(size_t slot=0;slot<LE_PAGES;slot++)resident(slot,(unsigned)slot+1,slot+1);
        selection(hand);++selection_cases;
        for(unsigned pattern=0;pattern<8;pattern++) {
            reset(UINT64_MAX,hand);
            for(size_t slot=0;slot<LE_PAGES;slot++)if((slot+pattern)%3)
                resident(slot,1+(unsigned)((slot*7+pattern)%LI2_PREEDGE_HEADS),ages[(slot+pattern)%11]);
            selection(reference());++selection_cases;
        }
    }
    /* Every larger graph eventually loses to a freshly completed smaller graph;
       old static minimum-head policy would select the smaller graph forever. */
    for(unsigned large=2;large<=LI2_PREEDGE_HEADS;large++)for(unsigned small=1;small<large;small++) {
        reset(large+1,0);resident(0,large,large+1);resident(1,small,1);
        selection(0);++aging_cases;
        /* A real successful hit refreshes completion, making the larger graph
           young again without changing its size or fabricating a new permit. */
        ler.permits[0].completion=selected_linked_epoch.completed;
        permitted_calls=plan_calls=0;selection(1);++aging_cases;
    }
    ler.cursor=0;ler.retirements=0;ler.generation=1;
    for(unsigned i=0;i<4*LE_PAGES;i++) {
        size_t victim=(17U*i+7U)%LE_PAGES;
        ler.pending=1;ler.retiring=1;ler.slot=victim;
        ler.retirement=(struct ler_retirement){1,1,1,0,victim,ler.generation};
        ler_published(victim);
        check(ler.retirements==i+1 && ler.cursor==(i+1)%LE_PAGES && !ler.retiring && ler.retirement.replaced);
        ++hand_cases;
        size_t unchanged=ler.cursor;uint64_t count=ler.retirements;
        ler_published(victim);check(ler.cursor==unchanged && ler.retirements==count);++hand_cases;
    }
    printf("{\"ratio_cases\":%llu,\"selection_cases\":%llu,\"aging_cases\":%llu,\"hand_cases\":%llu,\"guest_executions\":0}\n",
        (unsigned long long)ratio_cases,(unsigned long long)selection_cases,
        (unsigned long long)aging_cases,(unsigned long long)hand_cases);
    return 0;
}
