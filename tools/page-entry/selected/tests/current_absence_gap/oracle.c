/* Additive actual current()/append()/retire() checks. The original oracle file
   is included byte-for-byte for its exact linear/literal/state comparator;
   its own binary still runs all 3,716 original queries separately. */
#define main current_lookup_original_main
#include "tests/current_lookup/oracle.c"
#undef main

static unsigned certificates,revivals;
static const uintptr_t inside=UINT64_C(0x100000);
static const uintptr_t upper=UINT64_C(0x400000);
static const uintptr_t outside=UINT64_C(0x800000);
static void certificate(uintptr_t first,uintptr_t last) {
    oracle_require(current_absence.valid==1 && current_absence.used==used &&
        current_absence.first==first && current_absence.last==last,910);
    ++certificates;
}
static void no_replacement(uintptr_t address) {
    /* A retained but retired exact address cannot be cached as absent. */
    const __typeof__(current_absence) before=current_absence;
    check(address,RECORDS);
    oracle_require(current_absence.first==before.first && current_absence.last==before.last &&
        current_absence.used==before.used && current_absence.valid==before.valid,911);
}
int main(void) {
    _Static_assert(sizeof(current_absence)==32 && sizeof(uintptr_t)==8,
        "one bounded interval, no address/hash table");
    hooks.fail=fail_oracle;
    memset(records,0xa5,sizeof records); /* unused rows never bound a gap */
    start_round();
    check(0,RECORDS);certificate(0,UINTPTR_MAX);
    check(UINTPTR_MAX,RECORDS);check(1,RECORDS);check(UINTPTR_MAX-1,RECORDS);
    end_round();

    add(0);
    start_round();check(0,0);check(1,RECORDS);certificate(1,UINTPTR_MAX);
    check(UINTPTR_MAX,RECORDS);end_round();
    add(UINTPTR_MAX);
    start_round();check(UINTPTR_MAX,1);check(1,RECORDS);
    certificate(1,UINTPTR_MAX-1);check(UINTPTR_MAX-1,RECORDS);
    check(0,0);check(UINTPTR_MAX,1);end_round();

    add(upper);
    start_round();check(inside,RECORDS);certificate(1,upper-1);
    check(upper-1,RECORDS);check(upper,2);check(upper+1,RECORDS);
    certificate(upper+1,UINTPTR_MAX-1);check(inside,RECORDS);
    certificate(1,upper-1);end_round();
    /* An unrelated append also changes the exact used key. */
    add(outside);
    start_round();check(inside,RECORDS);certificate(1,upper-1);
    check(outside,3);end_round();
    /* An append inside the old gap must return its actual live row. */
    add(inside);
    start_round();check(inside,4);check(inside-1,RECORDS);
    certificate(1,inside-1);check(inside+1,RECORDS);
    certificate(inside+1,upper-1);end_round();

    retire(&records[4]);
    start_round();no_replacement(inside);check(inside+1,RECORDS);
    certificate(inside+1,upper-1);end_round();
    /* Stronger supplied metadata control: revive the same retained address
       without advancing used. No production writer does this. */
    records[4].live=1;
    start_round();check(inside,4);check(inside+1,RECORDS);end_round();
    records[4].live=0;++revivals;
    add(inside);
    start_round();check(inside,5);check(inside,5);end_round();
    retire(&records[5]);
    start_round();no_replacement(inside);end_round();
    records[4].live=1;
    start_round();check(inside,4);end_round();
    records[4].live=0;++revivals;

    /* A dead boundary still bounds the certified no-retained-address gap. */
    retire(&records[2]);
    start_round();check(upper-1,RECORDS);certificate(inside+1,upper-1);
    no_replacement(upper);check(upper+1,RECORDS);
    certificate(upper+1,outside-1);end_round();
    start_round();
    for(unsigned i=0;i<16;i++) {
        check(upper-1,RECORDS);certificate(inside+1,upper-1);
        check(upper+1,RECORDS);certificate(upper+1,outside-1);
    }
    end_round();
    /* Real RO-mirror-sized sweep: exact integer addresses, no guest access. */
    start_round();
    for(unsigned i=1;i<=89;i++)check(inside+(uintptr_t)i*PAGE,RECORDS);
    certificate(inside+1,upper-1);
    for(unsigned i=89;i;i--)check(inside+(uintptr_t)i*PAGE,RECORDS);
    certificate(inside+1,upper-1);end_round();
    add(inside+45*PAGE);
    start_round();
    for(unsigned i=1;i<=89;i++)check(inside+(uintptr_t)i*PAGE,i==45?6:RECORDS);
    certificate(inside+45*PAGE+1,upper-1);end_round();
    add(outside+PAGE);
    start_round();check(inside+46*PAGE,RECORDS);
    certificate(inside+45*PAGE+1,upper-1);check(outside+PAGE,7);end_round();

    for(size_t i=0;i<used;i++)if(records[i].live)retire(&records[i]);
    start_round();no_replacement(0);no_replacement(UINTPTR_MAX);
    check(1,RECORDS);certificate(1,inside-1);
    check(UINTPTR_MAX-1,RECORDS);certificate(outside+PAGE+1,UINTPTR_MAX-1);
    end_round();
    oracle_require(used==8 && generation==8 && counts.generations==8 &&
        counts.retained_records==8 && counts.retired==8 && !counts.live_pages,912);
    oracle_require(rounds==17 && queries==338 && hits==13 && misses==325 &&
        certificates==50 && revivals==2,913);
    printf("{\"version\":1,\"queries\":%"PRIu64",\"positive_results\":%"PRIu64
        ",\"null_results\":%"PRIu64",\"rounds\":%"PRIu64
        ",\"certificate_checks\":%u,\"same_used_revivals\":%u,\"appends\":8,"
        "\"retirements\":8,\"mirror_sweep_pages\":89,\"whole_state_unchanged\":1,"
        "\"linear_and_literal_equal\":1}\n",queries,hits,misses,rounds,certificates,revivals);
    return 0;
}
