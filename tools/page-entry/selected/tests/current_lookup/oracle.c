/* Actual lifecycle current()/append()/retire(), with dead-section GC for the
   unrelated loader. Integer addresses are never dereferenced. No timing. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exact predecessor, changing only the private function name. */
static struct owned_page *linear_current(uintptr_t address) {
    for (size_t i=used;i;i--) if (records[i-1].live && records[i-1].address==address) return &records[i-1];
    return 0;
}
__attribute__((noinline,used))
struct owned_page *li2_current_oracle(uintptr_t address) {
    return current(address);
}
static struct owned_page saved_records[RECORDS];
static struct li2_lifecycle_counts saved_counts;
static size_t saved_used;
static uint64_t saved_generation,queries,hits,misses,rounds;

static void fail_oracle(unsigned code,long detail) __attribute__((noreturn));
static void fail_oracle(unsigned code,long detail) {
    fprintf(stderr,"oracle failure %u detail=%ld round=%"PRIu64" query=%"PRIu64"\n",
            code,detail,rounds,queries);
    exit(1);
}
static void require(int value,unsigned code) { if(!value)fail_oracle(code,0); }
static void start_round(void) {
    memcpy(saved_records,records,sizeof(records));memcpy(&saved_counts,&counts,sizeof(counts));
    saved_used=used;saved_generation=generation;++rounds;
}
static void end_round(void) {
    require(used==saved_used && generation==saved_generation &&
            !memcmp(&counts,&saved_counts,sizeof(counts)) &&
            !memcmp(records,saved_records,sizeof(records)),900);
}
static void check(uintptr_t address,size_t slot) {
    require(slot==RECORDS || slot<used,901);
    struct owned_page *want=slot==RECORDS?0:&records[slot];
    struct owned_page *old=linear_current(address),*got=li2_current_oracle(address);
    ++queries;
    require(old==want && got==want,902);
    if(want) {
        require(want->live && want->address==address &&
                !memcmp(want,&saved_records[slot],sizeof(*want)),903);
        ++hits;
    } else ++misses;
}
static void add(uintptr_t address) {
    size_t slot=used;
    append(address,slot+11,slot*PAGE,SEALED,(unsigned)(slot%OBJECTS),PROT_READ|PROT_EXEC,PROT_READ);
    require(used==slot+1 && records[slot].address==address && records[slot].live &&
            records[slot].generation==slot+1,904);
}
static uintptr_t churn_address(size_t key) { return UINT64_C(0x100000)+key*PAGE; }
static size_t newest(size_t key) {
    size_t last=used-1;
    size_t distance=(last%257+257-key)%257;
    if(distance>last)return RECORDS;
    size_t slot=last-distance;
    return slot>=22?slot:RECORDS;
}
static void churn_queries(unsigned retired_even) {
    start_round();
    for(size_t key=0;key<257;key++) {
        size_t slot=newest(key);
        if(retired_even && !(key&1))slot=slot>=22+257?slot-257:RECORDS;
        check(churn_address(key),slot);check(churn_address(key),slot);
    }
    check(0,19);check(UINT64_C(0x8000000000000000),20);
    check(UINTPTR_MAX&~(uintptr_t)(PAGE-1),21);
    check(1,RECORDS);check(UINTPTR_MAX,RECORDS);check(UINT64_C(0x40000000),RECORDS);
    end_round();
}
int main(void) {
    _Static_assert(sizeof(uintptr_t)==8 && sizeof(struct owned_page)==64 &&
                   RECORDS==8192 && PAGE==4096,"exact current record domain");
    hooks.fail=fail_oracle;
    /* Poison unused storage; used stays its actual initial BSS zero. */
    memset(records,0xa5,sizeof(records));
    start_round();check(0,RECORDS);check(PAGE,RECORDS);check(UINTPTR_MAX,RECORDS);end_round();
    add(0);
    start_round();check(0,0);check(0,0);check(1,RECORDS);check(UINTPTR_MAX,RECORDS);end_round();
    add(PAGE);
    start_round();check(0,0);check(PAGE,1);check(0,0);end_round();
    /* Duplicate live addresses are stronger than normal ownership input:
       the exact old reverse order must still select the newest live slot. */
    add(0);
    start_round();check(0,2);check(0,2);check(PAGE,1);end_round();
    retire(&records[2]);
    start_round();check(0,0);check(PAGE,1);end_round();
    retire(&records[0]);
    start_round();check(0,RECORDS);check(PAGE,1);end_round();
    add(0);
    start_round();check(0,3);check(PAGE,1);end_round();
    retire(&records[1]);
    start_round();check(PAGE,RECORDS);check(0,3);end_round();
    /* Same epoch/slot, new facts: returning a saved row copy is incorrect. */
    records[3].actual=PROT_READ|PROT_EXEC;records[3].admitted=1;
    records[3].initial_extent=12345;
    start_round();check(0,3);check(0,3);end_round();
    records[3].actual=PROT_READ;records[3].admitted=0;
    start_round();check(0,3);end_round();
    for(size_t i=4;i<20;i++) {
        retire(&records[i-1]);add(0);
        start_round();check(0,i);check(0,i);check(PAGE,RECORDS);end_round();
    }
    add(UINT64_C(0x8000000000000000));add(UINTPTR_MAX&~(uintptr_t)(PAGE-1));
    start_round();check(UINT64_C(0x8000000000000000),20);
    check(UINT64_C(0x8000000000000001),RECORDS);
    check(UINTPTR_MAX&~(uintptr_t)(PAGE-1),21);check(UINTPTR_MAX,RECORDS);end_round();
    static const size_t ends[]={32,128,1024,4096,8192};
    for(size_t k=0;k<sizeof(ends)/sizeof(ends[0]);k++) {
        while(used<ends[k])add(churn_address(used%257));
        churn_queries(0);
    }
    /* Retire cached positives without changing used, leaving older matches. */
    for(size_t key=0;key<257;key+=2) {
        size_t slot=newest(key);
        start_round();check(churn_address(key),slot);end_round();
        retire(&records[slot]);
        start_round();check(churn_address(key),slot-257);end_round();
    }
    churn_queries(1);
    for(size_t i=0;i<used;i++)if(records[i].live)retire(&records[i]);
    start_round();
    for(size_t key=0;key<257;key++)check(churn_address(key),RECORDS);
    check(0,RECORDS);check(PAGE,RECORDS);check(UINT64_C(0x8000000000000000),RECORDS);
    check(UINTPTR_MAX&~(uintptr_t)(PAGE-1),RECORDS);check(UINTPTR_MAX,RECORDS);end_round();
    require(used==RECORDS && generation==RECORDS && counts.generations==RECORDS &&
            counts.retained_records==RECORDS && counts.retired==RECORDS && !counts.live_pages,905);
    require(rounds==292 && queries==3716 && hits==2615 && misses==1101,906);
    printf("{\"version\":1,\"record_capacity\":%u,\"record_bytes\":%zu,"
           "\"appends\":%zu,\"retirements\":%"PRIu64",\"rounds\":%"PRIu64
           ",\"queries\":%"PRIu64",\"hits\":%"PRIu64",\"misses\":%"PRIu64
           ",\"whole_records_and_counts_unchanged\":1,\"linear_and_literal_equal\":1}\n",
           (unsigned)RECORDS,sizeof(struct owned_page),used,counts.retired,rounds,queries,hits,misses);
    return 0;
}
