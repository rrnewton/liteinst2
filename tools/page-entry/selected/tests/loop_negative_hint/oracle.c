/* Actual installed loader TU and actual hint helpers. These are controlled
   metadata fixtures, not observations of an owner cancellation or permission
   to execute guest code. No decoder, equality, copying or syscall stub accepts
   work: unexpected loader hooks fail. Unreferenced owner paths are link-GCed. */
#include "lifecycle_loader.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned hits,misses;
static const uintptr_t hp[2]={UINT64_C(0x200000),UINT64_C(0x201000)};
static const uintptr_t root_pc=UINT64_C(0x200080);
static _Noreturn void fail(const char *label) {
    fprintf(stderr,"loop negative hint: %s\n",label);exit(1);
}
static void need(int yes,const char *label) {if(!yes)fail(label);}
static _Noreturn void unexpected_fail(unsigned code,long detail) {
    fprintf(stderr,"unexpected loader failure %u/%ld\n",code,detail);exit(1);
}
static long unexpected_raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;fail("unexpected raw syscall");
}
static void expect(unsigned expected,uintptr_t pc,const uintptr_t pages[2],const char *label) {
    static unsigned char source_before[sizeof pg_source],hint_before[sizeof pg_negative_hint];
    static struct owned_page records_before[RECORDS];
    struct li2_lifecycle_counts counts_before=counts;
    size_t used_before=used;uint64_t generation_before=generation;
    memcpy(source_before,&pg_source,sizeof pg_source);
    memcpy(hint_before,&pg_negative_hint,sizeof pg_negative_hint);
    memcpy(records_before,records,sizeof records);
    need(li2_pg_source_negative_decline(pc,pages)==(int)expected,label);
    need(!memcmp(source_before,&pg_source,sizeof pg_source) &&
        !memcmp(hint_before,&pg_negative_hint,sizeof pg_negative_hint) &&
        !memcmp(records_before,records,sizeof records) &&
        !memcmp(&counts_before,&counts,sizeof counts) && used==used_before &&
        generation==generation_before,"lookup has no metadata/counter effects");
    if(expected)++hits;else ++misses;
}
static struct li2_plnh_key key(size_t first,size_t second,uintptr_t pc) {
    struct li2_plnh_key k={.pc=pc};
    need(pgs_hint_page(first,&k.page[0]) && pgs_hint_page(second,&k.page[1]) &&
        li2_plnh_key_valid(&k),"valid actual owned key");return k;
}
static void fixture(unsigned backing) {
    memset(records,0,sizeof records);memset(&pg_source,0,sizeof pg_source);
    memset(&pg_negative_hint,0,sizeof pg_negative_hint);memset(&counts,0,sizeof counts);
    used=0;generation=0;allocation_id=1;object_count=backing==SEALED?2:0;active=1;
    hooks.raw=unexpected_raw;hooks.fail=unexpected_fail;
    pg_source.p.initialized=1;pg_source.p.phase=LI2_PGS_IDLE;
    for(unsigned i=0;i<2;i++)append(hp[i],1,i*PAGE,backing,backing==SEALED?0:OBJECTS,
        PROT_READ|PROT_EXEC,PROT_READ);
}
#define MUTATE(field,value) do { \
    records[j].field=(value);expect(0,root_pc,hp,#field);records[j]=original; \
} while(0)
static void identity_cases(unsigned backing) {
    fixture(backing);expect(0,root_pc,hp,"empty hint");
    struct li2_plnh_key k=key(0,1,root_pc);li2_plnh_put(&pg_negative_hint,&k);
    expect(1,root_pc,hp,"forced exact source lifetime hit");
    records[0].actual=PROT_READ|PROT_EXEC;expect(1,root_pc,hp,"first TF RX");
    records[0].actual=PROT_READ;records[1].actual=PROT_READ|PROT_EXEC;
    expect(1,root_pc,hp,"second TF RX");records[0].actual=PROT_READ|PROT_EXEC;
    expect(1,root_pc,hp,"both TF RX");records[0].actual=records[1].actual=PROT_READ;
    for(unsigned j=0;j<2;j++) {
        const struct owned_page original=records[j];
        MUTATE(address,original.address+PAGE);
        MUTATE(allocation,original.allocation+1);
        MUTATE(generation,original.generation+1);
        MUTATE(offset,original.offset+1);
        MUTATE(initial_extent,original.initial_extent+PAGE);
        MUTATE(backing,3);
        MUTATE(object,original.object+1);
        MUTATE(logical,PROT_READ|PROT_WRITE);
        MUTATE(actual,PROT_NONE);
        MUTATE(actual,PROT_READ|PROT_WRITE);
        MUTATE(actual,PROT_READ|PROT_WRITE|PROT_EXEC);
        MUTATE(live,0);
        MUTATE(admitted,1);
    }
    expect(0,root_pc+1,hp,"different full PC");
    expect(0,root_pc+(UINT64_C(1)<<32),hp,"same low PC bits");
    uintptr_t other[2]={hp[0]+PAGE,hp[1]+PAGE},reverse[2]={hp[1],hp[0]};
    expect(0,root_pc,other,"different full pair");expect(0,root_pc,reverse,"reversed pair");
    expect(0,root_pc,0,"missing pair");
    pg_source.p.initialized=0;expect(0,root_pc,hp,"not initialized");pg_source.p.initialized=1;
    pg_source.p.first_error=1;expect(0,root_pc,hp,"source error");pg_source.p.first_error=0;
    pg_source.p.aborted=1;expect(0,root_pc,hp,"source abort");pg_source.p.aborted=0;
    pg_source.p.phase=LI2_PGS_HELD;expect(0,root_pc,hp,"actual source interlock");
    pg_source.p.phase=LI2_PGS_IDLE;
    pg_negative_hint.count=LI2_PLNH_ENTRIES+1;expect(0,root_pc,hp,"invalid capacity");
    pg_negative_hint.count=1;pg_negative_hint.next=LI2_PLNH_ENTRIES;
    expect(0,root_pc,hp,"invalid cursor");pg_negative_hint.next=1;
    used=1;expect(0,root_pc,hp,"missing second record");used=RECORDS+1;
    expect(0,root_pc,hp,"invalid record bound");used=2;
    size_t old_objects=object_count;object_count=OBJECTS+1;
    expect(0,root_pc,hp,"invalid object bound");object_count=old_objects;
    /* Actual production retirement/append functions, not a replacement model.
       The same virtual address/allocation/offset gets a different lifetime. */
    retire(&records[0]);append(hp[0],1,0,backing,backing==SEALED?0:OBJECTS,
        PROT_READ|PROT_EXEC,PROT_READ);
    expect(0,root_pc,hp,"guest protection/remap retirement invalidates");
    k=key(2,1,root_pc);li2_plnh_put(&pg_negative_hint,&k);
    expect(1,root_pc,hp,"new independent lifetime can be remembered");
    retire(&records[1]);expect(0,root_pc,hp,"second page unmap invalidates");
}
#undef MUTATE
static void capacity_cases(void) {
    fixture(ANONYMOUS);
    for(unsigned i=0;i<LI2_PLNH_ENTRIES;i++) {
        struct li2_plnh_key k=key(0,1,root_pc+i);li2_plnh_put(&pg_negative_hint,&k);
    }
    need(pg_negative_hint.count==8 && pg_negative_hint.next==0,"fixed eight entry capacity");
    for(unsigned i=0;i<LI2_PLNH_ENTRIES;i++)expect(1,root_pc+i,hp,"all eight live keys");
    struct li2_plnh_key k=key(0,1,root_pc+7);li2_plnh_put(&pg_negative_hint,&k);
    need(pg_negative_hint.count==8 && pg_negative_hint.next==0,"duplicate does not evict");
    k=key(0,1,root_pc+8);li2_plnh_put(&pg_negative_hint,&k);
    need(pg_negative_hint.count==8 && pg_negative_hint.next==1,"bounded round-robin replacement");
    expect(0,root_pc,hp,"oldest key replaced");
    for(unsigned i=1;i<=LI2_PLNH_ENTRIES;i++)expect(1,root_pc+i,hp,"remaining eight live keys");
}
static unsigned protect_hint;
static int protected_fixture(uintptr_t a,size_t n) {
    if(n!=1)return 0;
    uintptr_t source=(uintptr_t)&pg_source,hint=(uintptr_t)&pg_negative_hint;
    return (a>=source && a-source<sizeof pg_source) ||
        (protect_hint && a>=hint && a-hint<sizeof pg_negative_hint);
}
static void storage_cases(void) {
    fixture(ANONYMOUS);pg_source.p.initialized=0;hooks.protected_range=protected_fixture;
    protect_hint=0;need(li2_pg_source_initialize()==LI2_FETCH_STATE && !pg_source.p.initialized,
        "cache storage must be protected");
    protect_hint=1;need(!li2_pg_source_initialize() && pg_source.p.initialized==1,
        "actual initialize protects both complete objects");
}
int main(void) {
    identity_cases(SEALED);identity_cases(ANONYMOUS);capacity_cases();storage_cases();
    need(hits==26 && misses==87,"fixed complete positive and invalidation populations");
    printf("loop_negative_hint hits=%u misses=%u storage=2 entries=8 owner_entries=0\n",hits,misses);
    return 0;
}
