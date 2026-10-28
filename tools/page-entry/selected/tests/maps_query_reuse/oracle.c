/* Whole real lifecycle TU. Supplied sorted tables test the pure predicate;
   a separate real sealed-memfd/maps sequence tests actual phase invalidation.
   No target instruction execution, timing, or application completion claim. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#ifndef LI2_ALIAS_QUERY_TEST
#error "oracle requires observation-only branch counters"
#endif
struct query {unsigned object,prot;uint64_t offset;size_t bytes;uintptr_t first,end;};
static struct map_row saved_rows[MAP_ROWS];
static struct owned_page saved_records[RECORDS];
static struct object saved_objects[OBJECTS];
static uint64_t checks,refusals,table_cases,real_cases,real_maps;
static void need(int yes,unsigned code) {
    if(!yes){fprintf(stderr,"alias oracle failure %u query=%"PRIu64"\n",code,checks);exit(1);}
}
__attribute__((noinline,used))
static int li2_alias_query_oracle(const struct query *q,struct check_error *e) {
    return alias_check_checked(q->object,q->offset,q->bytes,q->prot,q->first,q->end,e);
}
/* The real old body (macro-renamed, with every predicate and iteration intact)
   supplies one reference. Each scenario also supplies its literal result. */
static void check(struct query q,int expected,unsigned hit,unsigned initial_error) {
    size_t nr=row_count,nused=used,no=object_count;
    struct li2_maps_stats ms;struct li2_fetch_map_progress mr;
    struct li2_lifecycle_counts lc;struct transaction transaction;
    memcpy(&ms,&maps_stats,sizeof ms);memcpy(&mr,&maps_receipt,sizeof mr);
    memcpy(&lc,&counts,sizeof lc);memcpy(&transaction,&tx,sizeof tx);
    memcpy(saved_rows,rows,sizeof rows);memcpy(saved_records,records,sizeof records);
    memcpy(saved_objects,objects,sizeof objects);
    uint64_t hits=alias_query_hits,direct=alias_query_direct_calls;
    struct check_error a={initial_error,31},b=a;
    int old=alias_check_direct(q.object,q.offset,q.bytes,q.prot,q.first,q.end,&a);
    int got=li2_alias_query_oracle(&q,&b);++checks;if(expected)++refusals;
    need(old==expected && got==old && a.code==b.code && a.detail==b.detail,10);
    need(alias_query_hits-hits==(hit==1) && alias_query_direct_calls-direct==(hit==0),11);
    need(nr==row_count && nused==used && no==object_count &&
         !memcmp(saved_rows,rows,sizeof rows) && !memcmp(saved_records,records,sizeof records) &&
         !memcmp(saved_objects,objects,sizeof objects) && !memcmp(&ms,&maps_stats,sizeof ms) &&
         !memcmp(&mr,&maps_receipt,sizeof mr) && !memcmp(&lc,&counts,sizeof lc) &&
         !memcmp(&transaction,&tx,sizeof tx),12);
}
/* Explicitly supplied complete acquisition metadata, not kernel evidence.
   Monotonic keys mirror the actual publication shape without resetting it. */
static void publish_table(void) {
    maps_invalidate();active=1;tx.guard=0;
    __atomic_store_n(&maps_stats.active,1,__ATOMIC_RELEASE);
    uint64_t handler=maps_increment(&maps_stats.handler_id);
    uint64_t acquisition=maps_increment(&maps_stats.acquisitions);
    need(handler && acquisition && !maps_stats.poisoned,20);
    maps_receipt_handler=handler;maps_receipt_epoch=maps_stats.mutation_epoch;
    maps_receipt=(struct li2_fetch_map_progress){.fd=-1,.rows=row_count,
        .observation={acquisition,handler,maps_receipt_epoch,LI2_MAPS_FRESH,1}};
    __atomic_store_n(&maps_stats.valid,1,__ATOMIC_RELEASE);
    ++table_cases;
}
static struct query table(size_t n) {
    need(n<=MAP_ROWS,21);memset(rows,0xa5,sizeof rows);row_count=n;
    memset(records,0,sizeof records);used=0;memset(objects,0,sizeof objects);object_count=2;
    objects[0].major=7;objects[0].minor=8;objects[0].inode=9;objects[1]=objects[0];
    for(size_t i=0;i<n;i++)rows[i]=(struct map_row){.first=(16+i*2)*PAGE,
        .end=(17+i*2)*PAGE,.offset=i*PAGE,.major=1,.minor=2,.inode=100+i,
        .prot=PROT_READ,.private=1};
    uintptr_t first=16*PAGE;
    if(n){rows[n-1].major=7;rows[n-1].minor=8;rows[n-1].inode=9;
        rows[n-1].offset=0;rows[n-1].prot=PROT_READ|PROT_EXEC;first=rows[n-1].first;}
    publish_table();return (struct query){0,PROT_READ|PROT_EXEC,0,PAGE,first,first+PAGE};
}
static void supplied(void) {
    static const size_t sizes[]={0,1,2,31,MAP_ROWS};
    for(size_t i=0;i<sizeof sizes/sizeof sizes[0];i++) {
        struct query q=table(sizes[i]);
        /* Eight same-page calls split 7+1 by a new acquisition: exactly the
           conditional common TRACE path, with 2 scans and 6 memo hits. */
        uint64_t h=alias_query_hits,d=alias_query_direct_calls;
        for(unsigned j=0;j<7;j++)check(q,0,j!=0,0);
        publish_table();check(q,0,0,0);
        need(alias_query_hits-h==6 && alias_query_direct_calls-d==2,22);
    }
    struct query q=table(2),other=q;check(q,0,0,0);check(q,0,1,0);
    other.object=1;check(other,0,0,0);check(other,0,1,0);check(q,0,0,0);
    other=q;other.offset=PAGE;check(other,0,0,0);
    other=q;other.bytes=PAGE-1;check(other,0,0,0);
    other=q;other.first++;check(other,0,0,0);
    other=q;other.end--;check(other,0,0,0);
    other=q;other.prot=PROT_EXEC;check(other,0,0,0);check(other,0,0,0);
    other=q;other.prot=PROT_READ;check(other,0,0,0);check(other,0,0,0);
    check(q,0,0,0);check(q,0,0,77);check(q,0,0,0);
    /* Same object index with a changed identity must miss, as must every
       incomplete/changed acquisition or runtime-state component. */
    objects[0].major++;check(q,0,0,0);objects[0].major--;
    objects[0].minor++;check(q,0,0,0);objects[0].minor--;
    objects[0].inode++;check(q,0,0,0);objects[0].inode--;check(q,0,0,0);
    tx.guard=1;check(q,0,0,0);tx.guard=0;check(q,0,0,0);
    active=0;check(q,0,0,0);active=1;check(q,0,0,0);
    maps_stats.active=0;check(q,0,0,0);maps_stats.active=1;check(q,0,0,0);
    maps_stats.valid=0;check(q,0,0,0);publish_table();check(q,0,0,0);
    maps_stats.poisoned=1;check(q,0,0,0);maps_stats.poisoned=0;check(q,0,0,0);
    maps_receipt_handler++;check(q,0,0,0);maps_receipt_handler--;check(q,0,0,0);
    maps_receipt_epoch++;check(q,0,0,0);maps_receipt_epoch--;check(q,0,0,0);
    maps_receipt.observation.acquisition_id++;check(q,0,0,0);
    maps_receipt.observation.acquisition_id--;check(q,0,0,0);
    maps_receipt.observation.handler_id++;check(q,0,0,0);
    maps_receipt.observation.handler_id--;check(q,0,0,0);
    maps_receipt.observation.mutation_epoch++;check(q,0,0,0);
    maps_receipt.observation.mutation_epoch--;check(q,0,0,0);
    maps_receipt.rows++;check(q,0,0,0);maps_receipt.rows--;check(q,0,0,0);
    /* Error ordering and coalesced mapping exclusion: a byte-range exclusion
       must never erase the writable prefix/suffix of a larger same-file VMA. */
    q=table(1);rows[0].end+=2*PAGE;rows[0].prot=PROT_READ|PROT_WRITE;publish_table();
    q.first=rows[0].first+PAGE;q.end=q.first+PAGE;q.offset=PAGE;check(q,0,0,0);check(q,0,1,0);
    q.offset=0;check(q,119,0,0);check(q,119,0,0);
    q.offset=2*PAGE;check(q,119,0,0);q.first=0;q.end=0;check(q,119,0,0);
    q.offset=3*PAGE;check(q,0,0,0);q.offset=3*PAGE-1;check(q,119,0,0);
    q.offset=UINT64_MAX;q.bytes=1;check(q,117,2,0);check(q,77,2,77);
    q=table(1);rows[0].offset=UINT64_MAX-PAGE+1;publish_table();
    check(q,0,0,0);q.first=q.end=0;check(q,118,0,0);check(q,118,0,0);
    q=table(2);rows[0].major=7;rows[0].minor=8;rows[0].inode=9;rows[0].offset=0;
    rows[0].prot=PROT_WRITE;rows[1].offset=UINT64_MAX-PAGE+1;q.first=q.end=0;publish_table();
    check(q,119,0,0);rows[0].prot=PROT_READ;publish_table();check(q,118,0,0);
    /* UINTPTR high endpoints are integers only; no target dereference. */
    q=table(1);rows[0].first=UINT64_MAX-2*PAGE+1;rows[0].end=UINT64_MAX-PAGE+1;
    q.first=rows[0].first;q.end=rows[0].end;publish_table();check(q,0,0,0);check(q,0,1,0);
    /* A write query cannot reuse a prior success when live logical records
       change without a maps change. Exercise the maximum retained extent. */
    q=table(0);q.prot=PROT_READ|PROT_WRITE;used=RECORDS;
    for(size_t i=0;i<used;i++)records[i]=(struct owned_page){.address=(32+i)*PAGE,
        .offset=PAGE,.backing=SEALED,.object=0,.logical=PROT_READ,.live=1};
    check(q,0,0,0);check(q,0,0,0);
    records[RECORDS-1].offset=0;records[RECORDS-1].logical=PROT_READ|PROT_EXEC;
    check(q,119,0,0);records[RECORDS-1].live=0;check(q,0,0,0);
    records[RECORDS-1].live=1;records[RECORDS-1].offset=UINT64_MAX;
    check(q,118,0,0);
}
static long oracle_kernel(long n,long a,long b,long c,long d,long e,long f) {
    errno=0;long result=syscall(n,a,b,c,d,e,f);return result==-1?-errno:result;
}
static long oracle_raw(long n,long a,long b,long c,long d,long e,long f) {
    return li2_maps_raw(oracle_kernel,n,a,b,c,d,e,f);
}
static void fresh_real(void) {
    struct check_error error={0};struct li2_fetch_map_progress p;
    need(!read_maps_checked(&error,&p) && !error.code && p.observation.io_performed &&
         p.observation.acquisition_id && p.opened && p.closed && p.rows==row_count &&
         row_count && row_count<=MAP_ROWS,30);++real_maps;
}
static void real(void) {
    li2_maps_phase_end();hooks.raw=oracle_raw;active=1;tx.guard=0;used=0;
    int fd=(int)oracle_raw(SYS_memfd_create,(long)"alias-query-oracle",MFD_CLOEXEC|MFD_ALLOW_SEALING,0,0,0,0);
    need(fd>=0 && !oracle_raw(SYS_ftruncate,fd,3*PAGE,0,0,0,0) &&
         !oracle_raw(SYS_fcntl,fd,F_ADD_SEALS,SEALS,0,0,0),31);
    memset(objects,0,sizeof objects);object_count=1;
    need(!oracle_raw(SYS_fstat,fd,(long)&objects[0].stat,0,0,0,0),32);
    objects[0].major=major(objects[0].stat.st_dev);objects[0].minor=minor(objects[0].stat.st_dev);
    objects[0].inode=objects[0].stat.st_ino;objects[0].retained_fd=fd;
    long mapping_address=oracle_raw(SYS_mmap,0,PAGE,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0);
    need(!kernel_error(mapping_address),33);uintptr_t source=(uintptr_t)mapping_address;
    struct query q={0,PROT_READ|PROT_EXEC,0,PAGE,source,source+PAGE};
    need(!li2_maps_phase_begin(),34);fresh_real();
    check(q,0,0,0);check(q,0,1,0);++real_cases;
    struct stat actual_stat;
    need(oracle_raw(SYS_getpid,0,0,0,0,0,0)>0 &&
         !oracle_raw(SYS_fstat,fd,(long)&actual_stat,0,0,0,0) &&
         oracle_raw(SYS_fcntl,fd,F_GET_SEALS,0,0,0,0)==SEALS && maps_stats.valid,42);
    check(q,0,1,0);++real_cases;
    long alias=oracle_raw(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
    need(!kernel_error(alias) && !maps_stats.valid,35);fresh_real();
    check(q,119,0,0);check(q,119,0,0);++real_cases;
    need(!oracle_raw(SYS_munmap,alias,PAGE,0,0,0,0),36);fresh_real();check(q,0,0,0);++real_cases;
    need(!oracle_raw(SYS_mprotect,source,PAGE,PROT_READ,0,0,0) && !maps_stats.valid,43);
    fresh_real();check(q,0,0,0);++real_cases;
    need(!oracle_raw(SYS_mprotect,source,PAGE,PROT_READ|PROT_EXEC,0,0,0) && !maps_stats.valid,44);
    fresh_real();check(q,0,0,0);++real_cases;
    need(oracle_raw(SYS_getuid,0,0,0,0,0,0)>=0 && !maps_stats.valid,37);
    fresh_real();check(q,0,0,0);check(q,0,1,0);++real_cases;
    li2_maps_event_boundary();need(!maps_stats.active && !maps_stats.valid,38);
    fresh_real();check(q,0,0,0);check(q,0,0,0);++real_cases;
    need(!li2_maps_phase_begin(),39);fresh_real();check(q,0,0,0);check(q,0,1,0);
    need(oracle_raw(SYS_close,-1,0,0,0,0,0)==-EBADF && !maps_stats.active && !maps_stats.valid,40);
    fresh_real();check(q,0,0,0);check(q,0,0,0);++real_cases;
    li2_maps_phase_end();need(!oracle_raw(SYS_munmap,source,PAGE,0,0,0,0) &&
         !oracle_raw(SYS_close,fd,0,0,0,0,0),41);
}
int main(void) {
    _Static_assert(sizeof(uintptr_t)==8 && MAP_ROWS==2048 && RECORDS==8192,
                   "exact lifecycle address and fixed-storage domains");
    supplied();real();
    printf("{\"version\":1,\"checks\":%"PRIu64",\"refusals\":%"PRIu64
           ",\"memo_hits\":%"PRIu64",\"direct_calls\":%"PRIu64
           ",\"supplied_acquisitions\":%"PRIu64",\"real_cases\":%"PRIu64
           ",\"real_acquisitions\":%"PRIu64",\"old_and_literal_equal\":1,"
           "\"inputs_unchanged\":1,\"same_page_scans\":2,\"same_page_hits\":6}\n",
           checks,refusals,alias_query_hits,alias_query_direct_calls,table_cases,real_cases,real_maps);
    return 0;
}
