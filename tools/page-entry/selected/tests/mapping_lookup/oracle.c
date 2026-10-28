/* Integer interval lookup oracle. The complete real translation unit supplies
   mapping(), rows and row_count; dead-section GC drops unrelated runtime code.
   No copied binary helper, target instruction execution or performance claim. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* Byte-exact predecessor body, with only its function name changed. */
static const struct map_row *linear_mapping(uintptr_t address) {
    for (size_t i=0;i<row_count;i++) if (rows[i].first<=address && address<rows[i].end) return &rows[i];
    return 0;
}
__attribute__((noinline,used))
const struct map_row *li2_mapping_oracle(uintptr_t address) {
    return mapping(address);
}
static struct map_row saved_rows[MAP_ROWS];
static uint64_t oracle_queries,oracle_hits,oracle_misses;
static unsigned oracle_layouts;

static int check(uintptr_t address,size_t expected) {
    const struct map_row *want=expected==MAP_ROWS?0:&rows[expected];
    const struct map_row *old=linear_mapping(address);
    const struct map_row *got=li2_mapping_oracle(address);
    ++oracle_queries;
    if(old!=want || got!=want) {
        fprintf(stderr,"lookup mismatch layout=%u query=%"PRIu64" expected=%zu\n",
                oracle_layouts,oracle_queries,expected);
        return 1;
    }
    if(want)++oracle_hits;else ++oracle_misses;
    return 0;
}
static int query_layout(void) {
    size_t saved_count=row_count;
    memcpy(saved_rows,rows,sizeof(rows));
    ++oracle_layouts;
    if(check(0,row_count && rows[0].first==0?0:MAP_ROWS) ||
       check(UINTPTR_MAX,MAP_ROWS))return 1;
    for(size_t i=0;i<row_count;i++) {
        uintptr_t first=rows[i].first,end=rows[i].end;
        size_t previous=i && rows[i-1].end==first?i-1:MAP_ROWS;
        size_t next=i+1<row_count && rows[i+1].first==end?i+1:MAP_ROWS;
        if(check(first,i) || check(first+1,i) ||
           check(first+(end-first)/2,i) || check(end-1,i) ||
           check(end,next) || check(end+1,next))return 1;
        if(first && check(first-1,previous))return 1;
        if(i+1<row_count && end<rows[i+1].first) {
            uintptr_t next_first=rows[i+1].first;
            if(check(end+(next_first-end)/2,MAP_ROWS) ||
               check(next_first-1,MAP_ROWS))return 1;
        }
    }
    if(row_count!=saved_count || memcmp(saved_rows,rows,sizeof(rows))) {
        fputs("lookup mutated complete rows/count\n",stderr);return 1;
    }
    return 0;
}
static int make_layout(size_t n,unsigned mode) {
    if(n>MAP_ROWS || mode>2)return 2;
    /* Fill unused storage too: neither lookup may modify or return it. */
    memset(rows,0xa5,sizeof(rows));row_count=n;
    uintptr_t high=UINTPTR_MAX&~(uintptr_t)(PAGE-1);
    uintptr_t at=mode==2?high-(MAP_ROWS*8UL+8UL)*PAGE:PAGE;
    for(size_t i=0;i<n;i++) {
        uintptr_t bytes=(1+i%3)*PAGE;
        rows[i]=(struct map_row){.first=at,.end=at+bytes,.offset=i*PAGE,
            .major=i%7,.minor=i%11,.inode=i+1,.prot=(unsigned)(i%8),.private=1};
        at+=bytes+(mode?(1+i%4)*PAGE:0);
    }
    return query_layout();
}
int main(void) {
    _Static_assert(sizeof(uintptr_t)==8 && sizeof(struct map_row)==56 && PAGE==4096 && MAP_ROWS==2048,
                   "exact runtime address/page/row domain");
    static const size_t counts[]={0,1,2,3,7,8,9,31,32,33,127,128,129,2047,2048};
    for(unsigned mode=0;mode<3;mode++)
        for(size_t i=0;i<sizeof(counts)/sizeof(counts[0]);i++)
            if(make_layout(counts[i],mode))return 1;
    /* Literal endpoints include zero, adjacency, the signed-address boundary,
       a large empty gap and the last representable page-aligned end. None of
       these integers is dereferenced as a target address. */
    memset(rows,0x5a,sizeof(rows));row_count=5;
    rows[0]=(struct map_row){.first=0,.end=4096};
    rows[1]=(struct map_row){.first=4096,.end=8192};
    rows[2]=(struct map_row){.first=UINT64_C(0x7ffffffffffff000),.end=UINT64_C(0x8000000000000000)};
    rows[3]=(struct map_row){.first=UINT64_C(0x8000000000000000),.end=UINT64_C(0x8000000000002000)};
    rows[4]=(struct map_row){.first=UINT64_C(0xffffffffffffe000),.end=UINT64_C(0xfffffffffffff000)};
    if(query_layout())return 1;
    printf("{\"version\":1,\"layouts\":%u,\"queries\":%"PRIu64",\"hits\":%"PRIu64
           ",\"misses\":%"PRIu64",\"row_capacity\":%u,\"row_bytes\":%zu,"
           "\"whole_rows_unchanged\":1,\"linear_and_literal_equal\":1}\n",
           oracle_layouts,oracle_queries,oracle_hits,oracle_misses,(unsigned)MAP_ROWS,sizeof(struct map_row));
    return 0;
}
