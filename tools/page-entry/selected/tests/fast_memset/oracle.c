#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "tf_chain.h"
#include "sha256.h"

/* Link the actual bridge.c body, renamed only to avoid libc interposition. */
extern void *li2_test_memset(void *,int,size_t);
#define PAGE_BYTES 4096UL
#define MAX_ROWS 273
#define SAMPLES 8
#define ITERATIONS 256
struct row {
    uint64_t ordinal,length,extent,offset,fill,checked,return_ok,df_before,df_after;
    unsigned char before[32],after[32];
};
struct record {
    uint64_t magic,version,bytes,status,error,completed,slot_bytes,measured;
    uint64_t iterations,samples;
    struct row rows[MAX_ROWS];
    uint64_t nanoseconds[SAMPLES];
};
static struct record record;
_Static_assert(sizeof(struct row)==136,"closed row layout");
_Static_assert(sizeof(struct record)==37272,"closed record layout");
static uint64_t flags(void) {
    uint64_t v;__asm__ volatile("pushfq; popq %0":"=r"(v)::"memory");return v;
}
static unsigned char initial(size_t i,size_t ordinal) {
    return (unsigned char)(i*29+ordinal*17+0x3d);
}
static int emit(void) {
    const unsigned char *p=(const void *)&record;size_t left=sizeof record;
    while(left) {
        ssize_t n=write(1,p,left);
        if(n<0 && errno==EINTR)continue;
        if(n<=0 || (size_t)n>left)return 126;
        p+=(size_t)n;left-=(size_t)n;
    }
    return record.status?125:0;
}
static int failure(unsigned code) {
    if(!record.error)record.error=code;
    record.status=1;return emit();
}
static int one(size_t n,int fill,unsigned placement) {
    if(record.completed>=MAX_ROWS || n>sizeof(struct li2_tf_chain_slot)+1)return 1;
    size_t extent=(n+64+PAGE_BYTES-1)&~(PAGE_BYTES-1);
    unsigned char *mapping=mmap(0,extent+2*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(mapping==MAP_FAILED)return 2;
    unsigned char *p=mapping+PAGE_BYTES;
    if(mprotect(p,extent,PROT_READ|PROT_WRITE))return 3;
    struct row *r=&record.rows[record.completed];
    r->ordinal=record.completed;r->length=n;r->extent=extent;
    r->offset=placement==0?0:placement==1?1:placement==2?7:extent-n;
    r->fill=(uint64_t)(int64_t)fill;
    for(size_t i=0;i<extent;i++)p[i]=initial(i,r->ordinal);
    digest(p,extent,r->before);
    r->df_before=(flags()>>10)&1;
    void *returned=li2_test_memset(p+r->offset,fill,n);
    r->df_after=(flags()>>10)&1;r->return_ok=returned==p+r->offset;
    if(r->df_before || r->df_after || !r->return_ok)return 4;
    for(size_t i=0;i<extent;i++) {
        unsigned char expected=i>=r->offset && i-r->offset<n?(unsigned char)fill:initial(i,r->ordinal);
        if(p[i]!=expected)return 5;
        r->checked=i+1;
    }
    digest(p,extent,r->after);
    if(munmap(mapping,extent+2*PAGE_BYTES))return 6;
    ++record.completed;return 0;
}
static int clock_ns(uint64_t *out) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC_RAW,&t) || t.tv_sec<0 || t.tv_nsec<0 ||
       t.tv_nsec>=1000000000 || (uint64_t)t.tv_sec>UINT64_MAX/1000000000)return 1;
    uint64_t first=(uint64_t)t.tv_sec*1000000000;
    if(first>UINT64_MAX-(uint64_t)t.tv_nsec)return 1;
    *out=first+(uint64_t)t.tv_nsec;return 0;
}
static int measure(void) {
    const size_t n=sizeof(struct li2_tf_chain_slot);
    size_t extent=(2*n+PAGE_BYTES-1)&~(PAGE_BYTES-1);
    unsigned char *mapping=mmap(0,extent+2*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(mapping==MAP_FAILED)return 10;
    unsigned char *p=mapping+PAGE_BYTES;
    if(mprotect(p,extent,PROT_READ|PROT_WRITE))return 11;
    for(size_t i=0;i<extent;i++)p[i]=0xa5;
    record.measured=1;record.iterations=ITERATIONS;
    for(size_t sample=0;sample<SAMPLES;sample++) {
        uint64_t a,b;
        if(clock_ns(&a))return 12;
        for(size_t i=0;i<ITERATIONS;i++) {
            void *to=p+(i&1)*n;
            if(li2_test_memset(to,0,n)!=to)return 13;
        }
        if(clock_ns(&b) || b<=a)return 14;
        record.nanoseconds[sample]=b-a;record.samples=sample+1;
    }
    if((flags()>>10)&1)return 15;
    for(size_t i=0;i<extent;i++)if(p[i]!=(i<2*n?0:0xa5))return 16;
    if(munmap(mapping,extent+2*PAGE_BYTES))return 17;
    return 0;
}
int main(int argc,char **argv) {
    int measured=argc==2 && argv[1][0]=='m' && argv[1][1]==0;
    if(argc!=1 && !measured)return 124;
    record.magic=UINT64_C(0x315a53414632494c);record.version=1;
    record.bytes=sizeof record;record.slot_bytes=sizeof(struct li2_tf_chain_slot);
    if(sysconf(_SC_PAGESIZE)!=(long)PAGE_BYTES || record.slot_bytes>1024*1024)return failure(20);
    const size_t sizes[]={0,1,7,8,15,16,63,64,65,2444,4095,4096,4097,65536,
        sizeof(struct li2_tf_chain_slot)-1,sizeof(struct li2_tf_chain_slot),sizeof(struct li2_tf_chain_slot)+1};
    const int fills[]={0,0xa5,0x100,-1};
    for(size_t s=0;s<sizeof sizes/sizeof sizes[0];s++)
        for(size_t f=0;f<sizeof fills/sizeof fills[0];f++)
            for(unsigned placement=0;placement<4;placement++) {
                int r=one(sizes[s],fills[f],placement);if(r)return failure((unsigned)r);
            }
    /* Zero length must not access even NULL. The right-edge zero cases above
       independently use the first byte of a genuinely PROT_NONE guard. */
    struct row *z=&record.rows[record.completed];z->ordinal=record.completed;z->fill=0x5a;
    z->df_before=(flags()>>10)&1;z->return_ok=li2_test_memset(0,0x5a,0)==0;
    z->df_after=(flags()>>10)&1;
    if(!z->return_ok || z->df_before || z->df_after)return failure(21);
    ++record.completed;
    if(record.completed!=MAX_ROWS)return failure(22);
    if(measured){int r=measure();if(r)return failure((unsigned)r);}
    return emit();
}
