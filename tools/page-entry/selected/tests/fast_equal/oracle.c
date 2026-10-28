#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

extern int li2_equal_oracle(const void *,const void *,size_t);
#define PAGE 4096UL
#define ROWS 72
#define INTERVALS 8
#define ITERATIONS 8192
#define MEASURE_LENGTH 2444UL
struct row { uint64_t length,placements,equal_calls,unequal_calls,requested_bytes,
                      verified_image_bytes,pattern_mask,end_guard_inputs; };
struct record {
    uint64_t magic,version,bytes,fast,status,error,completed_lengths,zero_cases,
             overlap_cases,measured,iterations,completed_intervals,measure_length,
             map_attempts,unmap_attempts,unmap_completed;
    struct row rows[ROWS];
    uint64_t nanoseconds[INTERVALS];
};
static struct record record;
static unsigned char *mapping[2],*data[2];
static size_t extent;
static volatile uint64_t sink;
_Static_assert(sizeof(struct row)==64,"closed row extent");
_Static_assert(sizeof(struct record)==4800,"closed record extent");
static uint64_t flags(void) {
    uint64_t v;__asm__ volatile("pushfq; popq %0":"=r"(v)::"memory");return v;
}
static void first(unsigned e) { if(!record.error)record.error=e;record.status=1; }
static void release(void) {
    for(unsigned j=0;j<2;j++)if(mapping[j]) {
        ++record.unmap_attempts;
        if(munmap(mapping[j],extent+2*PAGE))first(2);else ++record.unmap_completed;
        mapping[j]=data[j]=0;
    }
}
static int allocate(size_t n) {
    if(n>65536 || mapping[0] || mapping[1])return 3;
    extent=(n+8+PAGE-1)&~(PAGE-1);
    for(unsigned j=0;j<2;j++) {
        ++record.map_attempts;
        void *p=mmap(0,extent+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p==MAP_FAILED)return 4;
        mapping[j]=p;data[j]=mapping[j]+PAGE;
    }
    return 0;
}
static unsigned char noise(size_t i,unsigned side,size_t ordinal) {
    return (unsigned char)(i*29+side*53+ordinal*17+0x3d);
}
static unsigned char pattern(size_t i,unsigned kind) {
    return kind==0?0:kind==1?0xff:(unsigned char)(i*131+(i>>8)*17+0xa5);
}
static int protect(unsigned j,int p) { return mprotect(data[j],extent,p)?5:0; }
static int call(const void *a,const void *b,size_t n,int expected) {
    if((flags()>>10)&1)return 6;
    int result=li2_equal_oracle(a,b,n);
    if(result!=expected || ((flags()>>10)&1))return 7;
    return 0;
}
static int change(unsigned char *p,unsigned char value) {
    if(protect(1,PROT_READ|PROT_WRITE))return 8;
    *p=value;
    return protect(1,PROT_READ);
}
static int mismatch(struct row *r,unsigned char *x,unsigned char *y,size_t n,size_t at) {
    unsigned char original=y[at];
    for(unsigned bit=1;bit<=128;bit*=128) {
        if(change(y+at,(unsigned char)(original^bit)))return 9;
        if(call(x,y,n,0)||call(y,x,n,0))return 10;
        r->unequal_calls+=2;r->requested_bytes+=2*n;
        if(change(y+at,original))return 11;
    }
    return 0;
}
static int placement(struct row *r,size_t ox,size_t oy,unsigned guarded,size_t ordinal) {
    const size_t n=(size_t)r->length;const unsigned kind=(unsigned)(ordinal%3);
    const size_t offsets[2]={ox,oy};
    if(ox>extent-n || oy>extent-n)return 12;
    for(unsigned j=0;j<2;j++) {
        if(protect(j,PROT_READ|PROT_WRITE))return 13;
        for(size_t i=0;i<extent;i++)data[j][i]=noise(i,j,ordinal);
        for(size_t i=0;i<n;i++)data[j][offsets[j]+i]=pattern(i,kind);
        if(protect(j,PROT_READ))return 14;
    }
    unsigned char *x=data[0]+ox,*y=data[1]+oy;
    if(call(x,y,n,1)||call(y,x,n,1)||call(x,x,n,1))return 15;
    r->equal_calls+=3;r->requested_bytes+=3*n;
    if(n<=33) {
        for(size_t at=0;at<n;at++) {int e=mismatch(r,x,y,n,at);if(e)return e;}
    } else {
        size_t sites[9]={0,1,7,8,9,n/2,(n/8)*8-1,(n/8)*8,n-1};
        for(size_t k=0;k<9;k++) {
            size_t at=sites[k];int duplicate=at>=n;
            for(size_t j=0;j<k;j++)if(sites[j]==at)duplicate=1;
            if(!duplicate) {int e=mismatch(r,x,y,n,at);if(e)return e;}
        }
    }
    /* Check every readable byte, including untouched prefix/suffix. Actual
       helper calls occur only while both complete mappings are read-only. */
    for(unsigned j=0;j<2;j++)for(size_t i=0;i<extent;i++) {
        unsigned char expected=i>=offsets[j]&&i-offsets[j]<n?
            pattern(i-offsets[j],kind):noise(i,j,ordinal);
        if(data[j][i]!=expected)return 16;
        ++r->verified_image_bytes;
    }
    ++r->placements;r->pattern_mask|=UINT64_C(1)<<kind;r->end_guard_inputs+=guarded;
    return 0;
}
static int length(size_t n) {
    if(record.completed_lengths>=ROWS)return 17;
    struct row *r=&record.rows[record.completed_lengths];r->length=n;
    int e=allocate(n);if(e)return e;size_t ordinal=0;
    for(size_t x=0;x<8;x++)for(size_t y=0;y<8;y++) {
        e=placement(r,x,y,0,ordinal++);if(e)return e;
    }
    for(size_t y=0;y<8;y++){e=placement(r,extent-n,y,1,ordinal++);if(e)return e;}
    for(size_t x=0;x<8;x++){e=placement(r,x,extent-n,1,ordinal++);if(e)return e;}
    e=placement(r,extent-n,extent-n,2,ordinal++);if(e)return e;
    if(ordinal!=81)return 18;
    release();if(record.status)return 19;
    ++record.completed_lengths;return 0;
}
static int extras(void) {
    int e=allocate(64);if(e)return e;
    const void *p[4]={0,mapping[0],data[0]+extent,data[1]};
    for(unsigned i=0;i<4;i++)for(unsigned j=0;j<4;j++) {
        if(call(p[i],p[j],0,1))return 20;
        ++record.zero_cases;
    }
    if(protect(0,PROT_READ|PROT_WRITE))return 21;
    for(size_t i=0;i<extent;i++)data[0][i]=0;
    if(protect(0,PROT_READ))return 22;
    for(size_t shift=1;shift<8;shift++) {
        if(call(data[0],data[0]+shift,33,1)||call(data[0]+shift,data[0],33,1))return 23;
        record.overlap_cases+=2;
    }
    if(protect(0,PROT_READ|PROT_WRITE))return 24;
    data[0][16]=0x80;
    if(protect(0,PROT_READ))return 25;
    for(size_t shift=1;shift<8;shift++) {
        if(call(data[0],data[0]+shift,33,0)||call(data[0]+shift,data[0],33,0))return 26;
        record.overlap_cases+=2;
    }
    for(size_t i=0;i<extent;i++)if(data[0][i]!=(i==16?0x80:0))return 27;
    release();return record.status?28:0;
}
static int clock_ns(uint64_t *out) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC_RAW,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000||
       (uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/1000000000)return 29;
    *out=(uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;return 0;
}
static int measure(void) {
    int e=allocate(MEASURE_LENGTH);if(e)return e;
    for(unsigned j=0;j<2;j++) {
        if(protect(j,PROT_READ|PROT_WRITE))return 30;
        for(size_t i=0;i<extent;i++)data[j][i]=pattern(i,2);
        if(protect(j,PROT_READ))return 31;
    }
    record.measured=1;record.iterations=ITERATIONS;record.measure_length=MEASURE_LENGTH;
    for(unsigned i=0;i<1024;i++)if(li2_equal_oracle(data[0],data[1],MEASURE_LENGTH)!=1)return 32;
    for(unsigned sample=0;sample<INTERVALS;sample++) {
        uint64_t start,end,total=0;
        if(clock_ns(&start))return 33;
        for(unsigned i=0;i<ITERATIONS;i++)total+=(unsigned)li2_equal_oracle(data[0],data[1],MEASURE_LENGTH);
        if(clock_ns(&end)||end<=start||total!=ITERATIONS)return 34;
        sink=total;record.nanoseconds[sample]=end-start;record.completed_intervals=sample+1;
    }
    if((flags()>>10)&1)return 35;
    for(unsigned j=0;j<2;j++)for(size_t i=0;i<extent;i++)if(data[j][i]!=pattern(i,2))return 36;
    release();return record.status?37:0;
}
static int emit(void) {
    const unsigned char *p=(const void *)&record;size_t left=sizeof record;
    while(left) {
        ssize_t n=write(1,p,left);
        if(n<0&&errno==EINTR)continue;
        if(n<=0||(size_t)n>left)return 126;
        p+=(size_t)n;left-=(size_t)n;
    }
    return record.status?125:0;
}
int main(int argc,char **argv) {
    int measured=argc==2&&argv[1][0]=='m'&&argv[1][1]==0;
    if(argc!=1&&!measured)return 124;
    record.magic=UINT64_C(0x314551464932494c);record.version=1;record.bytes=sizeof record;
#ifdef LI2_FAST_EQUAL
    record.fast=1;
#endif
    if(sysconf(_SC_PAGESIZE)!=(long)PAGE){first(38);return emit();}
    const size_t large[]={48,63,64,65,72,127,128,129,184,255,256,257,511,512,513,575,576,577,
        1023,1024,1025,2443,2444,2445,4095,4096,4097,8191,8192,8193,16383,16384,16385,
        32767,32768,32769,65535,65536};
    for(size_t n=0;n<=33&&!record.status;n++){int e=length(n);if(e)first((unsigned)e);}
    for(size_t i=0;i<sizeof large/sizeof large[0]&&!record.status;i++) {
        int e=length(large[i]);if(e)first((unsigned)e);
    }
    if(!record.status){int e=extras();if(e)first((unsigned)e);}
    if(!record.status&&measured){int e=measure();if(e)first((unsigned)e);}
    release();
    if(!record.status&&(record.completed_lengths!=ROWS||record.zero_cases!=16||
       record.overlap_cases!=28||record.unmap_completed!=record.map_attempts))first(39);
    return emit();
}
