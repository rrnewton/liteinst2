#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "repeat_lease.h"
#if LI2_FAST_EQUAL != 1 || LI2_REPEAT_ZERO_ORACLE != 1
#error "exact word-path actual-helper oracle recipe required"
#endif

extern int li2_repeat_owner_zero_oracle(const void *,size_t);
extern int li2_repeat_custody_zero_oracle(const void *,size_t);
#define PAGE_BYTES 4096UL
#define OWNER_BYTES 269440UL
_Static_assert(sizeof(struct li2_repeat_lease_owner)==OWNER_BYTES,"actual complete owner extent");
typedef int (*helper)(const void *,size_t);
static const helper helpers[2]={li2_repeat_owner_zero_oracle,li2_repeat_custody_zero_oracle};
static struct {
    uint64_t status,error,short_cases,large_cases,null_guard_cases;
    uint64_t zero_calls[2],nonzero_calls[2],requested[2],verified_bytes;
    uint64_t opened,closed;
} result;
static struct {
    unsigned char *reservation,*input,*writer;
    size_t extent;
    int fd;
} region={.fd=-1};

static int fail(unsigned error) {
    if(!result.error)result.error=error;
    result.status=1;return (int)error;
}
static void release(void) {
    int complete=region.reservation && region.writer && region.fd>=0;
    int cleanup_error=0;
    if(region.writer && munmap(region.writer,region.extent)) { fail(2);cleanup_error=1; }
    if(region.reservation && munmap(region.reservation,region.extent+2*PAGE_BYTES)) { fail(3);cleanup_error=1; }
    if(region.fd>=0 && close(region.fd)) { fail(4);cleanup_error=1; }
    if(complete && !cleanup_error)++result.closed;
    region.reservation=region.input=region.writer=0;region.extent=0;region.fd=-1;
}
static int allocate(size_t maximum) {
    if(region.reservation || region.writer || region.fd!=-1 || maximum>OWNER_BYTES+7)return fail(5);
    region.extent=(maximum+32+PAGE_BYTES-1)&~(PAGE_BYTES-1);
    region.fd=memfd_create("repeat-zero-input",MFD_CLOEXEC);
    if(region.fd<0 || ftruncate(region.fd,(off_t)region.extent))return fail(6);
    void *p=mmap(0,region.extent+2*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED)return fail(7);
    region.reservation=p;region.input=region.reservation+PAGE_BYTES;
    p=mmap(region.input,region.extent,PROT_READ,MAP_SHARED|MAP_FIXED,region.fd,0);
    if(p==MAP_FAILED || p!=region.input)return fail(8);
    p=mmap(0,region.extent,PROT_READ|PROT_WRITE,MAP_SHARED,region.fd,0);
    if(p==MAP_FAILED)return fail(9);
    region.writer=p;++result.opened;return 0;
}
static unsigned char noise(size_t at) { return (unsigned char)(1+at%255); }
static int reference(const void *p,size_t n) {
    const volatile unsigned char *b=p;
    for(size_t i=0;i<n;i++)if(b[i])return 0;
    return 1;
}
static int observe(const void *p,size_t n,int expected) {
    /* Only the R alias (or an unreadable pointer with n=0) reaches a helper.
       The distinct RW alias is fixture setup, never runtime write authority. */
    __asm__ volatile("":::"memory");
    if(reference(p,n)!=expected)return fail(10);
    for(unsigned j=0;j<2;j++) {
        int got=helpers[j](p,n);
        if(got!=expected)return fail(11+j);
        if(expected)++result.zero_calls[j];else ++result.nonzero_calls[j];
        result.requested[j]+=n;
    }
    __asm__ volatile("":::"memory");return 0;
}
static int mismatch(size_t offset,size_t n,size_t at) {
    if(at>=n)return fail(13);
    static const unsigned char bits[2]={1,128};
    for(unsigned b=0;b<2;b++) {
        region.writer[offset+at]=bits[b];
        if(observe(region.input+offset,n,0))return (int)result.error;
        if(region.input[offset+at]!=bits[b])return fail(14);
        region.writer[offset+at]=0;
    }
    return 0;
}
/* Whole-owner samples surround every actual FP extent and the final word/tail.
   The short matrix independently visits every byte and low/high bit. */
static int large_mismatches(size_t offset,size_t n) {
    const size_t frames[]={
        offsetof(struct li2_repeat_lease_owner,repeat.step.before.fp),
        offsetof(struct li2_repeat_lease_owner,repeat.step.after.fp),
        offsetof(struct li2_repeat_lease_owner,unexpected_frame.fp),
        offsetof(struct li2_repeat_lease_owner,nested_frame.fp)};
    size_t sites[40],used=0;
#define SITE(v) do { size_t at=(v);int duplicate=at>=n; \
    for(size_t k=0;k<used;k++)if(sites[k]==at)duplicate=1; \
    if(!duplicate) { if(used==40)return fail(15);sites[used++]=at; } } while(0)
    SITE(0);SITE(1);SITE(7);SITE(8);SITE(n/2);
    SITE(n-9);SITE(n-8);SITE(n-2);SITE(n-1);
    for(size_t j=0;j<4;j++) {
        if(frames[j])SITE(frames[j]-1);
        SITE(frames[j]);SITE(frames[j]+1);
        SITE(frames[j]+LI2_STEP_FP_BYTES-1);SITE(frames[j]+LI2_STEP_FP_BYTES);
    }
#undef SITE
    for(size_t i=0;i<used;i++)if(mismatch(offset,n,sites[i]))return (int)result.error;
    return 0;
}
static int placement(size_t offset,size_t n,int large) {
    if(offset>region.extent || n>region.extent-offset)return fail(16);
    for(size_t i=0;i<region.extent;i++)region.writer[i]=noise(i);
    for(size_t i=0;i<n;i++)region.writer[offset+i]=0;
    if(observe(region.input+offset,n,1))return (int)result.error;
    if(large) {
        if(large_mismatches(offset,n))return (int)result.error;
    } else for(size_t at=0;at<n;at++)if(mismatch(offset,n,at))return (int)result.error;
    if(observe(region.input+offset,n,1))return (int)result.error;
    /* All calls use the read-only mapping. Also retain full-image integrity,
       including nonzero readable bytes outside the exact requested range. */
    for(size_t i=0;i<region.extent;i++) {
        unsigned char want=i>=offset && i-offset<n?0:noise(i);
        if(region.input[i]!=want || region.writer[i]!=want)return fail(17);
        ++result.verified_bytes;
    }
    if(large)++result.large_cases;else ++result.short_cases;
    return 0;
}
static int run(void) {
    if(sysconf(_SC_PAGESIZE)!=(long)PAGE_BYTES)return fail(18);
    if(allocate(128))return (int)result.error;
    const void *zero[3]={0,region.reservation,region.input+region.extent};
    for(unsigned j=0;j<3;j++) {
        if(observe(zero[j],0,1))return (int)result.error;
        ++result.null_guard_cases;
    }
    for(size_t n=0;n<=128;n++) {
        for(size_t alignment=0;alignment<16;alignment++)
            if(placement(16+alignment,n,0))return (int)result.error;
        if(placement(0,n,0) || placement(region.extent-n,n,0))return (int)result.error;
    }
    release();if(result.status)return (int)result.error;
    if(allocate(OWNER_BYTES+7))return (int)result.error;
    for(size_t tail=0;tail<8;tail++) {
        size_t n=OWNER_BYTES+tail;
        if(placement(0,n,1) || placement(15,n,1) ||
           placement(region.extent-n,n,1))return (int)result.error;
    }
    release();if(result.status)return (int)result.error;
    if(result.short_cases!=2322 || result.large_cases!=24 || result.null_guard_cases!=3 ||
       result.opened!=2 || result.closed!=2 || result.verified_bytes!=15998976 ||
       result.zero_calls[0]!=4695 || result.zero_calls[1]!=4695 ||
       result.nonzero_calls[0]!=298572 || result.nonzero_calls[1]!=298572 ||
       result.requested[0]!=404057454 || result.requested[1]!=404057454)return fail(19);
    return 0;
}
int main(int argc,char **argv) {
    (void)argv;if(argc!=1)return 124;
    (void)run();release();
    int n=printf("{\"version\":1,\"status\":%"PRIu64",\"error\":%"PRIu64
        ",\"fast\":1,\"owner_bytes\":%lu,\"short_cases\":%"PRIu64
        ",\"large_cases\":%"PRIu64",\"null_guard_cases\":%"PRIu64
        ",\"calls\":[[%"PRIu64",%"PRIu64",%"PRIu64"],[%"PRIu64",%"PRIu64",%"PRIu64
        "]],\"verified_bytes\":%"PRIu64",\"opened\":%"PRIu64",\"closed\":%"PRIu64"}\n",
        result.status,result.error,OWNER_BYTES,result.short_cases,result.large_cases,result.null_guard_cases,
        result.zero_calls[0],result.nonzero_calls[0],result.requested[0],
        result.zero_calls[1],result.nonzero_calls[1],result.requested[1],result.verified_bytes,result.opened,result.closed);
    return n<0 || fflush(stdout)?126:result.status?125:0;
}
