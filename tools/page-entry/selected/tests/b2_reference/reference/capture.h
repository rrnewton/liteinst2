#ifndef LI2_B2_REFERENCE_CAPTURE_H
#define LI2_B2_REFERENCE_CAPTURE_H
/* Fixture-only observation. Caller supplies the real signal-frame allocation
   bounds and a gateway that performs actual ARCH_GET_FS/GS. No page permission,
   source, frame, callback result or application state is written by this code. */
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/ucontext.h>
struct b2_snapshot {
    uint64_t h[16];unsigned char si[128];
    unsigned char uc[2048],fp[65536],source[20480],data[8192];
};
_Static_assert(sizeof(siginfo_t)==128 && offsetof(siginfo_t,si_addr)==16,"Linux x86-64 siginfo wire");
_Static_assert(sizeof(struct b2_snapshot)==96512,"exact full snapshot wire");
typedef long (*b2_get_base)(unsigned,uintptr_t *);
static void b2_copy(void *dst,const void *src,size_t n) {
    unsigned char *d=dst;const volatile unsigned char *s=src;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static uint32_t b2_u32(const unsigned char *b) {
    return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);
}
static int b2_inside(uintptr_t at,size_t n,uintptr_t lo,size_t bytes) {
    return at>=lo && n<=bytes && at-lo<=bytes-n;
}
static int b2_overlap(uintptr_t a,size_t n,uintptr_t b,size_t m) {
    return a<=UINTPTR_MAX-n && b<=UINTPTR_MAX-m && a<b+m && b<a+n;
}
static int b2_capture(struct b2_snapshot *out,int signal,const siginfo_t *si,const ucontext_t *uc,
                      uintptr_t frame_lo,size_t frame_bytes,b2_get_base actual_get_base) {
    if(!out || !si || !uc || !actual_get_base)return 1;
    uintptr_t dst=(uintptr_t)out;
    if(dst>UINTPTR_MAX-sizeof *out || frame_lo>UINTPTR_MAX-frame_bytes ||
       b2_overlap(dst,sizeof *out,frame_lo,frame_bytes) ||
       b2_overlap(dst,sizeof *out,UINT64_C(0x200400000),20480) ||
       b2_overlap(dst,sizeof *out,UINT64_C(0x200600000),8192))return 1;
    uintptr_t u=(uintptr_t)uc;
    if(sizeof *uc>sizeof out->uc || !b2_inside(u,sizeof *uc,frame_lo,frame_bytes) ||
       !b2_inside((uintptr_t)si,sizeof *si,frame_lo,frame_bytes))return 1;
    uintptr_t p=(uintptr_t)uc->uc_mcontext.fpregs;
    if(
       !b2_inside(p,512,frame_lo,frame_bytes) || (p&15))return 1;
    const unsigned char *fp=(const void *)p;size_t n=512;
    if(b2_u32(fp+464)==UINT32_C(0x46505853)) {
        n=b2_u32(fp+468);size_t x=b2_u32(fp+480);
        if(n<580 || n>sizeof out->fp || !b2_inside(p,n,frame_lo,frame_bytes) ||
           x<576 || x!=n-4 || b2_u32(fp+n-4)!=UINT32_C(0x46505845))return 2;
    }
    uintptr_t fs,gs;
    /* The adapter must issue these real read-only requests, preserve their
       actual return values, and fail on either error. No cached/fake bases. */
    if(actual_get_base(0x1003,&fs)!=0 || actual_get_base(0x1004,&gs)!=0)return 3;
    unsigned short ds,es;
    __asm__ volatile("mov %%ds,%0; mov %%es,%1":"=r"(ds),"=r"(es)::"memory");
    volatile unsigned char *zero=(void *)out;
    for(size_t i=0;i<sizeof *out;i++)zero[i]=0;
    out->h[0]=sizeof *uc;out->h[1]=n;out->h[2]=u;out->h[3]=p;
    out->h[4]=fs;out->h[5]=gs;out->h[6]=ds;out->h[7]=es;
    out->h[8]=offsetof(ucontext_t,uc_mcontext.gregs);
    out->h[9]=offsetof(ucontext_t,uc_mcontext.fpregs);out->h[10]=offsetof(ucontext_t,uc_sigmask);
    out->h[12]=(unsigned)signal;out->h[13]=(uintptr_t)si;out->h[14]=sizeof *si;
    b2_copy(out->si,si,sizeof *si);
    b2_copy(out->uc,uc,sizeof *uc);b2_copy(out->fp,fp,n);
    b2_copy(out->source,(const void *)(uintptr_t)UINT64_C(0x200400000),sizeof out->source);
    b2_copy(out->data,(const void *)(uintptr_t)UINT64_C(0x200600000),sizeof out->data);
    return 0;
}
#endif
