#include "app.h"
#if PA_DSO
#define P(x) pa_dso_##x
#define MODULE 1U
#else
#define P(x) pa_main_##x
#define MODULE 0U
#endif
#define H __attribute__((visibility("hidden")))
H uint64_t P(input)[17],P(before)[17],P(after)[17],P(host)[8],P(mask),P(target);
H unsigned char P(before_live)[PA_LIVE] __attribute__((aligned(64)));
H unsigned char P(after_live)[PA_LIVE] __attribute__((aligned(64)));
H unsigned char P(vectors)[2048] __attribute__((aligned(64)));
H uint64_t P(masks)[8];
H unsigned short P(host_fcw);
extern unsigned char P(page)[],P(page_end)[],P(cpuid)[],P(cpuid_next)[],
    P(getpid)[],P(getpid_next)[],P(rdtsc)[],P(rdtsc_next)[],P(capture_after)[];
extern void P(machine)(void);
static unsigned char saved_page[PA_PAGE],stack[PA_STACK] __attribute__((aligned(64)));
static uint64_t extent,clock_previous;
static int ready;
static void bytes(void *d,const void *s,size_t n) {
    volatile unsigned char *to=d;const volatile unsigned char *from=s;
    for(size_t i=0;i<n;i++)to[i]=from[i];
}
static int equal(const void *a,const void *b,size_t n) {
    const volatile unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static void zero(void *d,size_t n) {
    volatile unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=0;
}
static unsigned char *site(unsigned kind) {
    return kind==PA_CPUID?P(cpuid):kind==PA_GETPID?P(getpid):P(rdtsc);
}
void P(image)(struct pa_image *out) {
    *out=(struct pa_image){MODULE,(uintptr_t)P(page),(uintptr_t)P(page_end),
        (uintptr_t)(stack+PA_STACK-256),{(uintptr_t)P(cpuid),(uintptr_t)P(getpid),(uintptr_t)P(rdtsc)},
        {(uintptr_t)P(cpuid_next),(uintptr_t)P(getpid_next),(uintptr_t)P(rdtsc_next)},
        (uintptr_t)P(capture_after)};
}
int P(setup)(uint64_t mask,uint64_t size) {
    if(ready || mask&~PA_KNOWN || (mask&0xe7)!=0xe7 || size<576 || size>PA_FP ||
       (uintptr_t)P(page)%PA_PAGE || (uintptr_t)P(page_end)-(uintptr_t)P(page)!=PA_PAGE ||
       (uintptr_t)P(cpuid)-(uintptr_t)P(page)!=128 || (uintptr_t)P(getpid)-(uintptr_t)P(page)!=160 ||
       (uintptr_t)P(rdtsc)-(uintptr_t)P(page)!=192)return 1;
    for(unsigned k=0;k<PA_KINDS;k++) {
        const unsigned char expected[5]={15,k==PA_CPUID?162:k==PA_GETPID?5:49,144,144,144};
        if(!equal(site(k),expected,5))return 2;
    }
    P(mask)=mask;extent=size;bytes(saved_page,P(page),PA_PAGE);
    for(size_t i=0;i<PA_STACK;i++)stack[i]=0x5a;
    for(unsigned r=0;r<32;r++)for(unsigned b=0;b<64;b++)
        P(vectors)[r*64+b]=(unsigned char)(1+(r*17+b*13)%255);
    for(unsigned r=0;r<8;r++)P(masks)[r]=UINT64_C(0x1020304050607080)+r*UINT64_C(0x0101010101010101);
    ready=1;return 0;
}
int P(step)(unsigned kind,unsigned iteration,int scripted,uint64_t pid,
            const uint32_t cpuid[4],struct pa_view *out) {
    if(!ready || kind>=PA_KINDS || iteration>=PA_STRESS_ROUNDS ||
       (scripted!=0 && scripted!=1) || !pid || !out)return 3;
    for(unsigned i=0;i<16;i++)P(input)[i]=UINT64_C(0x1111000000000000)+
        ((uint64_t)MODULE<<40)+((uint64_t)iteration<<16)+((uint64_t)kind<<8)+i;
    P(input)[4]=(uintptr_t)(stack+PA_STACK-256);P(input)[16]=PA_FLAGS;
    if(kind==PA_CPUID)P(input)[0]=P(input)[1]=0;
    if(kind==PA_GETPID)P(input)[0]=39;
    zero(P(before_live),PA_LIVE);zero(P(after_live),PA_LIVE);P(target)=(uintptr_t)site(kind);
    P(machine)();
    /* Read the actual restored original five bytes immediately after the
       assembly capture, before any further selected application operation. */
    const unsigned char expected_bytes[5]={15,kind==PA_CPUID?162:kind==PA_GETPID?5:49,144,144,144};
    bytes(out->restored,site(kind),5);
    if(!equal(out->restored,expected_bytes,5) || !equal(P(before),P(input),sizeof P(input)))return 4;
    uint64_t expected[17];bytes(expected,P(before),sizeof expected);
    if(kind==PA_CPUID) {
        static const uint32_t scripted_cpuid[2][4]={{0x13579bdf,0x2468ace0,0x10203040,0xa5a5a5a5},
            {0x11223344,0x55667788,0x99aabbcc,0xddeeff00}};
        const uint32_t *r=scripted?scripted_cpuid[MODULE]:cpuid;
        expected[0]=r[0];expected[3]=r[1];expected[1]=r[2];expected[2]=r[3];
    } else if(kind==PA_GETPID) {
        expected[0]=scripted?(MODULE?179:173):pid;
        expected[1]=P(target)+2;expected[11]=PA_FLAGS;
    } else {
        uint64_t value=P(after)[0]|(P(after)[2]<<32);
        if(P(after)[0]>UINT32_MAX || P(after)[2]>UINT32_MAX)return 5;
        if(scripted) {
            const uint64_t wanted=MODULE?UINT64_C(0xfedcba9876543210):UINT64_C(0x1234567887654321);
            if(value!=wanted)return 6;
        } else if(!value || value<=clock_previous)return 7;
        clock_previous=value;expected[0]=(uint32_t)value;expected[2]=(uint32_t)(value>>32);
    }
    if(!equal(P(after),expected,sizeof expected) || !equal(P(before_live),P(after_live),PA_LIVE) ||
       !equal(P(before_live),P(vectors),2048) || !equal(P(before_live)+2048,P(masks),64) ||
       P(before_live)[2112]!=0x7f || P(before_live)[2113]!=3 ||
       P(before_live)[2114]!=0 || P(before_live)[2115]!=0x30)return 8;
    for(size_t i=0;i<PA_STACK;i++)if(stack[i]!=0x5a)return 9;
    out->module=MODULE;out->kind=kind;out->site=P(target);out->next=P(target)+2;
    out->endpoint=(uintptr_t)P(capture_after);out->stack=P(input)[4];out->mask=P(mask);out->extent=extent;
    out->before=P(before);out->after=P(after);out->before_live=P(before_live);out->after_live=P(after_live);
    return 0;
}
int P(final)(void) {
    return !ready || !equal(saved_page,P(page),PA_PAGE);
}
