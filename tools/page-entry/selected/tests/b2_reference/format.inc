/* Observation only. No application/source/frame write or format synthesis. */
struct b2_format_sample { uint64_t h[16];uint32_t cpuid[67][6]; };
struct b2_format_record { uint64_t h[8];struct b2_format_sample sample[2]; };
_Static_assert(sizeof(struct b2_format_sample)==1736,"complete format sample");
_Static_assert(sizeof(struct b2_format_record)==3536,"separate bounded format trailer");
static struct b2_format_record b2_format_record;
static void b2_format_cpuid(struct b2_format_sample *s,unsigned slot,unsigned leaf,unsigned sub) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
    uint32_t *p=s->cpuid[slot];p[0]=leaf;p[1]=sub;p[2]=a;p[3]=b;p[4]=c;p[5]=d;
}
static void b2_format_sample(unsigned index) {
    checked(index<2 && b2_format_record.h[3]==index,1750,0);
    struct b2_format_sample *s=&b2_format_record.sample[index];uint64_t *h=s->h;
    h[0]=index;h[1]=1;unsigned cpu=0,node=0;
    h[4]=(uint64_t)raw(SYS_getcpu,(long)&cpu,(long)&node,0,0,0,0);h[5]=cpu;h[6]=node;
    b2_format_cpuid(s,0,0,0);b2_format_cpuid(s,1,1,0);b2_format_cpuid(s,2,7,0);
    if(s->cpuid[0][2]<13 || (s->cpuid[1][4]&UINT32_C(0x0c000000))!=UINT32_C(0x0c000000)) {
        h[3]=1;checked(0,1750,1);
    }
    for(unsigned i=0;i<64;i++)b2_format_cpuid(s,3+i,13,i);
    uint32_t lo,hi;h[7]=1;
    __asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");h[8]=((uint64_t)hi<<32)|lo;
    uint64_t supported=0,permitted=0;
    h[9]=(uint64_t)raw(SYS_arch_prctl,0x1021,(long)&supported,0,0,0,0);h[10]=supported;
    h[11]=(uint64_t)raw(SYS_arch_prctl,0x1022,(long)&permitted,0,0,0,0);h[12]=permitted;
    cpu=node=0;h[13]=(uint64_t)raw(SYS_getcpu,(long)&cpu,(long)&node,0,0,0,0);h[14]=cpu;h[15]=node;
    if(h[4] || h[9] || h[11] || h[13] || h[5]!=h[14] || h[6]!=h[15]) {
        h[3]=2;checked(0,1750,2);
    }
    __asm__ volatile("":::"memory");h[2]=1;b2_format_record.h[3]=index+1;
}
static void b2_format_initialize(void) {
    checked(!b2_format_record.h[0],1750,3);
    b2_format_record.h[0]=UINT64_C(0x315446584232494c);b2_format_record.h[1]=1;
    b2_format_record.h[2]=sizeof b2_format_record;b2_format_sample(0);
}
static void b2_format_emit(void) {
    size_t at=0;
    while(at<sizeof b2_format_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&b2_format_record+at),sizeof b2_format_record-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof b2_format_record-at)return;
        at+=(size_t)n;
    }
}
