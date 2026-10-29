/* Actual linked policy component; no application/mode-execution claim. */
#define main legacy_policy_main
#include "../native_pages/policy_probe.c"
#undef main

static uint64_t nh_counts[4];
static int nh_check(const unsigned char *p,size_t n,unsigned want,unsigned group) {
    unsigned got=li2_native_policy(p,n);++nh_counts[group];
    if(got==want)return 0;
    fprintf(stderr,"HLE_D1 group=%u case=%"PRIu64" expected=%u actual=%u\n",
            group,nh_counts[group],want,got);return 1;
}
static const unsigned char nh_prefixes[]={
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
    0x66,0x67,0x26,0x2e,0x36,0x3e,0x64,0x65,0xf0,0xf2,0xf3
};
static size_t nh_pattern(unsigned char *b,unsigned hint,unsigned order,
                         unsigned gap,unsigned modrm) {
    memset(b,0x66,16);b[0]=(unsigned char)(order?0xf0:hint);
    b[gap+1]=(unsigned char)(order?hint:0xf0);
    b[gap+2]=0xd1;b[gap+3]=(unsigned char)modrm;return gap+4;
}
int main(void) {
    /* The original entire finite population and exact first output line remain. */
    if(legacy_policy_main())return 1;
    unsigned char b[32];
    for(unsigned hint=0xf2;hint<=0xf3;hint++)for(unsigned order=0;order<2;order++) {
        for(unsigned m=0;m<256;m++) {
            for(size_t p=0;p<COUNT(nh_prefixes);p++) {
                b[0]=(unsigned char)(order?0xf0:hint);b[1]=nh_prefixes[p];
                b[2]=(unsigned char)(order?hint:0xf0);b[3]=0xd1;b[4]=(unsigned char)m;
                if(nh_check(b,5,0,0))return 1;
            }
            for(unsigned gap=0;gap<=12;gap++) {
                size_t n=nh_pattern(b,hint,order,gap,m);
                if(nh_check(b,n,gap==12?4:0,0))return 1;
            }
        }
        /* No other opcode is promoted, including undocumented neighbors. */
        for(unsigned op=0;op<256;op++) {
            b[0]=(unsigned char)(order?0xf0:hint);b[1]=(unsigned char)(order?hint:0xf0);
            b[2]=(unsigned char)op;b[3]=0x90;
            if(nh_check(b,4,op==0xd1?0:4,2))return 1;
        }
    }
    /* All offsets, including both executable-page halo seams. These are five
       distinct retained libc sites; duplicates preserve that exact population. */
    static const unsigned char sites[5][7]={
        {0xc4,0xe2,0xf0,0xf3,0xd1,0x48,0x21},
        {0xc4,0xe2,0xf0,0xf3,0xd1,0x48,0x21},
        {0xc4,0xe2,0xf0,0xf3,0xd1,0x48,0x21},
        {0xc4,0xe2,0xf0,0xf3,0xd1,0x73,0x1d},
        {0xc4,0xe2,0xf0,0xf3,0xd1,0x73,0x1b}
    };
    memset(window,0x90,sizeof(window));
    for(size_t s=0;s<COUNT(sites);s++)for(size_t at=0;at+7<=WINDOW;at++) {
        memcpy(window+at,sites[s],7);
        if(nh_check(window,sizeof(window),0,1))return 1;
        memset(window+at,0x90,7);
    }
    /* A local proof never clears independently found cores or true HLE. */
    const unsigned char benign[]={0xf0,0xf3,0xd1,0x73};
    for(unsigned order=0;order<2;order++)for(unsigned group=0;group<2;group++) {
        const struct sample *rows=group?hle:cores;
        size_t count=group?COUNT(hle):COUNT(cores);
        for(size_t i=0;i<count;i++) {
            size_t n=rows[i].length;
            memcpy(b,order?rows[i].bytes:benign,order?n:sizeof(benign));
            b[order?n:sizeof(benign)]=0x90;
            memcpy(b+(order?n:sizeof(benign))+1,order?benign:rows[i].bytes,
                   order?sizeof(benign):n);
            if(nh_check(b,n+sizeof(benign)+1,rows[i].want,2))return 1;
        }
    }
    /* Actual inaccessible edges: every prefix truncation, including full15B,
       missing ModRM,16B and D1 whose optional addressing bytes are absent. */
    unsigned char *g=mmap(0,3*PAGE_BYTES,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(g==MAP_FAILED || mprotect(g+PAGE_BYTES,PAGE_BYTES,PROT_READ|PROT_WRITE))return 2;
    for(unsigned hint=0xf2;hint<=0xf3;hint++)for(unsigned order=0;order<2;order++)
        for(unsigned gap=0;gap<=12;gap++) {
            size_t full=nh_pattern(b,hint,order,gap,0x80);
            for(size_t n=0;n<=full;n++)for(unsigned edge=0;edge<2;edge++) {
                unsigned char *p=g+(edge?2*PAGE_BYTES-n:PAGE_BYTES);
                memcpy(p,b,n);
                unsigned want=n<gap+2?0:(n==full && gap<=11?0:4);
                if(nh_check(p,n,want,3))return 1;
            }
        }
    if(nh_check(0,0,0,3))return 1;
    memcpy(g+PAGE_BYTES,benign,sizeof(benign));
    memcpy(g+2*PAGE_BYTES-sizeof(benign),benign,sizeof(benign));
    if(mprotect(g+PAGE_BYTES,PAGE_BYTES,PROT_READ))return 2;
    if(nh_check(g+PAGE_BYTES,sizeof(benign),0,3) ||
       nh_check(g+2*PAGE_BYTES-sizeof(benign),sizeof(benign),0,3))return 1;
    if(munmap(g,3*PAGE_BYTES))return 2;
    static const uint64_t wanted[]={40960,20590,1082,1147};
    if(memcmp(nh_counts,wanted,sizeof(wanted)))return 3;
    printf("{\"version\":1,\"d1_checks\":[%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"]}\n",
           nh_counts[0],nh_counts[1],nh_counts[2],nh_counts[3]);
    return 0;
}
