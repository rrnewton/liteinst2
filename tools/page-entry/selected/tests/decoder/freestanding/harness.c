#include "../../../decoder.h"
/* No libc calls, no selected instruction execution; all opcodes are input data. */
extern void *memset(void *,int,size_t);
extern void *memcpy(void *,const void *,size_t);
extern int memcmp(const void *,const void *,size_t);
static _Alignas(4096) unsigned char arena[16*1024*1024];
static unsigned char window[4096+28];
static struct li2_decoded rows[4096+28];
static char report[512];
static size_t used;
static long raw_write(int fd,const void *p,size_t n) {
    long r;
    __asm__ volatile("syscall":"=a"(r):"a"(1L),"D"((long)fd),"S"(p),"d"(n):"rcx","r11","memory");
    return r;
}
static void require(int condition) {
    if(!condition) li2_decoder_abort(200);
}
static void append(const char *s) {
    while(*s) { require(used<sizeof report);report[used++]=*s++; }
}
static void number(uint64_t n) {
    char reverse[20];size_t count=0;
    do { reverse[count++]=(char)('0'+n%10);n/=10; } while(n);
    require(count<=sizeof report-used);
    while(count) report[used++]=reverse[--count];
}
static struct li2_decoded decode(const unsigned char *b,size_t n) {
    struct li2_decoded d;
    require(li2_decoder_decode(0x1000,b,n,&d)==LI2_OK);
    require(d.abi_version==1 && d.available==n && !memcmp(d.bytes,b,n));
    return d;
}
int harness_main(void) {
    struct li2_decoder_stats a,b;struct li2_decoded d;
    const unsigned char nop[]={0x90};
    require(li2_decoder_decode(0x1000,nop,sizeof nop,&d)==LI2_NOT_READY);
    require(li2_decoder_initialize(arena,sizeof arena,&a)==LI2_OK);
    require(a.abi_version==1 && a.phase==2 && !a.first_fatal_reason);
    require(a.retained_high_water>0 && a.retained_high_water<=sizeof arena);
    require(li2_decoder_initialize(arena,sizeof arena,&b)==LI2_ALREADY_INITIALIZED);
    const struct {unsigned char bytes[4];unsigned length,kind;} cases[]={
        {{15,0xa2},2,LI2_CPUID},{{0x48,15,0xc7,0xf0},4,LI2_RDRAND},
        {{0x48,15,0xc7,0xf8},4,LI2_RDSEED},{{0xf3,15,0xc7,0xf8},4,LI2_RDPID},
        {{15,0x31},2,LI2_RDTSC},{{15,1,0xf9},3,LI2_RDTSCP},{{15,5},2,LI2_SYSCALL}};
    for(size_t i=0;i<sizeof cases/sizeof cases[0];i++) {
        d=decode(cases[i].bytes,cases[i].length);
        require(d.decode_status==LI2_VALID && d.kind==cases[i].kind);
        require(d.length==cases[i].length && d.next_pc==0x1000+cases[i].length);
        if(i>=1 && i<=3) require(d.destination==0 && d.width_bits==64);
    }
    d=decode(nop,sizeof nop);
    require(d.decode_status==LI2_VALID && d.step_disposition==LI2_STEP_CANDIDATE);
    const unsigned char lock[]={0xf0,15,0xc7,0xf0};
    require(decode(lock,sizeof lock).decode_status==LI2_INVALID);
    struct li2_scan s;
    memset(window,0x90,sizeof window);
    require(li2_decoder_scan_page(0xff2,window,sizeof window,0x1000,0,0,rows,4124,&s)==LI2_OK);
    require(s.complete && s.starts==4110 && !s.candidates);
    const unsigned char imm[]={0x48,0xb8,15,0xc7,0xf0,0,0,0,0,0};
    memcpy(window+46,imm,sizeof imm);
    require(li2_decoder_scan_page(0xff2,window,sizeof window,0x1000,0,0,rows,4124,&s)==LI2_OK);
    require(s.complete && s.candidates==1 && s.written==1 && rows[0].pc==0x1022
            && rows[0].kind==LI2_RDRAND);
    require(li2_decoder_scan_page(0xff2,window,sizeof window,0x1000,0,0,0,0,&s)==LI2_OUTPUT_CAPACITY);
    require(!s.complete && s.candidates==1 && !s.written);
    require(li2_decoder_scan_page(0x1000,window,4096,0x1000,0,0,rows,4124,&s)==LI2_MISSING_BOUNDARY);
    require(li2_decoder_stats(&b)==LI2_OK && b.phase==2 && !b.first_fatal_reason);
    require(a.retained_high_water==b.retained_high_water && a.allocation_calls==b.allocation_calls
            && a.deallocation_calls==b.deallocation_calls);
    append("{\"schema_version\":1,\"decoded_classes\":7,\"scan_starts\":4110,\"phase\":");number(b.phase);
    append(",\"arena_bytes\":");number(b.arena_bytes);
    append(",\"retained_high_water\":");number(b.retained_high_water);
    append(",\"allocation_calls\":");number(b.allocation_calls);
    append(",\"deallocation_calls\":");number(b.deallocation_calls);
    append(",\"first_fatal_reason\":");number(b.first_fatal_reason);append("}\n");
    size_t at=0;
    while(at<used) { long n=raw_write(1,report+at,used-at);if(n==-4)continue;require(n>0);at+=(size_t)n; }
    return 0;
}
