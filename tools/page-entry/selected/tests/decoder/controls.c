/* Supplied-byte controls. This program never executes a selected instruction
   or opens target executable pages. */
#include "../../decoder.h"
#include <assert.h>
#include <string.h>

static _Alignas(4096) unsigned char arena[16*1024*1024];
static unsigned char window[4096+28];
static struct li2_decoded rows[4096+28];

static struct li2_decoded decode(const unsigned char *p,size_t n) {
    struct li2_decoded out;
    assert(li2_decoder_decode(0x1000,p,n,&out)==LI2_OK);
    return out;
}
static void selected_registers(void) {
    for(unsigned kind=LI2_RDRAND;kind<=LI2_RDSEED;kind++)
        for(unsigned bits=16;bits<=64;bits*=2)
            for(unsigned reg=0;reg<16;reg++) {
                unsigned char b[8];size_t n=0;
                if(bits==16)b[n++]=0x66;
                unsigned rex=0x40|(bits==64?8:0)|(reg>=8?1:0);
                if(rex!=0x40)b[n++]=(unsigned char)rex;
                b[n++]=15;b[n++]=0xc7;b[n++]=(unsigned char)((kind==LI2_RDRAND?0xf0:0xf8)|(reg&7));
                struct li2_decoded d=decode(b,n);
                assert(d.decode_status==LI2_VALID && d.kind==kind && d.destination==reg && d.width_bits==bits);
                assert(d.length==n && d.next_pc==0x1000+n && !memcmp(d.bytes,b,n));
            }
    for(unsigned reg=0;reg<16;reg++) {
        unsigned char b[5];size_t n=0;b[n++]=0xf3;if(reg>=8)b[n++]=0x41;
        b[n++]=15;b[n++]=0xc7;b[n++]=(unsigned char)(0xf8|(reg&7));
        struct li2_decoded d=decode(b,n);
        assert(d.decode_status==LI2_VALID && d.kind==LI2_RDPID && d.destination==reg && d.width_bits==64);
    }
}
static void prefixes_and_unsafe(void) {
    const unsigned char before[]={0x48,0x66,15,0xc7,0xf0},after[]={0x66,0x48,15,0xc7,0xf0};
    assert(decode(before,sizeof before).width_bits==16);
    assert(decode(after,sizeof after).width_bits==64);
    const unsigned char lock[]={0xf0,15,0xc7,0xf0},truncated[]={15,0xc7};
    assert(decode(lock,sizeof lock).decode_status==LI2_INVALID);
    assert(decode(truncated,sizeof truncated).decode_status==LI2_TRUNCATED);
    unsigned char long_prefix[15];memset(long_prefix,0x66,sizeof long_prefix);
    assert(decode(long_prefix,sizeof long_prefix).decode_status!=LI2_VALID);
    const unsigned char pushf[]={0x9c},popf[]={0x9d},iret[]={0x48,0xcf};
    const unsigned char movss[]={0x8e,0xd0},lss[]={15,0xb2,0x00},syscall[]={15,5};
    assert(decode(pushf,sizeof pushf).step_disposition==LI2_STEP_FLAGS_OBSERVED);
    assert(decode(popf,sizeof popf).step_disposition==LI2_STEP_FLAGS_RESTORED);
    assert(decode(iret,sizeof iret).step_disposition==LI2_STEP_FLAGS_RESTORED);
    assert(decode(movss,sizeof movss).step_disposition==LI2_STEP_DEBUG_INHIBITION);
    assert(decode(lss,sizeof lss).step_disposition==LI2_STEP_DEBUG_INHIBITION);
    assert(decode(syscall,sizeof syscall).step_disposition==LI2_STEP_KERNEL_TRANSFER);
    const unsigned char xbegin[]={0xc7,0xf8,0,0,0,0},xend[]={15,1,0xd5};
    const unsigned char xabort[]={0xc6,0xf8,0},xtest[]={15,1,0xd6};
    const unsigned char acquire[]={0xf2,0xf0,1,0},release[]={0xf3,0xf0,1,0};
    const unsigned char enclu[]={15,1,0xd7},wrpkru[]={15,1,0xef};
    assert(decode(xbegin,sizeof xbegin).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(xend,sizeof xend).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(xabort,sizeof xabort).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(xtest,sizeof xtest).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(acquire,sizeof acquire).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(release,sizeof release).step_disposition==LI2_STEP_TRANSACTION);
    assert(decode(enclu,sizeof enclu).step_disposition==LI2_STEP_CONTROL_STATE);
    assert(decode(wrpkru,sizeof wrpkru).step_disposition==LI2_STEP_CONTROL_STATE);
    const unsigned char mov[]={0xb8,1,0,0,0},rsp[]={0xbc,1,0,0,0},add[]={0x48,1,0xc0};
    assert(decode(mov,sizeof mov).step_disposition==LI2_STEP_CANDIDATE);
    assert(decode(rsp,sizeof rsp).step_disposition==LI2_STEP_RSP_WRITE);
    assert(decode(add,sizeof add).step_disposition==LI2_STEP_UNSUPPORTED);
}
static void all_starts_and_boundaries(void) {
    struct li2_scan s;
    memset(window,0x90,sizeof window);
    assert(li2_decoder_scan_page(0x1000-14,window,sizeof window,0x1000,0,0,rows,4124,&s)==LI2_OK);
    assert(s.complete && s.candidates==0 && s.starts==4110);
    /* RDRAND is embedded inside a genuine MOV imm64, but remains a candidate. */
    const unsigned char imm[]={0x48,0xb8,15,0xc7,0xf0,0,0,0,0,0};
    memcpy(window+14+32,imm,sizeof imm);
    assert(li2_decoder_scan_page(0x1000-14,window,sizeof window,0x1000,0,0,rows,4124,&s)==LI2_OK);
    assert(s.candidates==1 && rows[0].pc==0x1000+34 && rows[0].kind==LI2_RDRAND);
    assert(li2_decoder_scan_page(0x1000-14,window,sizeof window,0x1000,0,0,0,0,&s)==LI2_OUTPUT_CAPACITY);
    assert(!s.complete && s.candidates==1 && !s.written);
    memset(window,0x90,sizeof window);window[12]=15;window[13]=0xc7;window[14]=0xf4;
    assert(li2_decoder_scan_page(0x1000-14,window,sizeof window,0x1000,0,0,rows,4124,&s)==LI2_OK);
    assert(s.candidates==1 && rows[0].pc==0xffe && rows[0].destination==4);
    assert(li2_decoder_scan_page(0x1000,window,4096,0x1000,0,0,rows,4124,&s)==LI2_MISSING_BOUNDARY);
    memset(window,0x90,sizeof window);
    assert(li2_decoder_scan_page(0x1000,window,4096,0x1000,1,1,rows,4124,&s)==LI2_OK);
    assert(s.complete && s.candidates==0 && s.starts==4096);
}
int main(void) {
    struct li2_decoder_stats a,b;struct li2_decoded d;const unsigned char nop=0x90;
    assert(li2_decoder_decode(1,&nop,1,&d)==LI2_NOT_READY);
    assert(li2_decoder_initialize(arena,sizeof arena,&a)==LI2_OK);
    assert(a.phase==2 && a.retained_high_water>0 && a.retained_high_water<=sizeof arena);
    assert(li2_decoder_initialize(arena,sizeof arena,&b)==LI2_ALREADY_INITIALIZED);
    selected_registers();prefixes_and_unsafe();all_starts_and_boundaries();
    assert(li2_decoder_decode(UINT64_MAX,&nop,1,&d)==LI2_ADDRESS_OVERFLOW);
    assert(li2_decoder_stats(&b)==LI2_OK && b.phase==2 && !b.first_fatal_reason);
    assert(a.retained_high_water==b.retained_high_water && a.allocation_calls==b.allocation_calls
           && a.deallocation_calls==b.deallocation_calls);
    return 0;
}
