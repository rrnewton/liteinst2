#define _GNU_SOURCE
#include "decoder.h"
#include <cpuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static unsigned char arena[2*1024*1024] __attribute__((aligned(64)));
_Noreturn void li2_decoder_abort(uint32_t code) { fprintf(stderr,"decoder_abort %u\n",code); _exit(125); }
static void need(int yes) { if(!yes) _exit(126); }
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"clock")) {
        unsigned a,b,c,d,cpu,lo,hi; unsigned long aux;
        need(!syscall(SYS_getcpu,&cpu,0,0));
        __asm__ volatile(".byte 0xf3,0x48,0x0f,0xc7,0xf8":"=a"(aux)::"memory");
        need(!(aux>>32));
        __cpuid_count(0,0,a,b,c,d);
        __asm__ volatile("rdtsc":"=a"(lo),"=d"(hi)::"memory");
        printf("{\"cpu\":%u,\"aux\":%lu,\"cpuid0\":[%u,%u,%u,%u],\"tsc\":%llu}\n",
               cpu,aux,a,b,c,d,(unsigned long long)(((unsigned long long)hi<<32)|lo));
        return 0;
    }
    if(argc==1) {
        unsigned a,b,c,d,one_c,seven_b,seven_c,cpu;
        __cpuid_count(1,0,a,b,c,d);one_c=c;
        __cpuid_count(7,0,a,b,c,d);seven_b=b;seven_c=c;
        (void)a;(void)d;
        need((one_c&(1U<<30)) && (seven_b&(1U<<18)) && (seven_c&(1U<<22)));
        unsigned long id;
        __asm__ volatile(".byte 0xf3,0x48,0x0f,0xc7,0xf8":"=a"(id)::"memory");
        need(!(id>>32) && !syscall(SYS_getcpu,&cpu,0,0));
        printf("{\"rdpid\":%lu,\"cpu\":%u,\"leaf1_ecx\":%u,\"leaf7_ebx\":%u,\"leaf7_ecx\":%u}\n",
               id,cpu,one_c,seven_b,seven_c);return 0;
    }
    need(argc==4 && !strcmp(argv[1],"decode"));
    char *end=0;unsigned long pc=strtoul(argv[2],&end,0);need(end && !*end);
    size_t n=strlen(argv[3]);need(n && !(n&1) && n<=30);unsigned char bytes[15];
    for(size_t i=0;i<n/2;i++) {
        unsigned value;need(sscanf(argv[3]+i*2,"%2x",&value)==1);bytes[i]=(unsigned char)value;
    }
    struct li2_decoder_stats before,after;struct li2_decoded row;
    need(!li2_decoder_initialize(arena,sizeof arena,&before) && before.phase==2);
    need(!li2_decoder_decode(pc,bytes,n/2,&row) && !li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    printf("{\"pc\":%llu,\"next_pc\":%llu,\"abi\":%u,\"decode_status\":%u,\"code\":%u,\"kind\":%u,"
           "\"destination\":%u,\"width\":%u,\"step_disposition\":%u,\"length\":%u}\n",
           (unsigned long long)row.pc,(unsigned long long)row.next_pc,row.abi_version,row.decode_status,
           row.code,row.kind,row.destination,row.width_bits,row.step_disposition,row.length);
    return 0;
}
