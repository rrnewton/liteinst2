#define _GNU_SOURCE
#include "record.h"
#include "capability.inc"
#include <asm/prctl.h>
#include <elf.h>
#include <sys/syscall.h>
#include <fcntl.h>

struct abi_record abi_record __attribute__((aligned(64),visibility("hidden")));
static long syscall6(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
    __asm__ volatile("syscall":"+a"(n):"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return n;
}
static void bad(void) __attribute__((noreturn));
static void bad(void) { (void)syscall6(SYS_exit_group,124,0,0,0,0,0);__builtin_trap(); }
static void check(int p) { if(!p)bad(); }
static void bytes(void *to,const void *from,size_t n) {
    unsigned char *d=to;const unsigned char *s=from;for(size_t i=0;i<n;i++)d[i]=s[i];
}
static int prefix(const char *s,const char *wanted) {
    while(*wanted) { if(*s++!=*wanted++)return 0; }
    return 1;
}
static uint64_t hex(const unsigned char *s,size_t end,size_t *at) {
    uint64_t v=0;size_t start=*at;
    while(*at<end) {
        unsigned c=s[*at],d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;
        if(d==16)break;
        check(v<=(UINT64_MAX-d)/16);v=v*16+d;++*at;
    }
    check(*at>start);return v;
}
static uint64_t word(uint64_t p) {
    check(p>=abi_record.stack_first && p<=abi_record.stack_end-8);
    uint64_t result;bytes(&result,abi_record.stack+p-abi_record.stack_first,8);return result;
}
static int pipe_fd(uint64_t env) {
    int fd=-1;size_t i;
    for(i=0;i<8192;i++,env+=8) {
        uint64_t p=word(env);if(!p)break;
        check(p>=abi_record.stack_first && p<abi_record.stack_end);
        const char *s=(void *)(abi_record.stack+p-abi_record.stack_first);
        size_t left=abi_record.stack_end-p,n=0;while(n<left && s[n])n++;check(n<left);
        if(n>=11 && prefix(s,"LI2_ABI_FD=")) {
            check(fd==-1);unsigned v=0;size_t at=11;
            check(at<n);
            for(;at<n;at++){check(s[at]>='0'&&s[at]<='9'&&v<=(65535U-(s[at]-'0'))/10);v=v*10+s[at]-'0';}
            check(v>2);fd=(int)v;
        }
    }
    check(i<8192 && fd>2);return fd;
}
void abi_collect(unsigned endpoint) {
    struct abi_record *r=&abi_record;
    r->magic=ABI_MAGIC;r->version=1;r->endpoint=endpoint;r->total_size=sizeof(*r);
    r->xsave_size=CAP_XSAVE_SIZE;r->capability_xcr0=CAP_XCR0;
    unsigned short selector;
#define SEG(name,i) __asm__ volatile("mov %%" #name ",%0":"=r"(selector));r->selectors[i]=selector
    SEG(cs,0);SEG(ss,1);SEG(ds,2);SEG(es,3);SEG(fs,4);SEG(gs,5);
#undef SEG
    check(!syscall6(SYS_arch_prctl,ARCH_GET_FS,(long)&r->fs_base,0,0,0,0));
    check(!syscall6(SYS_arch_prctl,ARCH_GET_GS,(long)&r->gs_base,0,0,0,0));
    long fd=syscall6(SYS_openat,AT_FDCWD,(long)"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);check(fd>=0);
    for(;;) {
        check(r->maps_size<ABI_MAPS_CAP);
        long n=syscall6(SYS_read,fd,(long)(r->maps+r->maps_size),ABI_MAPS_CAP-r->maps_size,0,0,0);
        check(n>=0);if(!n)break;r->maps_size+=(unsigned long)n;
    }
    check(!syscall6(SYS_close,fd,0,0,0,0,0));
    uint64_t sp=r->gpr[7];size_t at=0;unsigned found=0;
    while(at<r->maps_size) {
        uint64_t first=hex(r->maps,r->maps_size,&at);check(at<r->maps_size&&r->maps[at++]=='-');
        uint64_t end=hex(r->maps,r->maps_size,&at);check(end>first&&at<r->maps_size&&r->maps[at++]==' ');
        if(sp>=first&&sp<end) {
            check(++found==1&&r->maps_size-at>=4&&r->maps[at]=='r'&&r->maps[at+1]=='w'&&r->maps[at+2]=='-'&&r->maps[at+3]=='p');
            check(end-first<=ABI_STACK_CAP);r->stack_first=first;r->stack_end=end;r->stack_size=end-first;
        }
        while(at<r->maps_size&&r->maps[at]!='\n') { at++; }
        check(at<r->maps_size);at++;
    }
    check(found==1&&!(sp&15));bytes(r->stack,(void *)r->stack_first,r->stack_size);
    uint64_t argc=word(sp);check(argc<=4096);check(!word(sp+8*(argc+1)));
    uint64_t env=sp+8*(argc+2),aux=env;size_t env_count=0;
    while(word(aux)){check(++env_count<8192);aux+=8;}aux+=8;
    uint64_t phnum=0,phent=0;unsigned base_seen=0,ph_seen=0,count_seen=0,ent_seen=0;
    for(size_t i=0;i<128;i++,aux+=16) {
        uint64_t kind=word(aux),value=word(aux+8);r->aux_count=i+1;if(!kind)break;
        if(kind==AT_BASE){check(!base_seen++);r->at_base_offset=aux+8-r->stack_first;}
        if(kind==AT_PHDR){check(!ph_seen++);r->phdr_address=value;}
        if(kind==AT_PHNUM){check(!count_seen++);phnum=value;}
        if(kind==AT_PHENT){check(!ent_seen++);phent=value;}
    }
    check(r->aux_count<128&&base_seen==1&&ph_seen==1&&count_seen==1&&ent_seen==1&&phent==56&&phnum&&phnum<=ABI_PHDR_CAP/56);
    r->phdr_size=phnum*56;bytes(r->phdrs,(void *)r->phdr_address,r->phdr_size);
    int output=pipe_fd(env);size_t written=0;
    while(written<sizeof(*r)) {
        long n=syscall6(SYS_write,output,(long)((unsigned char *)r+written),sizeof(*r)-written,0,0,0);
        check(n>0&&(unsigned long)n<=sizeof(*r)-written);written+=(unsigned long)n;
    }
}
