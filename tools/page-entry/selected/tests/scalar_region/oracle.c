/* Actual finite scalar-DAG component: original hardware TF reference versus
   generated hardware execution. Full actual state is compared; no production
   owner authority, guest-data prediction, fault resumption or timing credit. */
#define _GNU_SOURCE
#include "region_plan.h"
#include "machine.h"
#include "step_owner.h"
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/rseq.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#define PAGE 4096UL
#define DATA (2*PAGE)
#define STACK (128*1024UL)
#define ALT (512*1024UL)
#define LOGICAL_STACK 160UL
#define SEALS (F_SEAL_SEAL|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_WRITE)
uint64_t region_seed[16],region_input_flags,region_xcr0,region_target;
struct region_live region_before,region_after;
unsigned char region_fp_before[REGION_FP] __attribute__((aligned(64)));
unsigned char region_fp_after[REGION_FP] __attribute__((aligned(64)));
long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;long r;
    __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return r;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static void bytes(void *d,const void *s,size_t n){unsigned char *x=d;const unsigned char *y=s;for(size_t i=0;i<n;i++)x[i]=y[i];}
static int same(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
#ifdef LI2_FAST_EQUAL
    /* GCC's alias-anything, alignment-one integer type permits the same
       immutable byte ranges as the scalar path. Each load is wholly inside
       the requested range; neither alignment nor a readable suffix is needed.
       No vector/string instruction or application-state normalization is used. */
    typedef uint64_t word __attribute__((__may_alias__,__aligned__(1)));
    _Static_assert(sizeof(word)==8 && __alignof__(word)==1,"bounded unaligned word");
    while(n>=sizeof(word)) {
        if(*(const word *)(const void *)x!=*(const word *)(const void *)y)return 0;
        x+=sizeof(word);y+=sizeof(word);n-=sizeof(word);
    }
#endif
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static void zero(void *d,size_t n){
#if defined(LI2_FAST_MEMSET) && LI2_FAST_MEMSET
    /* Exact production bridge memset instruction/constraint body, with fill0.
       Every requested byte is still reset; application flags remain saved. */
    int c=0;
    __asm__ volatile("cld; rep stosb" : "+D"(d), "+c"(n)
                     : "a"((unsigned char)c) : "memory","cc");
#else
    unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=0;
#endif
}
static int write_all(int fd,const void *p,size_t n){const unsigned char *s=p;while(n){long k=RAW(SYS_write,fd,s,n,0,0,0);if(k<=0||(size_t)k>n)return 0;s+=k;n-=(size_t)k;}return 1;}


struct owned_mapping {uintptr_t at;size_t n;int fd;struct stat stat;unsigned char expected[PAGE];};
static struct owned_mapping source={.fd=-1},image={.fd=-1};
static struct li2_region_plan plan;
static struct li2_decoder_stats decoder_before,decoder_after;
static uintptr_t stack_area,data_area,alt_area,reservation,stack_fault;
static unsigned char original_data[DATA],original_stack[LOGICAL_STACK],original_operands[16];
static unsigned mode,lane,handling,started,ended,current_head;
static uint64_t app_mask,xsave_bytes,first_error,cleanup_done;
static uint64_t source_address,image_address,stack_address,data_address,alt_address;
static uint64_t reference_steps,exit_kind;
static uint64_t xlayout[64][3],head_checks,interior_misses,authority_checks;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[256*1024];
static struct rseq rseq_probe __attribute__((aligned(32)));
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static const unsigned offsets[20]={0,3,6,12,15,17,21,24,26,28,33,35,43,46,48,54,59,62,69,71};
static const unsigned lengths[20]={3,3,6,3,2,4,3,2,2,5,2,8,3,2,6,5,3,7,2,6};
static const unsigned generated_offsets[20]={0,3,6,12,15,21,25,28,30,36,41,43,51,54,56,62,67,70,77,79};
/* Exact measured interpreter bytes at b5f2, including the genuine unsupported
   RIP-relative MOV boundary. Exit targets retain their original page offsets. */
static const unsigned char literal[83]={
  0x48,0x89,0xc8,0x48,0x85,0xd2,0x0f,0x84,0x40,0x01,0x00,0x00,0x48,0x85,0xc9,0x74,0x0b,
  0x0f,0xb6,0x41,0x05,0x83,0xe0,0x03,0x3c,0x03,0x74,0x62,0x4c,0x8b,0x7c,0x24,0x58,
  0x31,0xdb,0x41,0x0f,0xb6,0x87,0x1c,0x03,0x00,0x00,0x83,0xe0,0x03,0x3c,0x02,0x0f,
  0x84,0xec,0x03,0x00,0x00,0x4c,0x8b,0x54,0x24,0x50,0x4d,0x89,0xfd,0x41,0x8b,0xbf,
  0xe4,0x03,0x00,0x00,0x85,0xff,0x0f,0x84,0xd9,0x01,0x00,0x00,0x8b,0x05,0xbb,0xd4,0x02,0x00};
/* Full authenticated original interpreter page, never patched. */
static const unsigned char source_page[PAGE]=
    "\x78\x18\x48\x8b\x7c\x24\x28\x48\x8d\x04\xff\x48\x8d\x04\x47\x48\x8d\x3d\xea\xdf\x02\x00\x48\x83\x44\xc7\x60\x01\x48\x89\x4c\x24"
    "\x08\x48\x8b\x7c\x24\x30\xff\x15\x5c\xda\x02\x00\x48\x8b\x44\x24\x50\x48\x8b\x4c\x24\x08\x48\x89\x58\x08\x48\x89\x08\xe9\x9b\xfb"
    "\xff\xff\x4d\x29\xec\x4c\x89\xe0\x48\xc1\xe0\x05\x4c\x01\xc0\xeb\x12\x0f\x1f\x80\x00\x00\x00\x00\x49\x01\xd4\x48\x01\xf0\x4d\x39"
    "\xe5\x76\xdf\x48\x83\x78\x08\x00\x75\xee\x44\x89\x30\x48\x89\x78\x08\x48\x89\x48\x10\x48\x89\x58\x18\x0f\xb6\x83\x1c\x03\x00\x00"
    "\x83\xe0\x03\x3c\x02\x0f\x85\x77\xff\xff\xff\x80\xbb\x1f\x03\x00\x00\x00\x0f\x85\x6a\xff\xff\xff\xf6\x84\x24\xd0\x00\x00\x00\x08"
    "\x0f\x84\x59\x03\x00\x00\x80\xbb\x20\x03\x00\x00\x00\x0f\x85\x4f\xff\xff\xff\xf6\x05\x46\xda\x02\x00\x04\x0f\x85\xd0\x03\x00\x00"
    "\xc6\x83\x20\x03\x00\x00\x01\xe9\x36\xff\xff\xff\x0f\x1f\x40\x00\x4d\x29\xee\xe9\xcd\xfd\xff\xff\x4d\x29\xec\xe9\xdf\xfe\xff\xff"
    "\x48\x8b\x54\x24\x18\x31\xc0\x0f\xb6\x3a\x48\x85\xff\x0f\x84\xa2\x00\x00\x00\x0f\xb6\x42\x01\x84\xc0\x0f\x84\xb9\x02\x00\x00\x48"
    "\xc1\xe7\x04\x48\x01\xc7\x48\x8b\x44\x24\x18\x0f\xb6\x40\x02\x84\xc0\x0f\x84\xa1\x02\x00\x00\x48\xc1\xe7\x04\x48\x01\xc7\x48\x8b"
    "\x44\x24\x18\x0f\xb6\x40\x03\x84\xc0\x0f\x84\x89\x02\x00\x00\x48\xc1\xe7\x04\x48\x01\xc7\x48\x8b\x44\x24\x18\x0f\xb6\x40\x04\x84"
    "\xc0\x0f\x84\x71\x02\x00\x00\x48\xc1\xe7\x04\x48\x01\xf8\x48\x8b\x7c\x24\x18\x0f\xb6\x4f\x05\x48\x8d\x57\x05\x84\xc9\x74\x21\x48"
    "\xc1\xe0\x04\x48\x83\xc2\x01\x48\x01\xc1\x48\x89\xc8\x48\xc1\xe8\x18\x25\xf0\x00\x00\x00\x48\x31\xc8\x0f\xb6\x0a\x84\xc9\x75\xdf"
    "\x25\xff\xff\xff\x0f\x31\xd2\x48\x89\xc7\x48\xf7\xf6\x48\x8d\x04\x95\x00\x00\x00\x00\x48\x8b\x54\x24\x58\x48\x89\x3a\xe9\x23\xf9"
    "\xff\xff\x4d\x85\xed\x0f\x85\x69\x02\x00\x00\x48\x89\x4c\x24\x18\xbe\x1f\x00\x00\x00\xbf\x20\x00\x00\x00\xff\x15\xc0\xd8\x02\x00"
    "\x48\x89\x44\x24\x20\x48\x85\xc0\x0f\x84\xa9\x02\x00\x00\x48\x89\x45\x50\x48\x8b\x4c\x24\x18\x48\xba\x11\x42\x08\x21\x84\x10\x42"
    "\x08\x41\xbd\x1f\x00\x00\x00\x48\x8b\x05\x8a\xd8\x02\x00\x48\xc7\x45\x58\x1f\x00\x00\x00\x48\x89\x45\x68\x4c\x89\xf0\x48\xf7\xe2"
    "\x4c\x89\xf0\x48\x29\xd0\x48\xd1\xe8\x4c\x8d\x24\x02\x48\xba\x47\x58\xee\x69\x84\xe5\x9e\x46\x49\xc1\xec\x04\x4c\x89\xe0\x48\xc1"
    "\xe0\x05\x4c\x29\xe0\x4d\x89\xf4\x49\x29\xc4\x4c\x89\xf0\x48\xf7\xea\x48\x89\xd0\x4c\x89\xf2\x48\xc1\xfa\x3f\x48\xc1\xf8\x03\x48"
    "\x29\xd0\x48\x8d\x14\xc5\x00\x00\x00\x00\x48\x29\xc2\x48\x8d\x04\x90\x4c\x89\xf2\x48\x29\xc2\x48\x83\xc2\x01\xe9\x40\xfd\xff\xff"
    "\x45\x89\xf0\x4c\x8b\x7c\x24\x38\x48\x8b\xac\x24\xc0\x00\x00\x00\x4c\x8b\x74\x24\x40\xe9\xc8\xfc\xff\xff\x49\x8d\x7d\x01\xe8\x8d"
    "\x15\x00\x00\xbf\x20\x00\x00\x00\x48\x89\xc5\x48\x89\xc6\xff\x15\xec\xd7\x02\x00\x49\x89\xc7\x48\x85\xc0\x0f\x84\xd7\x01\x00\x00"
    "\x48\x8d\x45\xfe\x48\x8b\x54\x24\x20\x48\x8b\x4c\x24\x38\x48\x89\x44\x24\x18\x4c\x89\xe8\x48\xc1\xe0\x05\x48\x89\xd7\x48\x01\xd0"
    "\x4d\x85\xed\x49\x89\xc4\x74\x7e\x0f\x1f\x84\x00\x00\x00\x00\x00\x4c\x8b\x47\x08\x4d\x85\xc0\x74\x64\x44\x8b\x2f\x31\xd2\x4c\x8b"
    "\x57\x18\x4c\x8b\x5f\x10\x4c\x89\xe8\x4d\x89\xe9\x48\xf7\xf5\x4c\x89\xe8\x48\x89\xd6\x31\xd2\x48\xf7\x74\x24\x18\x48\x83\xc2\x01"
    "\x49\x89\xd5\x49\xc1\xe5\x05\x48\x89\xf0\x48\xc1\xe0\x05\x4c\x01\xf8\xeb\x14\x0f\x1f\x44\x00\x00\x48\x01\xd6\x4c\x01\xe8\x48\x39"
    "\xf5\x0f\x86\x89\x00\x00\x00\x48\x83\x78\x08\x00\x75\xea\x44\x89\x08\x4c\x89\x40\x08\x4c\x89\x58\x10\x4c\x89\x50\x18\x48\x83\xc7"
    "\x20\x49\x39\xfc\x75\x8a\x48\x8b\x7c\x24\x28\x48\x89\x4c\x24\x38\x49\x89\xed\x48\x8d\x04\xff\x48\x8d\x04\x47\x48\x8d\x3d\x9e\xdc"
    "\x02\x00\x4c\x8d\x24\xc7\x48\x8b\x7c\x24\x20\x41\xff\x54\x24\x68\x48\x8b\x05\x01\xd7\x02\x00\x31\xd2\x49\x89\x6c\x24\x58\x4d\x89"
    "\x7c\x24\x50\x48\x8b\x4c\x24\x38\x49\x89\x44\x24\x68\x4c\x89\xf0\x48\xf7\xf5\x4c\x89\x7c\x24\x20\x4c\x89\xf0\x49\x89\xd4\x31\xd2"
    "\x48\xf7\x74\x24\x18\x48\x83\xc2\x01\xe9\xf2\xfb\xff\xff\x66\x90\x48\x29\xee\xe9\x4f\xff\xff\xff\x48\x89\xf8\x31\xd2\x48\xf7\xf6"
    "\x48\x8d\x04\x95\x00\x00\x00\x00\xe9\xc8\xfd\xff\xff\x45\x89\xf0\x4c\x8b\x7c\x24\x38\x4c\x8b\x74\x24\x40\x48\x89\xc1\x48\x8b\xac"
    "\x24\xc0\x00\x00\x00\xe9\xa6\xf7\xff\xff\x48\x8b\x45\x10\x48\x8b\x7c\x24\x50\x48\x8b\x5d\x18\x48\x89\x07\xe9\x09\xfb\xff\xff\xf6"
    "\x05\xfa\xd6\x02\x00\x04\x75\x4d\xc6\x83\x1f\x03\x00\x00\x01\xe9\xee\xfb\xff\xff\xf6\x05\xe6\xd6\x02\x00\x08\x0f\x85\xfb\xfb\xff"
    "\xff\x48\x8d\x0d\x28\x36\x02\x00\xba\x3c\x01\x00\x00\x48\x8d\x35\x73\x1a\x02\x00\x48\x8d\x3d\x25\x46\x02\x00\xe8\xc0\x1e\x01\x00"
    "\x48\x8b\xac\x24\xc0\x00\x00\x00\x44\x8b\x84\x24\xe0\x00\x00\x00\xe9\x89\xf5\xff\xff\x48\x8b\x53\x30\x48\x8b\x73\x08\x31\xc0\x48"
    "\x89\x4c\x24\x08\x48\x8d\x3d\x1d\x46\x02\x00\xe8\xc0\x36\x00\x00\x48\x8b\x4c\x24\x08\xeb\x91\x48\x8b\x7c\x24\x30\xff\x15\x06\xd6"
    "\x02\x00\x48\x8d\x3d\x2a\x1a\x02\x00\x31\xc0\xe8\x00\x3a\x00\x00\x48\x8b\x53\x30\x48\x8b\x73\x08\x31\xc0\x48\x89\x4c\x24\x08\x48"
    "\x8d\x3d\xe2\x45\x02\x00\xe8\x85\x36\x00\x00\x48\x8b\x4c\x24\x08\xe9\x0b\xfc\xff\xff\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00"
    "\xf3\x0f\x1e\xfa\x41\x57\x41\x56\x41\x55\x41\x54\x49\x89\xfc\x55\x48\x89\xd5\x53\x48\x81\xec\x98\x00\x00\x00\x48\x89\x74\x24\x10"
    "\x48\x89\x4c\x24\x18\x4c\x89\x44\x24\x08\x44\x89\x4c\x24\x38\x41\x0f\xb6\x14\x24\x84\xd2\x0f\x84\x34\x02\x00\x00\x4c\x89\xe1\xbb"
    "\x05\x15\x00\x00\x0f\x1f\x40\x00\x48\x89\xd8\x48\x83\xc1\x01\x48\xc1\xe0\x05\x48\x01\xc3\x48\x01\xd3\x0f\xb6\x11\x84\xd2\x75\xe8"
    "\x89\xdb\x48\x83\x05\xee\xe4\x02\x00\x01\xb8\xff\xff\xff\xff\x48\x83\x7c\x24\x08\x00\x48\x89\x44\x24\x40\x48\xc7\x44\x24\x50\x00"
    "\x00\x00\x00\x48\xc7\x44\x24\x58\x00\x00\x00\x00\x74\x0e\xf6\x84\x24\xd0\x00\x00\x00\x02\x0f\x85\x70\x0c\x00\x00\x48\x83\xbc\x24"
    "\xd8\x00\x00\x00\x00\x48\x8b\x44\x24\x18\x4c\x8b\x08\x0f\x85\x6d\x02\x00\x00\x4d\x85\xc9\x0f\x84\xbe\x01\x00\x00\x48\xc7\x44\x24"
    "\x20\x00\x00\x00\x00\x48\x8b\x44\x24\x20\x4c\x8b\x6c\x24\x18\x4c\x8d\x7c\x24\x50\x4c\x8d\x74\x24\x40\xeb\x14\x0f\x1f\x44\x00\x00"
    "\x4d\x8b\x4d\x08\x49\x83\xc5\x08\x31\xc0\x4d\x85\xc9\x74\x3a\xff\x74\x24\x10\x8b\x7c\x24\x40\x4d\x89\xf8\x4c\x89\xf2\x48\x8b\x4d"
    "\x00\x57\x4c\x89\xe7\xff\xb4\x24\xe8\x00\x00\x00\x8b\xb4\x24\xe8\x00\x00\x00\x56\x48\x89\xde\xff\x74\x24\x28\x50\xe8\x0f\xf3\xff"
    "\xff\x48\x83\xc4\x30\x85\xc0\x74\xb7\x48\x8b\x4d\x00\x48\x8b\x54\x24\x50\x48\x89\xc8\x48\x85\xd2\x0f\x84\x40\x01\x00\x00\x48\x85"
    "\xc9\x74\x0b\x0f\xb6\x41\x05\x83\xe0\x03\x3c\x03\x74\x62\x4c\x8b\x7c\x24\x58\x31\xdb\x41\x0f\xb6\x87\x1c\x03\x00\x00\x83\xe0\x03"
    "\x3c\x02\x0f\x84\xec\x03\x00\x00\x4c\x8b\x54\x24\x50\x4d\x89\xfd\x41\x8b\xbf\xe4\x03\x00\x00\x85\xff\x0f\x84\xd9\x01\x00\x00\x8b"
    "\x05\xbb\xd4\x02\x00\xa9\x04\x08\x00\x00\x0f\x85\xe0\x01\x00\x00\x4c\x89\x55\x00\x48\x81\xc4\x98\x00\x00\x00\x4c\x89\xe8\x5b\x5d"
    "\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3\x0f\x1f\x80\x00\x00\x00\x00\x83\x7c\x24\x38\x01\x0f\x84\x7a\x04\x00\x00\x48\xc7\x44\x24\x70"
    "\x00\x00\x00\x00\x48\x8b\x44\x24\x18\x48\xc7\x44\x24\x78\x00\x00\x00\x00\x4c\x8b\x08\x4d\x85\xc9\x0f\x84\x50\x04\x00\x00\x4c\x8b"
    "\x54\x24\x18\x83\x7c\x24\x38\x04\x4c\x8d\x44\x24\x70\x48\x8b\x54\x24\x20\x0f\x94\x44\x24\x28\x4d\x89\xc5\x4d\x89\xd7\xeb\x4c\x90"
    "\x6a\x00\x4d\x89\xe8\x48\x89\xde\x4c\x89\xe7\x50\xff\xb4\x24\xe8\x00\x00\x00\x8b\x84\x24\xe8\x00\x00\x00\x50\xff\x74\x24\x28\x52"
    "\x4c\x89\xf2\xe8\x08\xf2\xff\xff\x48\x83\xc4\x30\x85\xc0\x0f\x85\xcb\x03\x00\x00\x4d\x8b\x4f\x08\x49\x83\xc7\x08\x4d\x85\xc9\x0f"
    "\x84\xba\x03\x00\x00\x48\x8b\x4d\x00\x31\xd2\x0f\xb6\x41\x04\x83\xe0\x0f\x3c\x01\x75\x0c\x80\x7c\x24\x28\x00\xb8\x04\x00\x00\x00"
    "\x75\x9e\xb8\x01\x00\x00\x00\xeb\x97\x0f\x1f\x80\x00\x00\x00\x00\xbb\x05\x15\x00\x00\xe9\xe8\xfd\xff\xff\x48\x8b\x45\x00\x48\x85"
    "\xc0\x74\x0f\x0f\xb6\x40\x04\xc0\xe8\x04\x3c\x02\x0f\x84\x81\x00\x00\x00\xf6\x05\xa8\xd3\x02\x00\x01\x75\x78\x48\x8b\x44\x24\x10"
    "\x48\x85\xc0\x0f\x84\xa6\x04\x00\x00\x48\x8b\x70\x08\x48\x83\x7c\x24\x08\x00\x0f\xb6\x06\x0f\x84\xb5\x05\x00\x00\x48\x8b\x7c\x24"
    "\x08\x48\x8d\x15\xf4\x27\x02\x00\x4c\x8d\x05\x33\x17\x02\x00\x4c\x8b\x0f\x4d\x85\xc9\x4c\x0f\x44\xca\x84\xc0\x0f\x84\x9d\x04\x00"
    "\x00\x4c\x8d\x6c\x24\x70\x4c\x89\xe1\x48\x8d\x15\x2e\x17\x02\x00\x31\xc0\x4c\x89\xef\xe8\x76\x94\xff\xff\x31\xff\x48\x8d\x15\x34"
    "\x17\x02\x00\x4c\x89\xee\xe8\x35\x6a\xff\xff\x4c\x89\xef\xe8\xed\x98\xff\xff\x45\x31\xd2\x45\x31\xed\xe9\x72\xfe\xff\xff\x66\x90"
    "\x49\x8b\x01\x48\x8b\x30\x48\x39\xb4\x24\xd8\x00\x00\x00\x0f\x84\x88\xfd\xff\xff\x48\x8b\x8c\x24\xd8\x00\x00\x00\x31\xd2\x66\x90"
    "\x48\x83\xc2\x01\x48\x39\x0c\xd0\x75\xf6\x48\x89\x54\x24\x20\xe9\x71\xfd\xff\xff\x0f\x1f\x40\x00\x41\xc7\x87\xe4\x03\x00\x00\x01"
    "\x00\x00\x00\xe9\x17\xfe\xff\xff\x0f\x1f\x84\x00\x00\x00\x00\x00\xa8\x04\x0f\x84\xad\x00\x00\x00\x49\x8b\x4d\x08\x85\xdb\x4d\x8b"
    "\x45\x30\x4c\x8d\x0d\x84\x16\x02\x00\x48\x8d\x05\x87\x16\x02\x00\x4c\x0f\x44\xc8\x80\x39\x00\x75\x18\x48\x8b\x05\x80\xd2\x02\x00"
    "\x48\x8b\x08\x48\x8d\x05\x31\x12\x02\x00\x48\x85\xc9\x48\x0f\x44\xc8\x48\x8b\x44\x24\x10\x48\x8b\x70\x08\x48\x8b\x50\x30\x80\x3e"
    "\x00\x75\x18\x48\x8b\x05\x56\xd2\x02\x00\x48\x8b\x30\x48\x8d\x05\x07\x12\x02\x00\x48\x85\xf6\x48\x0f\x44\xf0\x4c\x89\x54\x24\x18"
    "\x48\x83\xec\x08\x31\xc0\x41\x54\x48\x8d\x3d\x09\x43\x02\x00\xe8\x7c\x32\x00\x00\x59\x5e\x48\x8b\x44\x24\x08\x4c\x8b\x54\x24\x18"
    "\x48\x85\xc0\x0f\x84\x0d\x04\x00\x00\x48\x8b\x30\x48\x8d\x3d\x38\x16\x02\x00\x31\xc0\xe8\x06\x33\x00\x00\x8b\x05\x20\xd2\x02\x00"
    "\x4c\x8b\x54\x24\x18\xf6\xc4\x08\x0f\x84\x62\xfd\xff\xff\x48\x8b\x05\xe3\xd4\x02\x00\x48\x8b\x15\x04\xd7\x02\x00\x48\xc7\x44\x24"
    "\x60\x00\x00\x00\x00\x48\xc7\x44\x24\x68\x00\x00\x00\x00\x48\x85\xc0\x0f\x84\x0d\x02\x00\x00\x48\x39\xd0\x0f\x84\x04\x02\x00\x00"
    "\x4d\x85\xd2\x0f\x84\x17\x04\x00\x00\x41\x0f\xb6\x42\x04\x83\x64\x24\x38\x03\x83\xe0\x0f\x3c\x06\x0f\x84\x1a\x06\x00\x00\x31\xd2"
    "\x8b\x74\x24\x38\x89\xf1\x83\xc9\x08\x3c\x0a\x0f\x45\xce\x89\x4c\x24\x38\x85\xd2\x0f\x84\x01\x03\x00\x00\x48\x8b\x74\x24\x10\x4c"
    "\x8b\x4d\x00\x49\x8b\x52\x08\x49\x8b\x85\x58\x03\x00\x00\x48\x8b\x8e\x58\x03\x00\x00\x49\x29\xc9\x4c\x89\x54\x24\x08\x41\xb8\x10"
    "\x00\x00\x00\x48\x8d\x35\xaa\x15\x02\x00\x48\x8d\x3d\x5f\x42\x02\x00\x52\xba\x10\x00\x00\x00\x6a\x10\x50\x31\xc0\x6a\x10\xe8\x8d"
    "\x33\x00\x00\x48\x8b\x84\x24\x80\x00\x00\x00\x45\x31\xc0\x48\x83\xc4\x20\x31\xd2\x4c\x8b\x54\x24\x08\x48\x85\xc0\x74\x10\x4c\x8b"
    "\x40\x08\x48\x8b\x44\x24\x68\x48\x8b\x90\x58\x03\x00\x00\xb9\x10\x00\x00\x00\xbe\x10\x00\x00\x00\x48\x8d\x3d\x33\x15\x02\x00\x31"
    "\xc0\x4c\x89\x54\x24\x08\xe8\x45\x33\x00\x00\x4c\x8b\x54\x24\x08\x8b\x74\x24\x38\x4c\x89\xe2\x48\x8d\x3d\x27\x15\x02\x00\x31\xc0"
    "\x4c\x89\x54\x24\x08\xe8\x26\x33\x00\x00\x4c\x8b\x54\x24\x08\xe9\x3c\xfc\xff\xff\x4c\x39\x7c\x24\x10\x0f\x84\x09\xfc\xff\xff\xf6"
    "\x84\x24\xd0\x00\x00\x00\x01\x0f\x84\xfb\xfb\xff\xff\x41\x80\xbf\x1f\x03\x00\x00\x00\x0f\x85\xed\xfb\xff\xff\x8b\x84\x24\xd0\x00"
    "\x00\x00\x83\xe0\x08\x89\x44\x24\x20\x74\x0e\x41\x80\xbf\x20\x03\x00\x00\x00\x0f\x85\xcf\xfb\xff\xff\x48\x8b\x44\x24\x10\x48\x8b"
    "\xb0\xd8\x03\x00\x00\x49\x89\xf5\x48\x89\x74\x24\x28\x48\x8b\x80\xd0\x03\x00\x00\x49\x89\xc6\x48\x89\x44\x24\x28\x4d\x85\xf6\x0f"
    "\x84\x74\x02\x00\x00\x49\x8b\x06\x31\xd2\x48\x85\xc0\x75\x1c\xe9\x65\x02\x00\x00\x0f\x1f\x40\x00\x8d\x42\x01\x48\x89\xc2\x49\x8b"
    "\x04\xc6\x48\x85\xc0\x0f\x84\x4e\x02\x00\x00\x49\x39\xc7\x75\xe8\x4c\x8b\x6c\x24\x58\x4c\x8b\x54\x24\x50\xe9\x71\xfb\xff\xff\x48"
    "\x83\x7c\x24\x70\x00\x74\x27\x48\x8b\x74\x24\x10\x48\x39\x74\x24\x78\x74\x1b\x48\x8b\x45\x00\x48\x89\x74\x24\x58\x49\x89\xf7\x48"
    "\x89\x44\x24\x50\xbb\x01\x00\x00\x00\xe9\x27\xfb\xff\xff\x4c\x8b\x7c\x24\x58\xeb\xef\x48\x8b\x44\x24\x10\x49\x89\xca\x48\x39\x44"
    "\x24\x58\x0f\x84\x45\x03\x00\x00\x48\x89\x4c\x24\x50\x48\x89\x44\x24\x58\x4c\x8b\x7c\x24\x10\xbb\x01\x00\x00\x00\x4d\x89\xfd\xe9"
    "\x0c\xfb\xff\xff\x48\x39\x54\x24\x10\x0f\x84\xf1\xfd\xff\xff\x41\x0f\xb6\x0c\x24\x84\xc9\x0f\x84\x47\x04\x00\x00\x4c\x89\xe6\xb8"
    "\x05\x15\x00\x00\x0f\x1f\x40\x00\x48\x89\xc2\x48\x83\xc6\x01\x48\xc1\xe2\x05\x48\x01\xd0\x48\x01\xc8\x0f\xb6\x0e\x84\xc9\x75\xe8"
    "\x89\xc6\xb8\xff\xff\xff\xff\x48\x8d\x54\x24\x48\x4c\x89\x54\x24\x28\x48\x8b\x4d\x00\x48\x89\x44\x24\x48\x48\x8b\x44\x24\x10\x4c"
    "\x8b\x3d\xca\xd4\x02\x00\x48\xc7\x05\xbf\xd4\x02\x00\x00\x00\x00\x00\x50\x8b\x7c\x24\x40\x4c\x8b\x88\xa0\x03\x00\x00\x57\x4c\x89"
    "\xe7\x6a\x00\x6a\x00\xff\x74\x24\x28\x6a\x00\x4c\x8d\x84\x24\x90\x00\x00\x00\x48\x89\x54\x24\x50\x48\x89\x74\x24\x48\xe8\x2e\xed"
    "\xff\xff\x48\x83\xc4\x30\x4c\x8b\x54\x24\x28\x48\x8b\x74\x24\x18\x4c\x39\x54\x24\x60\x48\x8b\x54\x24\x20\x0f\x84\x75\x02\x00\x00"
    "\x4c\x89\x3d\x69\xd4\x02\x00\x4d\x85\xd2\x0f\x84\x89\x01\x00\x00\x41\x0f\xb6\x42\x04\x83\x64\x24\x38\x03\x83\xe0\x0f\x3c\x06\x0f"
    "\x84\xe6\x05\x00\x00\xba\x01\x00\x00\x00\xe9\x31\xfd\xff\xff\x4c\x8d\x05\x66\x23\x02\x00\x48\x83\x7c\x24\x08\x00\x4d\x89\xc1\x74"
    "\x1d\x48\x8b\x44\x24\x08\x4c\x8d\x05\x95\x12\x02\x00\x4c\x8b\x08\x48\x8d\x05\x45\x23\x02\x00\x4d\x85\xc9\x4c\x0f\x44\xc8\x48\x8b"
    "\x05\x9b\xce\x02\x00\x48\x8b\x30\x48\x8d\x05\x4c\x0e\x02\x00\x48\x85\xf6\x48\x0f\x44\xf0\xe9\x46\xfb\xff\xff\x48\x8b\x15\x76\xd1"
    "\x02\x00\x48\x85\xd2\x0f\x94\xc0\x48\x39\x54\x24\x10\x0f\x94\xc2\x08\xd0\x75\x0b\x83\x7c\x24\x38\x03\x0f\x8e\xd1\xf9\xff\xff\x48"
    "\x8b\x7c\x24\x10\x4c\x8b\x4d\x00\x49\x8b\x52\x08\x49\x8b\x85\x58\x03\x00\x00\x48\x8b\x8f\x58\x03\x00\x00\x49\x29\xc9\x4c\x89\x54"
    "\x24\x08\x41\xb8\x10\x00\x00\x00\x48\x8d\x35\x7e\x12\x02\x00\x48\x8d\x3d\x3a\x3f\x02\x00\x52\xba\x10\x00\x00\x00\x6a\x10\x50\x31"
    "\xc0\x6a\x10\xe8\x68\x30\x00\x00\x48\x83\xc4\x20\x4c\x8b\x54\x24\x08\xe9\x1a\xfd\xff\xff\x31\xc0\x48\x8d\x3d\x9c\x22\x02\x00\x4c"
    "\x89\x54\x24\x18\xe8\xf7\x2e\x00\x00\x8b\x05\x11\xce\x02\x00\x4c\x8b\x54\x24\x18\xe9\xec\xfb\xff\xff\x4d\x85\xed\x0f\x84\x93\x00"
    "\x00\x00\x45\x8b\x45\x00\x45\x85\xc0\x0f\x84\x89\x00\x00\x00\x41\x8d\x50\xff\x49\x8d\x45\x08\x49\x8d\x54\xd5\x10\xeb\x09\x48\x83"
    "\xc0\x08\x48\x39\xc2\x74\x71\x4c\x39\x38\x75\xf2\xe9\x7f\xfd\xff\xff\x4c\x8d\x05\x44\x22\x02\x00\x4d\x89\xc1\xe9\x59\xfa\xff\xff"
    "\x48\x85\xc0\x0f\x94\xc2\x48\x39\x44\x24\x10\x0f\x94\xc0\x08\xc2\x75\x0b\x83\x7c\x24\x38\x03\x0f\x8e\xf3\xf8\xff\xff\x48\x8b\x44"
    "\x24\x10\x4c\x8b\x4d\x00\x31\xd2\x48\x8b\x88\x58\x03\x00\x00\x31\xc0\x49\x29\xc9\xe9\x24\xff\xff\xff\x48\x8b\x44\x24\x10\x4c\x8b"
    "\x4d\x00\x31\xd2\x48\x8b\x88\x58\x03\x00\x00\x31\xc0\x49\x29\xc9\xe9\xe3\xfb\xff\xff\x45\x31\xc0\x49\x8b\x87\x80\x04\x00\x00\x48"
    "\x89\x44\x24\x28\x8b\x84\x24\xd0\x00\x00\x00\x83\xe0\x04\x89\x44\x24\x30\x0f\x85\x6f\x02\x00\x00\x44\x89\x44\x24\x3c\x48\x8d\x3d"
    "\xc4\xdb\x02\x00\xff\x15\xc6\xcc\x02\x00\x44\x8b\x44\x24\x3c\x4d\x89\xfa\x48\x8b\x44\x24\x10\x48\x8d\x3d\x22\xd2\x02\x00\x48\x8b"
    "\x50\x30\x48\x8d\x04\xd2\x48\x8d\x04\x42\x48\x8b\x04\xc7\x4c\x39\xd0\x0f\x84\xb9\x00\x00\x00\x48\x85\xc0\x75\x0d\xeb\x14\x66\x90"
    "\x4c\x39\xd0\x0f\x84\xa7\x00\x00\x00\x48\x8b\x40\x18\x48\x85\xc0\x75\xee\x48\x8d\x3d\x6f\xdb\x02\x00\xff\x15\x69\xcc\x02\x00\x8b"
    "\x54\x24\x30\x85\xd2\x0f\x84\xc4\xf6\xff\xff\x64\xc7\x04\x25\x1c\x00\x00\x00\x01\x00\x00\x00\x48\x8b\x44\x24\x10\x48\x8b\x80\x98"
    "\x03\x00\x00\x48\x89\x44\x24\x18\xe9\xa2\xf6\xff\xff\x49\x89\xd2\xe9\xbd\xfc\xff\xff\x4c\x39\x6c\x24\x68\x0f\x85\x80\xfd\xff\xff"
    "\x48\x8b\x44\x24\x10\xf6\x80\x1e\x03\x00\x00\x08\x74\x09\x4d\x85\xd2\x0f\x85\x3f\x04\x00\x00\x4c\x89\x3d\xd2\xd1\x02\x00\x4d\x85"
    "\xd2\x0f\x85\xa2\xfa\xff\xff\x48\x8b\x15\x4a\xcf\x02\x00\x48\x85\xd2\x0f\x94\xc0\x48\x39\x54\x24\x10\x0f\x94\xc2\x08\xd0\x0f\x84"
    "\xae\xfe\xff\xff\xe9\xb4\xfe\xff\xff\x0f\x1f\x80\x00\x00\x00\x00\x48\x85\xc0\x0f\x84\x59\xff\xff\xff\x48\x8b\x44\x24\x28\x49\x3b"
    "\x82\x80\x04\x00\x00\x0f\x85\x47\xff\xff\xff\x41\x80\xba\x1f\x03\x00\x00\x00\x75\x4f\x44\x8b\x4c\x24\x20\x45\x85\xc9\x74\x0a\x41"
    "\x80\xba\x20\x03\x00\x00\x00\x75\x3b\x48\x8b\x44\x24\x10\x0f\xb6\x80\x1c\x03\x00\x00\x88\x44\x24\x18\x83\xe0\x03\x3c\x02\x0f\x84"
    "\x89\x00\x00\x00\xf6\x05\xf5\xcb\x02\x00\x04\x0f\x85\xbd\x03\x00\x00\x83\x7c\x24\x20\x00\x0f\x85\xbc\x01\x00\x00\x41\xc6\x82\x1f"
    "\x03\x00\x00\x01\x48\x8d\x3d\x5d\xda\x02\x00\xff\x15\x57\xcb\x02\x00\x8b\x44\x24\x30\x4c\x8b\x6c\x24\x58\x4c\x8b\x54\x24\x50\x85"
    "\xc0\x0f\x84\xe9\xf6\xff\xff\x64\xc7\x04\x25\x1c\x00\x00\x00\x01\x00\x00\x00\xe9\xd8\xf6\xff\xff\x4c\x8b\x4d\x00\x49\x8b\x52\x08"
    "\xc7\x44\x24\x38\x04\x00\x00\x00\x48\x8b\x7c\x24\x10\x49\x8b\x85\x58\x03\x00\x00\x48\x8b\x8f\x58\x03\x00\x00\x49\x29\xc9\xe9\x1a"
    "\xfd\xff\xff\xbe\x05\x15\x00\x00\xe9\xd5\xfb\xff\xff\x48\x8b\x44\x24\x10\x8b\x80\xe0\x03\x00\x00\x44\x39\xc0\x0f\x86\x94\x01\x00"
    "\x00\x48\x8b\x74\x24\x10\x44\x89\xc2\x48\x8b\x86\xd8\x03\x00\x00\x4c\x89\x54\xd0\x08\x48\x8b\x86\xd8\x03\x00\x00\x41\x8d\x50\x01"
    "\x89\x10\xf6\x05\x37\xcb\x02\x00\x40\x0f\x84\x55\xff\xff\xff\x48\x8b\x44\x24\x10\x48\x8b\x48\x08\x4c\x8b\x40\x30\x80\x39\x00\x75"
    "\x13\x48\x8b\x05\xf8\xca\x02\x00\x48\x8b\x08\x48\x85\xc9\x0f\x84\x53\x04\x00\x00\x49\x8b\x72\x08\x49\x8b\x52\x30\x80\x3e\x00\x75"
    ;
static const unsigned exit_offsets[5]={0x73e,0x670,0xa14,0x818,0x63f};
static const unsigned trace_counts[11]={3,9,11,20,20,5,9,11,15,17,17};
static const unsigned fault_heads[6]={5,9,11,15,17,17};
struct observation {
    struct region_live before,after;
    unsigned char xbefore[REGION_FP],xafter[REGION_FP];
    struct li2_step_frame entry,exit;
    siginfo_t entry_si,exit_si;
    unsigned char stack[LOGICAL_STACK],data[DATA],operands[16];
    uint64_t trace[64];
    uint64_t meta[24]; /* lane,NX,TRACE,kind,raw/logicalPC,FS,GS,entry/exit,
       fault-address,head,source-offset,generated-offset,mask,restored-stack,
       expected-trace,whole-source-NX,whole-image-NX, before-FS/GS/mask,2 reserved */
};
static struct observation current,qualified[2];
_Static_assert(sizeof(struct observation)==272320,"actual object padding; wire explicitly emits 272288 bytes");
_Static_assert(sizeof(struct li2_region_plan)==53024,"complete actual plan");
_Static_assert(sizeof(struct li2_step_frame)==65792&&sizeof(siginfo_t)==128,"actual frame wire");
static int audit_mapping(const struct owned_mapping *,int);
static int dump(void);
static void retire(void);
static _Noreturn void die(unsigned code){if(!first_error)first_error=code;retire();(void)dump();(void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
static void need(int ok,unsigned code){if(!ok)die(code);}
_Noreturn void li2_decoder_abort(uint32_t code){die(1000+code);}
static uint32_t u32(const unsigned char *p){uint32_t x;bytes(&x,p,4);return x;}
static void sync_core(void){need(!RAW(SYS_membarrier,32,0,0,0,0,0),12);}
static void source_prot(int prot){need(!RAW(SYS_mprotect,source.at,source.n,prot,0,0,0),13);sync_core();need(audit_mapping(&source,prot),14);}
static void image_prot(int prot){need(!RAW(SYS_mprotect,image.at,image.n,prot,0,0,0),15);sync_core();need(audit_mapping(&image,prot),16);}
static void singleton(void){char out[8192];long fd=RAW(SYS_openat,AT_FDCWD,"/proc/self/status",O_RDONLY|O_CLOEXEC,0,0,0);need(fd>=0,137);long n=RAW(SYS_read,fd,out,sizeof(out)-1,0,0,0);need(n>0&&n<(long)sizeof(out)-1&&!RAW(SYS_close,fd,0,0,0,0,0),138);out[n]=0;unsigned threads=0,tracer=0;const char *p=out;while(*p){if(!strncmp(p,"Threads:\t1\n",11))threads++;if(!strncmp(p,"TracerPid:\t0\n",13))tracer++;while(*p&&*p!='\n')p++;if(*p)p++;}need(threads==1&&tracer==1,139);}
static int read_maps(void){long fd=RAW(SYS_openat,AT_FDCWD,"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);if(fd<0)return 0;size_t n=0;int ok=1;for(;;){if(n==sizeof(maps)-1){ok=0;break;}long k=RAW(SYS_read,fd,maps+n,sizeof(maps)-1-n,0,0,0);if(k<0){ok=0;break;}if(!k)break;n+=(size_t)k;}if(RAW(SYS_close,fd,0,0,0,0,0))ok=0;maps[n]=0;return ok;}
static __attribute__((always_inline)) inline uint64_t number(const char **p,unsigned radix,int *ok){uint64_t v=0;unsigned count=0;while(**p){unsigned c=(unsigned char)**p,x;if(c>='0'&&c<='9')x=c-'0';else if(c>='a'&&c<='f')x=c-'a'+10;else break;if(x>=radix)break;if(v>(UINT64_MAX-x)/radix){*ok=0;return 0;}v=v*radix+x;++*p;++count;}if(!count)*ok=0;return v;}
static int mapping_rows(uintptr_t address,size_t size,int prot,const struct stat *st){
    if(!read_maps()||!size||address>UINTPTR_MAX-size)return 0;unsigned found=0,aliases=0;const char *p=maps;
    while(*p){int ok=1;uint64_t lo=number(&p,16,&ok);if(*p++!='-')return 0;uint64_t hi=number(&p,16,&ok);if(!ok||lo>=hi||*p++!=' ')return 0;
        char r=*p++,w=*p++,x=*p++,share=*p++;if(*p++!=' ')return 0;uint64_t off=number(&p,16,&ok);if(*p++!=' ')return 0;uint64_t ma=number(&p,16,&ok);if(*p++!=':')return 0;uint64_t mi=number(&p,16,&ok);if(*p++!=' ')return 0;while(*p==' ')p++;uint64_t ino=number(&p,10,&ok);if(!ok)return 0;
        if(lo<=address&&address<hi){int actual=(r=='r'?PROT_READ:0)|(w=='w'?PROT_WRITE:0)|(x=='x'?PROT_EXEC:0);if(++found!=1||address+size>hi||actual!=prot||share!='p')return 0;if(st&&(lo!=address||hi!=address+size||off||ino!=(uint64_t)st->st_ino||ma!=major(st->st_dev)||mi!=minor(st->st_dev)))return 0;}
        if(st&&ino==(uint64_t)st->st_ino&&ma==major(st->st_dev)&&mi==minor(st->st_dev)){if(++aliases!=1||lo!=address||hi!=address+size||w!='-'||share!='p')return 0;}
        while(*p&&*p!='\n')p++;if(*p=='\n')p++;
    }
    return found==1&&(!st||aliases==1);
}
static int audit_mapping(const struct owned_mapping *m,int prot){struct stat st;if(!m->at||m->fd<0||RAW(SYS_fstat,m->fd,&st,0,0,0,0)||st.st_dev!=m->stat.st_dev||st.st_ino!=m->stat.st_ino||st.st_size!=(off_t)m->n||RAW(SYS_fcntl,m->fd,F_GET_SEALS,0,0,0,0)!=SEALS)return 0;return mapping_rows(m->at,m->n,prot,&st)&&same((void *)m->at,m->expected,m->n);}
static void sealed(struct owned_mapping *m,const unsigned char *data,size_t n,uintptr_t at,int prot){
    need(n&&n<=sizeof(m->expected)&&!(n&(PAGE-1)),20);m->n=n;m->fd=(int)RAW(SYS_memfd_create,"li2-region",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);need(m->fd>=0,21);
    need(!RAW(SYS_ftruncate,m->fd,n,0,0,0,0)&&write_all(m->fd,data,n),22);
    need(!RAW(SYS_fcntl,m->fd,F_ADD_SEALS,SEALS,0,0,0)&&!RAW(SYS_fstat,m->fd,&m->stat,0,0,0,0),23);
    long a=RAW(SYS_mmap,at,n,prot,MAP_PRIVATE|(at?MAP_FIXED_NOREPLACE:0),m->fd,0);need(a>0&&(!at||(uintptr_t)a==at),24);m->at=(uintptr_t)a;bytes(m->expected,data,n);sync_core();need(audit_mapping(m,prot),25);
}
static void retire(void){
    /* Revoke both executable mappings before any return. Each independent
       cleanup is attempted; first error is never replaced by a later error. */
    if(source.at&&RAW(SYS_mprotect,source.at,source.n,PROT_READ,0,0,0)&&!first_error)first_error=90;
    if(image.at&&RAW(SYS_mprotect,image.at,image.n,PROT_NONE,0,0,0)&&!first_error)first_error=91;
    if((source.at||image.at)&&RAW(SYS_membarrier,32,0,0,0,0,0)&&!first_error)first_error=92;
    struct owned_mapping *owned[2]={&image,&source};
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=owned[i];if(m->at){if(RAW(SYS_munmap,m->at,m->n,0,0,0,0)){if(!first_error)first_error=93;}else m->at=0;}if(m->fd>=0){if(RAW(SYS_close,m->fd,0,0,0,0,0)&&!first_error)first_error=94;m->fd=-1;}}
    if(handling)return; /* Failure on altstack exits nonreturningly, no false clean prefix. */
    if(reservation){if(RAW(SYS_munmap,reservation,2*PAGE,0,0,0,0)){if(!first_error)first_error=95;}else reservation=0;}
    if(data_area){if(RAW(SYS_munmap,data_area,DATA+PAGE,0,0,0,0)){if(!first_error)first_error=96;}else data_area=0;}
    if(stack_area){if(RAW(SYS_munmap,stack_area,STACK+2*PAGE,0,0,0,0)){if(!first_error)first_error=97;}else stack_area=0;}
    if(alt_area){stack_t disabled={.ss_flags=SS_DISABLE};if(RAW(SYS_sigaltstack,&disabled,0,0,0,0,0)){if(!first_error)first_error=98;}else if(RAW(SYS_munmap,alt_area,ALT+2*PAGE,0,0,0,0)){if(!first_error)first_error=99;}else alt_area=0;}
    cleanup_done=!first_error&&!source.at&&!image.at&&source.fd==-1&&image.fd==-1&&!reservation&&!data_area&&!stack_area&&!alt_area;
}
static void frame(struct li2_step_frame *out,const ucontext_t *uc){
    zero(out,sizeof(*out));bytes(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));bytes(&out->mask,&uc->uc_sigmask,8);
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;need(out->fp_address&&!(out->fp_address&15)&&out->fp_address>=alt_area+PAGE&&out->fp_address<=alt_area+PAGE+ALT-512,30);
    const unsigned char *p=(void *)out->fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);need(n>=580&&n<=REGION_FP&&n<=alt_area+PAGE+ALT-out->fp_address&&x>=576&&x==n-4&&u32(p+n-4)==UINT32_C(0x46505845),31);uint64_t comp;bytes(&comp,p+520,8);need(!comp,32);}
    out->fp_bytes=n;bytes(out->fp,p,n);out->initialized=n;need(out->mask==app_mask,33);
}

static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc){return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21&&(uintptr_t)g[REG_CR2]==pc;}
static uintptr_t fault_address(void){return mode==6?stack_fault:mode==8?stack_fault+PAGE-8:data_address+DATA;}
static unsigned head_at(uintptr_t pc){for(unsigned i=0;i<20;i++)if(pc==source.at+0x5f2+offsets[i])return i;return 20;}
static unsigned exit_at(uintptr_t pc){for(unsigned i=0;i<5;i++)if(pc==source.at+exit_offsets[i])return i;return 5;}
static void finish_event(ucontext_t *uc,const siginfo_t *si,unsigned kind,uintptr_t logical,unsigned head){
    need(started&&!ended,40);frame(&current.exit,uc);bytes(&current.exit_si,si,sizeof(*si));
    current.meta[3]=kind;current.meta[4]=(uint64_t)uc->uc_mcontext.gregs[REG_RIP];current.meta[5]=logical;
    current.meta[9]=1;current.meta[10]=kind==2?(uintptr_t)si->si_addr:0;current.meta[11]=head;
    current.meta[12]=kind==2?0x5f2+offsets[head]:(unsigned)(logical-source.at);
    current.meta[13]=kind==2?generated_offsets[head]:UINT64_MAX;
    /* Capture the genuine terminal frame first; revoke executable ownership
       before restoring read access solely for post-terminal byte observation. */
    if(!lane)source_prot(PROT_READ);else image_prot(PROT_READ);
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ),41);
    current.meta[17]=current.meta[18]=1;
    if(stack_fault){need(!RAW(SYS_mprotect,stack_fault,PAGE,PROT_READ,0,0,0),42);need(mapping_rows(stack_fault,PAGE,PROT_READ,NULL),43);current.meta[15]=1;}
    if(!lane)uc->uc_mcontext.gregs[REG_EFL]&=~(greg_t)LI2_STEP_TF;
    else need(!(uc->uc_mcontext.gregs[REG_EFL]&LI2_STEP_TF),44);
    uc->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)region_capture;ended=1;
}
static void handler(int sig,siginfo_t *si,void *ptr){
    need(!handling&&si&&ptr,45);handling=1;ucontext_t *uc=ptr;greg_t *g=uc->uc_mcontext.gregs;uintptr_t pc=(uintptr_t)g[REG_RIP];
    if(!started){
        need(nx(sig,si,g,plan.entry)&&!ended&&audit_mapping(&source,PROT_READ)&&audit_mapping(&image,lane?PROT_READ|PROT_EXEC:PROT_READ),46);
        frame(&current.entry,uc);bytes(&current.entry_si,si,sizeof(*si));current.meta[1]++;current.meta[8]=1;started=1;current_head=0;
        need((uint64_t)g[REG_EFL]==(region_input_flags|LI2_STEP_RF),47);
        if(!lane){source_prot(PROT_READ|PROT_EXEC);g[REG_EFL]|=LI2_STEP_TF;}else g[REG_RIP]=(greg_t)plan.generated;
        handling=0;return;
    }
    if(!lane&&sig==SIGTRAP){
        need(si->si_code==TRAP_TRACE&&!si->si_errno&&g[REG_TRAPNO]==1&&!g[REG_ERR]&&(g[REG_EFL]&LI2_STEP_TF)&&reference_steps<20&&current_head<20,48);
        const struct li2_region_head *h=&plan.head[current_head];unsigned matched=0;
        for(unsigned j=0;j<h->successor_count;j++){unsigned k=h->successors[j];uintptr_t next=k<20?source.at+plan.head[k].source_offset:plan.exit_pc[k-LI2_REGION_HEADS];if(pc==next)matched++;}
        need(matched==1,49);current.trace[reference_steps++]=pc;current.meta[2]++;
        unsigned at=exit_at(pc);if(at<5){need(mode<5&&at==mode,50);exit_kind=1;finish_event(uc,si,1,pc,current_head);handling=0;return;}
        current_head=head_at(pc);need(current_head<20,51);handling=0;return;
    }
    unsigned at=exit_at(pc);
    if(lane&&at<5&&nx(sig,si,g,pc)){
        need(mode<5&&at==mode&&!current.meta[2],52);current.meta[1]++;exit_kind=1;
        unsigned last=mode==0?2:mode==1?8:mode==2?14:19;
        finish_event(uc,si,1,pc,last);handling=0;return;
    }
    if(mode>=5&&sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&(uintptr_t)si->si_addr==fault_address()&&g[REG_TRAPNO]==14&&g[REG_ERR]==4&&(uintptr_t)g[REG_CR2]==fault_address()){
        unsigned head=fault_heads[mode-5];struct li2_region_pc association;
        if(!lane)need(pc==plan.entry+offsets[head]&&current_head==head&&reference_steps==trace_counts[mode]&&(g[REG_EFL]&LI2_STEP_TF),53);
        else need(!li2_region_map_pc(&plan,pc,&association)&&association.kind==LI2_REGION_PC_COPIED&&association.head_index==head&&association.source_offset==0x5f2+offsets[head]&&association.source_length==lengths[head]&&association.generated_length==lengths[head]&&association.original_pc==plan.entry+offsets[head]&&association.generated_pc==plan.generated+generated_offsets[head]&&!current.meta[2],54);
        exit_kind=2;finish_event(uc,si,2,plan.entry+offsets[head],head);handling=0;return;
    }
    die(55);
}
static void prepare_input(void){
    zero(&current,sizeof(current));zero(&region_before,sizeof(region_before));zero(&region_after,sizeof(region_after));zero(region_fp_before,REGION_FP);zero(region_fp_after,REGION_FP);
    /* Reset all actually compared bytes before either lane, with no skipped
       operand or inaccessible-stack byte. Only permissions differ while live. */
    need(!RAW(SYS_mprotect,stack_area+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),56);
    bytes((void *)data_area,original_data,DATA);bytes((void *)(region_seed[4]-128),original_stack,LOGICAL_STACK);bytes((void *)(region_seed[4]+0x50),original_operands,16);
    if(stack_fault)need(!RAW(SYS_mprotect,stack_fault,PAGE,PROT_NONE,0,0,0)&&mapping_rows(stack_fault,PAGE,PROT_NONE,NULL),57);
    started=ended=handling=current_head=0;reference_steps=exit_kind=0;region_target=plan.entry;
}
static void invoke(unsigned which){
    lane=which;prepare_input();need(!li2_region_plan_validate(&plan),58);need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ),59);
    if(which)image_prot(PROT_READ|PROT_EXEC);
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[19],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[20],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[21],8,0,0),76);
    region_enter();need(started&&ended&&!handling,60);bytes(&current.before,&region_before,sizeof(region_before));bytes(&current.after,&region_after,sizeof(region_after));
    bytes(current.xbefore,region_fp_before,REGION_FP);bytes(current.xafter,region_fp_after,REGION_FP);bytes(current.stack,(void *)(region_seed[4]-128),LOGICAL_STACK);bytes(current.data,(void *)data_area,DATA);bytes(current.operands,(void *)(region_seed[4]+0x50),16);
    current.meta[0]=lane;current.meta[16]=trace_counts[mode];need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&current.meta[6],0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&current.meta[7],0,0,0,0)&&!RAW(SYS_rt_sigprocmask,0,0,&current.meta[14],8,0,0),61);
}
static void check_seed(const unsigned char *x){
    uint16_t fcw,fsw;bytes(&fcw,x,2);bytes(&fsw,x+2,2);need(fcw==0x37f&&fsw==0x3000&&x[4]==0xc0&&u32(x+24)==0x1f80,129);
    uint64_t bv,comp;bytes(&bv,x+512,8);bytes(&comp,x+520,8);need((bv&0xe7)==0xe7&&!comp,130);
    for(unsigned r=0;r<32;r++)for(unsigned q=0;q<8;q++){uint64_t want=UINT64_C(0x3141592653589793)+(uint64_t)r*8+q+1,got;size_t off;
        if(r>=16){need(xlayout[7][0]&&xlayout[7][2]>=1024,131);off=(size_t)xlayout[7][1]+(r-16)*64+q*8;}
        else if(q>=4){need(xlayout[6][0]&&xlayout[6][2]>=512,132);off=(size_t)xlayout[6][1]+r*32+(q-4)*8;}
        else if(q>=2){need(xlayout[2][0]&&xlayout[2][2]>=256,133);off=(size_t)xlayout[2][1]+r*16+(q-2)*8;}
        else off=160+r*16+q*8;need(off+8<=xsave_bytes,134);bytes(&got,x+off,8);need(got==want,135);}
    const uint64_t masks[8]={UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0xaaaaaaaa55555555),UINT64_C(0x0f0ff0f0a5a55a5a),UINT64_C(0x1111222233334444),UINT64_C(0x8877665544332211),UINT64_C(0xffff00000000ffff),UINT64_C(0x5a5a5a5aa5a5a5a5)};
    need(xlayout[5][0]&&xlayout[5][2]>=64&&same(x+xlayout[5][1],masks,64),136);
}


static void check_observation(unsigned which){
    need(current.meta[3]==(mode>=5?2:1)&&current.meta[8]==1&&current.meta[9]==1&&current.meta[14]==app_mask&&current.meta[16]==trace_counts[mode]&&current.meta[17]==1&&current.meta[18]==1&&current.meta[19]==current.meta[6]&&current.meta[20]==current.meta[7]&&current.meta[21]==app_mask,62);
    need(current.meta[1]==(which&&mode<5?2:1)&&current.meta[2]==(which?0:trace_counts[mode])&&current.meta[15]==(uint64_t)(stack_fault!=0),63);
    check_seed(current.xbefore);check_seed(current.xafter);check_seed(current.entry.fp);check_seed(current.exit.fp);
    need(current.before.flags==region_input_flags&&!current.before.reserved&&!current.after.reserved&&same(current.before.selectors,current.after.selectors,sizeof(current.before.selectors)),64);
    uint64_t selectors=(uint64_t)current.before.selectors[0]|(uint64_t)current.before.selectors[5]<<16|(uint64_t)current.before.selectors[4]<<32|(uint64_t)current.before.selectors[1]<<48;
    need((uint64_t)current.entry.greg[REG_CSGSFS]==selectors&&(uint64_t)current.exit.greg[REG_CSGSFS]==selectors,77);
    need(same(current.xbefore,current.xafter,REGION_FP)&&same(current.stack,original_stack,LOGICAL_STACK)&&same(current.data,original_data,DATA)&&same(current.operands,original_operands,16),65);
    for(unsigned i=0;i<16;i++)need(current.before.gpr[i]==region_seed[i]&&(uint64_t)current.entry.greg[regs[i]]==region_seed[i]&&current.after.gpr[i]==(uint64_t)current.exit.greg[regs[i]],66);
    need((uint64_t)current.entry.greg[REG_RIP]==plan.entry&&(uint64_t)current.entry.greg[REG_EFL]==(region_input_flags|LI2_STEP_RF)&&current.entry.greg[REG_TRAPNO]==14&&current.entry.greg[REG_ERR]==21&&(uint64_t)current.entry.greg[REG_CR2]==plan.entry,67);
    need(current.entry.fp_bytes==current.exit.fp_bytes&&same(current.entry.fp,current.exit.fp,REGION_FP)&&current.entry.mask==current.exit.mask,68);
    /* Full actual flags, AF included. Only the actual reference TF and
       kernel-origin RF are absent after the architectural capture JMP. */
    need((uint64_t)current.exit.greg[REG_EFL]==(current.after.flags|(which||mode>=5?LI2_STEP_RF:LI2_STEP_TF)|(!which&&mode>=5?LI2_STEP_TF:0))&&!(current.after.flags&(LI2_STEP_RF|LI2_STEP_TF)),69);
    if(which){const struct observation *n=&qualified[0];
        need(same(&current.before,&n->before,sizeof(n->before))&&same(&current.after,&n->after,sizeof(n->after))&&same(current.xbefore,n->xbefore,REGION_FP)&&same(current.xafter,n->xafter,REGION_FP),70);
        need(current.exit.fp_bytes==n->exit.fp_bytes&&same(current.exit.fp,n->exit.fp,REGION_FP)&&current.exit.mask==n->exit.mask&&current.meta[6]==n->meta[6]&&current.meta[7]==n->meta[7]&&current.meta[14]==n->meta[14],71);
        for(unsigned i=0;i<NGREG;i++){uint64_t want=(uint64_t)n->exit.greg[i];
            if(mode>=5){if(i==REG_RIP)want=plan.generated+generated_offsets[fault_heads[mode-5]];if(i==REG_EFL)want&=~LI2_STEP_TF;}
            else {if(i==REG_EFL)want=(want&~LI2_STEP_TF)|LI2_STEP_RF;if(i==REG_ERR)want=21;if(i==REG_TRAPNO)want=14;if(i==REG_CR2)want=current.meta[5];}
            need((uint64_t)current.exit.greg[i]==want,72);}
        if(mode>=5)need(current.exit_si.si_signo==n->exit_si.si_signo&&current.exit_si.si_errno==n->exit_si.si_errno&&current.exit_si.si_code==n->exit_si.si_code&&current.exit_si.si_addr==n->exit_si.si_addr,73);
    }
    need(audit_mapping(&source,PROT_READ)&&audit_mapping(&image,PROT_READ)&&!li2_region_plan_validate(&plan),74);
}
static void plan_checks(void){
    need(plan.version==1&&plan.ready==1&&plan.heads==20&&plan.blocks==5&&plan.exits==5&&plan.maps==21&&plan.longest_path==20&&plan.stop_reason==LI2_REGION_STOP_UNSUPPORTED&&plan.source_bytes==77&&plan.image_bytes==90&&plan.decoder_calls==42&&!plan.decoder_result&&plan.page==source.at&&plan.entry==source.at+0x5f2&&plan.generated==image_address&&plan.boundary_pc==source.at+0x63f&&same(plan.source,source.expected,PAGE),160);
    for(unsigned i=0;i<20;i++)need(plan.head[i].source_offset==0x5f2+offsets[i]&&plan.head[i].source_length==lengths[i]&&plan.head[i].generated_offset==generated_offsets[i],161);
    for(unsigned i=0;i<5;i++)need(plan.exit_pc[i]==source.at+exit_offsets[i],162);
    /* The broad pure planner controls belong to the separate planner oracle.
       Here every actual emitted byte is independently associated or refused. */
    for(unsigned at=0;at<90;at++) {struct li2_region_pc pc,empty={0};unsigned row=0;while(row<21&&plan.map[row].generated_offset!=at)row++;int result=li2_region_map_pc(&plan,image_address+at,&pc);
        if(row<21){need(!result&&same(&pc,&plan.map[row],sizeof(pc)),163);head_checks++;}
        else{need(result==LI2_REGION_PLAN_MISS&&same(&pc,&empty,sizeof(pc)),164);interior_misses++;}}
    need(head_checks==21&&interior_misses==69,165);
}
static void authority_controls(void){
    for(unsigned i=0;i<2;i++){struct owned_mapping *m=i?&image:&source;long alias=RAW(SYS_mmap,0,PAGE,PROT_READ|PROT_WRITE,MAP_PRIVATE,m->fd,0);need(alias>0,166);need(!audit_mapping(m,PROT_READ),167);authority_checks++;need(!RAW(SYS_munmap,alias,PAGE,0,0,0,0)&&audit_mapping(m,PROT_READ),168);unsigned char value=0;need(RAW(SYS_pwrite64,m->fd,&value,1,0,0,0)==-EPERM,169);authority_checks++;}
}
static void make_source(void){
    long p=RAW(SYS_mmap,0,2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,170);reservation=(uintptr_t)p;source_address=reservation;image_address=reservation+PAGE;
    need(!RAW(SYS_munmap,reservation,2*PAGE,0,0,0,0),171);reservation=0;
    need(same(source_page+0x5f2,literal,sizeof(literal)),174);sealed(&source,source_page,PAGE,source_address,PROT_READ);
    need(!li2_region_plan_page(source.at,(void *)source.at,source.at+0x5f2,image_address,&plan),172);plan_checks();
    sealed(&image,plan.image,PAGE,image_address,PROT_READ);need(source.at+PAGE==image.at,173);authority_controls();
}
static void setup(void){
    need(getauxval(AT_PAGESZ)==PAGE&&RAW(SYS_getpid,0,0,0,0,0,0)==RAW(SYS_gettid,0,0,0,0,0,0),100);singleton();
    need(!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),0,UINT32_C(0x53053053),0,0)&&!RAW(SYS_rseq,&rseq_probe,sizeof(rseq_probe),RSEQ_FLAG_UNREGISTER,UINT32_C(0x53053053),0,0),101);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));need((c&0x0c000000)==0x0c000000,102);a=d=0;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));region_xcr0=(uint64_t)d<<32|a;need((region_xcr0&0xe7)==0xe7,103);a=7;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need((b&((1U<<16)|(1U<<30)))==((1U<<16)|(1U<<30)),104);a=13;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));xsave_bytes=b;need(xsave_bytes>=576&&xsave_bytes<=REGION_FP,105);
    for(unsigned k=2;k<64;k++)if(region_xcr0&(UINT64_C(1)<<k)){a=13;c=k;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));need(a&&b>=576&&(uint64_t)b+a<=xsave_bytes&&!(c&1),126);xlayout[k][0]=1;xlayout[k][1]=b;xlayout[k][2]=a;}
    unsigned long cet=0;long cr=RAW(SYS_arch_prctl,0x5005,&cet,0,0,0,0);need((!cr&&!cet)||cr==-EINVAL||cr==-ENOSYS,106);
    uint64_t initial=1;need(!RAW(SYS_rt_sigprocmask,0,0,&initial,8,0,0)&&!initial,107);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action,old;
    for(int sig=1;sig<=64;sig++)if(sig!=SIGKILL&&sig!=SIGSTOP)need(!RAW(SYS_rt_sigaction,sig,0,&old,8,0,0)&&!old.handler,108);
    app_mask=UINT64_MAX&~((UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSYS-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));need(!RAW(SYS_rt_sigprocmask,2,&app_mask,0,8,0,0),109);
    long q=RAW(SYS_membarrier,0,0,0,0,0,0);need(q>=0&&(q&96)==96&&!RAW(SYS_membarrier,64,0,0,0,0,0),110);
    long p=RAW(SYS_mmap,0,ALT+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,111);alt_area=alt_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,ALT,PROT_READ|PROT_WRITE,0,0,0),112);stack_t alt={.ss_sp=(void *)(p+PAGE),.ss_size=ALT};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),113);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=region_restorer;action.mask=app_mask;for(unsigned i=0;i<3;i++){int sig=(int[]){SIGSEGV,SIGTRAP,SIGSYS}[i];need(!RAW(SYS_rt_sigaction,sig,&action,0,8,0,0),114);}
    need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&decoder_before)&&decoder_before.abi_version==1&&decoder_before.phase==2&&!decoder_before.first_fatal_reason&&!decoder_before.reserved&&decoder_before.arena_bytes==sizeof(decoder_arena)&&decoder_before.retained_high_water&&decoder_before.retained_high_water<=sizeof(decoder_arena),115);
    p=RAW(SYS_mmap,0,STACK+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,116);stack_area=stack_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p+PAGE,STACK,PROT_READ|PROT_WRITE,0,0,0),117);
    p=RAW(SYS_mmap,0,DATA+PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(p>0,118);data_area=data_address=(uintptr_t)p;need(!RAW(SYS_mprotect,p,DATA,PROT_READ|PROT_WRITE,0,0,0),119);

    for(size_t i=0;i<DATA;i++)original_data[i]=(unsigned char)(1+(i*17)%255);
    for(unsigned i=0;i<16;i++)region_seed[i]=UINT64_C(0x3141592600000000)+(uint64_t)i*UINT64_C(0x102030405);
    region_seed[1]=mode==2?0:mode==1?data_area+DATA-6:data_area+123;region_seed[2]=mode==0?0:1;
    region_seed[4]=stack_area+PAGE+STACK-504;
    if(mode==6){stack_fault=stack_area+2*PAGE;region_seed[4]=stack_fault-0x58;}
    if(mode==8){stack_fault=stack_area+2*PAGE;region_seed[4]=stack_fault+PAGE-0x58;}
    need((region_seed[4]&15)==8&&region_seed[4]-128>=stack_area+PAGE&&region_seed[4]+0x60<=stack_area+PAGE+STACK,120);
    uintptr_t r15=data_area+DATA-4-0x3e4;
    if(mode==2)r15=data_area+DATA-1-0x31c;
    if(mode==7)r15=data_area+DATA-0x31c;
    if(mode==9)r15=data_area+DATA-0x3e4;
    if(mode==10)r15=data_area+DATA-2-0x3e4;
    if(mode==0)region_seed[1]=data_area+DATA; /* unreachable pointer stays unreadable */
    if(mode==5)region_seed[1]=data_area+DATA-5;
    if(mode!=0&&mode!=2&&mode!=5)original_data[mode==1?DATA-1:128]=mode==1?3:1;
    if(mode!=0&&mode!=1&&mode!=5&&mode!=6&&mode!=7){need(r15+0x31c>=data_area&&r15+0x31c<data_area+DATA,121);original_data[r15+0x31c-data_area]=mode==2?2:1;}
    if(mode==3||mode==4){uint32_t value=mode==3?0:UINT32_C(0x80000001);bytes(original_data+r15+0x3e4-data_area,&value,4);}
    for(size_t i=0;i<LOGICAL_STACK;i++)original_stack[i]=(unsigned char)(i*29+7);
    uint64_t r10=UINT64_C(0x8877665544332211);bytes(original_operands,&r10,8);bytes(original_operands+8,&r15,8);
    region_input_flags=mode%2?0x202:0xad7;
    make_source();
}
static int dump_observation(const struct observation *o){return write_all(3,&o->before,sizeof(o->before))&&write_all(3,&o->after,sizeof(o->after))&&write_all(3,o->xbefore,REGION_FP)&&write_all(3,o->xafter,REGION_FP)&&write_all(3,&o->entry,sizeof(o->entry))&&write_all(3,&o->exit,sizeof(o->exit))&&write_all(3,&o->entry_si,sizeof(o->entry_si))&&write_all(3,&o->exit_si,sizeof(o->exit_si))&&write_all(3,o->stack,LOGICAL_STACK)&&write_all(3,o->data,DATA)&&write_all(3,o->operands,16)&&write_all(3,o->trace,sizeof(o->trace))&&write_all(3,o->meta,sizeof(o->meta));}
static int dump(void){
    uint64_t h[48]={UINT64_C(0x314745524332494c),1,48,mode,first_error,cleanup_done,region_xcr0,xsave_bytes,source_address,image_address,stack_address,data_address,alt_address,app_mask,sizeof(plan),sizeof(struct li2_step_frame),REGION_FP,DATA,LOGICAL_STACK,2,authority_checks,head_checks,interior_misses,region_input_flags,trace_counts[mode],mode>=5,(uint64_t)source.stat.st_ino,(uint64_t)source.stat.st_dev,(uint64_t)image.stat.st_ino,(uint64_t)image.stat.st_dev,SEALS,stack_fault,region_seed[4]+0x50,region_seed[4]+0x58,mode>=5?fault_address():0,mode<5?source_address+exit_offsets[mode]:source_address+0x5f2+offsets[fault_heads[mode-5]],UINT64_C(272288),sizeof(decoder_before),20,5,5,90,77,21,69,0,0,0};
    return write_all(3,h,sizeof(h))&&write_all(3,region_seed,sizeof(region_seed))&&write_all(3,xlayout,sizeof(xlayout))&&write_all(3,&decoder_before,sizeof(decoder_before))&&write_all(3,&decoder_after,sizeof(decoder_after))&&write_all(3,source.expected,PAGE)&&write_all(3,image.expected,PAGE)&&write_all(3,&plan,sizeof(plan))&&dump_observation(&qualified[0])&&dump_observation(&qualified[1]);
}
int main(int argc,char **argv){
    if(argc!=2)return 2;char *end;unsigned long value=strtoul(argv[1],&end,10);if(!*argv[1]||*end||value>10||(value<10&&strlen(argv[1])!=1)||(value==10&&strcmp(argv[1],"10")))return 2;mode=(unsigned)value;setup();
    for(unsigned l=0;l<2;l++){invoke(l);check_observation(l);bytes(&qualified[l],&current,sizeof(current));}
    need(!li2_decoder_stats(&decoder_after)&&same(&decoder_before,&decoder_after,sizeof(decoder_before)),175);
    retire();need(cleanup_done&&!first_error&&dump(),122);
    printf("{\"schema\":1,\"mode\":%u,\"qualified_comparison\":1,\"completed_path\":%u,\"required_read_failure\":%u,\"cleanup\":1,\"reference_trace\":%llu,\"generated_trace\":0,\"exit_kind\":%u,\"authority_controls\":%llu,\"head_checks\":%llu,\"interior_misses\":%llu,\"postseal_equal\":1}\n",mode,mode<5,mode>=5,(unsigned long long)qualified[0].meta[2],mode>=5?2:1,(unsigned long long)authority_checks,(unsigned long long)head_checks,(unsigned long long)interior_misses);fflush(stdout);
    return mode>=5?125:0;
}
