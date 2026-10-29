#define _GNU_SOURCE
#include "app.h"
#include <asm/prctl.h>
#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern const ptrdiff_t __rseq_offset __attribute__((weak));
extern const unsigned int __rseq_size __attribute__((weak));
extern const unsigned int __rseq_flags __attribute__((weak));
_Static_assert(sizeof(uintptr_t)==8 && sizeof(struct pa_image)==88,"Linux x86-64 wire");
static unsigned char original[2][PA_PAGE];
static uint64_t statistics[6][14];
static uint64_t clocks[2][PA_STRESS_ROUNDS];
static uint32_t hardware[67][6];
static int output(const void *p,size_t n) {
    const unsigned char *b=p;
    while(n) {
        ssize_t count=write(STDOUT_FILENO,b,n);
        if(count<0 && errno==EINTR)continue;
        if(count<=0)return 1;
        b+=(size_t)count;n-=(size_t)count;
    }
    return 0;
}
static int failure(const char *message,unsigned code) {
    fprintf(stderr,"PROVIDER_APP_FAILED %s %u\n",message,code);return 99;
}
static void cpuid(unsigned index,unsigned leaf,unsigned sub) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
    uint32_t *r=hardware[index];r[0]=leaf;r[1]=sub;r[2]=a;r[3]=b;r[4]=c;r[5]=d;
}
static int format(uint64_t *mask,uint64_t *extent,uint64_t permission[2]) {
    cpuid(0,0,0);cpuid(1,1,0);cpuid(2,7,0);
    if(hardware[0][2]<13 || (hardware[1][4]&0x0c000000)!=0x0c000000)return 1;
    for(unsigned i=0;i<64;i++)cpuid(3+i,13,i);
    uint32_t a,d;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0):"memory");
    *mask=(uint64_t)a|((uint64_t)d<<32);*extent=hardware[3][3];
    if(syscall(SYS_arch_prctl,PA_ARCH_GET_XCOMP_SUPP,&permission[0]) ||
       syscall(SYS_arch_prctl,PA_ARCH_GET_XCOMP_PERM,&permission[1]))return 2;
    if((*mask&0xe7)!=0xe7 || (hardware[2][3]&0x40010000)!=0x40010000 ||
       *mask&~PA_KNOWN || *mask!=permission[0] || *mask!=permission[1] ||
       *mask!=((uint64_t)hardware[3][2]|((uint64_t)hardware[3][5]<<32)) ||
       *extent<576 || *extent>PA_FP || *extent!=hardware[3][4])return 3;
    return 0;
}
static int machine(uint64_t h[8]) {
    uint64_t mask=0,fs=0,gs=0;
    if(syscall(SYS_rt_sigprocmask,0,0,&mask,8) ||
       syscall(SYS_arch_prctl,ARCH_GET_FS,&fs) || syscall(SYS_arch_prctl,ARCH_GET_GS,&gs))return 1;
    unsigned short cs,ss,ds,es,fsel,gsel;
    __asm__ volatile("mov %%cs,%0;mov %%ss,%1;mov %%ds,%2;mov %%es,%3;mov %%fs,%4;mov %%gs,%5":
        "=r"(cs),"=r"(ss),"=r"(ds),"=r"(es),"=r"(fsel),"=r"(gsel)::"memory");
    h[0]=mask;h[1]=fs;h[2]=gs;h[3]=cs;h[4]=ss;h[5]=(uint64_t)ds|((uint64_t)es<<16);
    h[6]=(uint64_t)fsel|((uint64_t)gsel<<16);h[7]=0;return 0;
}
static int registration(uint64_t h[9],unsigned cpu) {
    if(!&__rseq_offset || !&__rseq_size || !&__rseq_flags)return 1;
    ptrdiff_t offset=__rseq_offset;uintptr_t tp=(uintptr_t)__builtin_thread_pointer(),address;
    if(offset>=0) {
        if((uintptr_t)offset>UINTPTR_MAX-tp)return 2;
        address=tp+(uintptr_t)offset;
    } else {
        uintptr_t magnitude=(uintptr_t)(-(offset+1))+1;
        if(magnitude>tp)return 3;
        address=tp-magnitude;
    }
    if(__rseq_size<20 || __rseq_size>PA_PAGE || __rseq_flags || (address&31))return 4;
    const volatile uint32_t *p=(const void *)address;
    h[0]=tp;h[1]=(uint64_t)offset;h[2]=__rseq_size;h[3]=__rseq_flags;h[4]=address;
    h[5]=p[0];h[6]=p[1];h[7]=*(const volatile uint64_t *)(const void *)(address+8);h[8]=p[4];
    return h[5]!=cpu || h[6]!=cpu || h[7] || h[8];
}
struct image_join {const struct pa_image *images;uint64_t base[2],phnum[2],matches[2];};
static int image_callback(struct dl_phdr_info *info,size_t bytes,void *argument) {
    struct image_join *join=argument;
    if(bytes<offsetof(struct dl_phdr_info,dlpi_phnum)+sizeof info->dlpi_phnum)return 1;
    for(unsigned m=0;m<2;m++)for(unsigned i=0;i<info->dlpi_phnum;i++) {
        const ElfW(Phdr) *p=info->dlpi_phdr+i;
        uintptr_t start=info->dlpi_addr+p->p_vaddr,page=join->images[m].page;
        if(p->p_type==PT_LOAD && p->p_flags==(PF_R|PF_X) && page>=start &&
           page-start<=p->p_memsz && PA_PAGE<=p->p_memsz-(page-start)) {
            join->matches[m]++;join->base[m]=info->dlpi_addr;join->phnum[m]=info->dlpi_phnum;
        }
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=3 || (strcmp(argv[1],"state") && strcmp(argv[1],"stress")) ||
       (strcmp(argv[2],"native") && strcmp(argv[2],"scripted")))return failure("arguments",1);
    unsigned detailed=!strcmp(argv[1],"state"),scripted=!strcmp(argv[2],"scripted");
    unsigned rounds=detailed?PA_STATE_ROUNDS:PA_STRESS_ROUNDS,cpu=0,node=0;
    uint64_t head[32]={PA_MAGIC,1,detailed,scripted,rounds,(uint64_t)rounds*6},
        permission[2]={0},first_machine[8],last_machine[8],first_rseq[9],last_rseq[9];
    head[6]=(uint64_t)getpid();head[7]=(uint64_t)syscall(SYS_gettid);
    if(!head[6] || head[6]!=head[7] || syscall(SYS_getcpu,&cpu,&node,0))return failure("single_thread_cpu",2);
    head[8]=cpu;head[9]=node;
    unsigned error=(unsigned)format(&head[10],&head[11],permission);
    if(error)return failure("format",error);
    if(machine(first_machine) || registration(first_rseq,cpu))return failure("default_rseq",3);
    if(pa_main_setup(head[10],head[11]) || pa_dso_setup(head[10],head[11]))return failure("setup",4);
    struct pa_image images[2];pa_main_image(images);pa_dso_image(images+1);
    struct image_join join={.images=images};
    if(dl_iterate_phdr(image_callback,&join) || join.matches[0]!=1 || join.matches[1]!=1 ||
       join.base[0]==join.base[1])return failure("actual_loader_images",5);
    head[12]=join.base[0];head[13]=join.base[1];head[14]=join.phnum[0];head[15]=join.phnum[1];
    for(unsigned m=0;m<2;m++) {
        const volatile unsigned char *p=(const void *)(uintptr_t)images[m].page;
        for(size_t i=0;i<PA_PAGE;i++)original[m][i]=p[i];
    }
    if(output(head,sizeof head) || output(permission,sizeof permission) || output(hardware,sizeof hardware) ||
       output(first_machine,sizeof first_machine) || output(first_rseq,sizeof first_rseq) ||
       output(images,sizeof images) || output(original,sizeof original))return failure("header_output",6);
    for(unsigned iteration=0;iteration<rounds;iteration++)for(unsigned m=0;m<2;m++)for(unsigned k=0;k<3;k++) {
        struct pa_view v={0};
        error=m?(unsigned)pa_dso_step(k,iteration,(int)scripted,head[6],hardware[0]+2,&v):
                (unsigned)pa_main_step(k,iteration,(int)scripted,head[6],hardware[0]+2,&v);
        if(error)return failure("effect",1000*m+100*k+error);
        unsigned index=3*m+k;uint64_t *s=statistics[index];
        s[0]=m;s[1]=k;s[2]++;
        if(s[2]==1)for(unsigned j=0;j<4;j++)s[3+j]=v.after[j];
        for(unsigned j=0;j<4;j++)s[7+j]=v.after[j];
        if(k==PA_RDTSC)clocks[m][iteration]=v.after[0]|(v.after[2]<<32);
        s[11]=(s[11]<<7)|(s[11]>>57);s[11]^=v.after[0]^v.after[1]^v.after[2]^v.after[3];
        s[12]=v.next;s[13]=0;
        for(unsigned j=0;j<5;j++)s[13]|=(uint64_t)v.restored[j]<<(8*j);
        if(detailed) {
            uint64_t row[12]={m,k,iteration,(uint64_t)iteration*6+index,v.site,v.next,v.endpoint,
                v.stack,v.mask,v.extent,s[13],0};
            if(output(row,sizeof row) || output(v.before,17*8) || output(v.after,17*8) ||
               output(v.before_live,PA_LIVE) || output(v.after_live,PA_LIVE))return failure("state_output",7);
        }
    }
    if(pa_main_final() || pa_dso_final() || machine(last_machine) ||
       memcmp(first_machine,last_machine,sizeof first_machine) ||
       syscall(SYS_getcpu,&cpu,&node,0) || cpu!=head[8] || node!=head[9] ||
       registration(last_rseq,cpu) || memcmp(first_rseq,last_rseq,sizeof first_rseq))return failure("terminal_identity",8);
    uint64_t end[8]={PA_MAGIC^1,1,rounds,(uint64_t)rounds*6,6,0,0,0};
    for(unsigned m=0;m<2;m++)if(output(clocks[m],rounds*sizeof(uint64_t)))return failure("clock_output",9);
    if(output(statistics,sizeof statistics) || output(last_machine,sizeof last_machine) ||
       output(last_rseq,sizeof last_rseq))return failure("terminal_output",9);
    for(unsigned m=0;m<2;m++)if(output((const void *)(uintptr_t)images[m].page,PA_PAGE))return failure("source_output",10);
    return output(end,sizeof end)?failure("terminal_marker",11):0;
}
