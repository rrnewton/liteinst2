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
