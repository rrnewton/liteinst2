/* Included only by the explicit CPUID NX-only profile. No syscall, page opening,
   invented signal frame or fallback from a failed hardware-control operation. */
enum selected_cpuid_nx_phase {
    SELECTED_CPUID_NX_EMPTY=0,SELECTED_CPUID_NX_ATTEMPTED=1,
    SELECTED_CPUID_NX_SAMPLED=2,SELECTED_CPUID_NX_COMMITTED=3
};
static struct {
    volatile sig_atomic_t hardware_entered,hardware_returned,phase;
    uint64_t attempts,samples,commits;
    uintptr_t pc,next_pc;
    uint32_t leaf,subleaf,raw[4],result[4];
} selected_cpuid_nx;

/* The caller has already authenticated the genuine NX frame and exact source
   borrow. This operation reads the actual low EAX/ECX and retains a raw sample;
   a separately composed scalar provider may change only the eventual result. */
static void selected_cpuid_nx_sample(const greg_t *g,
                                    uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d) {
    checked(selected_cpuid_nx.hardware_entered==1 && selected_cpuid_nx.hardware_returned==1 &&
        selected_decoded.kind==LI2_CPUID &&
        (selected_cpuid_nx.phase==SELECTED_CPUID_NX_EMPTY ||
         selected_cpuid_nx.phase==SELECTED_CPUID_NX_COMMITTED) &&
        selected_cpuid_nx.attempts==selected_cpuid_nx.samples &&
        selected_cpuid_nx.samples==selected_cpuid_nx.commits &&
        selected_cpuid_nx.attempts!=UINT64_MAX,1611,0);
    /* Retire the previous commit label before touching its retained payload.
       A terminal event during setup is uncommitted even before attempts grows. */
    __asm__ volatile("":::"memory");selected_cpuid_nx.phase=SELECTED_CPUID_NX_ATTEMPTED;
    __asm__ volatile("":::"memory");
    selected_cpuid_nx.pc=selected_decoded.pc;selected_cpuid_nx.next_pc=selected_decoded.next_pc;
    selected_cpuid_nx.leaf=(uint32_t)g[REG_RAX];selected_cpuid_nx.subleaf=(uint32_t)g[REG_RCX];
    for(size_t i=0;i<4;i++){selected_cpuid_nx.raw[i]=0;selected_cpuid_nx.result[i]=0;}
    ++selected_cpuid_nx.attempts;
    *a=selected_cpuid_nx.leaf;*c=selected_cpuid_nx.subleaf;
    __asm__ volatile("":::"memory");selected_cpuid_nx.phase=SELECTED_CPUID_NX_ATTEMPTED;
    __asm__ volatile("":::"memory");
    __asm__ volatile("cpuid":"+a"(*a),"=b"(*b),"+c"(*c),"=d"(*d)::"memory");
    selected_cpuid_nx.raw[0]=*a;selected_cpuid_nx.raw[1]=*b;
    selected_cpuid_nx.raw[2]=*c;selected_cpuid_nx.raw[3]=*d;
    ++selected_cpuid_nx.samples;
    __asm__ volatile("":::"memory");selected_cpuid_nx.phase=SELECTED_CPUID_NX_SAMPLED;
    __asm__ volatile("":::"memory");
}

/* Called only after the existing common builtin frame writes. Report the actual
   committed registers; do not manufacture enable-returned/rearm-returned phases. */
static void selected_cpuid_nx_committed(const greg_t *g) {
    checked(selected_cpuid_nx.phase==SELECTED_CPUID_NX_SAMPLED &&
        selected_cpuid_nx.attempts==selected_cpuid_nx.samples &&
        selected_cpuid_nx.samples==selected_cpuid_nx.commits+1 &&
        (uint64_t)g[REG_RIP]==selected_cpuid_nx.next_pc &&
        (uint64_t)g[REG_EFL]==selected_logical_flags &&
        (uint64_t)g[REG_RAX]==(uint32_t)g[REG_RAX] &&
        (uint64_t)g[REG_RBX]==(uint32_t)g[REG_RBX] &&
        (uint64_t)g[REG_RCX]==(uint32_t)g[REG_RCX] &&
        (uint64_t)g[REG_RDX]==(uint32_t)g[REG_RDX],1612,0);
    selected_cpuid_nx.result[0]=(uint32_t)g[REG_RAX];selected_cpuid_nx.result[1]=(uint32_t)g[REG_RBX];
    selected_cpuid_nx.result[2]=(uint32_t)g[REG_RCX];selected_cpuid_nx.result[3]=(uint32_t)g[REG_RDX];
    ++selected_cpuid_nx.commits;
    __asm__ volatile("":::"memory");selected_cpuid_nx.phase=SELECTED_CPUID_NX_COMMITTED;
    __asm__ volatile("":::"memory");
}

static void selected_cpuid_nx_report(unsigned status,unsigned code) {
    struct writer w={.used=0};
    text(&w,"LI2_CPUID_NX {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"hardware_entered\":",selected_cpuid_nx.hardware_entered);
    field(&w,",\"hardware_returned\":",selected_cpuid_nx.hardware_returned);
    field(&w,",\"phase\":",selected_cpuid_nx.phase);
    field(&w,",\"attempts\":",selected_cpuid_nx.attempts);
    field(&w,",\"samples\":",selected_cpuid_nx.samples);
    field(&w,",\"commits\":",selected_cpuid_nx.commits);
    field(&w,",\"pc\":",selected_cpuid_nx.pc);field(&w,",\"next_pc\":",selected_cpuid_nx.next_pc);
    field(&w,",\"leaf\":",selected_cpuid_nx.leaf);field(&w,",\"subleaf\":",selected_cpuid_nx.subleaf);
    text(&w,",\"raw\":[");
    for(size_t i=0;i<4;i++){if(i)text(&w,",");number(&w,selected_cpuid_nx.raw[i]);}
    text(&w,"],\"result\":[");
    for(size_t i=0;i<4;i++){if(i)text(&w,",");number(&w,selected_cpuid_nx.result[i]);}
    text(&w,"]}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
