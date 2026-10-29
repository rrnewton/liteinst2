/* Test-only observation around the real entry.S -> li2_boot -> restore path.
   The only fault injection changes an entry clock ID or sends a real signal.
   No source, signal frame, saved state or production predicate is changed. */
#ifndef ESO_MODE
#error fixed ESO_MODE required
#endif
#if ESO_MODE < 0 || ESO_MODE > 3
#error unknown entry-seam mode
#endif
#define ESO_FP 65536U
#define ESO_UC 2048U
#define ESO_STACK (2U<<20)
struct eso_saved {
    uint64_t complete,gpr[17],xmask,xmode,target;
    unsigned char fp[ESO_FP];
};
struct eso_frame {
    uint64_t complete,signal,info_address,frame_address,fp_address,fp_bytes,uc_bytes;
    siginfo_t info;
    unsigned char uc[ESO_UC],fp[ESO_FP];
};
struct eso_record {
    uint64_t magic,version,bytes,mode,initialized,terminal,status,code,detail;
    uint64_t kernel_sp,stack_first,stack_end,stack_bytes,at_base_offset,old_at_base;
    uint64_t fs,gs,selectors[6],initial_mask,mask_after_boot;
    uint64_t format[16]; uint32_t cpuid[67][6];
    uint64_t seed_gpr[17],seed_mask,seed_mode;
    unsigned char seed_fp[ESO_FP];
    struct eso_saved saved[2];
    struct eso_frame nx,trace,closed,returned,nested;
    uint64_t altstack_address,altstack_bytes,fs_endpoint,gs_endpoint,endpoint_selectors[6];
    uint64_t fs_returned,gs_returned,returned_selectors[6];
    uint64_t source_pc,source_bias,source_file_offset,release_seen,release_count;
    uint64_t bridge_start;struct li2_step_session session;
    struct li2_step_owner owner;
    struct li2_fetch_ref borrow;
    struct li2_fetch_progress released;
    struct li2_lifecycle_page_view page;
    __typeof__(selected_entry_time) timing;
    uint64_t nested_issued,nested_returned;long nested_result;
    unsigned char pages[5][4096];
    unsigned char stacks[6][ESO_STACK];
};
_Static_assert(sizeof(ucontext_t)<=ESO_UC && sizeof(struct eso_record)<(16U<<20),
    "complete real entry record under unchanged stream bound");
static struct eso_record eso_record;
/* Assembly-owned observations; initialized BSS, no pre-relocation pointers. */
uint64_t eso_kernel_sp,eso_stack_first,eso_stack_bytes,eso_seed_gpr[17],eso_seed_mask,eso_seed_mode;
unsigned char eso_seed_fp[ESO_FP] __attribute__((aligned(64)));
unsigned char eso_seed_stack[ESO_STACK];
extern void _start(void);
extern uint64_t li2_saved[17],li2_xmask,li2_xmode,li2_target;
extern unsigned char li2_xstate[ESO_FP];
static const siginfo_t *eso_trace_si;
static ucontext_t *eso_trace_uc;
static unsigned char eso_maps[65536];
static void eso_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void eso_boot_need(int ok) {
    if(!ok) {(void)raw(SYS_exit_group,124,0,0,0,0,0);__builtin_trap();}
}
static void eso_need(int ok,unsigned detail) { checked(ok,1787,detail); }
static uint64_t eso_hex(size_t n,size_t *at) {
    uint64_t v=0;size_t first=*at;
    while(*at<n) {
        unsigned c=eso_maps[*at],d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;
        if(d==16)break;
        eso_boot_need(v<=(UINT64_MAX-d)/16);v=v*16+d;++*at;
    }
    eso_boot_need(*at>first);return v;
}
static void eso_selectors(uint64_t out[6]) {
    unsigned short x;
#define ESO_SEG(name,i) __asm__ volatile("mov %%" #name ",%0":"=r"(x));out[i]=x
    ESO_SEG(cs,0);ESO_SEG(ss,1);ESO_SEG(ds,2);ESO_SEG(es,3);ESO_SEG(fs,4);ESO_SEG(gs,5);
#undef ESO_SEG
}
static void eso_cpuid(unsigned slot,unsigned leaf,unsigned sub) {
    uint32_t a,b,c,d;
    __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"0"(leaf),"2"(sub):"memory");
    uint32_t *p=eso_record.cpuid[slot];p[0]=leaf;p[1]=sub;p[2]=a;p[3]=b;p[4]=c;p[5]=d;
}
/* Runs on the fixture's private setup stack, before seeding and before _start.
   CPUID is still enabled. Subsequent observation uses general registers only. */
void eso_setup(void) {
    struct eso_record *r=&eso_record;
    eso_boot_need(!r->initialized && eso_kernel_sp && !(eso_kernel_sp&15));
    r->magic=UINT64_C(0x314d41455349324c);r->version=1;r->bytes=sizeof *r;r->mode=ESO_MODE;
    r->kernel_sp=eso_kernel_sp;eso_selectors(r->selectors);
    eso_boot_need(!raw(SYS_arch_prctl,ARCH_GET_FS,(long)&r->fs,0,0,0,0) &&
        !raw(SYS_arch_prctl,ARCH_GET_GS,(long)&r->gs,0,0,0,0) &&
        !raw(SYS_rt_sigprocmask,0,0,(long)&r->initial_mask,8,0,0));
    uint64_t *h=r->format;unsigned cpu=0,node=0;
    h[0]=1;h[1]=(uint64_t)raw(SYS_getcpu,(long)&cpu,(long)&node,0,0,0,0);h[2]=cpu;h[3]=node;
    eso_cpuid(0,0,0);eso_cpuid(1,1,0);eso_cpuid(2,7,0);
    eso_boot_need(r->cpuid[0][2]>=13 && (r->cpuid[1][4]&UINT32_C(0x0c000000))==UINT32_C(0x0c000000));
    for(unsigned i=0;i<64;i++)eso_cpuid(3+i,13,i);
    uint32_t lo,hi;__asm__ volatile("xgetbv":"=a"(lo),"=d"(hi):"c"(0):"memory");h[4]=((uint64_t)hi<<32)|lo;
    h[5]=(uint64_t)raw(SYS_arch_prctl,0x1021,(long)&h[6],0,0,0,0);
    h[7]=(uint64_t)raw(SYS_arch_prctl,0x1022,(long)&h[8],0,0,0,0);
    cpu=node=0;h[9]=(uint64_t)raw(SYS_getcpu,(long)&cpu,(long)&node,0,0,0,0);h[10]=cpu;h[11]=node;
    eso_boot_need(!h[1]&&!h[5]&&!h[7]&&!h[9]&&h[2]==h[10]&&h[3]==h[11] &&
        (h[4]&0xe7)==0xe7 && r->cpuid[3][3]<ESO_FP && r->cpuid[3][3]>=576);
    eso_seed_mask=h[4];eso_seed_mode=1;h[12]=1;
    long fd=raw(SYS_openat,AT_FDCWD,(long)"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);
    eso_boot_need(fd>=0);size_t n=0;
    for(;;) {
        eso_boot_need(n<sizeof eso_maps);
        long got=raw(SYS_read,fd,(long)(eso_maps+n),sizeof eso_maps-n,0,0,0);
        eso_boot_need(got>=0);if(!got)break;n+=(size_t)got;
    }
    eso_boot_need(!raw(SYS_close,fd,0,0,0,0,0));unsigned found=0;
    for(size_t at=0;at<n;) {
        uint64_t first=eso_hex(n,&at);eso_boot_need(at<n&&eso_maps[at++]=='-');
        uint64_t end=eso_hex(n,&at);eso_boot_need(end>first&&at<n&&eso_maps[at++]==' ');
        if(first<=eso_kernel_sp&&eso_kernel_sp<end) {
            eso_boot_need(++found==1&&n-at>=4&&eso_maps[at]=='r'&&eso_maps[at+1]=='w'&&
                eso_maps[at+2]=='-'&&eso_maps[at+3]=='p'&&end-first<=ESO_STACK);
            r->stack_first=first;r->stack_end=end;r->stack_bytes=end-first;
        }
        while(at<n&&eso_maps[at]!='\n')++at;
        eso_boot_need(at<n);++at;
    }
    eso_boot_need(found==1);eso_stack_first=r->stack_first;eso_stack_bytes=r->stack_bytes;
    const uint64_t *sp=(const void *)eso_kernel_sp;
    eso_boot_need(*sp<=4096 && (uint64_t)(sp+*sp+2)<=r->stack_end && !sp[*sp+1]);
    const uint64_t *aux=sp+*sp+2;unsigned env=0;
    while((uint64_t)(aux+1)<=r->stack_end&&*aux) {eso_boot_need(++env<8192);++aux;}
    eso_boot_need((uint64_t)(aux+1)<=r->stack_end);++aux;unsigned base=0,i;
    for(i=0;i<128;i++,aux+=2) {
        eso_boot_need((uint64_t)(aux+2)<=r->stack_end);if(!aux[0])break;
        if(aux[0]==AT_BASE) {eso_boot_need(!base++);r->at_base_offset=(uintptr_t)(aux+1)-r->stack_first;r->old_at_base=aux[1];}
    }
    eso_boot_need(i<128&&base==1);r->initialized=1;
}
static void eso_stack(unsigned i) {
    eso_need(i<6&&eso_record.stack_bytes<=ESO_STACK,1);
    eso_copy(eso_record.stacks[i],(const void *)eso_record.stack_first,eso_record.stack_bytes);
}
void eso_saved_before(void) {
    struct eso_record *r=&eso_record;struct eso_saved *s=&r->saved[0];
    eso_need(r->initialized&&!s->complete&&li2_target==original_interpreter.entry,2);
    r->bridge_start=(uintptr_t)_start;eso_copy(&r->session,&selected_session,sizeof r->session);
    r->altstack_address=(uintptr_t)fork_gate_stack.ss_sp;r->altstack_bytes=fork_gate_stack.ss_size;
    eso_copy(r->seed_gpr,eso_seed_gpr,sizeof r->seed_gpr);r->seed_mask=eso_seed_mask;r->seed_mode=eso_seed_mode;
    eso_copy(r->seed_fp,eso_seed_fp,sizeof r->seed_fp);eso_copy(r->stacks[0],eso_seed_stack,r->stack_bytes);
    eso_copy(s->gpr,li2_saved,sizeof s->gpr);s->xmask=li2_xmask;s->xmode=li2_xmode;s->target=li2_target;
    eso_copy(s->fp,li2_xstate,sizeof s->fp);eso_stack(1);
    r->source_pc=original_interpreter.entry;r->source_bias=original_interpreter.bias;
    eso_need(li2_lifecycle_query(r->source_pc,&r->page)==1,3);r->source_file_offset=r->page.offset;
    eso_copy(r->pages[0],(const void *)(r->source_pc&~UINT64_C(4095)),4096);
    eso_need(!raw(SYS_rt_sigprocmask,0,0,(long)&r->mask_after_boot,8,0,0),4);
    s->complete=1;
}
void eso_saved_after(void) {
    struct eso_record *r=&eso_record;struct eso_saved *s=&r->saved[1];
    eso_need(r->saved[0].complete&&!s->complete,5);
    eso_copy(s->gpr,li2_saved,sizeof s->gpr);s->xmask=li2_xmask;s->xmode=li2_xmode;s->target=li2_target;
    eso_copy(s->fp,li2_xstate,sizeof s->fp);eso_stack(2);
    eso_copy(r->pages[1],(const void *)(r->source_pc&~UINT64_C(4095)),4096);s->complete=1;
}
static void eso_frame(struct eso_frame *f,int signal,const siginfo_t *si,const ucontext_t *uc) {
    eso_need(!f->complete&&!selected_effect_frame_range(si,sizeof *si)&&
        !selected_effect_frame_range(uc,sizeof *uc),6);
    size_t n=selected_effect_fp_size(uc);f->signal=(unsigned)signal;
    f->info_address=(uintptr_t)si;f->frame_address=(uintptr_t)uc;f->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    f->fp_bytes=n;f->uc_bytes=sizeof *uc;eso_copy(&f->info,si,sizeof *si);
    eso_copy(f->uc,uc,sizeof *uc);eso_copy(f->fp,uc->uc_mcontext.fpregs,n);f->complete=1;
}
static void eso_ingress(int signal,const siginfo_t *si,ucontext_t *uc) {
    struct eso_record *r=&eso_record;
    if(!r->saved[0].complete || selected_entry_time.complete)return;
    if(r->nested_issued&&!r->nested.complete) {eso_frame(&r->nested,signal,si,uc);return;}
    if(selected_entry_time.started && !selected_entry_time.ingress) {
        eso_frame(&r->nx,signal,si,uc);eso_stack(3);
        eso_copy(r->pages[2],(const void *)(r->source_pc&~UINT64_C(4095)),4096);
    } else if(selected_entry_time.armed&&!r->trace.complete) {
        eso_frame(&r->trace,signal,si,uc);eso_trace_si=si;eso_trace_uc=uc;
    }
}
static void eso_released(void) {
    struct eso_record *r=&eso_record;
    if(!entry_pending() || selected_selftesting)return;
    eso_need(r->trace.complete&&!r->release_seen&&eso_trace_si&&eso_trace_uc,7);
    eso_frame(&r->closed,SIGTRAP,eso_trace_si,eso_trace_uc);eso_stack(4);
    eso_copy(&r->owner,&selected_step,sizeof r->owner);r->borrow=selected_borrow;
    eso_copy(&r->released,li2_lifecycle_fetch_progress(),sizeof r->released);
    r->release_count=li2_lifecycle_fetch_interlock();
    eso_copy(r->pages[3],(const void *)(r->source_pc&~UINT64_C(4095)),4096);
    eso_selectors(r->endpoint_selectors);
    eso_need(!raw(SYS_arch_prctl,ARCH_GET_FS,(long)&r->fs_endpoint,0,0,0,0) &&
        !raw(SYS_arch_prctl,ARCH_GET_GS,(long)&r->gs_endpoint,0,0,0,0),8);
    r->release_seen=1;
}
static void eso_returned(void) {
    struct eso_record *r=&eso_record;
    if(!r->release_seen || r->returned.complete)return;
    eso_need(selected_entry_time.complete&&eso_trace_si&&eso_trace_uc,12);
    eso_frame(&r->returned,SIGTRAP,eso_trace_si,eso_trace_uc);eso_stack(5);
    eso_selectors(r->returned_selectors);
    eso_need(!raw(SYS_arch_prctl,ARCH_GET_FS,(long)&r->fs_returned,0,0,0,0) &&
        !raw(SYS_arch_prctl,ARCH_GET_GS,(long)&r->gs_returned,0,0,0,0),13);
    eso_copy(r->pages[4],(const void *)(r->source_pc&~UINT64_C(4095)),4096);
}
static long eso_clock_id(unsigned index) {
    if((ESO_MODE==1&&index==0)||(ESO_MODE==2&&index==1))return -1;
    if(ESO_MODE==3&&index==1) {
        eso_need(!eso_record.nested_issued&&eso_record.release_seen,9);
        long pid=raw(SYS_getpid,0,0,0,0,0,0),tid=raw(SYS_gettid,0,0,0,0,0,0);
        eso_need(pid>0&&pid==tid,10);eso_record.nested_issued=1;
        eso_record.nested_result=raw(SYS_tgkill,pid,tid,SIGSEGV,0,0,0);eso_record.nested_returned=1;
        eso_need(0,11);
    }
    return 4;
}
static void eso_report(unsigned status,unsigned code,long detail) {
    struct eso_record *r=&eso_record;
    if(!r->initialized || r->terminal)return;
    r->terminal=1;r->status=status;r->code=code;r->detail=(uint64_t)detail;
    eso_copy(&r->timing,&selected_entry_time,sizeof r->timing);
    size_t at=0;
    while(at<sizeof *r) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)r+at),sizeof *r-at,0,0,0);
        if(n<=0 || (size_t)n>sizeof *r-at)return;
        at+=(size_t)n;
    }
}
