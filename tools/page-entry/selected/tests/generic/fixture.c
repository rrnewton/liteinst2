/* Finite same-address CPU reference/TF endpoint fixture; no loader/application
   claim. All mappings and every source borrow below are actual kernel owners. */
#define _GNU_SOURCE
#include "tf_owner.h"
#include "tf_continuation.h"
#include "fixture.h"
#include <asm/prctl.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

long raw(long n,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
    long result;
    __asm__ volatile("syscall":"=a"(result):"a"(n),"D"(a),"S"(b),"d"(c),
                     "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return result;
}
#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define PAGE LI2_STEP_PAGE
#define CODE_BYTES (3*PAGE)
#define SEALS (F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)
uintptr_t fixture_target;
uint64_t fixture_seed[16],fixture_flags,fixture_input_flags,fixture_xcr0;
struct live fixture_live_before,fixture_live_after;
unsigned char fixture_fp_before[FP_CAPACITY] __attribute__((aligned(64)));
unsigned char fixture_fp_after[FP_CAPACITY] __attribute__((aligned(64)));
static uintptr_t subject,data_page,data_fault;
static size_t xsave_bytes;
static struct li2_step_session session;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[256*1024];
static struct {uintptr_t first,end;} protected[128];
static size_t protected_count;
static uint64_t mask;
static unsigned lane,native_phase,handling,control;
extern void step_restorer(void);
size_t li2_tf_refusal_count(void);
int li2_tf_refusal_controls(size_t *,size_t *,uint32_t *,struct li2_tf_classification *);

struct state {
    struct li2_step_frame frame;
    uint64_t fs,gs;
    unsigned char stack[SUBJECT_BYTES],data[DATA_BYTES];
};
struct sample {
    uintptr_t mapping,pc,target,expected_post;
    size_t length,count;
    unsigned id,selftest,endpoint_int3,native_complete,native_fault,step_endpoint_seen;
    unsigned native_resume_suppressed,checked,negative_verified;
    uint64_t initial_flags,post_flags;
    unsigned char source[CODE_BYTES];
    struct li2_decoded decoded;
    struct state native_before,native_after,step_before,step_endpoint;
    struct li2_tf_owner owner;
    struct li2_fetch_ref ref;
    struct li2_fetch_page pages[2];
    struct li2_tf_continuation continuation;
    struct li2_fetch_progress native_fetch,step_fetch;
    struct live live[4];
    unsigned char actual_fp[4][FP_CAPACITY] __attribute__((aligned(64)));
};
static struct sample samples[PAIRS],negative_sample,*current;
struct result_header {
    uint64_t magic,version,header_bytes,sample_bytes,pairs,completed,control;
    uint64_t xcr0,xsave_bytes,refusals,failed_refusal,decoder_result,expected_failure_verified;
    uint64_t fixture_failure,owner_failure,owner_detail_abs,owner_detail_negative;
};
static struct result_header result;
static struct li2_tf_classification refused_last;

void *memcpy(void *d,const void *s,size_t n) {unsigned char *o=d;const unsigned char *p=s;for(size_t i=0;i<n;i++)o[i]=p[i];return d;}
void *memset(void *d,int c,size_t n) {unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=(unsigned char)c;return d;}
void *memmove(void *d,const void *s,size_t n) {unsigned char *o=d;const unsigned char *p=s;if((uintptr_t)o<(uintptr_t)p){for(size_t i=0;i<n;i++)o[i]=p[i];}else{for(size_t i=n;i;i--)o[i-1]=p[i-1];}return d;}
int memcmp(const void *a,const void *b,size_t n) {const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++){if(x[i]!=y[i])return x[i]<y[i]?-1:1;}return 0;}
int bcmp(const void *a,const void *b,size_t n) {return memcmp(a,b,n);}
int equal(const void *a,const void *b,size_t n) {return !memcmp(a,b,n);}
static size_t length(const char *s) {size_t n=0;while(s[n])++n;return n;}
static int same(const char *a,const char *b) {size_t i=0;while(a[i]&&b[i]&&a[i]==b[i])++i;return a[i]==b[i];}
static int write_all(int fd,const void *p,size_t n) {
    const unsigned char *s=p;size_t at=0;
    while(at<n){long done=RAW(SYS_write,fd,s+at,n-at,0,0,0);if(done<=0){return 0;}at+=(size_t)done;}return 1;
}
static void output(const char *s) {(void)write_all(1,s,length(s));}
static void number(uint64_t v) {char b[21];size_t at=sizeof(b);b[--at]='\n';do{b[--at]=(char)('0'+v%10);v/=10;}while(v);(void)write_all(1,b+at,sizeof(b)-at);}
static int dump(void) {
    result.header_bytes=sizeof(result);result.sample_bytes=sizeof(struct sample);
    return write_all(3,&result,sizeof(result)) && write_all(3,samples,sizeof(samples)) &&
           write_all(3,&negative_sample,sizeof(negative_sample)) && write_all(3,&refused_last,sizeof(refused_last));
}
static _Noreturn void die(unsigned code) {
    if(!result.fixture_failure)result.fixture_failure=code;
    (void)dump();output("LI2_TF_FIXTURE_FAILURE ");number(code);
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
static void need(int yes,unsigned code) {if(!yes)die(code);}
_Noreturn void li2_decoder_abort(uint32_t code) {die(1000+code);}
static _Noreturn void lifecycle_fail(unsigned code,long detail) {
    result.owner_failure=code;result.owner_detail_abs=detail<0?0ULL-(uint64_t)detail:(uint64_t)detail;
    result.owner_detail_negative=detail<0;die(2000+code);
}
static uint32_t u32(const unsigned char *p) {return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static long read_file(const char *path,char *out,size_t capacity) {
    long fd=RAW(SYS_openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0,0,0);if(fd<0){return fd;}
    size_t used=0;long error=0;
    while(used<capacity){long n=RAW(SYS_read,fd,out+used,capacity-used,0,0,0);if(n<0){error=n;break;}if(!n){break;}used+=(size_t)n;}
    long closed=RAW(SYS_close,fd,0,0,0,0,0);if(error){return error;}if(closed){return closed;}
    return used==capacity?-7:(long)used;
}
static uintptr_t hex(const char **p,const char *end,int *ok) {
    uintptr_t n=0;unsigned digits=0;
    while(*p<end){unsigned c=(unsigned char)**p,v;if(c>='0'&&c<='9')v=c-'0';else if(c>='a'&&c<='f')v=c-'a'+10;else break;
        if(n>(UINTPTR_MAX-v)/16){*ok=0;return 0;}n=n*16+v;++*p;++digits;}
    if(!digits)*ok=0;
    return n;
}
static int actual_protection(uintptr_t address,int collect) {
    long bytes=read_file("/proc/self/maps",maps,sizeof(maps));if(bytes<=0)return -1;
    const char *at=maps,*end=maps+bytes;int answer=-1;unsigned hits=0;
    while(at<end){const char *line=at;while(at<end&&*at!='\n')++at;const char *stop=at;if(at<end)++at;
        int ok=1;uintptr_t first=hex(&line,stop,&ok);if(line==stop||*line++!='-'){return -1;}
        uintptr_t last=hex(&line,stop,&ok);if(!ok||first>=last||line==stop||*line++!=' '||stop-line<5){return -1;}
        int prot=(line[0]=='r'?PROT_READ:0)|(line[1]=='w'?PROT_WRITE:0)|(line[2]=='x'?PROT_EXEC:0);
        if(collect){if(protected_count==128){return -1;}protected[protected_count].first=first;protected[protected_count++].end=last;}
        if(first<=address&&address<last){if(++hits!=1||line[3]!='p'){return -1;}answer=prot;}}
    return collect?0:answer;
}
static int protected_range(uintptr_t first,size_t n) {
    if(!n||first>UINTPTR_MAX-n)return 1;
    for(size_t i=0;i<protected_count;i++)if(first<protected[i].end&&protected[i].first<first+n)return 1;
    return 0;
}
static long dispatch(long n,long a,long b,long c,long d,long e,long f) {
    long args[6]={a,b,c,d,e,f},returned=0;
    need(!li2_lifecycle_fetch_interlock(),30);
    need(li2_lifecycle_dispatch(n,args,&returned)==1,31);return returned;
}
static unsigned char elf_bytes[PAGE];
static int sealed_elf(void) {
    Elf64_Ehdr *e=(void *)elf_bytes;Elf64_Phdr *p=(void *)(elf_bytes+sizeof(*e));
    memcpy(e->e_ident,ELFMAG,SELFMAG);e->e_ident[EI_CLASS]=ELFCLASS64;e->e_ident[EI_DATA]=ELFDATA2LSB;e->e_ident[EI_VERSION]=EV_CURRENT;
    e->e_type=ET_DYN;e->e_machine=EM_X86_64;e->e_version=EV_CURRENT;e->e_ehsize=sizeof(*e);
    e->e_phoff=sizeof(*e);e->e_phentsize=sizeof(*p);e->e_phnum=1;
    *p=(Elf64_Phdr){.p_type=PT_LOAD,.p_flags=PF_R,.p_filesz=PAGE,.p_memsz=PAGE,.p_align=PAGE};
    long fd=RAW(SYS_memfd_create,"li2-tf-context",MFD_ALLOW_SEALING|MFD_CLOEXEC,0,0,0,0);
    need(fd>=0&&write_all((int)fd,elf_bytes,sizeof(elf_bytes)),32);
    need(!RAW(SYS_fcntl,fd,F_ADD_SEALS,SEALS,0,0,0),33);return (int)fd;
}
static int authenticate(void *context,const struct li2_step_page *p,int prot) {
    struct sample *s=context;
    if(memcmp((const void *)s->mapping,s->source,sizeof(s->source)))return LI2_FETCH_SOURCE;
    for(size_t i=0;i<s->count;i++) {
        const struct li2_fetch_page *saved=&s->pages[i];
        if(p->address==saved->address && p->object==saved->allocation &&
           p->generation==saved->generation && p->offset==saved->offset &&
           p->closed_prot==PROT_READ && p->open_prot==(PROT_READ|PROT_EXEC))
            return li2_lifecycle_fetch_validate(&s->ref,i,prot);
    }
    return LI2_FETCH_PAGE;
}
static int continue_closed(void *context,uintptr_t pc) {
    struct sample *s=context;
    return li2_lifecycle_tf_continuation(&s->ref,pc,&s->continuation);
}
static void capture(struct state *out,ucontext_t *uc) {
    memcpy(out->frame.greg,uc->uc_mcontext.gregs,sizeof(out->frame.greg));memcpy(&out->frame.mask,&uc->uc_sigmask,8);
    out->frame.fp_address=(uintptr_t)uc->uc_mcontext.fpregs;need(out->frame.fp_address&&!(out->frame.fp_address&15),40);
    const unsigned char *p=(const void *)out->frame.fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)){n=u32(p+468);size_t x=u32(p+480);
        need(n>=580&&n<=FP_CAPACITY&&x>=576&&x<=n-4&&u32(p+n-4)==UINT32_C(0x46505845),41);}
    out->frame.fp_bytes=n;for(size_t i=0;i<n;i++){out->frame.fp[i]=p[i];out->frame.initialized=i+1;}
    memcpy(out->stack,(const void *)subject,SUBJECT_BYTES);memcpy(out->data,(const void *)data_page,DATA_BYTES);
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out->fs,0,0,0,0)&&!RAW(SYS_arch_prctl,ARCH_GET_GS,&out->gs,0,0,0,0),42);
}
static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static void compare_memory(const struct state *a,const struct state *b,unsigned code) {
    need(!memcmp(a->stack,b->stack,SUBJECT_BYTES)&&!memcmp(a->data,b->data,DATA_BYTES),code);
}
static void failure(void *context,const struct li2_step_owner *owner) {
    struct sample *s=context;
    result.owner_failure=owner->first_error;result.owner_detail_abs=owner->first_detail<0?0ULL-(uint64_t)owner->first_detail:(uint64_t)owner->first_detail;
    result.owner_detail_negative=owner->first_detail<0;
    if(control && s==&negative_sample) {
        unsigned expected=control==1?LI2_STEP_FOREIGN_EVENT:control==2?LI2_TF_CONTINUATION:LI2_TF_RSP_DOMAIN;
        need(owner->first_error==expected&&owner->phase==LI2_STEP_FAILED,150);
        for(size_t i=0;i<s->count;i++)need(owner->opened[i]&&owner->revoked[i]&&!owner->revoke_result[i]&&actual_protection(s->pages[i].address,0)==PROT_READ,151);
        need(!owner->revoke_sync&&owner->revoke_sync_started,152);
        if(control==1){need(s->native_fault&&!owner->trace_seen&&s->owner.unexpected_frame_observed,153);
            need(owner->after.greg[REG_RIP]==(greg_t)s->pc&&owner->after.greg[REG_ERR]==s->native_after.frame.greg[REG_ERR],154);
            need(owner->signal_number==SIGSEGV&&owner->signal_code==SEGV_ACCERR&&owner->signal_address==data_fault,155);}
        else {need(s->native_complete&&owner->trace_seen&&!s->owner.continuation_complete,156);
            if(control==2)need(s->owner.continuation_started&&s->owner.continuation_result==LI2_FETCH_PAGE&&
                s->owner.actual_post_pc==s->target&&s->continuation.attempted&&!s->continuation.complete,157);
            else need((uint64_t)owner->after.greg[REG_RSP]==(UINT64_C(1)<<47)&&
                !s->owner.continuation_started&&s->native_resume_suppressed,158);}
        for(unsigned i=0;i<16;i++)need(owner->after.greg[regs[i]]==s->native_after.frame.greg[regs[i]],159);
        uint64_t native_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
        uint64_t step_flags=(uint64_t)owner->after.greg[REG_EFL];
        if(control==1)need(native_flags==(step_flags&~LI2_STEP_TF),160);
        else need((native_flags&~LI2_STEP_RF)==(step_flags&~LI2_STEP_TF),160);
        need(owner->after.fp_bytes==s->native_after.frame.fp_bytes&&
             !memcmp(owner->after.fp,s->native_after.frame.fp,owner->after.fp_bytes),161);
        need(!memcmp((const void *)subject,s->native_after.stack,SUBJECT_BYTES)&&
             !memcmp((const void *)data_page,s->native_after.data,DATA_BYTES),162);
        s->step_fetch=*li2_lifecycle_fetch_progress();s->negative_verified=1;result.expected_failure_verified=1;
        need(dump(),163);output("LI2_TF_EXPECTED_FAILURE ");number(expected);
    } else {(void)dump();output("LI2_TF_UNEXPECTED_OWNER_FAILURE ");number(owner->first_error);}
}
static void permissions(struct sample *s,int prot) {
    for(size_t i=0;i<s->count;i++)need(!RAW(SYS_mprotect,s->pages[i].address,PAGE,prot,0,0,0),43);
    need(!RAW(SYS_membarrier,32,0,0,0,0,0),44);
}
static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc) {
    return sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
        (uintptr_t)si->si_addr==pc&&(uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==14&&g[REG_ERR]==21;
}
static void handler(int sig,siginfo_t *si,void *frame_) {
    need(current&&si&&frame_,45);struct sample *s=current;
    if(handling)li2_tf_abort(&s->owner,LI2_STEP_REENTRY,sig);
    handling=1;ucontext_t *uc=frame_;greg_t *g=uc->uc_mcontext.gregs;
    if(!lane) {
        if(!native_phase) {
            need(nx(sig,si,g,s->pc)&&(uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),46);
            capture(&s->native_before,uc);permissions(s,PROT_READ|PROT_EXEC);native_phase=1;
        } else {
            if(control==1&&s==&negative_sample){
                need(sig==SIGSEGV&&si->si_code==SEGV_ACCERR&&!si->si_errno&&
                     (uintptr_t)si->si_addr==data_fault&&(uintptr_t)g[REG_RIP]==s->pc&&
                     g[REG_TRAPNO]==14&&g[REG_ERR]==4,47);s->native_fault=1;
            } else {
                need(s->endpoint_int3?(sig==SIGTRAP&&si->si_code==SI_KERNEL&&!si->si_errno&&
                    g[REG_TRAPNO]==3&&!g[REG_ERR]&&(uintptr_t)g[REG_RIP]==s->expected_post+1):
                    nx(sig,si,g,s->expected_post),48);s->native_complete=1;
            }
            capture(&s->native_after,uc);permissions(s,PROT_READ);native_phase=2;
            if(control==3&&s==&negative_sample){
                /* Retain the CPU's nonrepresentable RSP, then suppress its
                   continuation. This diagnostic escape is never compared as
                   successful user state or substituted into the saved frame. */
                s->native_resume_suppressed=1;g[REG_RSP]=(greg_t)fixture_seed[4];
            }
            g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        }
    } else if(s->owner.step.phase==LI2_STEP_ARMED) {
        need(nx(sig,si,g,s->pc)&&s->owner.step.request.original_flags==fixture_flags,49);
        capture(&s->step_before,uc);
        struct li2_decoded observed;
        need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&observed)&&!memcmp(&observed,&s->decoded,sizeof(observed)),50);
        if(s->selftest)li2_step_begin(&s->owner.step,sig,si,uc);else li2_tf_begin(&s->owner,sig,si,uc);
    } else if(s->owner.step.phase==LI2_STEP_RUNNING) {
        if(s->selftest)li2_step_trace(&s->owner.step,sig,si,uc);
        else if(sig==SIGTRAP)li2_tf_trace(&s->owner,sig,si,uc);
        else li2_tf_unexpected(&s->owner,sig,si,uc);
    } else if(s->owner.step.phase==LI2_STEP_COMPLETE) {
        need(nx(sig,si,g,s->expected_post)&&(uint64_t)g[REG_EFL]==(s->post_flags|LI2_STEP_RF),51);
        capture(&s->step_endpoint,uc);s->step_endpoint_seen=1;
        for(size_t i=0;i<s->count;i++)need(!authenticate(s,&s->owner.step.request.pages[i],PROT_READ),52);
        need(actual_protection(s->expected_post,0)==PROT_READ,53);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else li2_tf_abort(&s->owner,LI2_STEP_FOREIGN_EVENT,sig);
    fixture_vector_clobber();handling=0;
}
static uint64_t word(const unsigned char *p) {uint64_t v;memcpy(&v,p,8);return v;}
static void compare(struct sample *s) {
    const struct li2_step_owner *o=&s->owner.step;
    need(s->native_complete&&s->step_endpoint_seen&&o->phase==LI2_STEP_COMPLETE&&
         !o->first_error&&o->trace_seen&&!o->open_sync&&!o->revoke_sync,60);
    for(size_t i=0;i<s->count;i++)need(o->open_started[i]&&o->opened[i]&&o->revoke_started[i]&&
        o->revoked[i]&&!o->open_result[i]&&!o->revoke_result[i],61);
    for(unsigned i=0;i<16;i++) {
        need(s->native_before.frame.greg[regs[i]]==s->step_before.frame.greg[regs[i]]&&
             s->step_before.frame.greg[regs[i]]==o->before.greg[regs[i]],62);
        need(s->native_after.frame.greg[regs[i]]==o->after.greg[regs[i]]&&
             o->after.greg[regs[i]]==s->step_endpoint.frame.greg[regs[i]],63);
    }
    need((uint64_t)s->native_before.frame.greg[REG_EFL]==(s->initial_flags|LI2_STEP_RF)&&
         (uint64_t)s->step_before.frame.greg[REG_EFL]==(s->initial_flags|LI2_STEP_RF),64);
    need((uint64_t)s->native_after.frame.greg[REG_EFL]==(s->post_flags|(s->endpoint_int3?0:LI2_STEP_RF))&&
         (uint64_t)o->after.greg[REG_EFL]==(s->post_flags|LI2_STEP_TF)&&
         (uint64_t)s->step_endpoint.frame.greg[REG_EFL]==(s->post_flags|LI2_STEP_RF),65);
    need((uintptr_t)s->native_after.frame.greg[REG_RIP]==s->expected_post+(s->endpoint_int3?1:0)&&
         (uintptr_t)o->after.greg[REG_RIP]==s->expected_post&&
         (uintptr_t)s->step_endpoint.frame.greg[REG_RIP]==s->expected_post,66);
    compare_memory(&s->native_before,&s->step_before,67);compare_memory(&s->native_after,&s->step_endpoint,68);
    const struct state *states[4]={&s->native_before,&s->native_after,&s->step_before,&s->step_endpoint};
    for(unsigned i=0;i<4;i++)need(states[i]->fs==states[0]->fs&&states[i]->gs==states[0]->gs,69);
    const struct li2_step_frame *frames[6]={&s->native_before.frame,&s->native_after.frame,
        &s->step_before.frame,&o->before,&o->after,&s->step_endpoint.frame};
    for(unsigned i=0;i<6;i++)need(frames[i]->initialized==frames[i]->fp_bytes&&
        frames[i]->fp_bytes==frames[0]->fp_bytes&&frames[i]->mask==mask&&
        frames[i]->greg[REG_CSGSFS]==frames[0]->greg[REG_CSGSFS],70);
    need(!memcmp(frames[0]->fp,frames[2]->fp,frames[0]->fp_bytes)&&
         !memcmp(frames[0]->fp,frames[3]->fp,frames[0]->fp_bytes)&&
         !memcmp(frames[1]->fp,frames[4]->fp,frames[1]->fp_bytes)&&
         !memcmp(frames[1]->fp,frames[5]->fp,frames[1]->fp_bytes),71);
    const struct li2_step_frame *from[4]={frames[0],frames[1],frames[2],frames[5]};
    for(unsigned i=0;i<4;i++) {
        const struct live *l=&s->live[i];
        need(l->started==1&&l->complete==1&&!l->reserved&&l->rflags==(i%2?s->post_flags:s->initial_flags),72);
        for(unsigned j=0;j<16;j++)need(l->gpr[j]==(uint64_t)from[i]->greg[regs[j]],73);
        for(unsigned j=0;j<6;j++)need(l->selectors[j]==s->live[0].selectors[j],74);
        need(l->selectors[0]==((uint64_t)from[i]->greg[REG_CSGSFS]&0xffff)&&
             l->selectors[1]==((uint64_t)from[i]->greg[REG_CSGSFS]>>48),75);
    }
    need(!memcmp(s->actual_fp[0],s->actual_fp[2],xsave_bytes)&&
         !memcmp(s->actual_fp[1],s->actual_fp[3],xsave_bytes),76);
    need(!memcmp((const void *)s->mapping,s->source,sizeof(s->source)),77);
    if(!s->selftest)need(s->owner.continuation_started&&s->owner.continuation_complete&&
        !s->owner.continuation_result&&s->continuation.complete&&s->continuation.page_observed&&
        s->continuation.pc==s->expected_post&&s->continuation.page.closed_prot==PROT_READ&&
        s->continuation.page.logical==(PROT_READ|PROT_EXEC)&&s->continuation.page.allocation&&
        s->continuation.page.generation,78);
    /* Literal finite-program checks supplement, never replace, native pairs. */
    switch(s->id) {
    case 1:need((uint64_t)o->after.greg[REG_RAX]==UINT64_C(0x8000000000000000)&&
                (s->post_flags&UINT64_C(0x8c1))==UINT64_C(0x880),80);break;
    case 2:need(!o->after.greg[REG_RAX]&&(s->post_flags&0x41)==0x41,81);break;
    case 3:need((uint64_t)o->after.greg[REG_RAX]==(fixture_seed[0]^1),82);break;
    case 4:need(!(s->initial_flags&0x400)&&(s->post_flags&0x400),83);break;
    case 5:need((uint64_t)o->after.greg[REG_RAX]==word(s->native_before.data),84);break;
    case 6:need(word(s->native_after.data+8)==fixture_seed[0],85);break;
    case 7:need(word(s->native_before.data+8)==UINT64_MAX&&!word(s->native_after.data+8)&&
                (s->post_flags&0x41)==0x41,86);break;
    case 8:need((uint64_t)o->after.greg[REG_RSP]==fixture_seed[4]-16,87);break;
    case 9:need((uint64_t)o->after.greg[REG_RSP]==fixture_seed[4]-8&&
                word(s->native_after.stack+SUBJECT_BYTES/2-8)==fixture_seed[0],88);break;
    case 10:need((uint64_t)o->after.greg[REG_RSP]==fixture_seed[4]+8&&
                 (uint64_t)o->after.greg[REG_RBX]==word(s->native_before.stack+SUBJECT_BYTES/2),89);break;
    case 14:case 15:
        need((uint64_t)o->after.greg[REG_RSP]==fixture_seed[4]-8&&
             word(s->native_after.stack+SUBJECT_BYTES/2-8)==s->pc+s->length&&s->count==1,90);
        need(actual_protection(s->pc+s->length,0)==PROT_READ&&
             actual_protection(s->target,0)==PROT_READ,91);break;
    case 16:case 17:need((uint64_t)o->after.greg[REG_RSP]==fixture_seed[4]+8+(s->id==17?16:0),92);break;
    case 18:need(s->count==2&&(uint64_t)o->after.greg[REG_R12]==UINT64_C(0x1122334455667788),93);break;
    case 19:
        for(size_t i=0;i<16;i++)need(s->actual_fp[1][160+i]==
            (unsigned char)(s->actual_fp[0][160+i]^s->actual_fp[0][160+7*16+i]),94);
        need(memcmp(s->actual_fp[0]+160,s->actual_fp[1]+160,16)!=0,95);break;
    case 20: {
        const unsigned char endbr64[]={0xf3,0x0f,0x1e,0xfa};
        need(s->length==sizeof(endbr64)&&!memcmp(s->decoded.bytes,endbr64,sizeof(endbr64))&&
             s->owner.classification.policy==1&&s->owner.classification.flow==LI2_TF_FALLTHROUGH&&
             s->owner.classification.family==LI2_TF_INTEGER&&s->expected_post==s->pc+4,134);
        /* Architectural no-op within each actual lane, in addition to the
           unchanged independent native/stepped comparison above. */
        for(unsigned i=0;i<16;i++)need(
            s->native_before.frame.greg[regs[i]]==s->native_after.frame.greg[regs[i]]&&
            s->step_before.frame.greg[regs[i]]==o->after.greg[regs[i]]&&
            s->step_before.frame.greg[regs[i]]==s->step_endpoint.frame.greg[regs[i]],135);
        need(s->initial_flags==s->post_flags,136);
        compare_memory(&s->native_before,&s->native_after,137);
        compare_memory(&s->step_before,&s->step_endpoint,138);
        need(!memcmp(frames[0]->fp,frames[1]->fp,frames[0]->fp_bytes)&&
             !memcmp(frames[2]->fp,frames[5]->fp,frames[2]->fp_bytes)&&
             !memcmp(frames[3]->fp,frames[4]->fp,frames[3]->fp_bytes),139);
        need(!memcmp(s->actual_fp[0],s->actual_fp[1],xsave_bytes)&&
             !memcmp(s->actual_fp[2],s->actual_fp[3],xsave_bytes),140);
        need(!memcmp(s->live[0].gpr,s->live[1].gpr,sizeof(s->live[0].gpr))&&
             !memcmp(s->live[2].gpr,s->live[3].gpr,sizeof(s->live[2].gpr))&&
             s->live[0].rflags==s->live[1].rflags&&s->live[2].rflags==s->live[3].rflags,141);
        break;
    }
    default:break;
    }
    s->checked=1;
}
static void inputs(struct sample *s) {
    for(size_t i=0;i<SUBJECT_BYTES;i++)((unsigned char *)subject)[i]=(unsigned char)(i*29+11);
    for(size_t i=0;i<DATA_BYTES;i++)((unsigned char *)data_page)[i]=(unsigned char)(i*17+3);
    for(unsigned i=0;i<16;i++)fixture_seed[i]=UINT64_C(0x123456789abcdef)+UINT64_C(0x101010101010101)*i;
    fixture_seed[4]=subject+SUBJECT_BYTES/2;fixture_seed[6]=data_page;fixture_seed[7]=data_page+8;
    fixture_input_flags=UINT64_C(0x247);
    if(s->id==1){fixture_seed[0]=UINT64_C(0x7fffffffffffffff);fixture_seed[3]=1;}
    if(s->id==2){fixture_seed[0]=UINT64_C(0xabcddcbaFFFFFFFF);fixture_seed[3]=0;}
    if(s->id==7){uint64_t v=UINT64_MAX;memcpy((void *)(data_page+8),&v,8);}
    if(s->id==13)fixture_seed[0]=s->target;
    if(s->id==15)memcpy((void *)data_page,&s->target,8);
    if(s->id==16||s->id==17)memcpy((void *)fixture_seed[4],&s->target,8);
    if(s==&negative_sample) {
        if(control==1)fixture_seed[6]=data_fault;
        else if(control==2)fixture_seed[0]=s->target;
        else if(control==3)fixture_seed[0]=UINT64_C(1)<<47;
    }
    memset(&fixture_live_before,0,sizeof(fixture_live_before));memset(&fixture_live_after,0,sizeof(fixture_live_after));
    memset(fixture_fp_before,0,sizeof(fixture_fp_before));memset(fixture_fp_after,0,sizeof(fixture_fp_after));
}
static void borrow(struct sample *s) {
    need(!li2_lifecycle_fetch_prepare(s->pc,s->length,&s->ref),100);
    struct li2_fetch_view view;need(!li2_lifecycle_fetch_view(&s->ref,&view)&&view.length==s->length&&
        view.pc==s->pc&&view.page_count==s->count&&view.identity_observed&&view.pid==view.tid&&
        view.pid==session.pid&&!memcmp(view.bytes,(const void *)s->pc,s->length),101);
    for(size_t i=0;i<s->count;i++)s->pages[i]=view.pages[i];
}
static void run_pair(struct sample *s) {
    current=s;fixture_target=s->pc;inputs(s);borrow(s);lane=0;native_phase=0;fixture_enter();
    s->initial_flags=fixture_flags;s->live[0]=fixture_live_before;s->live[1]=fixture_live_after;
    memcpy(s->actual_fp[0],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[1],fixture_fp_after,xsave_bytes);
    need(s->native_complete||(s==&negative_sample&&control==1&&s->native_fault),102);
    s->post_flags=(uint64_t)s->native_after.frame.greg[REG_EFL];
    if(!s->endpoint_int3)s->post_flags&=~LI2_STEP_RF;
    need(!(s->initial_flags&(LI2_STEP_RF|LI2_STEP_TF))&&!(s->post_flags&(LI2_STEP_RF|LI2_STEP_TF)),103);
    need(!li2_lifecycle_fetch_release(&s->ref),104);s->native_fetch=*li2_lifecycle_fetch_progress();
    inputs(s);borrow(s);
    struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=s->initial_flags};
    for(size_t i=0;i<s->count;i++)request.pages[i]=(struct li2_step_page){s->pages[i].address,
        s->pages[i].allocation,s->pages[i].generation,s->pages[i].offset,PROT_READ,PROT_READ|PROT_EXEC};
    struct li2_tf_hooks hooks={{s,authenticate,failure},continue_closed};
    int error=s->selftest?li2_step_arm(&s->owner.step,&session,&hooks.step,&request,1):
                         li2_tf_arm(&s->owner,&session,&hooks,&request);
    if(error)li2_tf_abort(&s->owner,(unsigned)error,0);
    lane=1;fixture_enter();
    need(!(s==&negative_sample),105);
    s->live[2]=fixture_live_before;s->live[3]=fixture_live_after;
    memcpy(s->actual_fp[2],fixture_fp_before,xsave_bytes);memcpy(s->actual_fp[3],fixture_fp_after,xsave_bytes);
    compare(s);need(!li2_lifecycle_fetch_release(&s->ref),106);s->step_fetch=*li2_lifecycle_fetch_progress();
    ++result.completed;
}
static void emit_i32(unsigned char *p,int64_t value) {need(value>=INT32_MIN&&value<=INT32_MAX,110);int32_t n=(int32_t)value;memcpy(p,&n,4);}
static void prepare_case(struct sample *s,unsigned id) {
    static const unsigned char encodings[PAIRS][10]={
        {0x90},{0x48,0x01,0xd8},{0x11,0xd8},{0x80,0xf0,0x01},{0xfd},
        {0x48,0x8b,0x06},{0x48,0x89,0x07},{0x48,0x83,0x07,0x01},
        {0x48,0x8d,0x64,0x24,0xf0},{0x50},{0x5b},
        {0x0f,0x84,0,0,0,0},{0x0f,0x85,0,0,0,0},{0xff,0xe0},
        {0xe8,0,0,0,0},{0xff,0x16},{0xc3},{0xc2,0x10,0},
        {0x49,0xbc,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11},{0x66,0x0f,0xef,0xc7},
        {0xf3,0x0f,0x1e,0xfa}};
    static const unsigned char sizes[PAIRS]={1,3,2,3,1,3,3,4,5,1,1,6,6,2,5,2,1,3,10,4,4};
    need(id<PAIRS,111);s->id=id;s->selftest=id==0;s->length=sizes[id];
    long reserved=dispatch(SYS_mmap,0,5*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(reserved>0,112);s->mapping=(uintptr_t)reserved+PAGE;
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),113);
    memset(s->source,0xcc,sizeof(s->source));size_t offset=id==18?PAGE-5:PAGE-s->length;
    s->pc=s->mapping+offset;s->target=s->mapping+2*PAGE+32;
    s->expected_post=s->pc+s->length;s->endpoint_int3=id==18;
    memcpy(s->source+offset,encodings[id],s->length);
    if(id==11||id==12)emit_i32(s->source+offset+2,(int64_t)(s->target-(s->pc+s->length)));
    if(id==14)emit_i32(s->source+offset+1,(int64_t)(s->target-(s->pc+s->length)));
    if(id==11||id==13||id==14||id==15||id==16||id==17)s->expected_post=s->target;
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0),114);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded)&&
         s->decoded.decode_status==LI2_VALID&&s->decoded.kind==LI2_NONE&&s->decoded.length==s->length,115);
    s->count=((s->pc+s->length-1)&~(PAGE-1))==(s->pc&~(PAGE-1))?1:2;
}
static void prepare_negative(void) {
    struct sample *s=&negative_sample;
    prepare_case(s,control==1?5:control==2?13:8);s->selftest=0;
    if(control==2){long target=RAW(SYS_mmap,0,PAGE,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        need(target>0,120);s->target=(uintptr_t)target;s->expected_post=s->target;}
    if(control==3){
        /* Change only this separate case before any fetch borrow exists. */
        need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_WRITE,0,0,0),121);
        memset(s->source,0xcc,sizeof(s->source));s->length=3;s->pc=s->mapping+PAGE-s->length;
        const unsigned char mov_rsp[]={0x48,0x89,0xc4};memcpy(s->source+PAGE-3,mov_rsp,sizeof(mov_rsp));
        memcpy((void *)s->mapping,s->source,sizeof(s->source));s->expected_post=s->pc+s->length;s->count=1;
        need(!dispatch(SYS_mprotect,s->mapping,CODE_BYTES,PROT_READ|PROT_EXEC,0,0,0)&&
             !li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&s->decoded),122);
    }
}
static void setup(unsigned long *stack) {
    need(stack[0]<128,10);const char *const *argv=(const void *)(stack+1),*const *env=argv+stack[0]+1;
    size_t count=0;while(env[count])need(++count<1024,11);
    const unsigned long *aux=(const void *)(env+count+1);unsigned long page=0,minimum=0;
    for(size_t i=0;i<128&&aux[2*i];i++){if(aux[2*i]==6)page=aux[2*i+1];if(aux[2*i]==51)minimum=aux[2*i+1];}
    need(page==PAGE&&minimum&&minimum<512*1024-16384,12);
    long n=read_file("/proc/self/status",maps,sizeof(maps));need(n>0,13);
    const char key[]="TracerPid:\t";unsigned found=0;
    for(long i=0;i<n-(long)sizeof(key);i++)if((!i||maps[i-1]=='\n')&&!memcmp(maps+i,key,sizeof(key)-1)){
        need(maps[i+sizeof(key)-1]=='0'&&maps[i+sizeof(key)]=='\n',14);++found;}
    need(found==1,15);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));need((c&0x0c000000)==0x0c000000,16);
    a=d=0;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));fixture_xcr0=(uint64_t)d<<32|a;need((fixture_xcr0&3)==3,17);
    a=13;c=0;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d));xsave_bytes=b;need(xsave_bytes>=576&&xsave_bytes<=FP_CAPACITY,18);
    unsigned long cet=0;long ce=RAW(SYS_arch_prctl,0x5005,&cet,0,0,0,0);need((!ce&&!cet)||ce==-22||ce==-38,19);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action,old;
    for(int sig=1;sig<=64;sig++)if(sig!=SIGKILL&&sig!=SIGSTOP)need(!RAW(SYS_rt_sigaction,sig,0,&old,8,0,0)&&!old.handler,20);
    uint64_t before=0;need(!RAW(SYS_rt_sigprocmask,0,0,&before,8,0,0)&&!before,21);
    mask=UINT64_MAX&~((UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSEGV-1))|
        (UINT64_C(1)<<(SIGSYS-1))|(UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
    need(!RAW(SYS_rt_sigprocmask,2,&mask,0,8,0,0),22);
    long area=RAW(SYS_mmap,0,512*1024+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(area>0,23);
    need(!RAW(SYS_mprotect,area+PAGE,512*1024,PROT_READ|PROT_WRITE,0,0,0),24);
    stack_t alt={.ss_sp=(void *)(area+PAGE),.ss_size=512*1024};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),25);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0)&&!RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0)&&
         !RAW(SYS_rt_sigaction,SIGSYS,&action,0,8,0,0),26);
    need(!li2_step_session_init(&session,mask),27);
    long stack_area=RAW(SYS_mmap,0,SUBJECT_BYTES+2*PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(stack_area>0,28);
    subject=(uintptr_t)stack_area+PAGE;need(!RAW(SYS_mprotect,subject,SUBJECT_BYTES,PROT_READ|PROT_WRITE,0,0,0),29);
    long data=RAW(SYS_mmap,0,DATA_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(data>0,34);data_page=(uintptr_t)data;
    long fault=RAW(SYS_mmap,0,PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(fault>0,35);data_fault=(uintptr_t)fault;
    need(actual_protection(0,1)==0,36);
    int fd=sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};
    li2_lifecycle_initialize(&fd,1,&hooks);need(li2_lifecycle_enabled(),37);
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&stats)&&stats.phase==2,38);
    if(stack[0]==2){if(same(argv[1],"load-fault"))control=1;else if(same(argv[1],"unowned-target"))control=2;
        else if(same(argv[1],"rsp-domain"))control=3;else die(39);}else need(stack[0]==1,39);
    result.control=control;result.xcr0=fixture_xcr0;result.xsave_bytes=xsave_bytes;
}
int fixture_main(unsigned long *stack) {
    _Static_assert(sizeof(result)+sizeof(samples)+sizeof(negative_sample)+sizeof(refused_last)<16*1024*1024,"bounded complete private record");
    result.magic=UINT64_C(0x314649585446324c);result.version=1;result.pairs=PAIRS;
    setup(stack);size_t complete=0,failed=0;uint32_t decoder_result=0;
    int rc=li2_tf_refusal_controls(&complete,&failed,&decoder_result,&refused_last);
    result.refusals=complete;result.failed_refusal=failed;result.decoder_result=decoder_result;
    need(!rc&&complete==li2_tf_refusal_count()&&complete==47,130);
    prepare_case(&samples[0],0);run_pair(&samples[0]);need(session.self_test_complete,131);
    if(control){prepare_negative();run_pair(&negative_sample);die(132);}
    for(unsigned i=1;i<PAIRS;i++){prepare_case(&samples[i],i);run_pair(&samples[i]);}
    need(result.completed==PAIRS&&dump(),133);
    output("LI2_GENERIC_TF_PASS pairs=21 generic=20 selftest=1 refusal_bytes=47 full_state=21 full_memory=21 live_endpoints=21\n");
    return 0;
}
