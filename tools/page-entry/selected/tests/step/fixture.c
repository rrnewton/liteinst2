/* Freestanding supplied-program fixture; no libc, interpreter, rseq, thread
   library or target TLS. This is not the first-entry loader integration. */
#define _GNU_SOURCE
#include "step_owner.h"
#include "fixture.h"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <asm/prctl.h>

#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CASES 20
#define REGISTER_CASES 15
#define REFUSALS 13
uintptr_t fixture_target;
uint64_t fixture_flags,fixture_xcr0;
struct li2_live_capture fixture_live_before,fixture_live_after;
static struct li2_step_session session;
static unsigned char decoder_arena[2*1024*1024] __attribute__((aligned(64)));
static char maps[65536];
struct state {
    struct li2_step_frame frame;
    unsigned char redzone[128];
    unsigned long fs,gs;
};
struct sample {
    uintptr_t mapping,pc;
    size_t length,count;
    uint64_t generation;
    unsigned char source[3*LI2_STEP_PAGE];
    struct li2_decoded decoded;
    struct state native_before,native_after,step_endpoint;
    struct li2_step_owner owner;
    unsigned native_complete,step_endpoint_seen;
    struct li2_live_capture native_live_before,native_live_after,step_live_before,step_live_after;
    unsigned register_move,expected_source,expected_destination,expected_width;
};
static struct sample samples[CASES],*current;
/* Literal expectations are independent of both the decoder and owner parser.
   source=4 denotes the actual captured SP/ESP/RSP, never a synthetic stack. */
static const struct register_case {
    unsigned char bytes[4];
    unsigned length,source,destination,width,cross;
} register_cases[REGISTER_CASES]={
    {{0x66,0x89,0xc8},3,1,0,16,0},
    {{0x66,0x45,0x89,0xf7},4,14,15,16,0},
    {{0x66,0x44,0x8b,0xd4},4,4,10,16,1},
    {{0x66,0x8b,0xdb},3,3,3,16,0},
    {{0x66,0x41,0x89,0xd8},4,3,8,16,0},
    {{0x89,0xd1},2,2,1,32,0},
    {{0x45,0x8b,0xf9},3,9,15,32,0},
    {{0x41,0x89,0xe2},3,4,10,32,0},
    {{0x8b,0xc0},2,0,0,32,0},
    {{0x44,0x89,0xe6},3,12,6,32,0},
    {{0x48,0x89,0xe7},3,4,7,64,1},
    {{0x4d,0x8b,0xe5},3,13,12,64,0},
    {{0x4c,0x8b,0xfc},3,4,15,64,0},
    {{0x48,0x89,0xdb},3,3,3,64,0},
    {{0x49,0x89,0xd8},3,3,8,64,0},
};
static struct sample refused_samples[REFUSALS];
static struct li2_step_owner refused_claims[REFUSALS];
static unsigned refusal_complete[REFUSALS];
_Static_assert(sizeof(samples)+2*sizeof(struct li2_live_capture)+sizeof(refused_samples)+
    sizeof(refused_claims)+sizeof(refusal_complete)<16*1024*1024,"private dump retains original 16 MiB file bound");
static unsigned lane,native_phase,handling,control;
static uint64_t mask;
extern void step_restorer(void);

/* Also the no_std decoder's explicit freestanding memory boundary. */
void *memcpy(void *d,const void *s,size_t n) {
    unsigned char *o=d;const unsigned char *p=s;for(size_t i=0;i<n;i++)o[i]=p[i];return d;
}
void *memmove(void *d,const void *s,size_t n) {
    unsigned char *o=d;const unsigned char *p=s;
    if((uintptr_t)o<(uintptr_t)p)for(size_t i=0;i<n;i++)o[i]=p[i];
    else for(size_t i=n;i;i--)o[i-1]=p[i-1];
    return d;
}
void *memset(void *d,int c,size_t n) {unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=(unsigned char)c;return d;}
int memcmp(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;for(size_t i=0;i<n;i++)if(x[i]!=y[i])return x[i]<y[i]?-1:1;return 0;
}
int bcmp(const void *a,const void *b,size_t n) {return memcmp(a,b,n);}
static size_t length(const char *p) {size_t n=0;while(p[n])++n;return n;}
static int same_string(const char *a,const char *b) {
    size_t i=0;while(a[i] && b[i] && a[i]==b[i])++i;return a[i]==b[i];
}
static void output(const char *p) {(void)RAW(SYS_write,1,p,length(p),0,0,0);}
static void number(unsigned long n) {
    char b[21];size_t at=sizeof(b);b[--at]='\n';do{b[--at]=(char)('0'+n%10);n/=10;}while(n);
    (void)RAW(SYS_write,1,b+at,sizeof(b)-at,0,0,0);
}
static _Noreturn void die(unsigned n) {
    output("LI2_STEP_FIXTURE_FAILURE ");number(n);
    (void)RAW(SYS_write,3,samples,sizeof(samples),0,0,0);
    (void)RAW(SYS_write,3,&fixture_live_before,sizeof(fixture_live_before),0,0,0);
    (void)RAW(SYS_write,3,&fixture_live_after,sizeof(fixture_live_after),0,0,0);
    (void)RAW(SYS_write,3,refused_samples,sizeof(refused_samples),0,0,0);
    (void)RAW(SYS_write,3,refused_claims,sizeof(refused_claims),0,0,0);
    (void)RAW(SYS_write,3,refusal_complete,sizeof(refusal_complete),0,0,0);
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
_Noreturn void li2_decoder_abort(uint32_t n) {die(1000+n);}
static void need(int yes,unsigned n) {if(!yes)die(n);}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static long read_file(const char *path,char *bytes,size_t capacity) {
    long fd=RAW(SYS_openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0,0,0);if(fd<0)return fd;
    size_t used=0;long result=0;
    while(used<capacity) {
        long n=RAW(SYS_read,fd,bytes+used,capacity-used,0,0,0);
        if(n<0){result=n;break;}if(!n)break;used+=(size_t)n;
    }
    long closed=RAW(SYS_close,fd,0,0,0,0,0);
    if(result)return result;
    if(closed)return closed;
    return used==capacity?-7:(long)used;
}
static uintptr_t hex(const char **p,const char *end,int *ok) {
    uintptr_t n=0;unsigned count=0;
    while(*p<end) {
        unsigned c=(unsigned char)**p,v;
        if(c>='0' && c<='9')v=c-'0';else if(c>='a' && c<='f')v=c-'a'+10;else break;
        if(n>(UINTPTR_MAX-v)/16){*ok=0;return 0;}n=n*16+v;++*p;++count;
    }
    if(!count)*ok=0;
    return n;
}
/* This callback authenticates actual permission rows for the private anonymous
   mmap retained in this sample. Fresh freestanding fixture code has created no
   alias and offers no concurrent mutation route; maps absence is not the
   general proof of source ownership. Every initialized source byte is compared. */
static int authenticate(void *context,const struct li2_step_page *page,int prot) {
    struct sample *s=context;
    if(page->object!=s->mapping || page->generation!=s->generation ||
       page->address<s->mapping || page->address>=s->mapping+3*LI2_STEP_PAGE ||
       page->offset!=page->address-s->mapping ||
       memcmp((void *)s->mapping,s->source,sizeof(s->source)))return 1;
    long n=read_file("/proc/self/maps",maps,sizeof(maps));if(n<=0)return 2;
    const char *at=maps,*end=maps+n;unsigned found=0;
    while(at<end) {
        const char *line=at;while(at<end && *at!='\n')++at;const char *stop=at;if(at<end)++at;
        int ok=1;uintptr_t first=hex(&line,stop,&ok);
        if(line==stop || *line++!='-')return 3;
        uintptr_t last=hex(&line,stop,&ok);
        if(!ok || line==stop || *line++!=' ' || stop-line<5)return 3;
        int observed=(line[0]=='r'?PROT_READ:0)|(line[1]=='w'?PROT_WRITE:0)|(line[2]=='x'?PROT_EXEC:0);
        if(first<=page->address && page->address+LI2_STEP_PAGE<=last) {
            if(++found!=1 || line[3]!='p' || observed!=prot)return 4;
        }
    }
    return found==1?0:5;
}
static void failure(void *context,const struct li2_step_owner *owner) {
    (void)context;
    output("LI2_STEP_OWNER_FAILURE ");number(owner->first_error);
    output("opened ");number(owner->opened[0]+owner->opened[1]);
    output("revoked ");number(owner->revoked[0]+owner->revoked[1]);
    (void)RAW(SYS_write,3,samples,sizeof(samples),0,0,0);
    (void)RAW(SYS_write,3,&fixture_live_before,sizeof(fixture_live_before),0,0,0);
    (void)RAW(SYS_write,3,&fixture_live_after,sizeof(fixture_live_after),0,0,0);
    (void)RAW(SYS_write,3,refused_samples,sizeof(refused_samples),0,0,0);
    (void)RAW(SYS_write,3,refused_claims,sizeof(refused_claims),0,0,0);
    (void)RAW(SYS_write,3,refusal_complete,sizeof(refusal_complete),0,0,0);
}
static void capture(struct state *out,ucontext_t *uc) {
    memcpy(out->frame.greg,uc->uc_mcontext.gregs,sizeof(out->frame.greg));
    memcpy(&out->frame.mask,&uc->uc_sigmask,8);
    out->frame.fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    need(out->frame.fp_address && !(out->frame.fp_address&15),40);
    const unsigned char *p=(const void *)out->frame.fp_address;size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);need(n>=580 && n<=LI2_STEP_FP_BYTES && u32(p+480)>=576 &&
            u32(p+480)<=n-4 && u32(p+n-4)==UINT32_C(0x46505845),41);
    }
    out->frame.fp_bytes=n;
    for(size_t i=0;i<n;i++){out->frame.fp[i]=p[i];out->frame.initialized=i+1;}
    uintptr_t sp=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    memcpy(out->redzone,(const void *)(sp-128),128);
    need(!RAW(SYS_arch_prctl,ARCH_GET_FS,&out->fs,0,0,0,0) &&
         !RAW(SYS_arch_prctl,ARCH_GET_GS,&out->gs,0,0,0,0),42);
}
static void permissions(struct sample *s,int prot) {
    uintptr_t first=s->pc&~(LI2_STEP_PAGE-1);
    for(size_t i=0;i<s->count;i++)need(!RAW(SYS_mprotect,first+i*LI2_STEP_PAGE,LI2_STEP_PAGE,prot,0,0,0),43);
    need(!RAW(SYS_membarrier,32,0,0,0,0,0),44);
}
static int nx(int sig,const siginfo_t *si,const greg_t *g,uintptr_t pc) {
    return sig==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
        (uintptr_t)si->si_addr==pc && (uintptr_t)g[REG_RIP]==pc && g[REG_TRAPNO]==14 && g[REG_ERR]==21;
}
static void handler(int sig,siginfo_t *si,void *frame) {
    need(current && si && frame,45);
    if(handling)li2_step_abort(&current->owner,LI2_STEP_REENTRY,sig);
    handling=1;ucontext_t *uc=frame;greg_t *g=uc->uc_mcontext.gregs;
    struct sample *s=current;
    if(!lane) {
        if(!native_phase) {
            need(nx(sig,si,g,s->pc) && (uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),46);
            capture(&s->native_before,uc);
            permissions(s,PROT_READ|PROT_EXEC);native_phase=1;
        } else {
            uintptr_t next=s->pc+s->length;
            int page_end=!(next&(LI2_STEP_PAGE-1));
            /* INT3 is only the native reference's diagnostic endpoint on a
               same-page continuation; the step owner never inserts or uses it. */
            need(page_end?nx(sig,si,g,next):(sig==SIGTRAP && si->si_code==SI_KERNEL &&
                g[REG_TRAPNO]==3 && !g[REG_ERR] && (uintptr_t)g[REG_RIP]==next+1),47);
            capture(&s->native_after,uc);permissions(s,PROT_READ);s->native_complete=1;
            g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
        }
    } else if(s->owner.phase==LI2_STEP_ARMED) {
        need(s->owner.request.original_flags==fixture_flags,48);
        if(sig!=SIGSEGV)li2_step_abort(&s->owner,LI2_STEP_FOREIGN_EVENT,sig);
        /* The real decoder may clobber live vector registers. The saved
           original kernel FP frame remains owned by rt_sigreturn. */
        struct li2_decoded observed;
        need(!li2_decoder_decode(s->pc,(const void *)s->pc,s->length,&observed) &&
             !memcmp(&observed,&s->decoded,sizeof(observed)),49);
        li2_step_begin(&s->owner,sig,si,uc);
        if(control==2)__asm__ volatile("int3"); /* actual nested trap after RX opening */
    } else if(s->owner.phase==LI2_STEP_RUNNING) {
        li2_step_trace(&s->owner,sig,si,uc);
    } else if(s->owner.phase==LI2_STEP_COMPLETE) {
        need(nx(sig,si,g,s->pc+s->length) && (uint64_t)g[REG_EFL]==(fixture_flags|LI2_STEP_RF),50);
        capture(&s->step_endpoint,uc);s->step_endpoint_seen=1;
        for(size_t i=0;i<s->count;i++)need(!authenticate(s,&s->owner.request.pages[i],PROT_READ),51);
        g[REG_RIP]=(greg_t)(uintptr_t)fixture_capture_return;
    } else li2_step_abort(&s->owner,LI2_STEP_FOREIGN_EVENT,sig);
    fixture_vector_clobber();handling=0;
}
static void compare(struct sample *s) {
    static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    need(s->native_complete && s->step_endpoint_seen && s->owner.phase==LI2_STEP_COMPLETE &&
         !s->owner.first_error && s->owner.trace_seen && !s->owner.open_sync && !s->owner.revoke_sync,60);
    for(size_t i=0;i<s->count;i++)need(s->owner.open_started[i] && s->owner.opened[i] &&
        s->owner.revoke_started[i] && s->owner.revoked[i] && !s->owner.open_result[i] && !s->owner.revoke_result[i],61);
    for(unsigned i=0;i<16;i++) {
        need(s->native_before.frame.greg[regs[i]]==s->owner.before.greg[regs[i]],62);
        need(s->native_after.frame.greg[regs[i]]==s->owner.after.greg[regs[i]] &&
             s->owner.after.greg[regs[i]]==s->step_endpoint.frame.greg[regs[i]],63);
    }
    if(s->register_move) {
        need(s->expected_source<16 && s->expected_destination<16 && s->expected_destination!=4 &&
             s->owner.effect==LI2_STEP_MOV_REGISTER && s->owner.source==s->expected_source &&
             s->owner.destination==s->expected_destination && s->owner.width==s->expected_width,97);
        for(unsigned i=0;i<16;i++) {
            uint64_t expected=s->native_before.frame.greg[regs[i]];
            if(i==s->expected_destination) {
                uint64_t source=s->native_before.frame.greg[regs[s->expected_source]];
                if(s->expected_width==16)expected=(expected&UINT64_C(0xffffffffffff0000))|(source&65535);
                else if(s->expected_width==32)expected=(uint32_t)source;
                else {need(s->expected_width==64,98);expected=source;}
            }
            need((uint64_t)s->native_after.frame.greg[regs[i]]==expected &&
                 (uint64_t)s->step_endpoint.frame.greg[regs[i]]==expected,99);
        }
    }
    uint64_t native_flags=s->native_after.frame.greg[REG_EFL];
    need(native_flags==(fixture_flags|(!(s->decoded.next_pc&(LI2_STEP_PAGE-1))?LI2_STEP_RF:0)) &&
         (uint64_t)s->owner.after.greg[REG_EFL]==(fixture_flags|LI2_STEP_TF),64);
    need(!memcmp(s->native_before.redzone,s->native_after.redzone,128) &&
         !memcmp(s->native_after.redzone,s->step_endpoint.redzone,128),65);
    need(s->native_before.fs==s->native_after.fs && s->native_after.fs==s->step_endpoint.fs &&
         s->native_before.gs==s->native_after.gs && s->native_after.gs==s->step_endpoint.gs,66);
    const struct li2_step_frame *frames[5]={&s->native_before.frame,&s->native_after.frame,
        &s->owner.before,&s->owner.after,&s->step_endpoint.frame};
    need(frames[0]->initialized==frames[0]->fp_bytes && frames[0]->mask==mask,68);
    for(unsigned i=1;i<5;i++) {
        need(frames[i]->fp_bytes==frames[0]->fp_bytes && frames[i]->initialized==frames[i]->fp_bytes &&
             !memcmp(frames[i]->fp,frames[0]->fp,frames[0]->fp_bytes),67);
        need(frames[i]->mask==mask && frames[i]->greg[REG_CSGSFS]==frames[0]->greg[REG_CSGSFS],68);
    }
    need(!memcmp((void *)s->mapping,s->source,sizeof(s->source)),69);
    const struct li2_live_capture *live[4]={&s->native_live_before,&s->native_live_after,
        &s->step_live_before,&s->step_live_after};
    const struct li2_step_frame *from[4]={&s->native_before.frame,&s->native_after.frame,
        &s->owner.before,&s->step_endpoint.frame};
    for(unsigned i=0;i<4;i++) {
        need(live[i]->started==1 && live[i]->complete==1 && !live[i]->reserved,90);
        need(live[i]->rflags==fixture_flags,91);
        for(unsigned j=0;j<16;j++)need(live[i]->gpr[j]==(uint64_t)from[i]->greg[regs[j]],92);
        for(unsigned j=0;j<6;j++)need(live[i]->selectors[j]==live[0]->selectors[j],93);
        /* Only CS/SS are actual selector fields in this kernel frame ABI.
           DS/ES/FS/GS evidence comes solely from the user-mode MOV stores. */
        need(live[i]->selectors[0]==((uint64_t)from[i]->greg[REG_CSGSFS]&0xffff) &&
             live[i]->selectors[1]==((uint64_t)from[i]->greg[REG_CSGSFS]>>48),94);
    }
}
static void prepare(struct sample *s,const unsigned char *bytes,size_t n,size_t offset,unsigned id) {
    long base=RAW(SYS_mmap,0,5*LI2_STEP_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    need(base>0,70);s->mapping=(uintptr_t)base+LI2_STEP_PAGE;s->pc=s->mapping+offset;
    s->length=n;s->count=((s->pc+n-1)&~(LI2_STEP_PAGE-1))==(s->pc&~(LI2_STEP_PAGE-1))?1:2;s->generation=id;
    need(offset+n<sizeof(s->source) && !RAW(SYS_mprotect,s->mapping,sizeof(s->source),PROT_READ|PROT_WRITE,0,0,0),71);
    memcpy(s->source+offset,bytes,n);s->source[offset+n]=0xcc;
    memcpy((void *)s->mapping,s->source,sizeof(s->source));
    need(!RAW(SYS_mprotect,s->mapping,sizeof(s->source),PROT_READ,0,0,0),72);
    need(!li2_decoder_decode(s->pc,(const void *)s->pc,n,&s->decoded),73);
}
static void run(struct sample *s,int self_test) {
    memset(&fixture_live_before,0,sizeof(fixture_live_before));
    memset(&fixture_live_after,0,sizeof(fixture_live_after));
    current=s;lane=0;native_phase=0;fixture_target=s->pc;fixture_enter();
    memcpy(&s->native_live_before,&fixture_live_before,sizeof(fixture_live_before));
    memcpy(&s->native_live_after,&fixture_live_after,sizeof(fixture_live_after));
    need(s->native_complete && !(fixture_flags&(LI2_STEP_TF|LI2_STEP_RF)),74);
    struct li2_step_request req={.decoded=s->decoded,.page_count=s->count,.original_flags=fixture_flags};
    for(size_t i=0;i<s->count;i++) {
        uintptr_t page=(s->pc&~(LI2_STEP_PAGE-1))+i*LI2_STEP_PAGE;
        req.pages[i]=(struct li2_step_page){page,s->mapping,s->generation,page-s->mapping,PROT_READ,PROT_READ|PROT_EXEC};
    }
    if(control==3)req.original_flags|=LI2_STEP_TF;
    if(control==4)req.original_flags|=LI2_STEP_RF;
    const struct li2_step_hooks hooks={s,authenticate,failure};
    int code=li2_step_arm(&s->owner,&session,&hooks,&req,self_test);
    if(code)li2_step_abort(&s->owner,(unsigned)code,0);
    memset(&fixture_live_before,0,sizeof(fixture_live_before));
    memset(&fixture_live_after,0,sizeof(fixture_live_after));
    lane=1;
    if(control==1)__asm__ volatile("int3"); /* actual foreign event, never TRAP_TRACE */
    fixture_enter();
    memcpy(&s->step_live_before,&fixture_live_before,sizeof(fixture_live_before));
    memcpy(&s->step_live_after,&fixture_live_after,sizeof(fixture_live_after));
    compare(s);
}
/* No refused instruction executes. Each real immutable mapping stays R, with
   zero opened/revoked prefixes. A second new owner receives a deliberately
   false CANDIDATE classification to check that decoder facts cannot bypass
   the owner's independent exact-byte parser. The decoder row stays retained. */
static void refusals(void) {
    static const struct {
        unsigned char bytes[6];unsigned length,disposition;
    } cases[REFUSALS]={
        {{0x66,0x89,0xc4},3,LI2_STEP_RSP_WRITE},
        {{0x8b,0xe0},2,LI2_STEP_RSP_WRITE},
        {{0x48,0x89,0xc4},3,LI2_STEP_RSP_WRITE},
        {{0x48,0x89,0x07},3,LI2_STEP_UNSUPPORTED},
        {{0x48,0x8b,0x07},3,LI2_STEP_UNSUPPORTED},
        {{0x4a,0x89,0xe7},3,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x40,0x89,0xcf},3,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x48,0x48,0x89,0xe7},4,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x66,0x66,0x89,0xc8},4,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x64,0x48,0x89,0xe7},4,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x67,0x48,0x89,0xe7},4,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0xf3,0x48,0x89,0xe7},4,LI2_STEP_PREFIX_UNQUALIFIED},
        {{0x66,0x48,0x89,0xe7},4,LI2_STEP_PREFIX_UNQUALIFIED},
    };
    for(unsigned i=0;i<REFUSALS;i++) {
        struct sample *s=&refused_samples[i];
        prepare(s,cases[i].bytes,cases[i].length,LI2_STEP_PAGE-cases[i].length,CASES+i+1);
        need(s->decoded.decode_status==LI2_VALID && s->decoded.kind==LI2_NONE &&
             s->decoded.length==cases[i].length && s->decoded.step_disposition==cases[i].disposition,110);
        struct li2_step_request request={.decoded=s->decoded,.page_count=s->count,.original_flags=fixture_flags};
        uintptr_t page=s->pc&~(LI2_STEP_PAGE-1);
        request.pages[0]=(struct li2_step_page){page,s->mapping,s->generation,page-s->mapping,PROT_READ,PROT_READ|PROT_EXEC};
        const struct li2_step_hooks hooks={s,authenticate,failure};
        need(li2_step_arm(&s->owner,&session,&hooks,&request,0)==LI2_STEP_ENCODING,111);
        request.decoded.step_disposition=LI2_STEP_CANDIDATE;
        need(li2_step_arm(&refused_claims[i],&session,&hooks,&request,0)==LI2_STEP_ENCODING,112);
        const struct li2_step_owner *owners[2]={&s->owner,&refused_claims[i]};
        for(unsigned j=0;j<2;j++) {
            need(owners[j]->phase==LI2_STEP_FAILED && owners[j]->first_error==LI2_STEP_ENCODING &&
                 !owners[j]->in_handler && !owners[j]->trace_seen && !owners[j]->revoke_sync_started &&
                 !owners[j]->before.initialized && !owners[j]->after.initialized,113);
            for(unsigned k=0;k<2;k++)need(!owners[j]->open_started[k] && !owners[j]->opened[k] &&
                 !owners[j]->revoke_started[k] && !owners[j]->revoked[k],114);
        }
        need(!authenticate(s,&request.pages[0],PROT_READ) &&
             !memcmp((void *)s->mapping,s->source,sizeof(s->source)),115);
        refusal_complete[i]=1;
    }
}
static void setup(unsigned long *stack) {
    need(stack[0]<128,10);const char *const *argv=(const void *)(stack+1);
    const char *const *env=argv+stack[0]+1;size_t count=0;while(env[count])need(++count<1024,11);
    const unsigned long *aux=(const void *)(env+count+1);unsigned long page=0,minimum=0;
    for(size_t i=0;i<128 && aux[2*i];i++) {
        if(aux[2*i]==6)page=aux[2*i+1];
        if(aux[2*i]==51)minimum=aux[2*i+1];
    }
    need(page==LI2_STEP_PAGE && minimum && minimum<512*1024-16384,12);
    long n=read_file("/proc/self/status",maps,sizeof(maps));need(n>0,13);
    const char key[]="TracerPid:\t";unsigned found=0;
    for(long i=0;i<n-(long)sizeof(key);i++)if((!i || maps[i-1]=='\n') && !memcmp(maps+i,key,sizeof(key)-1)) {
        need(maps[i+sizeof(key)-1]=='0' && maps[i+sizeof(key)]=='\n',14);++found;
    }
    need(found==1,15);
    unsigned a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    need((c&0x0c000000)==0x0c000000,16);
    a=d=0;__asm__ volatile("xgetbv":"=a"(a),"=d"(d):"c"(0));fixture_xcr0=(uint64_t)d<<32|a;
    need((fixture_xcr0&3)==3,17);
    unsigned long cet=0;long result=RAW(SYS_arch_prctl,0x5005,&cet,0,0,0,0);
    need((!result && !cet)||result==-22||result==-38,18);
    struct {void (*handler)(int,siginfo_t *,void *);unsigned long flags;void (*restorer)(void);uint64_t mask;} action,old;
    for(int sig=1;sig<=64;sig++)if(sig!=SIGKILL && sig!=SIGSTOP)
        need(!RAW(SYS_rt_sigaction,sig,0,&old,8,0,0) && !old.handler,19);
    uint64_t before=0;need(!RAW(SYS_rt_sigprocmask,0,0,&before,8,0,0) && !before,20);
    mask=UINT64_MAX&~((UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSEGV-1))|
        (UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1)));
    need(!RAW(SYS_rt_sigprocmask,2,&mask,0,8,0,0),21);
    long area=RAW(SYS_mmap,0,512*1024+2*LI2_STEP_PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(area>0,22);
    need(!RAW(SYS_mprotect,area+LI2_STEP_PAGE,512*1024,PROT_READ|PROT_WRITE,0,0,0),23);
    stack_t alt={.ss_sp=(void *)(area+LI2_STEP_PAGE),.ss_size=512*1024};need(!RAW(SYS_sigaltstack,&alt,0,0,0,0,0),24);
    action.handler=handler;action.flags=SA_SIGINFO|SA_ONSTACK|SA_NODEFER|0x04000000UL;action.restorer=step_restorer;action.mask=mask;
    need(!RAW(SYS_rt_sigaction,SIGSEGV,&action,0,8,0,0) && !RAW(SYS_rt_sigaction,SIGTRAP,&action,0,8,0,0),25);
    need(!li2_step_session_init(&session,mask),26);
    struct li2_decoder_stats stats;need(!li2_decoder_initialize(decoder_arena,sizeof(decoder_arena),&stats) && stats.phase==2,27);
    if(stack[0]==2) {
        if(same_string(argv[1],"foreign"))control=1;
        else if(same_string(argv[1],"nested"))control=2;
        else if(same_string(argv[1],"tf"))control=3;
        else if(same_string(argv[1],"rf"))control=4;
        else die(28);
    } else need(stack[0]==1,29);
}
int fixture_main(unsigned long *stack) {
    setup(stack);
    static const unsigned char nop[]={0x90},mov16[]={0x66,0xb8,0x68,0x24},
        mov32[]={0xb8,0x78,0x56,0x34,0x12},mov64[]={0x49,0xbc,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    prepare(&samples[0],nop,sizeof(nop),LI2_STEP_PAGE-1,1);run(&samples[0],1);
    need(session.self_test_complete,80);
    prepare(&samples[1],mov16,sizeof(mov16),LI2_STEP_PAGE-sizeof(mov16),2);run(&samples[1],0);
    prepare(&samples[2],mov32,sizeof(mov32),LI2_STEP_PAGE-sizeof(mov32),3);run(&samples[2],0);
    prepare(&samples[3],mov64,sizeof(mov64),LI2_STEP_PAGE-sizeof(mov64),4);run(&samples[3],0);
    prepare(&samples[4],mov64,sizeof(mov64),LI2_STEP_PAGE-5,5);run(&samples[4],0);
    for(unsigned i=0;i<REGISTER_CASES;i++) {
        const struct register_case *c=&register_cases[i];struct sample *s=&samples[5+i];
        s->register_move=1;s->expected_source=c->source;
        s->expected_destination=c->destination;s->expected_width=c->width;
        size_t offset=LI2_STEP_PAGE-(c->cross?1:c->length);
        prepare(s,c->bytes,c->length,offset,6+i);
        need(s->decoded.decode_status==LI2_VALID && s->decoded.kind==LI2_NONE &&
             s->decoded.length==c->length && s->decoded.step_disposition==LI2_STEP_CANDIDATE,100);
        run(s,0);
    }
    refusals();
    /* Private initialized records bind actual frames/prefixes. Their addresses
       are intentionally not a public JSON interface. No timing claim. */
    long written=RAW(SYS_write,3,samples,sizeof(samples),0,0,0);
    need(written==(long)sizeof(samples),81);
    need(RAW(SYS_write,3,&fixture_live_before,sizeof(fixture_live_before),0,0,0)==(long)sizeof(fixture_live_before),95);
    need(RAW(SYS_write,3,&fixture_live_after,sizeof(fixture_live_after),0,0,0)==(long)sizeof(fixture_live_after),96);
    need(RAW(SYS_write,3,refused_samples,sizeof(refused_samples),0,0,0)==(long)sizeof(refused_samples),116);
    need(RAW(SYS_write,3,refused_claims,sizeof(refused_claims),0,0,0)==(long)sizeof(refused_claims),117);
    need(RAW(SYS_write,3,refusal_complete,sizeof(refusal_complete),0,0,0)==(long)sizeof(refusal_complete),118);
    output("LI2_STEP_OWNER_PASS selftest=1 cases=20 native=20 trace=20 revoked=23 endpoints=20 source_unchanged=20 register_mov=15 refusals=13\n");
    return 0;
}
