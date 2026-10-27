#define _GNU_SOURCE
#include "step_owner.h"
#include <sys/mman.h>
#include <sys/syscall.h>

extern long raw(long,long,long,long,long,long,long);
long li2_step_raw(long n,long a,long b,long c,long d,long e,long f) {
    /* Every production syscall uses the actual SUD-whitelisted bridge. */
    return raw(n,a,b,c,d,e,f);
}
#define RAW(n,a,b,c,d,e,f) li2_step_raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
static void copy(void *d,const void *s,size_t n) {
    unsigned char *out=d; const unsigned char *in=s;
    for(size_t i=0;i<n;i++)out[i]=in[i];
}
static int equal(const void *a,const void *b,size_t n) {
    const unsigned char *x=a,*y=b;
    for(size_t i=0;i<n;i++)if(x[i]!=y[i])return 0;
    return 1;
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static void first(struct li2_step_owner *o,unsigned code,long detail) {
    if(!o->first_error){o->first_error=code;o->first_detail=detail;}
}
static int identity(const struct li2_step_session *s) {
    return RAW(SYS_getpid,0,0,0,0,0,0)==s->pid &&
           RAW(SYS_gettid,0,0,0,0,0,0)==s->tid;
}
/* Each page is one actual mprotect operation. Even an unsuccessful opening
   receives an independent revoke attempt; no error is mistaken for no effect. */
static void revoke_pages(struct li2_step_owner *o) {
    o->phase=LI2_STEP_REVOKING;
    for(size_t i=0;i<o->request.page_count && i<2;i++) if(o->open_started[i] && !o->revoke_started[i]) {
        o->revoke_started[i]=1;
        o->revoke_result[i]=RAW(SYS_mprotect,o->request.pages[i].address,LI2_STEP_PAGE,
                                o->request.pages[i].closed_prot,0,0,0);
        if(o->revoke_result[i])first(o,LI2_STEP_REVOKE,o->revoke_result[i]);
        else {
            o->revoked[i]=1;
            if(o->hooks.authenticate(o->hooks.context,&o->request.pages[i],o->request.pages[i].closed_prot))
                first(o,LI2_STEP_PAGE_BINDING,(long)i);
        }
    }
    if(!o->revoke_sync_started) {
        o->revoke_sync_started=1;
        o->revoke_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
        if(o->revoke_sync)first(o,LI2_STEP_SYNC_REVOKE,o->revoke_sync);
    }
}
_Noreturn void li2_step_abort(struct li2_step_owner *o,unsigned code,long detail) {
    first(o,code,detail);
    if(o->session && o->session->initialized)revoke_pages(o);
    o->phase=LI2_STEP_FAILED;
    if(o->hooks.failure)o->hooks.failure(o->hooks.context,o);
    (void)RAW(SYS_exit_group,125,0,0,0,0,0);
    __builtin_trap();
}
static void require(struct li2_step_owner *o,int yes,unsigned code,long detail) {
    if(!yes)li2_step_abort(o,code,detail);
}
int li2_step_session_init(struct li2_step_session *s,uint64_t mask) {
    if(!s || s->initialized || s->pid || s->tid)return LI2_STEP_REUSE;
    const uint64_t allowed=(UINT64_C(1)<<(SIGSEGV-1))|(UINT64_C(1)<<(SIGTRAP-1))|(UINT64_C(1)<<(SIGSYS-1))|
                           (UINT64_C(1)<<(SIGKILL-1))|(UINT64_C(1)<<(SIGSTOP-1));
    if(mask!=(UINT64_MAX&~allowed))return LI2_STEP_ARGUMENT;
    s->application_mask=mask;s->pid=RAW(SYS_getpid,0,0,0,0,0,0);s->tid=RAW(SYS_gettid,0,0,0,0,0,0);
    if(s->pid<=0 || s->pid!=s->tid)return LI2_STEP_IDENTITY;
    s->sync_query=RAW(SYS_membarrier,0,0,0,0,0,0);
    if(s->sync_query<0 || (s->sync_query&96)!=96)return LI2_STEP_SELFTEST;
    s->sync_register=RAW(SYS_membarrier,64,0,0,0,0,0);
    if(s->sync_register)return LI2_STEP_SELFTEST;
    s->initialized=1;return 0;
}
static int encoding(struct li2_step_owner *o) {
    const struct li2_decoded *d=&o->request.decoded;
    if(d->abi_version!=1 || d->reserved || d->decode_status!=LI2_VALID || d->kind!=LI2_NONE ||
       d->step_disposition!=LI2_STEP_CANDIDATE || !d->length || d->length>15 ||
       d->available<d->length || d->available>15 || d->pc>UINTPTR_MAX-d->length ||
       d->next_pc!=d->pc+d->length)return 0;
    o->destination=16;o->width=0;o->immediate=0;
    o->effect=LI2_STEP_UNCHANGED;o->source=16;
    if(d->length==1 && d->bytes[0]==0x90)return 1;
    size_t at=0;unsigned small=0,rex=0;
    if(d->bytes[at]==0x66){small=1;++at;}
    if(at<d->length && d->bytes[at]>=0x40 && d->bytes[at]<=0x4f)rex=d->bytes[at++];
    if(at<d->length && (d->bytes[at]==0x89 || d->bytes[at]==0x8b)) {
        /* A new, independently parsed register-only effect. REX.R/B/W are
           meaningful; REX.X, bare REX and ignored 66+W remain refused. */
        if((rex&2) || rex==0x40 || (small && (rex&8)) || at+2!=d->length)return 0;
        unsigned op=d->bytes[at++],modrm=d->bytes[at];
        if((modrm&0xc0)!=0xc0)return 0;
        unsigned reg=((modrm>>3)&7)+(rex&4?8:0),rm=(modrm&7)+(rex&1?8:0);
        o->destination=op==0x89?rm:reg;o->source=op==0x89?reg:rm;
        if(o->destination==4)return 0;
        o->width=rex&8?64:small?16:32;o->effect=LI2_STEP_MOV_REGISTER;
        return 1;
    }
    /* Canonical prefix shapes only. Ignored REX.R/X, address/segment/REP/LOCK,
       repeated prefixes and NOP aliases require separate native qualification. */
    if((rex && rex!=0x41 && rex!=0x48 && rex!=0x49) || (small && (rex&8)) || at>=d->length)return 0;
    unsigned op=d->bytes[at++];if(op<0xb8 || op>0xbf)return 0;
    o->destination=op-0xb8+(rex&1?8:0);if(o->destination==4)return 0;
    o->width=rex&8?64:small?16:32;
    size_t n=o->width/8;if(at+n!=d->length)return 0;
    for(size_t i=0;i<n;i++)o->immediate|=(uint64_t)d->bytes[at+i]<<(i*8);
    o->effect=LI2_STEP_MOV_IMMEDIATE;
    return 1;
}
int li2_step_arm(struct li2_step_owner *o,struct li2_step_session *s,
                const struct li2_step_hooks *hooks,const struct li2_step_request *request,int self_test) {
    if(!o || !s || !hooks || !request || !hooks->authenticate)return LI2_STEP_ARGUMENT;
    if(o->phase!=LI2_STEP_EMPTY || o->session)return LI2_STEP_REUSE;
    o->session=s;o->hooks=*hooks;o->request=*request;o->self_test=!!self_test;
    o->phase=LI2_STEP_ARMED;
    unsigned error=0;
    if(!s->initialized || !identity(s))error=LI2_STEP_IDENTITY;
    else if((self_test && s->self_test_complete) || (!self_test && !s->self_test_complete))error=LI2_STEP_SELFTEST;
    else if(request->original_flags&(LI2_STEP_TF|LI2_STEP_RF))error=LI2_STEP_INPUT_FLAGS;
    else if(!encoding(o) || (self_test && o->destination!=16))error=LI2_STEP_ENCODING;
    else {
        uintptr_t first_page=request->decoded.pc&~(LI2_STEP_PAGE-1);
        uintptr_t last_page=(request->decoded.next_pc-1)&~(LI2_STEP_PAGE-1);
        size_t count=first_page==last_page?1:2;
        if(request->page_count!=count)error=LI2_STEP_PAGE_BINDING;
        for(size_t i=0;!error && i<count;i++) {
            const struct li2_step_page *p=&request->pages[i];
            if(p->address!=first_page+i*LI2_STEP_PAGE || !p->object || !p->generation ||
               p->closed_prot!=PROT_READ || p->open_prot!=(PROT_READ|PROT_EXEC) ||
               hooks->authenticate(hooks->context,p,p->closed_prot))error=LI2_STEP_PAGE_BINDING;
        }
    }
    if(error){first(o,error,0);o->phase=LI2_STEP_FAILED;}
    return (int)error;
}
static void frame(struct li2_step_owner *o,struct li2_step_frame *out,const ucontext_t *uc) {
    copy(out->greg,uc->uc_mcontext.gregs,sizeof(out->greg));
    copy(&out->mask,&uc->uc_sigmask,sizeof(out->mask));
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;
    require(o,out->fp_address && !(out->fp_address&15),LI2_STEP_FRAME,1);
    const unsigned char *p=(const void *)out->fp_address;
    /* Linux x86 signal ABI _fpx_sw_bytes. Preserve the actual initialized
       frame including both magic fields; do not manufacture an XSAVE image. */
    size_t n=512;
    if(u32(p+464)==UINT32_C(0x46505853)) {
        n=u32(p+468);size_t x=u32(p+480);
        require(o,n>=580 && n<=LI2_STEP_FP_BYTES && x>=576 && x<=n-4 &&
                u32(p+n-4)==UINT32_C(0x46505845),LI2_STEP_FRAME,2);
    }
    out->fp_bytes=n;
    for(size_t i=0;i<n;i++){out->fp[i]=p[i];out->initialized=i+1;}
}
static void enter(struct li2_step_owner *o,enum li2_step_phase expected,int sig,siginfo_t *si,ucontext_t *uc) {
    require(o,!o->in_handler,LI2_STEP_REENTRY,sig);o->in_handler=1;
    require(o,o->phase==expected && !o->first_error && o->session && identity(o->session),LI2_STEP_IDENTITY,o->phase);
    require(o,si && uc,LI2_STEP_FRAME,0);
    o->signal_number=sig;o->signal_code=si->si_code;o->signal_errno=si->si_errno;o->signal_address=(uintptr_t)si->si_addr;
    uint64_t mask=0;copy(&mask,&uc->uc_sigmask,sizeof(mask));
    require(o,mask==o->session->application_mask,LI2_STEP_FRAME,3);
}
void li2_step_begin(struct li2_step_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    enter(o,LI2_STEP_ARMED,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    uintptr_t pc=o->request.decoded.pc;
    require(o,sig==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
            (uintptr_t)g[REG_RIP]==pc && g[REG_TRAPNO]==14 && g[REG_ERR]==21 &&
            (uintptr_t)si->si_addr==pc,LI2_STEP_FOREIGN_EVENT,sig);
    require(o,(uint64_t)g[REG_EFL]==(o->request.original_flags|LI2_STEP_RF),LI2_STEP_INPUT_FLAGS,g[REG_EFL]);
    frame(o,&o->before,uc);
    require(o,equal((const void *)pc,o->request.decoded.bytes,o->request.decoded.length),LI2_STEP_PAGE_BINDING,2);
    o->phase=LI2_STEP_OPENING;
    for(size_t i=0;i<o->request.page_count;i++) {
        const struct li2_step_page *p=&o->request.pages[i];
        require(o,!o->hooks.authenticate(o->hooks.context,p,p->closed_prot),LI2_STEP_PAGE_BINDING,(long)i);
        o->open_started[i]=1;
        o->open_result[i]=RAW(SYS_mprotect,p->address,LI2_STEP_PAGE,p->open_prot,0,0,0);
        require(o,!o->open_result[i],LI2_STEP_OPEN,o->open_result[i]);o->opened[i]=1;
        require(o,!o->hooks.authenticate(o->hooks.context,p,p->open_prot),LI2_STEP_PAGE_BINDING,(long)i);
    }
    o->open_sync=RAW(SYS_membarrier,32,0,0,0,0,0);
    require(o,!o->open_sync,LI2_STEP_SYNC_OPEN,o->open_sync);
    require(o,equal(uc->uc_mcontext.fpregs,o->before.fp,o->before.fp_bytes),LI2_STEP_FRAME,4);
    g[REG_EFL]|=LI2_STEP_TF;
    o->phase=LI2_STEP_RUNNING;o->in_handler=0;
}
void li2_step_trace(struct li2_step_owner *o,int sig,siginfo_t *si,ucontext_t *uc) {
    enter(o,LI2_STEP_RUNNING,sig,si,uc);
    greg_t *g=uc->uc_mcontext.gregs;
    require(o,sig==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            g[REG_TRAPNO]==1 && !g[REG_ERR] && (uintptr_t)g[REG_RIP]==o->request.decoded.next_pc &&
            (uintptr_t)si->si_addr==o->request.decoded.next_pc,LI2_STEP_FOREIGN_EVENT,sig);
    o->trace_seen=1;frame(o,&o->after,uc);
    /* Revocation precedes result checks and ANY return to application code. */
    revoke_pages(o);
    if(o->first_error)li2_step_abort(o,o->first_error,o->first_detail);
    require(o,equal((const void *)o->request.decoded.pc,o->request.decoded.bytes,o->request.decoded.length),LI2_STEP_PAGE_BINDING,3);
    static const unsigned regs[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
        REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
    for(unsigned i=0;i<16;i++) {
        uint64_t expected=(uint64_t)o->before.greg[regs[i]];
        if(i==o->destination) {
            uint64_t value=o->immediate;
            if(o->effect==LI2_STEP_MOV_REGISTER) {
                require(o,o->source<16,LI2_STEP_RESULT,18);
                value=(uint64_t)o->before.greg[regs[o->source]];
            } else require(o,o->effect==LI2_STEP_MOV_IMMEDIATE,LI2_STEP_RESULT,19);
            if(o->width==16)expected=(expected&~UINT64_C(0xffff))|(value&UINT64_C(0xffff));
            else if(o->width==32)expected=value&UINT64_C(0xffffffff);
            else {require(o,o->width==64,LI2_STEP_RESULT,20);expected=value;}
        }
        require(o,(uint64_t)g[regs[i]]==expected,LI2_STEP_RESULT,i);
    }
    require(o,(uint64_t)g[REG_EFL]==(o->request.original_flags|LI2_STEP_TF),LI2_STEP_RESULT,16);
    require(o,o->before.fp_bytes==o->after.fp_bytes &&
            equal(o->before.fp,o->after.fp,o->before.fp_bytes),LI2_STEP_RESULT,17);
    require(o,g[REG_CSGSFS]==o->before.greg[REG_CSGSFS] &&
            equal(uc->uc_mcontext.fpregs,o->after.fp,o->after.fp_bytes),LI2_STEP_FRAME,5);
    g[REG_EFL]&=~LI2_STEP_TF;
    o->phase=LI2_STEP_COMPLETE;o->in_handler=0;
    if(o->self_test)o->session->self_test_complete=1;
}
