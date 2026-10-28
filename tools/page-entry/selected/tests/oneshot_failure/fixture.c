/* Test-only link interposer. Product owner and real lifecycle stay unchanged.
   Only real kernel events are accepted before a named malformed-input edit.
   No selected effect or Rust COMPLETE transition is implemented here. */
#define _GNU_SOURCE
#include "fixture.h"
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

extern const char *const *bridge_environment(void);
int li2_fixture_product_initialize(struct li2_oneshot_owner *,const struct li2_step_session *,const struct li2_oneshot_hooks *);
int li2_fixture_product_nx(struct li2_oneshot_owner *,const struct li2_oneshot_plan *,int,siginfo_t *,ucontext_t *);
int li2_fixture_product_ud(struct li2_oneshot_owner *,int,siginfo_t *,ucontext_t *,struct li2_oneshot_handoff *);
void li2_fixture_product_abort_close(struct li2_oneshot_owner *);

static struct failure_record li2_oneshot_failure_record;
#define receipt li2_oneshot_failure_record
static struct li2_oneshot_hooks actual;
static struct li2_oneshot_owner *subject;
static siginfo_t *live_si[2];
static ucontext_t *live_uc[2];
static char maps[256*1024];
static unsigned capturing;
static unsigned active_lane;

static int require(int value,unsigned code) {
    if(!value && !receipt.oracle_error)receipt.oracle_error=code;
    return value;
}
static long direct(long n,long a,long b,long c,long d,long e,long f) {
    return actual.raw(n,a,b,c,d,e,f);
}
static uintptr_t hexadecimal(const char **p,const char *end,int *ok) {
    uintptr_t n=0;unsigned count=0;
    while(*p<end) {
        unsigned c=(unsigned char)**p,v;
        if(c>='0'&&c<='9')v=c-'0';else if(c>='a'&&c<='f')v=c-'a'+10;else break;
        if(n>(UINTPTR_MAX-v)/16){*ok=0;return 0;}
        n=n*16+v;++*p;++count;
    }
    if(!count)*ok=0;
    return n;
}
static int protection(uintptr_t page) {
    long fd=direct(SYS_openat,AT_FDCWD,(long)"/proc/self/maps",O_RDONLY|O_CLOEXEC,0,0,0);
    if(!require(fd>=0,1))return -1;
    size_t used=0;long n=0;
    while(used<sizeof(maps)) {
        n=direct(SYS_read,fd,(long)(maps+used),sizeof(maps)-used,0,0,0);
        if(n<=0)break;
        used+=(size_t)n;
    }
    long closed=direct(SYS_close,fd,0,0,0,0,0);
    if(!require(!n&&!closed&&used<sizeof(maps),2))return -1;
    const char *p=maps,*end=maps+used;unsigned hits=0;int answer=-1;
    while(p<end) {
        const char *line=p;while(p<end&&*p!='\n')++p;const char *stop=p;if(p<end)++p;
        int ok=1;uintptr_t first=hexadecimal(&line,stop,&ok);
        if(!require(ok&&line<stop&&*line++=='-',3))return -1;
        uintptr_t last=hexadecimal(&line,stop,&ok);
        if(!require(ok&&first<last&&line<stop&&*line++==' '&&stop-line>=5,4))return -1;
        if(first<=page&&page<last) {
            if(!require(++hits==1&&last-page>=LI2_ONESHOT_PAGE&&line[3]=='p',5))return -1;
            answer=(line[0]=='r'?PROT_READ:0)|(line[1]=='w'?PROT_WRITE:0)|(line[2]=='x'?PROT_EXEC:0);
        }
    }
    require(hits==1,6);return answer;
}
static unsigned selector(void) {
    static const char prefix[]="LI2_ONESHOT_FAILURE=";
    const char *const *env=bridge_environment();unsigned found=0,result=0;
    for(size_t i=0;env&&env[i]&&i<4096;i++) {
        const char *s=env[i];size_t k=0;while(k<sizeof(prefix)-1&&s[k]==prefix[k])++k;
        if(k!=sizeof(prefix)-1)continue;
        if(!require(!found++,10))return 0;
        unsigned n=0,digits=0;
        for(s+=k;*s;s++) {
            if(!require(*s>='0'&&*s<='9'&&digits++<2,11))return 0;
            n=10*n+(unsigned)(*s-'0');
        }
        if(!require(digits&&n>=1&&n<=LI2_FAILURE_MODES,12))return 0;
        result=n;
    }
    require(found==1,13);return result;
}
static void source_before(void) {
    struct li2_fetch_view v={0};li2_lifecycle_fetch_partial_view(&v);
    if(!require(v.pc&&v.length>=5&&v.page_count==1&&v.pages&&v.bytes,14))return;
    receipt.source_page=v.pages[0].address;receipt.source_pc=v.pc;receipt.source_bytes=LI2_ONESHOT_PAGE;
    receipt.fetch_busy_before=li2_lifecycle_fetch_interlock();
    receipt.source_protection_before=protection(receipt.source_page);
    if(!require(receipt.fetch_busy_before==LI2_FETCH_BUSY&&receipt.source_protection_before==PROT_READ&&
        v.pc>=receipt.source_page&&v.pc-receipt.source_page<=LI2_ONESHOT_PAGE-5,15))return;
    memcpy(receipt.source_before,(void *)(uintptr_t)receipt.source_page,LI2_ONESHOT_PAGE);
    require(!memcmp(v.bytes,receipt.source_before+v.pc-receipt.source_page,5),16);
    receipt.source_before_observed=1;
    static const unsigned char first[5]={0x0f,0x31,0x90,0x90,0x90};
    if(!require(v.pc==receipt.source_page&&!memcmp(v.bytes,first,sizeof(first))&&
        receipt.source_page<=UINTPTR_MAX-3*LI2_ONESHOT_PAGE,17))return;
    /* The unchanged integrated ELF reader separately proves .data begins
       two pages after this exact first-main RDTSC. Compare the whole real
       mapped data page; only its initial 328-byte fixture prefix is literal. */
    receipt.data_address=receipt.source_page+2*LI2_ONESHOT_PAGE;
    if(!require(protection(receipt.data_address)==(PROT_READ|PROT_WRITE),18))return;
    memcpy(receipt.data_before,(const void *)(uintptr_t)receipt.data_address,LI2_ONESHOT_PAGE);
    static const char marker[]="ONESHOT-READY!!\n";
    require(!memcmp(receipt.data_before,marker,sizeof(marker)-1),19);
    for(size_t i=sizeof(marker)-1;i<328;i++)require(!receipt.data_before[i],19);
    receipt.data_before_observed=1;
}
static uint32_t u32(const void *p) {uint32_t n;memcpy(&n,p,4);return n;}
static void event_before(unsigned lane,int sig,siginfo_t *si,ucontext_t *uc) {
    struct failure_event *e=&receipt.event[lane];
    if(!require(!e->received&&si&&uc&&!actual.frame_range(actual.context,si,sizeof(*si))&&
        !actual.frame_range(actual.context,uc,sizeof(*uc)),20))return;
    e->received=1;e->signal=(unsigned)sig;e->frame_address=(uintptr_t)uc;e->si_address=(uintptr_t)si;
    memcpy(&e->original_si,si,sizeof(*si));memcpy(&e->original_uc,uc,sizeof(*uc));
    const unsigned char *fp=(const void *)uc->uc_mcontext.fpregs;e->fp_address=(uintptr_t)fp;
    if(!require(fp&&!((uintptr_t)fp&15)&&!actual.frame_range(actual.context,fp,512),21))return;
    size_t n=512;
    if(u32(fp+464)==UINT32_C(0x46505853)) {
        n=u32(fp+468);size_t x=u32(fp+480);
        if(!require(n>=580&&n<=LI2_STEP_FP_BYTES&&x>=576&&x<=n-4&&
            !actual.frame_range(actual.context,fp,n)&&u32(fp+n-4)==UINT32_C(0x46505845),22))return;
    }
    e->fp_bytes=n;memcpy(e->original_fp,fp,n);live_si[lane]=si;live_uc[lane]=uc;
    greg_t *g=uc->uc_mcontext.gregs;uint64_t mask=0;memcpy(&mask,&uc->uc_sigmask,8);
    uintptr_t pc=lane?subject->plan.landing:receipt.source_pc;
    if(!require(sig==(lane?SIGILL:SIGSEGV)&&si->si_signo==sig&&!si->si_errno&&
        si->si_code==(lane?ILL_ILLOPN:SEGV_ACCERR)&&(uintptr_t)si->si_addr==pc&&
        (uintptr_t)g[REG_RIP]==pc&&g[REG_TRAPNO]==(lane?6:14)&&g[REG_ERR]==(lane?0:21)&&
        (uintptr_t)g[REG_CR2]==receipt.source_pc&&((uint64_t)g[REG_CSGSFS]&0xffff)==0x33&&
        mask==LI2_ONESHOT_MASK&&((uint64_t)g[REG_EFL]&LI2_STEP_RF)&&!((uint64_t)g[REG_EFL]&LI2_STEP_TF),23))return;
    e->authenticated=1;
}
static void event_after(unsigned lane) {
    struct failure_event *e=&receipt.event[lane];if(!e->received)return;
    if(!require(live_si[lane]&&live_uc[lane]&&e->fp_bytes&&e->fp_bytes<=LI2_STEP_FP_BYTES,24))return;
    if(e->after_observed) {
        require(!memcmp(&e->after_si,live_si[lane],sizeof(e->after_si))&&
            !memcmp(&e->after_uc,live_uc[lane],sizeof(e->after_uc))&&
            !memcmp(e->after_fp,(const void *)(uintptr_t)e->fp_address,e->fp_bytes),26);
        return;
    }
    memcpy(&e->after_si,live_si[lane],sizeof(e->after_si));
    memcpy(&e->after_uc,live_uc[lane],sizeof(e->after_uc));
    /* The original authenticated extent is retained even when a negative case
       deliberately changes the frame's FP pointer. Never follow that new pointer. */
    memcpy(e->after_fp,(const void *)(uintptr_t)e->fp_address,e->fp_bytes);
    e->after_observed=1;
}
static unsigned expected_error(void) {
    unsigned m=(unsigned)receipt.mode;
    if(m<=8)return (m==3||m==5||m==8)?LI2_ONESHOT_SYNC:LI2_ONESHOT_PROTECT;
    if(m<=19) {
        static const unsigned e[11]={LI2_ONESHOT_BIND,LI2_ONESHOT_IDENTITY,LI2_ONESHOT_GENERATION,
            LI2_ONESHOT_IDENTITY,LI2_ONESHOT_IDENTITY,LI2_ONESHOT_IDENTITY,LI2_ONESHOT_IDENTITY,
            LI2_ONESHOT_GENERATION,LI2_ONESHOT_IDENTITY,LI2_ONESHOT_IDENTITY,LI2_ONESHOT_RELEASE};
        return e[m-9];
    }
    if(m<=30)return LI2_ONESHOT_FRAME;
    if(m<=37)return LI2_ONESHOT_LANDING;
    if(m<=42)return LI2_ONESHOT_FRAME;
    if(m<=44)return 1566; /* Actual controller's failed initializer gate. */
    if(m<=46)return LI2_ONESHOT_REENTRY;
    return m==47?0:LI2_ONESHOT_IDENTITY;
}
/* libc's sizeof(ucontext_t) can include bytes also occupied by the kernel's
   adjacent siginfo and FP storage. Retain real addresses and require every
   original overlap to agree; a named edit must appear in every aliased view. */
struct expected_edit { uintptr_t address;unsigned char value; };
static int same_overlap(uintptr_t a,const unsigned char *x,size_t n,
                        uintptr_t b,const unsigned char *y,size_t m) {
    if(!require(a&&b&&n&&m&&a<=UINTPTR_MAX-n&&b<=UINTPTR_MAX-m,75))return 0;
    uintptr_t first=a>b?a:b,last=a+n<b+m?a+n:b+m;
    if(first<last&&!require(!memcmp(x+(first-a),y+(first-b),last-first),76))return 0;
    return 1;
}
static void append_edit(struct expected_edit *edits,size_t *count,uintptr_t address,unsigned char value) {
    for(size_t i=0;i<*count;i++)if(edits[i].address==address) {
        require(edits[i].value==value,77);return;
    }
    if(!require(*count<8,78))return;
    edits[*count]=(struct expected_edit){address,value};++*count;
}
static void collect_edits(struct expected_edit *edits,size_t *count,uintptr_t address,
                          const void *original,const void *expected,size_t n) {
    const unsigned char *a=original,*b=expected;
    for(size_t i=0;i<n;i++)if(a[i]!=b[i])append_edit(edits,count,address+i,b[i]);
}
static void apply_edits(void *expected,uintptr_t address,size_t n,
                        const struct expected_edit *edits,size_t count) {
    unsigned char *p=expected;
    for(size_t i=0;i<count;i++)if(edits[i].address>=address&&edits[i].address-address<n)
        p[edits[i].address-address]=edits[i].value;
}
static void validate_event(unsigned lane) {
    const struct failure_event *e=&receipt.event[lane];if(!e->received)return;
    require(e->authenticated&&e->after_observed&&e->fp_bytes>=512&&e->fp_bytes<=LI2_STEP_FP_BYTES,50);
    siginfo_t si;ucontext_t uc;
    memcpy(&si,&e->original_si,sizeof(si));memcpy(&uc,&e->original_uc,sizeof(uc));
    greg_t *g=uc.uc_mcontext.gregs;
    unsigned m=(unsigned)receipt.mode;size_t fp_edit=SIZE_MAX;
    /* Independent expected delta: all other siginfo/ucontext/FP bytes remain
       exact, including the full flags word and every unmodified GREG. */
    if(!lane) {
        if(m==20)si.si_code=SI_USER;
        if(m==21)si.si_addr=(void *)((uintptr_t)si.si_addr+1);
        if(m==22)g[REG_RIP]++;
        if(m==23)g[REG_CR2]++;
        if(m==24)g[REG_TRAPNO]=13;
        if(m==25)g[REG_ERR]^=1;
        if(m==26)g[REG_CSGSFS]=(greg_t)(((uint64_t)g[REG_CSGSFS]&~UINT64_C(0xffff))|0x23);
        if(m==27)((uint64_t *)&uc.uc_sigmask)[0]^=UINT64_C(1)<<(SIGILL-1);
        if(m==28)g[REG_EFL]|=LI2_STEP_TF;
        if(m==29)g[REG_EFL]&=~LI2_STEP_RF;
        if(m==30)uc.uc_mcontext.fpregs=(void *)((uintptr_t)uc.uc_mcontext.fpregs+1);
    } else {
        if(m==31)si.si_code=SI_USER;
        if(m==32)si.si_addr=(void *)((uintptr_t)si.si_addr+1);
        if(m==33)g[REG_RIP]++;
        if(m==34)g[REG_TRAPNO]=13;
        if(m==35)g[REG_ERR]=1;
        if(m==36)((uint64_t *)&uc.uc_sigmask)[0]^=UINT64_C(1)<<(SIGILL-1);
        if(m==37)fp_edit=160;
        if(m==38)g[REG_CR2]++;
        if(m==39)g[REG_EFL]^=1;
        if(m==40)g[REG_RAX]^=1;
        if(m==41)g[REG_CSGSFS]=(greg_t)(((uint64_t)g[REG_CSGSFS]&~UINT64_C(0xffff))|0x23);
        if(m==42)uc.uc_mcontext.fpregs=(void *)((uintptr_t)uc.uc_mcontext.fpregs+1);
    }
    if(!same_overlap(e->si_address,(const void *)&e->original_si,sizeof(si),
                     e->frame_address,(const void *)&e->original_uc,sizeof(uc))||
       !same_overlap(e->si_address,(const void *)&e->original_si,sizeof(si),
                     e->fp_address,e->original_fp,e->fp_bytes)||
       !same_overlap(e->frame_address,(const void *)&e->original_uc,sizeof(uc),
                     e->fp_address,e->original_fp,e->fp_bytes))return;
    struct expected_edit edits[8];size_t count=0;
    collect_edits(edits,&count,e->si_address,&e->original_si,&si,sizeof(si));
    collect_edits(edits,&count,e->frame_address,&e->original_uc,&uc,sizeof(uc));
    if(fp_edit<e->fp_bytes)append_edit(edits,&count,e->fp_address+fp_edit,e->original_fp[fp_edit]^1);
    apply_edits(&si,e->si_address,sizeof(si),edits,count);
    apply_edits(&uc,e->frame_address,sizeof(uc),edits,count);
    require(!memcmp(&si,&e->after_si,sizeof(si))&&!memcmp(&uc,&e->after_uc,sizeof(uc)),51);
    for(size_t i=0;i<e->fp_bytes;i++) {
        unsigned char expected=e->original_fp[i];
        apply_edits(&expected,e->fp_address+i,1,edits,count);
        require(e->after_fp[i]==expected,52);
    }
}
static void validate(void) {
    const struct li2_oneshot_owner *o=&receipt.owner_after_cleanup;
    unsigned m=(unsigned)receipt.mode;
    if(!require(m>=1&&m<=LI2_FAILURE_MODES&&receipt.pid&&receipt.pid==receipt.tid&&
        receipt.source_before_observed&&receipt.source_after_observed&&receipt.backend_observed&&
        receipt.raw_count<=LI2_FAILURE_RAW_ROWS&&receipt.raw_count<=LI2_ONESHOT_OPERATIONS&&
        receipt.backend_count<=11,53))return;
    unsigned calls=0,raw_prefix=0,ud=0,wrote=0,restored_bytes=0,published=0,transferred=0;
    if(m<=8) {
        static const unsigned counts[8]={3,4,4,6,6,8,9,9};
        calls=counts[m-1];raw_prefix=m;ud=m>=4;wrote=m>=2;restored_bytes=m>=7;
        published=m>=4;transferred=1;
    } else if(m<=19) {
        static const unsigned counts[11]={0,0,0,1,3,3,5,5,6,8,8};
        calls=m-8;raw_prefix=counts[calls-1];ud=calls>=6;wrote=calls>=5;
        restored_bytes=calls>=10;published=calls>=6;transferred=calls!=1;
    } else if(m>=31&&m<=42) {
        calls=5;raw_prefix=3;ud=1;wrote=published=transferred=1;
    } else if(m==45||m==46) {
        calls=m==45?5:11;raw_prefix=m==45?3:8;ud=m==46;
        wrote=published=transferred=1;restored_bytes=m==46;
    } else if(m>=48) {calls=5;raw_prefix=3;wrote=transferred=1;}
    require(receipt.backend_count==calls&&receipt.raw_count==raw_prefix+2*transferred&&
        receipt.ud_calls==ud&&o->transferred==transferred&&o->state.published==published&&
        o->write_completed_mask==(wrote?31U:0U)&&o->restore_completed_mask==(restored_bytes?31U:0U),71);
    require(receipt.injected==(m>=48?2U:1U)&&receipt.source_protection_before==PROT_READ&&
        receipt.source_protection_after==(m==48?(PROT_READ|PROT_EXEC):PROT_READ),54);
    require(receipt.data_before_observed&&receipt.data_after_observed&&
        !memcmp(receipt.data_before,receipt.data_after,LI2_ONESHOT_PAGE),74);
    require(o->state.first_error==expected_error()&&o->state.phase==(m==47?LI2_ONESHOT_EMPTY:LI2_ONESHOT_FAILED)&&
        o->state.phase!=LI2_ONESHOT_COMPLETED&&o->state.restored==(m==46),55);
    require(!memcmp(&receipt.owner_before_cleanup.state,&o->state,sizeof(o->state)),56);
    if(m==43||m==44)require(!receipt.nx_calls&&!receipt.ud_calls&&
        (m==43?receipt.initialize_result:receipt.repeat_result)==LI2_ONESHOT_REUSE,57);
    else require(receipt.nx_calls==1&&receipt.event[0].authenticated,58);
    if(m==47)require(!receipt.cleanup&&!o->transferred&&!o->state.mutation_started&&!o->state.published&&
        !receipt.raw_count&&!receipt.backend_count&&receipt.nx_result==LI2_ONESHOT_REFUSED_UNTOUCHED&&
        receipt.fetch_busy_after==LI2_FETCH_BUSY,59);
    else require(receipt.cleanup==1,60);
    require((o->write_completed_mask==0||o->write_completed_mask==31)&&
        (o->restore_completed_mask==0||o->restore_completed_mask==31)&&
        o->write_attempted_mask==o->write_completed_mask&&o->restore_attempted_mask==o->restore_completed_mask,61);
    size_t window=(size_t)(receipt.source_pc-receipt.source_page);
    for(size_t i=0;i<LI2_ONESHOT_PAGE;i++) {
        unsigned char value=receipt.source_before[i];
        if(o->write_completed_mask==31&&!o->restore_completed_mask&&i>=window&&i-window<5)
            value=o->plan.redirect[i-window];
        require(receipt.source_after[i]==value,62);
    }
    require(receipt.raw_count==o->operations&&receipt.raw_count<=LI2_FAILURE_RAW_ROWS,63);
    for(unsigned i=0;i<receipt.raw_count;i++) {
        const struct failure_raw *r=&receipt.raw[i];const struct li2_oneshot_operation *v=&o->operation[i];
        static const unsigned kinds[8]={1,1,2,1,2,1,1,2};
        static const unsigned permissions[8]={PROT_READ|PROT_WRITE,PROT_READ|PROT_EXEC,0,PROT_READ,0,
            PROT_READ|PROT_WRITE,PROT_READ,0};
        unsigned kind=i<raw_prefix?kinds[i]:(i==raw_prefix?3U:4U);
        unsigned prot=i<raw_prefix?permissions[i]:(i==raw_prefix?PROT_READ:0);
        require(r->number==i+1&&r->started&&r->returned&&v->call.started&&v->call.returned&&
            r->result==v->call.result&&(r->injected?r->result==-22:r->result==0)&&
            v->kind==kind&&!v->page&&v->protection==prot&&r->cleanup==(i>=raw_prefix)&&
            r->syscall_number==((kind==1||kind==3)?SYS_mprotect:SYS_membarrier),64);
        require(r->requested[0]==((kind==1||kind==3)?(int64_t)receipt.source_page:32)&&
            r->requested[1]==((kind==1||kind==3)?LI2_ONESHOT_PAGE:0)&&r->requested[2]==prot&&
            !r->requested[3]&&!r->requested[4]&&!r->requested[5],72);
        for(unsigned j=0;j<6;j++)require(r->issued[j]==(j==0&&r->injected?
            (r->syscall_number==SYS_mprotect?r->requested[j]+1:0x40000000):r->requested[j]),73);
        if(r->cleanup)require(!v->call.verified,65); /* Best effort is never verified closure. */
    }
    for(unsigned i=0;i<receipt.backend_count;i++) {
        const struct failure_backend *b=&receipt.backend[i];
        static const unsigned kinds[11]={1,3,2,3,3,3,3,2,3,3,4};
        require(b->number==i+1&&b->kind==kinds[i]&&b->started&&b->returned&&!b->actual_result&&
            b->returned_result==(b->injected?-117:0),66);
    }
    if(m>=9&&m<=19)require(receipt.backend_count==m-8,67);
    if(m<=8)require(receipt.raw[m-1].injected&&receipt.raw_count==m+2,68);
    if(receipt.event[1].received) {
        const struct failure_event *a=&receipt.event[0],*b=&receipt.event[1];
        require(a->authenticated&&b->authenticated&&a->fp_bytes==b->fp_bytes&&
            !memcmp(a->original_fp,b->original_fp,a->fp_bytes)&&
            !memcmp(&a->original_uc.uc_sigmask,&b->original_uc.uc_sigmask,8),69);
        for(unsigned i=0;i<NGREG;i++)if(i!=REG_RIP&&i!=REG_TRAPNO&&i!=REG_ERR)
            require(a->original_uc.uc_mcontext.gregs[i]==b->original_uc.uc_mcontext.gregs[i],70);
    }
    validate_event(0);validate_event(1);
    receipt.verified=!receipt.oracle_error;
}
static void emit(void) {
    if(receipt.emitted||capturing)return;
    capturing=1;
    if(subject) {
        memcpy(&receipt.owner_after_cleanup,subject,sizeof(*subject));
        const struct li2_oneshot_lifecycle_progress *p=li2_lifecycle_oneshot_progress(actual.context);
        if(p){memcpy(&receipt.backend_after,p,sizeof(*p));receipt.backend_observed=1;}
    }
    receipt.fetch_busy_after=li2_lifecycle_fetch_interlock();
    if(receipt.source_before_observed) {
        receipt.source_protection_after=protection(receipt.source_page);
        if(require((receipt.source_protection_after&PROT_READ)!=0,25)) {
            memcpy(receipt.source_after,(void *)(uintptr_t)receipt.source_page,LI2_ONESHOT_PAGE);
            receipt.source_after_observed=1;
        }
    }
    if(receipt.data_before_observed&&require(protection(receipt.data_address)==(PROT_READ|PROT_WRITE),27)) {
        memcpy(receipt.data_after,(const void *)(uintptr_t)receipt.data_address,LI2_ONESHOT_PAGE);
        receipt.data_after_observed=1;
    }
    /* Earlier kernel altstack frames can be overwritten by the next event.
       Each was retained before returning; only the current frame remains live. */
    if(live_uc[active_lane])event_after(active_lane);
    validate();
    receipt.emitted=1;
    const unsigned char *p=(const void *)&receipt;size_t left=sizeof(receipt);
    while(left) {long n=direct(SYS_write,3,(long)p,left,0,0,0);if(n<=0)break;p+=n;left-=(size_t)n;}
    capturing=0;
}
static long failed_raw(long n,long a,long b,long c,long d,long e,long f) {
    if(n!=SYS_mprotect&&n!=SYS_membarrier)return direct(n,a,b,c,d,e,f);
    if(!require(receipt.raw_count<LI2_FAILURE_RAW_ROWS,30))return -75;
    unsigned index=(unsigned)receipt.raw_count++;struct failure_raw *r=&receipt.raw[index];
    r->number=index+1;r->cleanup=receipt.cleanup;r->syscall_number=n;
    const long args[6]={a,b,c,d,e,f};for(unsigned i=0;i<6;i++)r->requested[i]=r->issued[i]=args[i];
    int inject=(!receipt.cleanup&&receipt.mode<=8&&r->number==receipt.mode)||
        (receipt.cleanup&&receipt.mode==48&&n==SYS_mprotect)||
        (receipt.cleanup&&receipt.mode==49&&n==SYS_membarrier);
    if(inject) {r->injected=1;receipt.injected++;if(n==SYS_mprotect)r->issued[0]++;
        else r->issued[0]=0x40000000;}
    r->started=1;__asm__ volatile("":::"memory");
    r->result=direct(n,r->issued[0],r->issued[1],r->issued[2],r->issued[3],r->issued[4],r->issued[5]);
    __asm__ volatile("":::"memory");r->returned=1;
    if(inject)require(r->result==-22,31);
    return r->result;
}
static struct failure_backend *backend_begin(unsigned kind) {
    if(!require(receipt.backend_count<LI2_FAILURE_BACKEND_ROWS,32))return 0;
    unsigned i=(unsigned)receipt.backend_count++;struct failure_backend *r=&receipt.backend[i];
    r->number=i+1;r->kind=kind;r->started=1;return r;
}
static int backend_end(struct failure_backend *r,int actual_result) {
    if(!r)return -75;
    r->actual_result=actual_result;r->returned_result=actual_result;r->returned=1;
    int inject=(receipt.mode>=9&&receipt.mode<=19&&r->number==receipt.mode-8)||
        (receipt.mode>=48&&r->number==5);
    if(inject) {require(!actual_result,33);r->injected=1;receipt.injected++;r->returned_result=-117;}
    return (int)r->returned_result;
}
static int failed_transfer(void *p,const struct li2_oneshot_plan *q,struct li2_oneshot_transfer *v) {
    struct failure_backend *r=backend_begin(1);return backend_end(r,actual.transfer(p,q,v));
}
static int failed_advance(void *p,const struct li2_oneshot_plan *q,unsigned restore,struct li2_oneshot_generation *v) {
    struct failure_backend *r=backend_begin(2);return backend_end(r,actual.advance_generation(p,q,restore,v));
}
static int failed_observe(void *p,const struct li2_oneshot_plan *q,struct li2_oneshot_observation *v) {
    struct failure_backend *r=backend_begin(3);return backend_end(r,actual.observe(p,q,v));
}
static int failed_release(void *p,const struct li2_oneshot_plan *q,struct li2_oneshot_release *v) {
    struct failure_backend *r=backend_begin(4);return backend_end(r,actual.release(p,q,v));
}
static void malformed(unsigned lane,siginfo_t *si,ucontext_t *uc) {
    unsigned mode=(unsigned)receipt.mode;greg_t *g=uc->uc_mcontext.gregs;
    if(!lane&&mode>=20&&mode<=30) {
        switch(mode) {
        case 20:si->si_code=SI_USER;break;
        case 21:si->si_addr=(void *)((uintptr_t)si->si_addr+1);break;
        case 22:g[REG_RIP]++;break;
        case 23:g[REG_CR2]++;break;
        case 24:g[REG_TRAPNO]=13;break;
        case 25:g[REG_ERR]^=1;break;
        case 26:g[REG_CSGSFS]=(greg_t)(((uint64_t)g[REG_CSGSFS]&~UINT64_C(0xffff))|0x23);break;
        case 27:((uint64_t *)&uc->uc_sigmask)[0]^=UINT64_C(1)<<(SIGILL-1);break;
        case 28:g[REG_EFL]|=LI2_STEP_TF;break;
        case 29:g[REG_EFL]&=~LI2_STEP_RF;break;
        case 30:uc->uc_mcontext.fpregs=(void *)((uintptr_t)uc->uc_mcontext.fpregs+1);break;
        }receipt.injected++;
    } else if(lane&&mode>=31&&mode<=42) {
        switch(mode) {
        case 31:si->si_code=SI_USER;break;
        case 32:si->si_addr=(void *)((uintptr_t)si->si_addr+1);break;
        case 33:g[REG_RIP]++;break;
        case 34:g[REG_TRAPNO]=13;break;
        case 35:g[REG_ERR]=1;break;
        case 36:((uint64_t *)&uc->uc_sigmask)[0]^=UINT64_C(1)<<(SIGILL-1);break;
        case 37:((unsigned char *)uc->uc_mcontext.fpregs)[160]^=1;break;
        case 38:g[REG_CR2]++;break;
        case 39:g[REG_EFL]^=1;break;
        case 40:g[REG_RAX]^=1;break;
        case 41:g[REG_CSGSFS]=(greg_t)(((uint64_t)g[REG_CSGSFS]&~UINT64_C(0xffff))|0x23);break;
        case 42:uc->uc_mcontext.fpregs=(void *)((uintptr_t)uc->uc_mcontext.fpregs+1);break;
        }receipt.injected++;
    }
}
int li2_oneshot_initialize(struct li2_oneshot_owner *o,const struct li2_step_session *s,const struct li2_oneshot_hooks *h) {
    if(subject)return li2_fixture_product_initialize(o,s,h);
    subject=o;actual=*h;receipt.magic=UINT64_C(0x3146494f32494c);receipt.version=1;receipt.bytes=sizeof(receipt);
    receipt.pid=direct(SYS_getpid,0,0,0,0,0,0);receipt.tid=direct(SYS_gettid,0,0,0,0,0,0);
    receipt.mode=selector();receipt.initializations=1;source_before();
    if(!receipt.mode||receipt.oracle_error)return LI2_ONESHOT_ARGUMENT;
    struct li2_oneshot_hooks wrapped=*h;wrapped.raw=failed_raw;wrapped.transfer=failed_transfer;
    wrapped.advance_generation=failed_advance;wrapped.observe=failed_observe;wrapped.release=failed_release;
    if(receipt.mode==43){o->state.first_detail=1;receipt.injected++;}
    int result=li2_fixture_product_initialize(o,s,&wrapped);receipt.initialize_result=result;
    if(receipt.mode==44&&!result) {receipt.repeat_result=li2_fixture_product_initialize(o,s,&wrapped);
        receipt.injected++;return (int)receipt.repeat_result;}
    return result;
}
int li2_oneshot_nx(struct li2_oneshot_owner *o,const struct li2_oneshot_plan *p,int sig,siginfo_t *si,ucontext_t *uc) {
    if(o!=subject)return li2_fixture_product_nx(o,p,sig,si,uc);
    active_lane=0;receipt.nx_calls++;receipt.request=*p;event_before(0,sig,si,uc);malformed(0,si,uc);
    struct li2_oneshot_plan altered=*p;
    if(receipt.mode==47) {altered.landing=p->pc+UINT64_C(0x100000000);receipt.injected++;}
    int result=li2_fixture_product_nx(o,receipt.mode==47?&altered:p,sig,si,uc);
    receipt.nx_result=result;receipt.owner_result_observed=1;event_after(0);
    if(receipt.mode==45&&!result) {receipt.repeat_result=li2_fixture_product_nx(o,p,sig,si,uc);
        receipt.injected++;return (int)receipt.repeat_result;}
    if(receipt.mode==47) {require(result==LI2_ONESHOT_REFUSED_UNTOUCHED,40);
        memcpy(&receipt.owner_before_cleanup,o,sizeof(*o));emit();}
    return result;
}
int li2_oneshot_ud(struct li2_oneshot_owner *o,int sig,siginfo_t *si,ucontext_t *uc,struct li2_oneshot_handoff *out) {
    if(o!=subject)return li2_fixture_product_ud(o,sig,si,uc,out);
    active_lane=1;receipt.ud_calls++;event_before(1,sig,si,uc);malformed(1,si,uc);
    int result=li2_fixture_product_ud(o,sig,si,uc,out);receipt.ud_result=result;
    memcpy(&receipt.handoff,out,sizeof(*out));receipt.owner_result_observed=1;event_after(1);
    if(receipt.mode==46&&!result) {receipt.repeat_result=li2_fixture_product_ud(o,sig,si,uc,out);
        receipt.injected++;return (int)receipt.repeat_result;}
    return result;
}
void li2_oneshot_abort_close(struct li2_oneshot_owner *o) {
    if(o!=subject){li2_fixture_product_abort_close(o);return;}
    memcpy(&receipt.owner_before_cleanup,o,sizeof(*o));receipt.cleanup=1;
    li2_fixture_product_abort_close(o);emit();
}
_Static_assert(sizeof(struct failure_record)<16*1024*1024,"finite complete failure record cap");
