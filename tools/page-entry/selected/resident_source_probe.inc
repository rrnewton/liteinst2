/* Observation of actual owner/handler/effect paths only. No event is injected,
   no guard result replaced, and no record field grants execution authority. */
#include "resident_source_probe.h"
#include "resident_source_probe_config.h"
#define RSO_MAGIC UINT64_C(0x3152534f5352324c)
#define RSO_FOOT UINT64_C(0x3146534f5352324c)
#define RSO_QUERY 512U
struct rso_frame {
    uint64_t h[16];
    unsigned char si[128],uc[968],logical[968],fp[LI2_STEP_FP_BYTES];
};
struct rso_first_bind {
    uint64_t h[8];
    struct li2_pg_token token;
    struct li2_rsl_progress before,after;
};
struct rso_binding {
    uint64_t h[16];
    struct li2_pg_token token;
    struct li2_rsl_ref ref;
    struct li2_rsl_progress progress;
    struct li2_mg_table table;
    struct li2_fork_range registry[RANGES];
};
struct rso_event {
    uint64_t h[32];
    struct li2_rsl_progress before,after;
    struct rso_frame frame;
    uint64_t owner[16],rseq[24];
    struct li2_private_code_query closed[12];
    struct li2_fork_range registry[RANGES];
    struct li2_write_footprint footprint;
    unsigned char target[PAGE],query[RSO_QUERY];
};
struct rso_wire {
    uint64_t h[64];
    struct stat initial,terminal;
    struct rso_first_bind first_bind;
    struct li2_pg_source_page source[LI2_RSL_PAGES];
    struct rso_binding binding[2];
    struct rso_event event[4];
    unsigned char initial_target[PAGE],final_target[PAGE],control[PAGE];
    struct li2_fork_range registry[RANGES],final_registry[RANGES];
    unsigned char initial_query[RSO_QUERY],terminal_query[RSO_QUERY];
};
static struct rso_wire rso_wire;
static const siginfo_t *rso_si;
static const ucontext_t *rso_uc;
static int rso_sig;
static siginfo_t rso_saved_si;
static ucontext_t rso_saved_uc;
static const ucontext_t *rso_checked_uc;
static struct li2_decoded rso_checked_instruction;
static uint64_t rso_sequence,rso_route;
static unsigned rso_ready,rso_mode,rso_events,rso_bindings,rso_pending,rso_written;
static struct li2_rsl_ref rso_first;
_Static_assert(sizeof(struct li2_pg_source_page)==4376 && sizeof(struct li2_rsl_progress)==56 &&
    sizeof(struct rso_frame)==67728 && sizeof(struct rso_binding)==6488 &&
    sizeof(struct rso_event)==77040 && sizeof(struct rso_first_bind)==192 && sizeof(struct rso_wire)==619600 &&
    sizeof(struct li2_private_code_query)<=RSO_QUERY && sizeof(struct li2_rseq_state)>0 &&
    sizeof(struct rso_wire)+64<1024*1024,"literal bounded source witness, not an old capture schema");
static void rso_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;for(size_t i=0;i<n;i++)d[i]=s[i];
}
static unsigned rso_zero(const void *p,size_t n) {
    const unsigned char *b=p;for(size_t i=0;i<n;i++)if(b[i])return 0;return 1;
}
static uint64_t rso_hash(const void *p,size_t n) {
    uint64_t h=UINT64_C(1469598103934665603);const unsigned char *b=p;
    for(size_t i=0;i<n;i++){h^=b[i];h*=UINT64_C(1099511628211);}return h;
}
static void rso_query(unsigned char *out) {
    struct li2_private_code_query q={0};
    checked(!li2_lifecycle_private_code_query(LI2_RSO_TARGET,PAGE,PROT_READ|PROT_WRITE,&q),LI2_FETCH_STATE,201);
    rso_copy(out,&q,sizeof q);
}
static void rso_frame(struct rso_frame *f,const ucontext_t *logical) {
    checked(rso_si && rso_uc && logical && !f->h[0] && handling,LI2_FETCH_STATE,202);
    checked(le_range(rso_si,sizeof *rso_si) && le_range(rso_uc,sizeof *rso_uc) &&
        (const unsigned char *)rso_si==(const unsigned char *)&rso_uc->uc_sigmask+8,LI2_FETCH_STATE,203);
    f->h[0]=1;f->h[1]=(uint64_t)(int64_t)rso_sig;f->h[2]=(uintptr_t)rso_si;f->h[3]=(uintptr_t)rso_uc;
    f->h[4]=(uintptr_t)rso_saved_uc.uc_mcontext.fpregs;
    const unsigned char *fp=(void *)(uintptr_t)f->h[4];size_t n=512;
    checked(!(f->h[4]&15) && le_range(fp,512),LI2_FETCH_STATE,204);
    if(le_u32(fp+464)==UINT32_C(0x46505853)) {
        n=le_u32(fp+468);size_t x=le_u32(fp+480);
        checked(n>=580 && n<=LI2_STEP_FP_BYTES && x>=576 && x<=n-4 &&
            le_range(fp,n) && le_u32(fp+n-4)==UINT32_C(0x46505845),LI2_FETCH_STATE,205);
    }
    f->h[5]=n;f->h[10]=rso_route;f->h[11]=rso_sequence;
    f->h[12]=(uintptr_t)rso_saved_uc.uc_mcontext.gregs[REG_RIP];
    f->h[13]=(uintptr_t)logical->uc_mcontext.gregs[REG_RIP];
    rso_copy(f->si,&rso_saved_si,sizeof rso_saved_si);rso_copy(f->uc,&rso_saved_uc,sizeof rso_saved_uc);
    rso_copy(f->logical,logical,sizeof *logical);rso_copy(f->fp,fp,n);
    f->h[8]=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&f->h[6],0,0,0,0);
    f->h[9]=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&f->h[7],0,0,0,0);
    checked(!f->h[8] && !f->h[9],LI2_FETCH_STATE,206);f->h[14]=1;
}
static unsigned rso_parse_mode(void) {
    const char *const *env=bridge_environment();const char key[]="LI2_RESIDENT_SOURCE_PROBE_MODE=";
    unsigned found=0,result=0;
    for(size_t i=0;env[i];i++) {
        size_t j=0;while(j<sizeof key-1 && env[i][j]==key[j])j++;
        if(j!=sizeof key-1)continue;
        checked(!found,LI2_FETCH_ARGUMENT,200);found=1;unsigned digits=0;
        while(env[i][j]) {checked(digits<2 && env[i][j]>='0' && env[i][j]<='9',LI2_FETCH_ARGUMENT,201);
            result=result*10+(unsigned)(env[i][j++]-'0');++digits;}
        checked(digits && result<=15,LI2_FETCH_ARGUMENT,202);
    }
    checked(found,LI2_FETCH_ARGUMENT,203);return result;
}
static void rso_initialize(void) {
    checked(!rso_ready && !rso_written && rso_zero(&rso_wire,sizeof rso_wire),LI2_FETCH_STATE,207);
    rso_mode=rso_parse_mode();
    long mapped=raw(SYS_mmap,LI2_RSO_TARGET,2*PAGE,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    checked(mapped==(long)LI2_RSO_TARGET,LI2_FETCH_STATE,mapped);
    protect(LI2_RSO_TARGET,2*PAGE);
    for(unsigned i=0;i<PAGE;i++)((volatile unsigned char *)LI2_RSO_TARGET)[i]=0xa5;
    uint64_t *control=(void *)LI2_RSO_CONTROL;
    control[0]=UINT64_C(0x52534c50524f4245);control[1]=1;control[2]=LI2_RSO_TARGET;control[3]=PAGE;
    checked(!li2_rso_backing(UINT64_C(0x410000),control+4),LI2_FETCH_STATE,208);
    checked(!raw(SYS_mprotect,LI2_RSO_CONTROL,PAGE,PROT_READ,0,0,0),LI2_FETCH_STATE,209);
    uint64_t *h=rso_wire.h;h[0]=RSO_MAGIC;h[1]=1;h[2]=sizeof rso_wire;h[3]=rso_mode;
    h[4]=raw(SYS_getpid,0,0,0,0,0,0);h[5]=raw(SYS_gettid,0,0,0,0,0,0);
    unsigned cpu=0,node=0;
    checked(!raw(SYS_getcpu,(long)&cpu,(long)&node,0,0,0,0) && h[4] && h[4]==h[5],LI2_FETCH_STATE,210);
    h[6]=cpu;h[7]=node;h[8]=(uintptr_t)&rso_wire;h[9]=LI2_RSO_TARGET;h[10]=LI2_RSO_CONTROL;
    h[11]=sizeof(struct li2_private_code_query);h[12]=sizeof(struct li2_pg_source_page);
    h[13]=sizeof(struct li2_rsl_progress);h[14]=sizeof(struct rso_event);h[15]=sizeof(struct rso_frame);
    h[16]=raw(SYS_fcntl,3,F_GETFD,0,0,0,0);h[17]=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    h[18]=raw(SYS_fstat,3,(long)&rso_wire.initial,0,0,0,0);
    checked(!h[16] && (h[17]&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !h[18] &&
        S_ISREG(rso_wire.initial.st_mode) && (rso_wire.initial.st_mode&07777)==0600 &&
        rso_wire.initial.st_nlink==1 && !rso_wire.initial.st_size,LI2_FETCH_STATE,211);
    rso_copy(rso_wire.initial_target,(void *)LI2_RSO_TARGET,PAGE);
    rso_copy(rso_wire.control,(void *)LI2_RSO_CONTROL,PAGE);rso_query(rso_wire.initial_query);
    h[19]=protected_count;checked(protected_count<=RANGES,LI2_FETCH_STATE,212);
    rso_copy(rso_wire.registry,protected,protected_count*sizeof *protected);rso_ready=1;
}
static void rso_ingress(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!rso_ready)return;
    checked(rso_sequence!=UINT64_MAX,LI2_FETCH_STATE,213);++rso_sequence;
    rso_si=si;rso_uc=uc;rso_sig=sig;rso_route=selected_pending_route;
    checked(le_range(si,sizeof *si) && le_range(uc,sizeof *uc),LI2_FETCH_STATE,225);
    rso_copy(&rso_saved_si,si,sizeof *si);rso_copy(&rso_saved_uc,uc,sizeof *uc);
    rso_checked_uc=0;
}
void li2_rso_lease_bound(const struct li2_pg_token *token,const struct li2_rsl_progress *before) {
    if(!rso_ready || before->bindings)return;
    struct rso_first_bind *b=&rso_wire.first_bind;struct li2_rsl_ref ref={0};unsigned pages=0;
    checked(!b->h[0] && li2_pg_owner_phase(token)==LI2_PG_HELD &&
        !li2_rsl_snapshot(token,&ref,&pages),LI2_FETCH_STATE,229);
    const uint64_t *control=(const void *)LI2_RSO_CONTROL;unsigned found=0;
    for(unsigned i=0;i<pages;i++) {
        struct li2_pg_source_page page={0};
        checked(!li2_rsl_page_at(&ref,i,&page),LI2_FETCH_STATE,230);
        if(page.identity.address==control[20]) {
            ++found;b->h[3]=page.identity.address;b->h[4]=page.identity.generation;
            b->h[5]=page.identity.allocation;b->h[6]=page.identity.object;
        }
    }
    checked(found==1,LI2_FETCH_STATE,231);b->token=*token;b->before=*before;b->after=*li2_rsl_progress();
    b->h[0]=1;b->h[1]=li2_pg_owner_phase(token);b->h[2]=rso_sequence;b->h[7]=li2_rsl_ref_live(&ref);
}
void li2_rso_bound(const struct li2_pg_token *token,uintptr_t entry,const struct li2_mg_table *table) {
    if(!rso_ready || entry!=UINT64_C(0x410200))return;
    ++rso_wire.h[20];
    const struct li2_rsl_progress *p=li2_rsl_progress();
    if(rso_bindings && (rso_bindings==2 || p->epoch==rso_wire.binding[0].progress.epoch))return;
    struct rso_binding *b=&rso_wire.binding[rso_bindings];unsigned pages=0;
    checked(rso_bindings<2 && li2_pg_owner_phase(token)==LI2_PG_BOUND &&
        !li2_rsl_snapshot(token,&b->ref,&pages) && pages && pages<=LI2_RSL_PAGES &&
        !li2_rsl_covers(&b->ref,table),LI2_FETCH_STATE,214);
    b->token=*token;b->progress=*p;b->table=*table;b->h[0]=1;b->h[1]=entry;b->h[2]=pages;
    b->h[3]=li2_pg_owner_phase(token);b->h[4]=rso_bindings;b->h[5]=rso_sequence;
    b->h[6]=li2_rsl_ref_live(&b->ref);b->h[7]=li2_rsl_ref_live(&rso_first);
    checked(protected_count<=RANGES,LI2_FETCH_STATE,227);b->h[8]=protected_count;
    rso_copy(b->registry,protected,protected_count*sizeof *protected);
    if(!rso_bindings) {
        rso_first=b->ref;
        for(unsigned i=0;i<pages;i++)checked(!li2_rsl_page_at(&b->ref,i,&rso_wire.source[i]),LI2_FETCH_STATE,215);
    }
    ++rso_bindings;
}
static struct rso_event *rso_event(unsigned kind,const ucontext_t *uc) {
    checked(rso_ready && !rso_written && rso_events<4 && handling,LI2_FETCH_STATE,216);
    struct rso_event *e=&rso_wire.event[rso_events];e->h[0]=kind;e->h[1]=rso_events;
    e->h[2]=rso_sequence;e->h[3]=li2_rsl_owner_quiet();e->h[4]=li2_rsl_ref_live(&rso_first);
    checked(protected_count<=RANGES,LI2_FETCH_STATE,228);e->h[18]=protected_count;
    rso_copy(e->registry,protected,protected_count*sizeof *protected);
    e->before=*li2_rsl_progress();li2_rso_owner(e->owner,e->closed);rso_frame(&e->frame,uc);
    rso_copy(e->target,(void *)LI2_RSO_TARGET,PAGE);rso_query(e->query);
    ++rso_events;return e;
}
static int rso_selected_effect(long n,const long a[6]) {
    switch(rso_mode) {
    case 1:case 8:return n==SYS_mprotect && a[0]==0x410000 && a[1]==PAGE;
    case 2:return n==SYS_mmap && a[0]==0x410000 && a[1]==PAGE;
    case 3:return n==SYS_munmap && a[0]==0x410000 && a[1]==PAGE;
    case 5:return n==SYS_read && a[1]==0x410000 && a[2]==1;
    case 6:return n==SYS_set_tid_address && a[0];
    case 7:return n==SYS_set_robust_list && a[0];
    case 14:return n==SYS_mmap && a[1]==PAGE && a[4]==((const uint64_t *)LI2_RSO_CONTROL)[4];
    case 15:return n==SYS_getrandom && a[0]==LI2_RSO_TARGET+0x200 && a[1]==8;
    default:return 0;
    }
}
static void rso_effect_before(long n,const long a[6],const ucontext_t *uc) {
    if(!rso_ready || !rso_selected_effect(n,a))return;
    checked(!rso_pending,LI2_FETCH_STATE,217);
    struct rso_event *e=rso_event(1,uc);e->h[5]=(uint64_t)n;
    for(unsigned i=0;i<6;i++)e->h[6+i]=(uint64_t)a[i];rso_pending=rso_events;
}
static void rso_effect_after(long n,const long a[6],int result) {
    if(!rso_ready || !rso_selected_effect(n,a))return;
    checked(rso_pending==rso_events && rso_pending,LI2_FETCH_STATE,218);
    struct rso_event *e=&rso_wire.event[rso_pending-1];e->h[12]=(uint64_t)(int64_t)result;
    e->h[13]=1;e->after=*li2_rsl_progress();e->h[14]=li2_rsl_ref_live(&rso_first);
}
static void rso_effect_done(long n,const long a[6]) {
    if(rso_ready && rso_selected_effect(n,a)) {checked(rso_pending,LI2_FETCH_STATE,219);rso_pending=0;}
}
void li2_rso_raw(long n,long a,long b,long c,long d,long e,long f,unsigned returned,long result) {
    if(!rso_ready || !rso_pending)return;
    struct rso_event *row=&rso_wire.event[rso_pending-1];const long args[6]={a,b,c,d,e,f};
    if(n!=(long)row->h[5])return;
    for(unsigned i=0;i<6;i++)if((uint64_t)args[i]!=row->h[6+i])return;
    if(returned) {++row->h[16];row->h[17]=(uint64_t)result;}
    else ++row->h[15];
}
void li2_rso_instruction(const struct li2_decoded *d,const ucontext_t *uc) {
    if(!rso_ready || !d || !uc)return;
    rso_checked_uc=uc;rso_checked_instruction=*d;
    uintptr_t wanted=rso_mode==9?LI2_RSO_STORE_PC:rso_mode==10?LI2_RSO_CHAIN_PC:
        rso_mode==11?LI2_RSO_TLS_PC:rso_mode==12?LI2_RSO_CALL_PC:rso_mode==13?LI2_RSO_REP_PC:0;
    if(!wanted || d->pc!=wanted)return;
    struct rso_event *e=rso_event(2,uc);e->h[5]=d->pc;e->h[6]=d->code;e->h[7]=d->length;
    checked(!rso_pending,LI2_FETCH_STATE,220);rso_pending=rso_events;
}
void li2_rso_range(uintptr_t first,size_t bytes,int overlap,const struct li2_rseq_state *s) {
    if(!rso_ready)return;
    if(!rso_pending && rso_mode==4 && first==UINT64_C(0x410100) && bytes==1 && overlap) {
        checked(rso_checked_uc!=0,LI2_FETCH_STATE,226);
        struct rso_event *e=rso_event(2,rso_checked_uc);
        e->h[5]=rso_checked_instruction.pc;e->h[6]=rso_checked_instruction.code;
        e->h[7]=rso_checked_instruction.length;rso_pending=rso_events;
    }
    if(!rso_pending)return;
    struct rso_event *e=&rso_wire.event[rso_pending-1];if(e->h[0]!=2)return;
    e->h[8]=first;e->h[9]=bytes;e->h[10]=(unsigned)overlap;e->h[11]=1;e->after=*li2_rsl_progress();
    const uint64_t row[]={s->initialized,s->registered,s->held,s->first_error,s->phase,
        (uint64_t)s->first_detail,s->pid,s->tid,s->epoch,s->fs_base,s->gs_base,
        (uint64_t)s->fs_result,(uint64_t)s->gs_result,s->tls_attempted,s->tls_complete,
        s->instruction_checks,s->range_checks,s->repeat_checks,s->run_checks,s->syscall_checks,
        s->last_first,s->last_end,s->last_pc,s->last_policy};
    rso_copy(e->rseq,row,sizeof row);e->footprint=s->last_footprint;
}
static void rso_fd_guard(long n,const long a[6]) {
    if(!rso_ready)return;
    if((n==SYS_close || n==SYS_write || n==SYS_writev || n==SYS_fcntl) && a[0]==3)
        fail(LI2_FETCH_ARGUMENT,204);
}
static void rso_report(unsigned status,unsigned code,long detail) {
    if(!rso_ready || rso_written)return;rso_written=1;
    uint64_t *h=rso_wire.h;h[21]=rso_events;h[22]=rso_bindings;h[23]=rso_sequence;
    h[24]=status;h[25]=code;h[26]=(uint64_t)detail;h[27]=li2_rsl_ref_live(&rso_first);
    h[28]=raw(SYS_fstat,3,(long)&rso_wire.terminal,0,0,0,0);
    checked(!h[28] && rso_wire.initial.st_dev==rso_wire.terminal.st_dev &&
        rso_wire.initial.st_ino==rso_wire.terminal.st_ino && !rso_wire.terminal.st_size &&
        rso_wire.terminal.st_nlink==1,LI2_FETCH_STATE,221);
    rso_copy(rso_wire.final_target,(void *)LI2_RSO_TARGET,PAGE);rso_query(rso_wire.terminal_query);
    h[29]=protected_count;
    checked(protected_count>=h[19] && protected_count<=RANGES,LI2_FETCH_STATE,222);
    rso_copy(rso_wire.final_registry,protected,protected_count*sizeof *protected);
    li2_rso_owner(h+32,0);rso_copy(h+48,li2_rsl_progress(),sizeof(struct li2_rsl_progress));
    h[30]=1;const unsigned char *p=(const void *)&rso_wire;size_t done=0;
    while(done<sizeof rso_wire) {
        long n=raw(SYS_write,3,(long)(p+done),sizeof rso_wire-done,0,0,0);
        if(n<=0 || (size_t)n>sizeof rso_wire-done)fail(LI2_FETCH_STATE,223);done+=(size_t)n;
    }
    uint64_t footer[8]={RSO_FOOT,1,sizeof rso_wire,rso_hash(&rso_wire,sizeof rso_wire),h[4],h[3],status,1};
    if(raw(SYS_write,3,(long)footer,sizeof footer,0,0,0)!=(long)sizeof footer)fail(LI2_FETCH_STATE,224);
}
