#include "../../oneshot_reusable.h"
/* Fixture-only observation, after selected_effect_controller.inc. No observer
   call changes source permissions, a real frame, provider decisions or guards.
   Every selected sample is raw; stress samples are a fixed declared subset. */
#define PAO_ROWS 18U
#define PAO_UC 2048U
#define PAO_FP 65536U
struct pao_frame {
    uint64_t signal,info_address,frame_address,fp_address,fp_bytes,uc_bytes,complete;
    siginfo_t info;
    unsigned char uc[PAO_UC],fp[PAO_FP];
};
struct pao_row {
    uint64_t index,site,module,iteration,phase,pc,bias,stack,landing;
    uint64_t begin_effect_sequence,end_effect_sequence,policy_before,policy_after;
    uint64_t ds_before,es_before,ds_after,es_after,fs_after,gs_after;
    uint64_t fs_started,fs_returned,gs_started,gs_returned,tls_complete;
    long fs_result,gs_result;
    struct li2_decoded decoded;
    struct li2_fetch_page source;
    struct li2_fetch_backing backing;
    struct pao_frame nx,ud;
    struct li2_oneshot_owner published,retired;
    __typeof__(selected_effect_runtime) effect;
    struct selected_effect_raw_prefix raw;
    struct selected_builtin_prefix builtin;
    struct li2_rseq_state rseq_before,rseq_after;
    struct li2_rseq_publication_state pin_published,pin_restored,pin_retired;
    struct li2_oneshot_lifecycle_progress backend_retired;
    struct li2_lifecycle_counts lifecycle_before,lifecycle_after;
    struct li2_oneshot_reuse_stats reuse_after;
    __typeof__(selected_oneshot_counts) counts_before,counts_after;
    unsigned char source_before[PA_PAGE],source_published[PA_PAGE],source_after[PA_PAGE];
    unsigned char stack_before[PA_STACK],stack_after[PA_STACK];
};
struct pao_record {
    uint64_t magic,version,bytes,row_bytes,uc_bytes,fp_capacity,rounds,scripted;
    uint64_t initialized,hardware_initialized,terminal,status,code,detail_abs,detail_negative;
    uint64_t bridge_bias,altstack_address,altstack_bytes,session_address,owner_address,policy_address,policy_sites_address;
    struct li2_step_session session;
    uint64_t begun,published,landed,restored,effect_completed,retired,sampled,pending;
    uint64_t module_bias[2],module_seen[2],visits[6],max_retained_at_fixture_retire;
    uint64_t pending_index,pending_site,pending_row,pending_phase;
    uint64_t tls_queries_started,tls_queries_returned;
    struct pab_state bootstrap;
    struct pa_policy_site policy_sites[6];
    struct pa_policy_context policy_terminal;
    struct li2_selected_hardware hardware;
    __typeof__(selected_oneshot_counts) terminal_counts;
    struct li2_oneshot_reuse_stats terminal_reuse;
    struct li2_lifecycle_counts terminal_lifecycle;
    struct li2_rseq_state terminal_rseq;
    struct li2_rseq_publication_state terminal_pin;
    struct li2_oneshot_owner terminal_publication;
    __typeof__(selected_effect_runtime) terminal_effect;
    struct selected_effect_raw_prefix terminal_raw;
    uint64_t terminal_active,terminal_resetting;
    struct pao_row rows[PAO_ROWS];
};
_Static_assert(sizeof(ucontext_t)<=PAO_UC && LI2_STEP_FP_BYTES==PAO_FP &&
    sizeof(struct pao_record)<(16U<<20),"complete bounded publication observation");
static struct pao_record pao_record;
static void pao_copy(void *out,const void *in,size_t n) {
    unsigned char *d=out;const volatile unsigned char *s=in;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void pao_need(int ok,unsigned detail) { checked(ok,1781,(long)detail); }
static unsigned pao_keep(uint64_t i) {
    return PA_WORKLOAD_ROUNDS==3 || i<9 || (i>=8189 && i<=8193) || i>=9212;
}
static struct pao_row *pao_current(void) {
    if(pao_record.pending_row==UINT64_MAX)return 0;
    pao_need(pao_record.pending_row<PAO_ROWS,1);return &pao_record.rows[pao_record.pending_row];
}
static void pao_frame(struct pao_frame *out,int signal,const siginfo_t *si,const ucontext_t *uc) {
    pao_need(!selected_effect_frame_range(si,sizeof(*si)) &&
        !selected_effect_frame_range(uc,sizeof(*uc)),2);
    size_t n=selected_effect_fp_size(uc);
    out->signal=(unsigned)signal;out->info_address=(uintptr_t)si;out->frame_address=(uintptr_t)uc;
    out->fp_address=(uintptr_t)uc->uc_mcontext.fpregs;out->fp_bytes=n;out->uc_bytes=sizeof(*uc);
    pao_copy(&out->info,si,sizeof(*si));pao_copy(out->uc,uc,sizeof(*uc));
    pao_copy(out->fp,uc->uc_mcontext.fpregs,n);out->complete=1;
}
static void pao_initialize(void) {
    volatile unsigned char *p=(void *)&pao_record;
    for(size_t i=0;i<sizeof pao_record;i++)p[i]=0;
    pao_record.magic=UINT64_C(0x31534f425041324c);pao_record.version=2;
    pao_record.bytes=sizeof pao_record;pao_record.row_bytes=sizeof(struct pao_row);
    pao_record.uc_bytes=sizeof(ucontext_t);pao_record.fp_capacity=PAO_FP;
    pao_record.rounds=PA_WORKLOAD_ROUNDS;pao_record.scripted=PA_POLICY_SCRIPTED;
    pao_record.pending_row=UINT64_MAX;
    pao_record.bridge_bias=bridge_runtime_image()->bias;
    pao_record.altstack_address=(uintptr_t)fork_gate_stack.ss_sp;pao_record.altstack_bytes=fork_gate_stack.ss_size;
    pao_record.session_address=(uintptr_t)&selected_session;
    pao_record.owner_address=(uintptr_t)&selected_oneshot_current;
    pao_record.policy_address=(uintptr_t)&pa_policy_context;
    pao_record.initialized=1;
}
static void pao_hardware(void) {
    pao_need(pao_record.initialized && !pao_record.hardware_initialized &&
        selected_hardware.abi_version==1 && !selected_hardware.reserved,16);
    pao_copy(&pao_record.hardware,&selected_hardware,sizeof selected_hardware);
    __asm__ volatile("":::"memory");pao_record.hardware_initialized=1;
}
/* Observe only after the genuine selftest TRACE, revoke/release and cleanup. */
static void pao_session_ready(void) {
    pao_need(pao_record.initialized==1 && pao_record.hardware_initialized==1 &&
        !pao_record.session.initialized && !pao_record.begun &&
        selected_selftests==1 && !selected_selftesting &&
        selected_session.initialized==1 && selected_session.self_test_complete==1 &&
        !selected_step_pending && !li2_lifecycle_fetch_interlock(),17);
    pao_copy(&pao_record.session,&selected_session,sizeof selected_session);
}
static void pao_bind(void) {
    pao_need(pao_record.initialized && pab_state.complete && pa_policy_context.count==6,3);
    pao_copy(&pao_record.bootstrap,&pab_state,sizeof pab_state);
    pao_copy(pao_record.policy_sites,pa_policy_context.sites,sizeof pao_record.policy_sites);
    pao_record.policy_sites_address=(uintptr_t)pa_policy_context.sites;
}
/* Called only after genuine selected_oneshot_try's range/authentication guards
   and exact decode, before the first source release or publication action. */
static void pao_begin(int signal,const siginfo_t *si,ucontext_t *uc) {
    if(!pab_state.complete || selected_view.page_count!=1)return;
    const struct li2_fetch_page *p=selected_view.pages;
    if(p->backing!=1 || selected_decoded.pc<p->address ||
       selected_decoded.pc-p->address>=PA_PAGE || p->offset>UINT64_MAX-(selected_decoded.pc-p->address))return;
    uint64_t object_id=(uint64_t)p->object+1,offset=p->offset+selected_decoded.pc-p->address;
    unsigned site=6;
    for(unsigned i=0;i<6;i++)if(pa_policy_context.sites[i].object_id==object_id &&
        pa_policy_context.sites[i].file_offset==offset) {pao_need(site==6,4);site=i;}
    if(site==6)return;
    uint64_t index=pao_record.begun;unsigned module=site/3;
    const struct pab_module *image=&pab_state.modules[module];
    pao_need(!pao_record.pending && index<6U*PA_WORKLOAD_ROUNDS && index%6==site &&
        pa_policy_context.matched==index && selected_decoded.pc>=image->sites[site%3] &&
        selected_decoded.next_pc==selected_decoded.pc+2 && selected_decoded.kind==pa_policy_context.sites[site].kind &&
        selected_decoded.length==2 && p->offset==image->page_offset,5);
    uint64_t bias=selected_decoded.pc-image->sites[site%3];
    pao_need(bias<=UINT64_MAX-image->page_vaddr && p->address==bias+image->page_vaddr &&
        bias<=UINT64_MAX-image->stack_vaddr-PA_STACK &&
        (uint64_t)uc->uc_mcontext.gregs[REG_RSP]==bias+image->stack_vaddr+PA_STACK-256,6);
    if(pao_record.module_seen[module])pao_need(pao_record.module_bias[module]==bias,7);
    else {pao_record.module_seen[module]=1;pao_record.module_bias[module]=bias;}
    pao_record.pending=1;pao_record.pending_index=index;pao_record.pending_site=site;
    pao_record.pending_phase=1;pao_record.pending_row=UINT64_MAX;pao_record.begun++;
    pao_record.visits[site]++;
    if(pao_keep(index)) {
        pao_need(pao_record.sampled<PAO_ROWS,8);pao_record.pending_row=pao_record.sampled++;
        struct pao_row *r=pao_current();r->index=index;r->site=site;r->module=module;
        r->iteration=index/6;r->phase=1;r->pc=selected_decoded.pc;r->bias=bias;
        r->stack=bias+image->stack_vaddr;r->begin_effect_sequence=selected_effect_runtime.sequence;
        r->policy_before=pa_policy_context.matched;
        pao_copy(&r->decoded,&selected_decoded,sizeof r->decoded);pao_copy(&r->source,p,sizeof(*p));
        pao_copy(&r->backing,selected_view.backing,sizeof r->backing);
        pao_frame(&r->nx,signal,si,uc);
        pao_copy(&r->rseq_before,li2_rseq_snapshot(),sizeof r->rseq_before);
        li2_lifecycle_snapshot(&r->lifecycle_before);
        pao_copy(&r->counts_before,&selected_oneshot_counts,sizeof selected_oneshot_counts);
        pao_copy(r->source_before,(const void *)(uintptr_t)p->address,PA_PAGE);
        pao_copy(r->stack_before,(const void *)(uintptr_t)r->stack,PA_STACK);
    }
}
static void pao_published(const struct li2_oneshot_owner *o) {
    if(!pao_record.pending)return;
    pao_need(pao_record.pending_phase==1 && o==selected_oneshot_active &&
        o->state.phase==LI2_ONESHOT_PUBLISHED,9);
    struct pao_row *r=pao_current();
    if(r) {r->landing=o->plan.landing;r->phase=2;pao_copy(&r->published,o,sizeof(*o));
        pao_copy(&r->pin_published,li2_rseq_publication_snapshot(),sizeof r->pin_published);
        pao_copy(r->source_published,(const void *)(uintptr_t)r->source.address,PA_PAGE);}
    pao_record.published++;pao_record.pending_phase=2;
}
static void pao_landed(int signal,const siginfo_t *si,ucontext_t *uc) {
    if(!pao_record.pending)return;
    pao_need(pao_record.pending_phase==2,10);struct pao_row *r=pao_current();
    if(r) {pao_frame(&r->ud,signal,si,uc);r->phase=3;}
    pao_record.landed++;pao_record.pending_phase=3;
}
static void pao_restored(const struct li2_oneshot_owner *o) {
    if(!pao_record.pending)return;
    pao_need(pao_record.pending_phase==3 && o==selected_oneshot_active &&
        o->state.phase==LI2_ONESHOT_RESTORED,11);struct pao_row *r=pao_current();
    if(r) {pao_copy(&r->pin_restored,li2_rseq_publication_snapshot(),sizeof r->pin_restored);
        unsigned short ds,es;__asm__ volatile("mov %%ds,%0;mov %%es,%1":"=r"(ds),"=r"(es)::"memory");
        r->ds_before=ds;r->es_before=es;r->phase=4;}
    pao_record.restored++;pao_record.pending_phase=4;
}
static void pao_effect(void) {
    if(!pao_record.pending)return;
    pao_need(pao_record.pending_phase==4 && selected_effect_runtime.finished &&
        selected_effect_runtime.owner.phase==LI2_EFFECT_COMMITTED &&
        pa_policy_context.matched==pao_record.pending_index+1,12);
    struct pao_row *r=pao_current();
    if(r) {pao_copy(&r->effect,&selected_effect_runtime,sizeof selected_effect_runtime);
        pao_copy(&r->raw,&selected_effect_raw,sizeof selected_effect_raw);
        pao_copy(&r->builtin,&selected_builtin_prefix,sizeof selected_builtin_prefix);
        r->end_effect_sequence=selected_effect_runtime.sequence;r->policy_after=pa_policy_context.matched;r->phase=5;}
    pao_record.effect_completed++;pao_record.pending_phase=5;
}
static void pao_retired(const struct li2_oneshot_owner *o) {
    if(!pao_record.pending)return;
    pao_need(pao_record.pending_phase==5 && o==selected_oneshot_active &&
        o->state.phase==LI2_ONESHOT_COMPLETED && !li2_lifecycle_fetch_interlock() &&
        !li2_lifecycle_oneshot_interlock(),13);
    pao_record.retired++;
    struct li2_lifecycle_counts counts;li2_lifecycle_snapshot(&counts);
    if(counts.retained_records>pao_record.max_retained_at_fixture_retire)pao_record.max_retained_at_fixture_retire=counts.retained_records;
    struct pao_row *r=pao_current();
    if(r) {
        pao_copy(&r->retired,o,sizeof(*o));pao_copy(&r->rseq_after,li2_rseq_snapshot(),sizeof r->rseq_after);
        pao_copy(&r->pin_retired,li2_rseq_publication_last_complete(),sizeof r->pin_retired);
        pao_copy(&r->backend_retired,li2_lifecycle_oneshot_last_complete(),sizeof r->backend_retired);
        pao_copy(&r->reuse_after,li2_lifecycle_oneshot_reuse_snapshot(),sizeof r->reuse_after);
        pao_copy(&r->counts_after,&selected_oneshot_counts,sizeof selected_oneshot_counts);
        pao_copy(&r->lifecycle_after,&counts,sizeof counts);
        pao_copy(r->source_after,(const void *)(uintptr_t)r->source.address,PA_PAGE);
        pao_copy(r->stack_after,(const void *)(uintptr_t)r->stack,PA_STACK);r->phase=6;
        /* Genuine publication and effect retirement precede these separate
           observer-only TLS queries. Their own failure prefix is retained. */
        unsigned short ds,es;__asm__ volatile("mov %%ds,%0;mov %%es,%1":"=r"(ds),"=r"(es)::"memory");
        r->ds_after=ds;r->es_after=es;
        r->fs_started=1;pao_record.tls_queries_started++;__asm__ volatile("":::"memory");
        r->fs_result=raw(SYS_arch_prctl,ARCH_GET_FS,(long)&r->fs_after,0,0,0,0);
        r->fs_returned=1;pao_record.tls_queries_returned++;pao_need(!r->fs_result,14);
        r->gs_started=1;pao_record.tls_queries_started++;__asm__ volatile("":::"memory");
        r->gs_result=raw(SYS_arch_prctl,ARCH_GET_GS,(long)&r->gs_after,0,0,0,0);
        r->gs_returned=1;pao_record.tls_queries_returned++;pao_need(!r->gs_result,15);
        r->tls_complete=1;r->phase=7;
    }
    pao_record.pending=0;pao_record.pending_phase=0;pao_record.pending_row=UINT64_MAX;
}
/* Invoke after report's one-shot reported=1, including failed prefixes. The
   enclosing process capture requires the complete exact stream; a short/error
   write cannot turn an original failure into a pass. No callback is invoked. */
static void pao_terminal(unsigned status,unsigned code,long detail) {
    if(!pao_record.initialized || pao_record.terminal)return;
    pao_record.terminal=1;pao_record.status=status;pao_record.code=code;
    pao_record.detail_negative=detail<0;pao_record.detail_abs=detail<0?0ULL-(uint64_t)detail:(uint64_t)detail;
    pao_copy(&pao_record.bootstrap,&pab_state,sizeof pab_state);
    pao_copy(&pao_record.policy_terminal,&pa_policy_context,sizeof pa_policy_context);
    pao_copy(&pao_record.terminal_counts,&selected_oneshot_counts,sizeof selected_oneshot_counts);
    pao_copy(&pao_record.terminal_reuse,li2_lifecycle_oneshot_reuse_snapshot(),sizeof pao_record.terminal_reuse);
    li2_lifecycle_snapshot(&pao_record.terminal_lifecycle);
    pao_copy(&pao_record.terminal_rseq,li2_rseq_snapshot(),sizeof pao_record.terminal_rseq);
    pao_copy(&pao_record.terminal_pin,li2_rseq_publication_snapshot(),sizeof pao_record.terminal_pin);
    pao_record.terminal_active=selected_oneshot_active!=0;
    pao_record.terminal_resetting=selected_oneshot_resetting;
    pao_copy(&pao_record.terminal_publication,&selected_oneshot_current,sizeof selected_oneshot_current);
    pao_copy(&pao_record.terminal_effect,&selected_effect_runtime,sizeof selected_effect_runtime);
    pao_copy(&pao_record.terminal_raw,&selected_effect_raw,sizeof selected_effect_raw);
    size_t done=0;
    while(done<sizeof pao_record) {
        long n=raw(SYS_write,3,(long)((const unsigned char *)&pao_record+done),sizeof pao_record-done,0,0,0);
        if(n<=0 || (uint64_t)n>sizeof pao_record-done)break;
        done+=(size_t)n;
    }
}
