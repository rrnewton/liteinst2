/* Two genuine resident RX activations; observation never grants a token,
   source identity, lifetime, closure or permission. Each record retains its own kernel frames. */
#if LI2_RESIDENT_RX_CAPTURE != 1 || LI2_RESIDENT_RX != 1 || LI2_RESIDENT_STABLE_GENERATION != 1
#error "distinct retained-RX two-activation observer"
#endif
#include "resident_three_observe.h"
#include "resident_rx_config.h"
#define R3O_MAGIC UINT64_C(0x315758525732494c)
#define R3O_FOOTER UINT64_C(0x314658525732494c)
struct r3o_scan { uint64_t compared,differences,first_offset,expected,actual; };
#include "resident_rx_replace_control.inc"
struct r3o_state {
    unsigned phase,busy,active,consumed,released,exit_seen,first_error,registry_bound;
    long first_detail;
    uint64_t serial,publications,entries,completed,cancelled,unexpected,ingresses;
    uintptr_t arena,directory,root;
    unsigned count,planned,exit_member,exit_index,registry_count;
    struct li2_r3_token token;
    struct li2_rsl_ref source;
    struct li2_rsl_content_ref content;
    struct li2_rsl_generation_progress generation_progress;
    unsigned source_pages;
    uint64_t flags,gpr_written,flags_written;
    unsigned references[3],closed[3],installed[3];
    uint64_t generation[3];
    struct li2_fetch_progress fetch;
    struct li2_r3_rseq_progress rseq;
    struct li2_rsl_progress source_progress;
    struct li2_rsl_resident_progress resident_progress;
    struct li2_maps_stats maps;
    unsigned rx_lifetime;
    struct li2_fetch_progress rx_release;
    struct li2_r3_rx_progress rx_progress;
};
struct r3o_certificate {
    struct li2_sealed_identity identity;
    struct r3_payload payload;
    unsigned char proof_tail[R3_PROOF_BYTES-sizeof(struct r3_payload)];
    unsigned char code[R3_CODE_BYTES],slots[PAGE],spill_entered[PAGE],spill_closed[PAGE];
    struct li2_sealed_code_query published[3],opened[3],released[3],proof[2];
    struct li2_private_code_query slot_query[2],spill_query[2];
    struct r3o_scan proof_scan,code_scan,slot_scan;
};
struct r3o_wire {
    uint64_t h[48],ingress[6];
    uint64_t bootstrap[9];
    struct li2_rsl_resident_progress resident_before;
    struct li2_rsl_generation_progress generation_before;
    struct li2_r3_rx_progress rx_before;
    struct stat sink_initial,sink_terminal;
    struct image main,interpreter;
    __typeof__(selected_hardware) hardware;
    struct li2_step_session session;
    struct li2_span_transfer_progress transfer;
    struct li2_span_fetch_observation held;
    struct r3o_state entered,terminal,closed,handoff;
    struct le_frame before,after,next;
    struct li2_r3o_memory memory[3];
    struct li2_fork_range registry[RANGES];
    struct li2_pg_source_page source[LI2_RSL_PAGES];
    struct r3o_certificate certificate[3];
    unsigned char directory[LI2_JD_DOMAIN_BYTES];
    struct li2_private_code_query directory_query[2];
    struct r3o_scan directory_scan,unexpected_scan;
    struct li2_tf_chain_slot next_closed;
};
struct rrx_bundle {
    uint64_t h[16],ingress[6];
    struct r3o_state final;
    struct r3o_wire record[2];
    uint64_t control[16],mailbox_before[10],mailbox_after[10];
    struct li2_private_code_query mailbox_query;
    uint64_t attack_greg[23];
    unsigned char attack_si[128],attack_uc[968],metadata_before[16];
    struct li2_sealed_code_query final_code[3][3];
    int final_code_result[3];
    struct rrx_replace_control replacement;
};
static struct rrx_bundle rrx_bundle;
#define rrx_current_record (rrx_bundle.record[rrx_bundle.h[4]])

static unsigned r3o_ready,r3o_frozen,r3o_busy,r3o_finished;
static const uint64_t r3o_step_frame_fp_alignment __attribute__((used))=
    __alignof__(((struct li2_step_frame *)0)->fp);
_Static_assert(sizeof(struct rrx_bundle)+64<4U*1024U*1024U,"unchanged strict owned-record ceiling");
_Static_assert(sizeof(struct rrx_bundle)==4173888 && sizeof(struct r3o_wire)==2065920 &&
    sizeof(struct li2_r3_owner)==1247040 && sizeof(struct li2_r3_rx_progress)==184,
    "distinct complete RX observation layout");
static void r3o_callback(void) {
    if(r3o_frozen){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
static void rrx_arm(void);
static void rrx_stale(void);
static void rrx_attack(int,const siginfo_t *,const ucontext_t *);
static void r3o_copy(void *to,const void *from,size_t n) {
    unsigned char *d=to;const volatile unsigned char *s=from;
    for(size_t i=0;i<n;i++)d[i]=s[i];
}
static void r3o_compare(struct r3o_scan *o,const void *expected,const void *actual,size_t bytes) {
    const unsigned char *a=expected;const volatile unsigned char *b=actual;
    for(size_t i=0;i<bytes;i++) {
        unsigned char x=b[i],y=a?a[i]:0;
        if(x!=y){if(!o->differences){o->first_offset=o->compared;o->expected=y;o->actual=x;}++o->differences;}
        ++o->compared;
    }
    r3_need(!o->differences,R3_RESULT,110);
}
#define LI2_RRX_REPLACE_IMPLEMENTATION 1
#include "resident_rx_replace_control.inc"
#undef LI2_RRX_REPLACE_IMPLEMENTATION
/* The old two-member owner may have rebound source after the last guest RAW.
   Retain its complete actual progress immediately before the real D3 bind;
   this copy supplies no token, validation or source permission. */
static void r3o_source_before_bind(void) {
    r3o_callback();
    r3_need(r3o_ready && !r3o_busy && rrx_bundle.h[5]<2 &&
        r3.serial==rrx_bundle.h[5]+1 && rrx_bundle.h[6]==rrx_bundle.h[5],R3_STATE,126);
    if(rrx_bundle.h[5])r3_need(rrx_bundle.record[0].h[27]==1 &&
        r3.publications==3 && r3.entries==1 && r3.completed==1,R3_STATE,126);
    rrx_bundle.h[4]=rrx_bundle.h[5];uint64_t *h=rrx_current_record.h;
    _Static_assert(sizeof(struct li2_rsl_progress)==7U*sizeof(uint64_t),
        "whole source progress occupies the seven reserved header words");
    r3_need(!h[24] && !h[41] && r3.phase==LI2_R3_HELD && r3.busy && !r3.active &&
        !r3.consumed && r3.publications==(rrx_bundle.h[4]?3U:0U) &&
        r3.entries==rrx_bundle.h[4] && r3.completed==rrx_bundle.h[4],R3_STATE,126);
    const struct li2_rsl_progress *p=li2_rsl_progress();
    const struct li2_rsl_resident_progress *r=li2_rsl_resident_progress();
    r3_need(p->initialized==1 && p->valid<=1 && p->epoch && !p->reserved &&
        p->pages && p->pages<=LI2_RSL_PAGES && p->bindings<UINT64_MAX &&
        r->last_serial==rrx_bundle.h[4] && r->bindings==rrx_bundle.h[4] &&
        r->snapshots==rrx_bundle.h[4],R3_SOURCE,127);
    r3o_copy(h+41,p,sizeof *p);
    r3o_copy(&rrx_current_record.resident_before,r,sizeof *r);
    r3o_copy(&rrx_current_record.generation_before,li2_rsl_generation_progress(),sizeof rrx_current_record.generation_before);
    r3o_copy(&rrx_current_record.rx_before,li2_r3_rx_progress(),sizeof rrx_current_record.rx_before);
    r3o_copy(rrx_current_record.ingress,rrx_bundle.ingress,sizeof rrx_current_record.ingress);
    rrx_stale();
}
static void r3o_state(struct r3o_state *o) {
#define O(n) o->n=r3.n
    O(phase);O(busy);O(active);O(consumed);O(released);O(exit_seen);O(first_error);O(first_detail);
    O(registry_bound);O(serial);O(publications);O(entries);O(completed);O(cancelled);O(unexpected);O(ingresses);
    O(arena);O(directory);O(root);O(count);O(planned);O(exit_member);O(exit_index);O(registry_count);
    O(token);O(source);O(content);O(source_pages);O(flags);O(gpr_written);O(flags_written);
#undef O
    for(unsigned i=0;i<3;i++) {
        o->references[i]=r3.certificate[i].active_refs;o->closed[i]=r3.certificate[i].closed;
        o->installed[i]=r3.certificate[i].installed;o->generation[i]=r3.certificate[i].generation;
    }
    r3o_copy(&o->fetch,li2_lifecycle_fetch_progress(),sizeof o->fetch);
    r3o_copy(&o->rseq,li2_r3_rseq_progress(),sizeof o->rseq);
    r3o_copy(&o->source_progress,li2_rsl_progress(),sizeof o->source_progress);
    r3o_copy(&o->resident_progress,li2_rsl_resident_progress(),sizeof o->resident_progress);
    r3o_copy(&o->generation_progress,li2_rsl_generation_progress(),sizeof o->generation_progress);
    li2_maps_stats_read(&o->maps);
    o->rx_lifetime=r3.rx_lifetime;o->rx_release=r3.rx_release;
    r3o_copy(&o->rx_progress,li2_r3_rx_progress(),sizeof o->rx_progress);
}
static void r3o_memory(unsigned site) {
    r3_need(site<3 && !li2_lifecycle_r3o_memory(rrx_current_record.h[22],site,&rrx_current_record.memory[site]),R3_FRAME,111);
    const struct li2_r3o_stack *a=&rrx_current_record.memory[0].origin,*b=&rrx_current_record.memory[site].origin;
    r3_need(a->anchor==b->anchor && a->origin_first==b->origin_first && a->origin_end==b->origin_end &&
        a->origin_acquisition==b->origin_acquisition && a->first==b->first && a->end==b->end &&
        a->first==rrx_current_record.h[22]-256 && a->end==rrx_current_record.h[22]+264,R3_FRAME,112);
    if(site)r3_need(equal(rrx_current_record.memory[0].stack,rrx_current_record.memory[site].stack,520),R3_RESULT,113);
}
/* Test-only observations and causal changes. No address or result below is
   accepted by a production authority predicate. Positive case0 never writes
   a guest mailbox or changes source/content state. */
static void rrx_arm(void) {
    if(!LI2_RRX_CASE)return;
    uintptr_t at=LI2_RRX_MAILBOX,first=at&~(PAGE-1),end=(at+80+PAGE-1)&~(PAGE-1);
    r3_need(LI2_RRX_CASE<=7 && LI2_RRX_MAILBOX_BYTES==80 && at>=PAGE &&
        at<(UINT64_C(1)<<47)-80 && r3.completed==1 && r3.entries==1 &&
        r3.rx_lifetime==LI2_R3_RX_RESIDENT && !r3.active && !r3.busy &&
        !rrx_bundle.control[2] && r3_registry(),R3_STATE,132);
    for(unsigned i=0;i<r3.registry_count;i++)
        r3_need(!(at<r3.registry[i].end && r3.registry[i].first<at+80),R3_STATE,133);
    r3_need(!li2_lifecycle_private_code_query(first,end-first,PROT_READ|PROT_WRITE,
        &rrx_bundle.mailbox_query),R3_STATE,134);
    r3o_copy(rrx_bundle.mailbox_before,(const void *)at,80);
    const uint64_t *v=rrx_bundle.mailbox_before;
    r3_need(v[0]==UINT64_C(0x315852524d32494c) && v[1]==LI2_RRX_CASE &&
        !v[2] && !v[3] && !v[4] && !v[5] && !v[7] && !v[8] && !v[9] &&
        (LI2_RRX_CASE==4?(v[6]>0 && v[6]<=INT32_MAX):!v[6]),R3_STATE,135);
    volatile uint64_t *out=(void *)at;
    out[3]=r3.certificate[0].identity.code+1;out[4]=r3.certificate[0].proof;
    out[5]=LI2_RRX_SOURCE_OFFSET;out[2]=1;
    r3o_copy(rrx_bundle.metadata_before,(const void *)(uintptr_t)out[4],16);
    rrx_bundle.control[2]=1;rrx_bundle.control[8]=1;
}
static void rrx_stale(void) {
    if(LI2_RRX_CASE!=5 || !rrx_bundle.h[4])return;
    r3_need(rrx_bundle.h[5]==1 && rrx_bundle.h[6]==1 && r3.serial==2 &&
        r3.phase==LI2_R3_HELD && r3.busy && !r3.active && !r3.consumed &&
        r3.completed==1 && r3.entries==1 && rrx_bundle.control[2]==1 &&
        !rrx_bundle.control[4] && r3.content.generation &&
        r3.content.generation<UINT64_MAX,R3_STATE,136);
    rrx_bundle.control[4]=1;rrx_bundle.control[5]=r3.content.generation;
    ++r3.content.generation;rrx_bundle.control[6]=r3.content.generation;
}
static void rrx_attack(int sig,const siginfo_t *si,const ucontext_t *uc) {
    if(!LI2_RRX_CASE || !rrx_bundle.control[2] || !si || !uc)return;
    uintptr_t pc=(uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    if(LI2_RRX_CASE==4 && pc==LI2_RRX_AFTER_ATTACK) {
        ++rrx_bundle.control[11];rrx_bundle.control[12]=(uint64_t)uc->uc_mcontext.gregs[REG_RAX];
        rrx_bundle.control[13]=pc;
    }
    uintptr_t expected=LI2_RRX_CASE==1?r3.certificate[0].identity.code+1:LI2_RRX_ATTACK;
    if(!expected || pc!=expected)return;
    ++rrx_bundle.control[3];
    if(rrx_bundle.control[3]!=1)return;
    r3o_copy(rrx_bundle.attack_greg,uc->uc_mcontext.gregs,sizeof rrx_bundle.attack_greg);
    r3o_copy(rrx_bundle.attack_si,si,sizeof rrx_bundle.attack_si);
    r3o_copy(rrx_bundle.attack_uc,uc,sizeof rrx_bundle.attack_uc);
    (void)sig;
}
static void r3o_initialize(void) {
    r3o_callback();__asm__ volatile(""::"r"(&r3o_step_frame_fp_alignment):"memory");
    r3_need(!r3o_ready && !r3o_finished && !r3.initialized && !original_main.bias,R3_STATE,100);
    const uint64_t initial[]={UINT64_C(0x314258525732494c),1,sizeof rrx_bundle,
        sizeof(struct r3o_wire),0,0,0,2,0,0,0,0,0,0,0,sizeof r3};
    r3o_copy(rrx_bundle.h,initial,sizeof initial);
    r3_need(!selected_run_protect_add(0,(uintptr_t)&rrx_bundle,sizeof rrx_bundle),R3_STATE,101);
    for(unsigned ordinal=0;ordinal<2;ordinal++) {
    rrx_bundle.h[4]=ordinal;uint64_t *h=rrx_current_record.h;
    h[0]=R3O_MAGIC;h[1]=1;h[2]=sizeof rrx_current_record;h[3]=sizeof r3;h[4]=sizeof(struct r3_payload);
    h[5]=R3_PROOF_BYTES;h[6]=R3_CODE_BYTES;h[7]=sizeof(ucontext_t);h[8]=sizeof(siginfo_t);
    h[9]=(uintptr_t)&r3;h[10]=(uintptr_t)&rrx_current_record;h[11]=(uintptr_t)&selected_chain;
    h[12]=(uintptr_t)fork_gate_stack.ss_sp;h[13]=fork_gate_stack.ss_size;
    h[14]=1;
    long fdflags=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long result=raw(SYS_fstat,3,(long)&rrx_current_record.sink_initial,0,0,0,0);
    h[15]=(uint64_t)fdflags;h[16]=(uint64_t)flags;h[17]=(uint64_t)result;
    r3_need(fdflags==0 && flags>=0 && (flags&(O_ACCMODE|O_APPEND|O_NONBLOCK))==O_WRONLY && !result &&
        S_ISREG(rrx_current_record.sink_initial.st_mode) && (rrx_current_record.sink_initial.st_mode&07777)==0600 &&
        rrx_current_record.sink_initial.st_nlink==1 && !rrx_current_record.sink_initial.st_size,R3_STATE,102);h[18]=1;
    h[19]=LI2_R3_ROOT_RVA;h[20]=LI2_R3_TERMINAL_RVA;h[21]=LI2_R3_CAPTURE_RVA;
    h[23]=LI2_R3_CAPTURE_POINTER_RVA;
    r3o_copy(&rrx_current_record.main,&original_main,sizeof original_main);
    r3o_copy(&rrx_current_record.interpreter,&original_interpreter,sizeof original_interpreter);
    r3o_copy(&rrx_current_record.hardware,&selected_hardware,sizeof selected_hardware);
    r3o_copy(&rrx_current_record.session,&selected_session,sizeof selected_session);
    r3o_copy(rrx_current_record.bootstrap,rsl_initialization,sizeof rrx_current_record.bootstrap);
    const uint64_t *boot=rrx_current_record.bootstrap;
    r3_need(selected_session.pid>0 && selected_session.pid==selected_session.tid &&
        boot[0]==(uint64_t)selected_session.pid && boot[1]==boot[0] && boot[2]==boot[0] &&
        boot[3]==boot[0] && boot[4]==boot[0] && !boot[5] && !boot[6] &&
        boot[7]==3*sizeof(uintptr_t) && boot[8]==1,R3_STATE,125);
    }
    rrx_bundle.h[4]=0;rrx_bundle.control[0]=1;rrx_bundle.control[1]=LI2_RRX_CASE;r3o_ready=1;
}
static void r3o_ingress(int sig,siginfo_t *si,ucontext_t *uc) {
    r3o_callback();if(!r3o_ready)return;
    r3_need(!r3o_busy && rrx_bundle.ingress[0]!=UINT64_MAX,R3_STATE,103);
    ++rrx_bundle.ingress[0];unsigned i=sig==SIGSEGV?1U:sig==SIGTRAP?2U:sig==SIGILL?3U:sig==SIGSYS?4U:5U;
    r3_need(rrx_bundle.ingress[i]!=UINT64_MAX,R3_STATE,104);++rrx_bundle.ingress[i];
    rrx_attack(sig,si,uc);
    if(rrx_current_record.h[27])return;
    r3o_copy(rrx_current_record.ingress,rrx_bundle.ingress,sizeof rrx_current_record.ingress);
    uint64_t *h=rrx_current_record.h;
    if(h[25] && !h[26]) {
        r3_need(!handling && uc && si && r3.phase==LI2_R3_DRAINED && !r3.active && !r3.busy &&
            rrx_current_record.ingress[0]==h[29]+1 && selected_pending_route==SELECTED_GENERIC_TF &&
            selected_step_pending==1 && selected_chain.active>=0 && selected_chain.active<2 &&
            sig==SIGTRAP && si->si_signo==SIGTRAP && si->si_code==TRAP_TRACE && !si->si_errno &&
            (uintptr_t)si->si_addr==h[21] && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[21] &&
            uc->uc_mcontext.gregs[REG_TRAPNO]==1 && !uc->uc_mcontext.gregs[REG_ERR] &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_CR2]==h[20] &&
            (uintptr_t)uc->uc_mcontext.gregs[REG_RSP]==h[22] &&
            (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==(UINT64_C(0x246)|SELECTED_TF),R3_EVENT,105);
        r3_need(!le_capture(&rrx_current_record.next,sig,si,uc),R3_FRAME,106);
        h[26]=1;h[30]=rrx_current_record.ingress[0];h[31]=(uint64_t)selected_chain.active;
    }
}
static void r3o_entered(const siginfo_t *si,const ucontext_t *uc) {
    r3o_callback();uint64_t *h=rrx_current_record.h;
    r3_need(r3o_ready && !r3o_busy && !h[24] && !h[25] && r3.phase==LI2_R3_ACTIVE &&
        r3.active==1 && r3.busy==1 && r3.serial==rrx_bundle.h[4]+1 && r3.count==3 && r3.planned==3 &&
        r3.publications==3 && r3.entries==rrx_bundle.h[4]+1 &&
        r3.completed==rrx_bundle.h[4] && r3.ingresses==rrx_bundle.h[4] && !r3.unexpected &&
        r3.consumed==1 && !r3.released && r3.registry_bound==1 && r3_registry() &&
        r3.before.complete==1 && r3.before.tls_complete==1 && le_unchanged(&r3.before,si,uc) &&
        r3.transfer.phase==LI2_ST_CONSUMED && r3.transfer.consumed==1 &&
        r3.source_pages>0 && r3.source_pages<=LI2_RSL_PAGES &&
        r3.root==h[19] && (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==h[19] &&
        (uint64_t)uc->uc_mcontext.gregs[REG_EFL]==UINT64_C(0xad7) &&
        uc->uc_mcontext.gregs[REG_RAX]==1 && uc->uc_mcontext.gregs[REG_RCX]==4 &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_R11]==h[23] &&
        selected_pending_route==SELECTED_RESIDENT_THREE && selected_step_pending==1,R3_STATE,114);
    r3o_busy=1;h[22]=(uintptr_t)uc->uc_mcontext.gregs[REG_RSP];h[28]=rrx_current_record.ingress[0];
    r3o_copy(&rrx_current_record.before,&r3.before,sizeof r3.before);
    r3o_copy(&rrx_current_record.transfer,&r3.transfer,sizeof r3.transfer);
    r3o_copy(&rrx_current_record.held,&r3.fetch,sizeof r3.fetch);
    r3o_copy(rrx_current_record.registry,r3.registry,r3.registry_count*sizeof *r3.registry);
    for(unsigned i=0;i<r3.source_pages;i++)
        r3_need(!li2_rsl_page_at(&r3.source,i,&rrx_current_record.source[i]),R3_SOURCE,115);
    for(unsigned i=0;i<3;i++) {
        const struct r3_certificate *c=&r3.certificate[i];struct r3o_certificate *o=&rrx_current_record.certificate[i];
        r3_need(c->active_refs==1 && !c->closed && c->installed==1 && c->generation==i+1 &&
            !r3_bytes(i),R3_PUBLICATION,116);
        r3o_copy(&o->identity,&c->identity,sizeof o->identity);
        r3o_copy(&o->payload,(const void *)c->proof,sizeof o->payload);
        r3o_copy(o->proof_tail,(const void *)(c->proof+sizeof o->payload),sizeof o->proof_tail);
        r3o_copy(o->code,(const void *)c->identity.code,sizeof o->code);
        r3_need(!li2_lifecycle_private_code_query(c->layout.slots,PAGE,PROT_READ,&o->slot_query[0]) &&
            !li2_lifecycle_private_code_query(c->layout.spill,PAGE,PROT_READ|PROT_WRITE,&o->spill_query[0]),
            R3_PUBLICATION,117);
        r3o_copy(o->slots,(const void *)c->layout.slots,PAGE);
        r3o_copy(o->spill_entered,(const void *)c->layout.spill,PAGE);
        r3o_copy(o->published,c->published,sizeof o->published);
        r3_need(!r3_code_query(i,PROT_READ|PROT_EXEC,o->opened),R3_PUBLICATION,130);
        r3o_copy(o->proof,c->proof_query,sizeof o->proof);
    }
    r3_need(!li2_lifecycle_private_code_query(r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,
        &rrx_current_record.directory_query[0]) && r3_directory_equal(),R3_PUBLICATION,118);
    r3o_copy(rrx_current_record.directory,(const void *)r3.directory,LI2_JD_DOMAIN_BYTES);
    r3o_memory(0);r3o_state(&rrx_current_record.entered);h[24]=1;
    r3_need(rrx_bundle.h[6]==rrx_bundle.h[4],R3_STATE,128);
    ++rrx_bundle.h[6];r3o_busy=0;
}
static void r3o_terminal(void) {
    r3o_callback();uint64_t *h=rrx_current_record.h;
    r3_need(r3o_ready && !r3o_busy && h[24]==1 && !h[25] && !h[26] &&
        r3.phase==LI2_R3_DRAINED && !r3.busy && !r3.active && r3.serial==rrx_bundle.h[4]+1 &&
        r3.publications==3 && r3.entries==rrx_bundle.h[4]+1 &&
        r3.completed==rrx_bundle.h[4]+1 && r3.ingresses==rrx_bundle.h[4]+1 &&
        !r3.unexpected && !r3.first_error && r3.consumed==1 && r3.released==1 &&
        r3.exit_seen==1 && r3_registry() && rrx_current_record.ingress[0]==h[28]+1 &&
        r3.after.complete && r3.after.tls_complete && r3.after.sig==SIGSEGV &&
        (uintptr_t)r3.after.frame.greg[REG_RIP]==h[20] &&
        (uintptr_t)r3.after.frame.greg[REG_RSP]==h[22] &&
        r3.after.frame.greg[REG_RAX]==29 && !r3.after.frame.greg[REG_RCX] &&
        (uint64_t)r3.after.frame.greg[REG_EFL]==(UINT64_C(0x246)|SELECTED_RF) &&
        selected_pending_route==SELECTED_NO_STEP && !selected_step_pending,R3_STATE,119);
    r3o_busy=1;r3o_copy(&rrx_current_record.after,&r3.after,sizeof r3.after);
    for(unsigned i=0;i<3;i++) {
        const struct r3_certificate *c=&r3.certificate[i];struct r3o_certificate *o=&rrx_current_record.certificate[i];
        r3_need(!c->active_refs && !c->closed && c->generation==i+1 &&
            equal(&o->identity,&c->identity,sizeof o->identity),R3_PUBLICATION,120);
        r3_need(!r3_code_query(i,PROT_READ|PROT_EXEC,o->released),R3_PUBLICATION,131);
        r3o_compare(&o->proof_scan,&o->payload,(const void *)c->proof,sizeof o->payload);
        r3o_compare(&o->proof_scan,o->proof_tail,(const void *)(c->proof+sizeof o->payload),sizeof o->proof_tail);
        r3o_compare(&o->code_scan,o->code,(const void *)c->identity.code,R3_CODE_BYTES);
        r3o_compare(&o->slot_scan,o->slots,(const void *)c->layout.slots,PAGE);
        r3_need(!li2_lifecycle_private_code_query(c->layout.slots,PAGE,PROT_READ,&o->slot_query[1]) &&
            !li2_lifecycle_private_code_query(c->layout.spill,PAGE,PROT_READ|PROT_WRITE,&o->spill_query[1]),
            R3_PUBLICATION,121);
        r3o_copy(o->spill_closed,(const void *)c->layout.spill,PAGE);
    }
    r3_need(!li2_lifecycle_private_code_query(r3.directory,LI2_JD_DOMAIN_BYTES,PROT_READ,
        &rrx_current_record.directory_query[1]),R3_PUBLICATION,122);
    r3o_compare(&rrx_current_record.directory_scan,rrx_current_record.directory,(const void *)r3.directory,LI2_JD_DOMAIN_BYTES);
    r3o_memory(1);r3o_state(&rrx_current_record.terminal);h[29]=rrx_current_record.ingress[0];h[25]=1;r3o_busy=0;
    if(!rrx_bundle.h[4]){rrx_arm();rrx_replace();}
}
void li2_r3o_trace_closed(const struct li2_tf_chain *chain,const struct li2_tf_chain_slot *slot) {
    r3o_callback();if(!r3o_ready || !rrx_current_record.h[25] || rrx_current_record.h[27])return;
    uint64_t *h=rrx_current_record.h;unsigned selected=(unsigned)h[31];
    r3_need(!r3o_busy && h[26]==1 && selected<2 && h[30]==h[29]+1 &&
        h[30]==rrx_current_record.ingress[0] && chain==&selected_chain && slot==&chain->slots[selected] &&
        chain->active==(int)selected && chain->in_handler==1 && chain->pending==1 && handling==1 &&
        chain->event_id>slot->event_id && !chain->first_error && !chain->unexpected_events &&
        slot->phase==LI2_CHAIN_CLOSED && !slot->unexpected_frame_observed &&
        slot->decoded.pc==h[20] && slot->owner.actual_post_pc==h[21] &&
        rrx_current_record.next.complete && (uintptr_t)rrx_current_record.next.frame.greg[REG_RIP]==h[21],R3_STATE,123);
    r3o_busy=1;r3o_copy(&rrx_current_record.next_closed,slot,sizeof *slot);
    r3o_compare(&rrx_current_record.unexpected_scan,0,&slot->unexpected,sizeof slot->unexpected);
    r3_tls(&rrx_current_record.next);r3o_memory(2);r3o_state(&rrx_current_record.closed);
    r3o_state(&rrx_current_record.handoff);
    h[27]=1;h[32]=chain->event_id;
    r3_need(rrx_bundle.h[5]==rrx_bundle.h[4] && rrx_bundle.h[6]==rrx_bundle.h[4]+1,
        R3_STATE,129);++rrx_bundle.h[5];r3o_busy=0;
}
static void r3o_finish(unsigned status,unsigned code,long detail) {
    if(!r3o_ready || r3o_finished)return;
    r3o_finished=1;unsigned incomplete=rrx_bundle.h[4]!=1 || rrx_bundle.h[5]!=2 ||
        rrx_bundle.h[6]!=2 || r3o_busy || r3.publications!=3 || r3.entries!=2 ||
        r3.completed!=2 || r3.ingresses!=2 || r3.active || r3.busy ||
        r3.first_error || r3.unexpected;
    for(unsigned i=0;i<2;i++) {
        const struct r3o_wire *o=&rrx_bundle.record[i];const uint64_t *h=o->h;
        incomplete|=h[24]!=1 || h[25]!=1 || h[26]!=1 || h[27]!=1 ||
            o->next.tls_complete!=1 || o->memory[2].complete!=1;
    }
    unsigned forced=!status && incomplete;
    if(forced){status=125;code=R3_STATE;detail=124;}
    rrx_bundle.h[8]=status;rrx_bundle.h[9]=code;rrx_bundle.h[10]=(uint64_t)detail;
    rrx_bundle.h[11]=1;rrx_bundle.h[12]=incomplete;
    r3o_state(&rrx_bundle.final);
    for(unsigned i=0;i<3;i++)if(r3.certificate[i].identity.code_live)
        rrx_bundle.final_code_result[i]=r3_code_query(i,PROT_READ,rrx_bundle.final_code[i]);
    if(rrx_bundle.control[2]) {
        r3o_copy(rrx_bundle.mailbox_after,(const void *)(uintptr_t)LI2_RRX_MAILBOX,sizeof rrx_bundle.mailbox_after);
        const volatile unsigned char *p=(const void *)rrx_bundle.mailbox_after[4];
        rrx_bundle.control[9]=1;
        for(unsigned i=0;i<16;i++)rrx_bundle.control[10]+=p[i]!=rrx_bundle.metadata_before[i];
    }
    rrx_bundle.control[14]=status;
    long flags=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);unsigned sink_ok=1;long result=0;
    for(unsigned i=0;i<2;i++) {
        struct r3o_wire *o=&rrx_bundle.record[i];uint64_t *h=o->h;
        h[33]=incomplete;h[34]=status;h[35]=code;h[36]=(uint64_t)detail;h[37]=1;
        result=raw(SYS_fstat,3,(long)&o->sink_terminal,0,0,0,0);
        h[38]=(uint64_t)flags;h[39]=(uint64_t)result;
        const struct stat *a=&o->sink_initial,*b=&o->sink_terminal;
        unsigned ok=!result && flags==(long)h[16] && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
            a->st_mode==b->st_mode && a->st_uid==b->st_uid && a->st_gid==b->st_gid &&
            a->st_nlink==b->st_nlink && !b->st_size;
        h[40]=ok;sink_ok&=ok;
    }
    if(sink_ok) {
        rrx_bundle.h[14]=1;r3o_frozen=1;__asm__ volatile("":::"memory");
        size_t at=0;uint64_t calls=0;result=0;
        while(at<sizeof rrx_bundle && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)&rrx_bundle+at),sizeof rrx_bundle-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof rrx_bundle-at)goto done;
            at+=(size_t)result;
        }
        if(at!=sizeof rrx_bundle)goto done;
        const uint64_t footer[]={R3O_FOOTER,1,sizeof rrx_bundle,at,calls,(uint64_t)result,status,code};
        at=0;calls=0;
        while(at<sizeof footer && calls<64) {
            ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
            if(result<=0 || (size_t)result>sizeof footer-at)goto done;
            at+=(size_t)result;
        }
    }
done:
    if(forced || !sink_ok){(void)li2_raw6(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();}
}
#undef rrx_current_record
