/* Test-only by-value observation of genuine CACHE8 activations. These fields
   never participate in publication, membership, dispatch or source authority. */
#include "loop_cache8_observe.h"
#define LC8O_MAGIC UINT64_C(0x314f38434132494c)
#define LC8O_FOOTER UINT64_C(0x314638434132494c)
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
#include "loop_group_descriptor_observe.h"
enum { LC8O_EPOCHS=5,LC8O_CONTROLS=24,LC8O_STOP=8971 };
#else
enum { LC8O_EPOCHS=4,LC8O_CONTROLS=24,LC8O_STOP=8971 };
#endif
struct lc8o_frame {
    uint64_t h[16],greg[23];
    unsigned char si[128],uc[968],fp[65536];
};
struct lc8o_member {
    uint64_t h[24];
    struct li2_pg_source_key key;
    uint64_t head[128];
};
struct lc8o_epoch {
    uint64_t h[32],counts[4][32];
    struct lc8o_member member[8];
    unsigned char directory[12288];
    struct lc8o_frame entry,event;
};
struct lc8o_wire {
    uint64_t h[32];
    struct stat initial,terminal;
    struct lc8o_epoch epoch[LC8O_EPOCHS];
    uint64_t controls[LC8O_CONTROLS][4];
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    struct lgdo_wire descriptor;
#endif
};
_Static_assert(LI2_PTR_SLOTS==8 && LI2_PGD_MEMBERS==8 && LI2_PGD_RECEIPTS==9 &&
    LI2_PG_HEADS==128 && LI2_JD_DOMAIN_BYTES==12288 && sizeof(struct li2_pg_source_key)==8760,
    "distinct cache8 dimensions, original plan and directory bounds");
_Static_assert(sizeof(siginfo_t)==128 && sizeof(ucontext_t)==968 && sizeof(struct stat)==144 &&
    sizeof(struct lc8o_frame)==66944 && sizeof(struct lc8o_member)==9976 &&
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    sizeof(struct lc8o_epoch)==227264 && sizeof(struct lc8o_wire)==1186576,
#else
    sizeof(struct lc8o_epoch)==227264 && sizeof(struct lc8o_wire)==910368,
#endif
    "literal independently read cache8 wire");
_Static_assert(sizeof(struct lc8o_wire)+64<4U*1024U*1024U,"unchanged bounded record capacity");
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
/* Read from the actual readonly ELF by the existing build inspection. These
   offsets describe compiler layout and never participate in runtime policy. */
const uint64_t li2_lgdo_layout[] __attribute__((used,visibility("hidden")))={
    2,sizeof(struct lc8o_wire),sizeof(struct lc8o_epoch),offsetof(struct lc8o_wire,descriptor),
    sizeof(struct lgdo_wire),sizeof(struct lgdo_snapshot),sizeof(struct lgdo_raw),
    sizeof(struct li2_private_code_query),sizeof(struct le_permission),sizeof(struct pda_completion),
    offsetof(struct li2_pg_epoch,domain)+offsetof(struct pda_state,completion),
    offsetof(struct lhc_storage,capsule),sizeof(union lhc_capsule),sizeof lgd_group,
    sizeof pe,sizeof lhc,sizeof lgd_writer,LC8O_EPOCHS,
    sizeof lhc.root,sizeof(union lhc_certificate_page),offsetof(struct lhc_root,cell),
    sizeof(struct lhc_certificate),sizeof(struct lgd_common_token)};
#endif
static struct {
    struct lc8o_wire wire;
    struct le_frame scratch;
    unsigned initialized,active,epochs,failure,busy,reported,controls,restorations;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    struct lgdo_preentry_observation preentry;
    struct lgdo_common_observation common;
    struct lgdo_isolation_observation isolation;
    struct lhc_certificate isolation_certificate;
    uint64_t isolation_epoch[4];
#endif
#if LI2_LOOP_CACHE8_CONTROL == 1 || (defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) && LI2_LOOP_CACHE8_CONTROL != 0)
    struct li2_pgd_view saved_view;
    struct li2_pgs_entry saved_entry;
    struct pda_completion saved_completion;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    union lgdo_saved descriptor_saved;
#endif
#endif
} lc8o;
static _Noreturn void lc8o_fail(unsigned code) {
    if(!lc8o.failure)lc8o.failure=code;
    selected_persistent_abort(PE_PUBLICATION,9000+(long)code);
}
static void lc8o_need(int value,unsigned code) {if(!value)lc8o_fail(code);}
static void lc8o_counts(uint64_t out[32]) {
    out[0]=*PGC_EVENT_REF;for(unsigned i=0;i<5;i++)out[1+i]=*PGC_SIGNAL_REF(i);
    const uint64_t owner[]={PGC_VALUE(publications),PGC_VALUE(cold_attempts),PGC_VALUE(hits),
        PGC_VALUE(offers),PGC_VALUE(entries),PGC_VALUE(completed)};
    copy(out+6,owner,sizeof owner);
    const uint64_t rx[]={pe.rx.code_opens,pe.rx.code_revokes,pe.rx.code_writes,pe.rx.code_syncs,
        pe.rx.metadata_permissions,pe.rx.metadata_syncs,pe.rx.retained_entries};
    copy(out+12,rx,sizeof rx);
    const struct li2_loop_cache8_progress *p=li2_loop_cache8_progress();
    const uint64_t cache[]={p->cold_calls,p->compact_build_calls,p->compact_validate_calls,
        p->attach_attempts,p->accepted,p->source_declines};copy(out+19,cache,sizeof cache);
}
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
#include "loop_group_descriptor_observe.inc"
#endif
static void lc8o_frame(struct lc8o_frame *out,const struct le_frame *in,
                      const siginfo_t *si,const ucontext_t *uc) {
    lc8o_need(!out->h[0] && in->started==1 && in->si_saved==1 && in->uc_saved==1 &&
        in->complete==1 && in->frame.fp_bytes>=580 && in->frame.fp_bytes<=65536 &&
        in->frame.initialized==in->frame.fp_bytes,1);
    uint64_t *h=out->h;
    h[0]=1;h[1]=(unsigned)in->sig;h[2]=(uintptr_t)si;h[3]=(uintptr_t)uc;
    h[4]=in->frame.fp_address;h[5]=in->frame.fp_bytes;
    h[6]=(uintptr_t)fork_gate_stack.ss_sp;h[7]=fork_gate_stack.ss_size;
    h[8]=in->frame.mask;h[9]=in->tls_complete;h[10]=in->fs;h[11]=in->gs;
    h[12]=(uint64_t)in->fs_result;h[13]=(uint64_t)in->gs_result;
    copy(out->greg,in->frame.greg,sizeof out->greg);copy(out->si,&in->si,sizeof out->si);
    copy(out->uc,&in->uc,sizeof out->uc);copy(out->fp,in->frame.fp,sizeof out->fp);
}
static int lc8o_initialize(void) {
    if(lc8o.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lc8o,sizeof lc8o))return PE_STATE;
    uint64_t *h=lc8o.wire.h;
    long fd=raw(SYS_fcntl,3,F_GETFD,0,0,0,0),fl=raw(SYS_fcntl,3,F_GETFL,0,0,0,0);
    long st=raw(SYS_fstat,3,(long)&lc8o.wire.initial,0,0,0,0);
    if(fd || fl<0 || (fl&(O_ACCMODE|O_APPEND|O_NONBLOCK))!=O_WRONLY || st ||
       !S_ISREG(lc8o.wire.initial.st_mode) || (lc8o.wire.initial.st_mode&07777)!=0600 ||
       lc8o.wire.initial.st_nlink!=1 || lc8o.wire.initial.st_size)return PE_STATE;
    #ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    h[0]=LC8O_MAGIC;h[1]=2;h[2]=sizeof lc8o.wire;h[3]=sizeof(struct lc8o_epoch);
#else
    h[0]=LC8O_MAGIC;h[1]=1;h[2]=sizeof lc8o.wire;h[3]=sizeof(struct lc8o_epoch);
#endif
    h[4]=LI2_LOOP_CACHE8_CONTROL;h[5]=8;h[6]=8;h[7]=9;h[8]=LC8O_EPOCHS;
    h[9]=(uintptr_t)&pe;h[10]=(uintptr_t)&lc8o;
    h[11]=(uint64_t)fd;h[12]=(uint64_t)fl;h[13]=(uint64_t)st;
    h[14]=(uintptr_t)fork_gate_stack.ss_sp;h[15]=fork_gate_stack.ss_size;
#ifdef LI2_LOOP_CACHE8_EFFECTS
    if(lc8e_initialize())return PE_STATE;
    h[1]=2;
#endif
    lc8o.initialized=1;return 0;
}
#if LI2_LOOP_CACHE8_CONTROL == 1 || (defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) && LI2_LOOP_CACHE8_CONTROL != 0)
static void lc8o_result(unsigned index,int value,int restored) {
    lc8o_need(index==lc8o.controls && index<LC8O_CONTROLS && value==0 && restored==1,2);
    uint64_t *r=lc8o.wire.controls[index];r[0]=index;r[1]=0;r[2]=(unsigned)value;r[3]=1;
    ++lc8o.controls;++lc8o.restorations;
}
static void lc8o_bound_controls(void) {
    if(lc8o.epochs!=2 || lc8o.controls)return;
    lc8o_need(pe.domain.work.view.count==3 && pda_ready(0),3);
    lc8o.busy=1;lc8o.saved_view=pe.domain.work.view;lc8o.saved_entry=pe.entry;
    for(unsigned kind=0;kind<12;kind++) {
        struct li2_pgd_view *v=&pe.domain.work.view;
        switch(kind) {
        case 0:v->member[2].identity.generation^=1;break;
        case 1:v->member[2].identity.slot=8;break;
        case 2:v->member[2].identity.bank=2;break;
        case 3:v->member[2].identity.proof^=PAGE;break;
        case 4:v->member[2].identity.layout.generated[0]^=PAGE;break;
        case 5:v->member[2].key=v->member[1].key;break;
        case 6:v->count=9;break;
        case 7:++pe.entry.target.pc;v->entry=pe.entry;break;
        case 8:pe.entry.generation^=1;v->entry=pe.entry;break;
        case 9:++pe.entry.target.generated;v->entry=pe.entry;break;
        case 10:pe.entry.target.head=128;v->entry=pe.entry;break;
        default:pe.entry.complete=0;v->entry=pe.entry;break;
        }
        int refused=pda_ready(0);
        pe.domain.work.view=lc8o.saved_view;pe.entry=lc8o.saved_entry;
        lc8o_need(equal(&pe.domain.work.view,&lc8o.saved_view,sizeof lc8o.saved_view) &&
            equal(&pe.entry,&lc8o.saved_entry,sizeof lc8o.saved_entry),4);
        lc8o_result(kind,refused,pda_ready(0));
    }
    lc8o.busy=0;
}
static void lc8o_completion_controls(const struct pda_completion *original) {
    if(lc8o.epochs!=3)return;
    lc8o_need(lc8o.controls==12 && original->count==3 && pda_receipt(original),5);
    lc8o.busy=1;copy(&lc8o.saved_completion,original,sizeof lc8o.saved_completion);
    struct pda_completion *c=(struct pda_completion *)original;
    for(unsigned kind=0;kind<12;kind++) {
        lc8o_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ|PROT_WRITE,0,0,0),6);
        switch(kind) {
        case 0:c->count=9;break;
        case 1:c->member[2].identity.generation^=1;break;
        case 2:c->member[2].source.page[0].bytes[0]^=1;break;
        case 3:c->member[2].source.page[1].bytes[0]^=1;break;
        case 4:c->member[2].source.page[0].identity.generation^=1;break;
        case 5:c->member[2].generation.generation^=1;break;
        case 6:c->member[2].generation.build_serial^=1;break;
        case 7:c->member[2].identity.proof^=PAGE;break;
        case 8:c->domain_source.ref[2].generation^=1;break;
        case 9:c->rseq.domain_ref[2].generation^=1;break;
        case 10:c->rx.source.ref[2].generation^=1;break;
        default:c->domain_source.peer[1].key.page[0].bytes[0]^=1;break;
        }
        lc8o_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ,0,0,0),7);
        int refused=pda_receipt(c);
        lc8o_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ|PROT_WRITE,0,0,0),8);
        copy(c,&lc8o.saved_completion,sizeof *c);
        lc8o_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ,0,0,0) &&
            equal(c,&lc8o.saved_completion,sizeof *c) && !lrc_readonly((uintptr_t)c,sizeof *c),9);
        int restored=pda_receipt(c);
        for(unsigned i=0;i<c->count;i++)restored=restored && pda_permitted(c->member[i].identity.slot);
        lc8o_result(12+kind,refused,restored);
    }
    lc8o.busy=0;
}
#endif
static void lc8o_bound(void) {
#ifdef LI2_LOOP_CACHE8_EFFECTS
    if(lc8o.epochs>=3){lc8e_bound();return;}
#endif
    uintptr_t entry=pe.domain.work.view.entry.target.pc;
    if(entry!=UINT64_C(0x410200) && entry!=UINT64_C(0x412400) &&
       entry!=UINT64_C(0x414600) && entry!=UINT64_C(0x416000))return;
    lc8o_need(lc8o.initialized && !lc8o.active && !lc8o.busy && lc8o.epochs<LC8O_EPOCHS,10);
    const struct li2_pgd_view *v=&pe.domain.work.view;
    lc8o_need(pda_ready(0) && v->count && v->count<=8,11);
#if LI2_LOOP_CACHE8_CONTROL == 1 || (defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) && LI2_LOOP_CACHE8_CONTROL != 0)
    lc8o_bound_controls();
#endif
    struct lc8o_epoch *e=&lc8o.wire.epoch[lc8o.epochs];uint64_t *h=e->h;
    h[0]=1;h[4]=entry;h[5]=pe.p.serial;h[6]=v->count;h[7]=pe.warm;
    h[8]=pe.selected_slot;h[9]=pe.selected_bank;h[10]=pe.domain.work.receipt;
    h[11]=v->directory;h[12]=pe.entry.generation;h[13]=pe.entry.build_serial;
    h[14]=pe.entry.target.root;h[15]=pe.entry.target.generated;h[16]=pe.entry.target.head;
    lc8o_counts(e->counts[0]);copy(e->directory,(void *)v->directory,sizeof e->directory);
    for(unsigned i=0;i<v->count;i++) {
        const struct li2_pgd_member *m=&v->member[i];const struct li2_pg_generation *g=&pe.retained[m->identity.slot].generation;
        struct lc8o_member *out=&e->member[i];uint64_t *w=out->h;
        lc8o_need(m->plan->heads && m->plan->heads<=128,12);
        w[0]=1;w[1]=m->identity.slot;w[2]=m->identity.bank;w[3]=m->identity.generation;
        w[4]=g->build_serial;w[5]=m->identity.root;w[6]=m->identity.proof;
        w[7]=m->plan->version;w[8]=m->plan->heads;w[9]=m->plan->exits;w[10]=m->plan->links;
        w[11]=m->key->entry;copy(w+12,&m->identity.layout,sizeof m->identity.layout);
        w[18]=g->ready_generation;w[19]=g->installed;w[20]=g->complete;w[21]=g->domain_refs;
        copy(&out->key,m->key,sizeof out->key);
        for(unsigned j=0;j<m->plan->heads;j++)out->head[j]=m->plan->original[j].decoded.pc;
    }
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lgdo_snapshot(lc8o.epochs,0);
#endif
    lc8o.active=lc8o.epochs+1;
}
static void lc8o_enter(void) {
#ifdef LI2_LOOP_CACHE8_EFFECTS
    if(lc8o.epochs>=3){lc8e_enter();return;}
#endif
    if(!lc8o.active)return;
    struct lc8o_epoch *e=&lc8o.wire.epoch[lc8o.active-1];
    lc8o_need(e->h[0]==1 && !e->h[1] && e->h[5]==pe.p.serial && pda_ready(1),13);
    e->h[1]=1;e->h[17]=pe.domain.work.rx_retained_mask;lc8o_counts(e->counts[1]);
    lc8o_frame(&e->entry,&pe.before,0,0);
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lgdo_snapshot(lc8o.active-1,1);
#endif
}
static void lc8o_preentry(int sig,const siginfo_t *si,const ucontext_t *uc) {
#ifdef LI2_LOOP_CACHE8_EFFECTS
    if(lc8o.epochs>=3){lc8e_preentry(sig,si,uc);return;}
#endif
    if(!lc8o.active)return;
    struct lc8o_epoch *e=&lc8o.wire.epoch[lc8o.active-1];
    lc8o_need(e->h[1]==1 && !e->h[2] && !lc8o.busy,14);
    e->h[2]=1;lc8o_counts(e->counts[2]);le_zero(&lc8o.scratch,sizeof lc8o.scratch);
    lc8o_need(!le_capture(&lc8o.scratch,sig,si,uc),15);
    lc8o_frame(&e->event,&lc8o.scratch,si,uc);
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lgdo_preentry(lc8o.active-1);
    lgdo_snapshot(lc8o.active-1,2);
#endif
}
static void lc8o_complete(const struct pda_completion *c) {
#ifdef LI2_LOOP_CACHE8_EFFECTS
    if(lc8o.epochs>=3){lc8e_completed(c);return;}
#endif
    if(!lc8o.active)return;
    struct lc8o_epoch *e=&lc8o.wire.epoch[lc8o.active-1];
    lc8o_need(e->h[2]==1 && !e->h[3] && c->serial==e->h[5] && c->count==e->h[6] &&
        c->complete==1 && pda_receipt(c),16);
    e->h[3]=1;e->h[18]=c->id;e->h[19]=c->rx.version;e->h[20]=c->rx.retained_mask;
    e->h[21]=pe.domain.work.exit_member;e->h[22]=pe.exit_index;e->h[23]=pe.exit_seen;
    e->h[24]=pe.recovery_complete;e->h[25]=pe.guest_data_fault;e->h[26]=pe.p.phase;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lc8o_counts(e->counts[3]);
    lgdo_snapshot(lc8o.active-1,3);
    ++lc8o.epochs;lc8o.active=0;
#else
    lc8o_counts(e->counts[3]);++lc8o.epochs;lc8o.active=0;
#endif
#ifdef LI2_LOOP_CACHE8_EFFECTS
    lc8e_completed_first(c);
#endif
#if LI2_LOOP_CACHE8_CONTROL == 1 || (defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) && LI2_LOOP_CACHE8_CONTROL != 0)
    lc8o_completion_controls(c);
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lgdo_finished(c);
#endif
    if(lc8o.epochs==LC8O_EPOCHS) {
        lc8o_need(lc8o.controls==LC8O_CONTROLS && lc8o.restorations==LC8O_CONTROLS && !lc8o.busy,17);
        selected_persistent_abort(PE_PUBLICATION,LC8O_STOP);
    }
#endif
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
#if LI2_LOOP_CACHE8_CONTROL == 0
    lgdo_finished(c);
#endif
#endif
}
static void lc8o_report(unsigned status,unsigned code) {
    if(!lc8o.initialized || lc8o.reported)return;
    lc8o.reported=1;uint64_t *h=lc8o.wire.h;
    h[16]=lc8o.epochs;h[17]=lc8o.active;h[18]=lc8o.failure;h[19]=lc8o.busy;
    h[20]=lc8o.controls;h[21]=lc8o.restorations;h[22]=status;h[23]=code;
    h[24]=pe.p.first_error;h[25]=(uint64_t)pe.p.first_detail;h[26]=pe_active;h[27]=pe_busy;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    lgdo_isolation_report(status,code);
    lgdo_common_report(status,code);
    lgdo_preentry_report(status,code);
#endif
    long fl=raw(SYS_fcntl,3,F_GETFL,0,0,0,0),st=raw(SYS_fstat,3,(long)&lc8o.wire.terminal,0,0,0,0);
    h[28]=(uint64_t)fl;h[29]=(uint64_t)st;h[30]=(uint64_t)pe.session.pid;h[31]=(uint64_t)pe.session.tid;
    const struct stat *a=&lc8o.wire.initial,*b=&lc8o.wire.terminal;
    if(st || fl!=(long)h[12] || a->st_dev!=b->st_dev || a->st_ino!=b->st_ino ||
       a->st_mode!=b->st_mode || a->st_uid!=b->st_uid || a->st_gid!=b->st_gid ||
       a->st_nlink!=b->st_nlink || b->st_size)return;
    size_t at=0;uint64_t calls=0;long result=0;
    while(at<sizeof lc8o.wire && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((unsigned char *)&lc8o.wire+at),sizeof lc8o.wire-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof lc8o.wire-at)return;
        at+=(size_t)result;
    }
    if(at!=sizeof lc8o.wire)return;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE
    const uint64_t footer[]={LC8O_FOOTER,2,sizeof lc8o.wire,at,calls,(uint64_t)result,status,code};
#else
    const uint64_t footer[]={LC8O_FOOTER,1,sizeof lc8o.wire,at,calls,(uint64_t)result,status,code};
#endif
    at=0;calls=0;
    while(at<sizeof footer && calls<64) {
        ++calls;result=raw(SYS_write,3,(long)((const unsigned char *)footer+at),sizeof footer-at,0,0,0);
        if(result<=0 || (size_t)result>sizeof footer-at)return;
        at+=(size_t)result;
    }
#ifdef LI2_LOOP_CACHE8_EFFECTS
    lc8e_report(status,code);
#endif
}
#ifdef LI2_LOOP_CACHE8_EFFECTS
#include "loop_cache8_effects_observe.inc"
#endif
