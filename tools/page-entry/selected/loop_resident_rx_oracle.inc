/* Test-only observations and actual restored mutations. No observation is
   used by a production gate, target selection or publication authority. */
#include "loop_resident_rx_oracle.h"
enum { LRXO_STOP=8850,LRXO_CONTROLS=32 };
struct lrxo_counts { uint64_t cold,publications,hits,opens,closes,writes,syncs; };
struct lrxo_member {
    unsigned seen,prot,slot,bank,retained;
    uint64_t generation,serial,root,entry,code,proof;
    uint64_t opens_before,opens_after,syncs_before,syncs_after;
};
struct lrxo_epoch {
    unsigned started,complete,count,mask,warm,receipt;
    uint64_t entry,released_pc,root,head,id,serial;
    struct lrxo_counts before,after;
    struct lrxo_member member[2];
};
struct lrxo_result { unsigned expected,actual,restored; };
struct lrxo_targets {
    unsigned complete,checks,restorations,cell;
    uint64_t id,serial,target,code,proof,owner;
    unsigned known[4],strict[4],allowed[4];
    unsigned kind_index,kind_before,kind_after,mutation_executed,mutated_allowed;
    unsigned restored_allowed,armed,receipt;
};
enum { LRXO_TRANSIT_CONTROLS=16 };
struct lrxo_transit {
    unsigned complete,checks,restorations,cell,branches,arm,slot,previous_slot;
    uint64_t id,serial,pc,target,flags,code,length,available,pages,borrow,source_page,source_generation;
    uint64_t generation,event,previous_generation,previous_event,bytes;
    struct lrxo_result result[LRXO_TRANSIT_CONTROLS];
};
struct lrxo_state {
    unsigned initialized,active,epochs,failure,busy,cell_done,branch_done;
    unsigned controls,restorations,unsafe_reason,unsafe_queries,complete;
    uint64_t unsafe_opens,unsafe_closes,unsafe_syncs;
    struct lrxo_epoch epoch[3];
    struct lrxo_result result[LRXO_CONTROLS];
    struct pda_completion saved;
    struct lrxo_targets targets;
    struct lrxo_transit transit;
};
static struct lrxo_state lrxo;
static _Noreturn void lrxo_fail(unsigned code) {
    if(!lrxo.failure)lrxo.failure=code;
    selected_persistent_abort(PE_PUBLICATION,8900+(long)code);
}
static void lrxo_need(int condition,unsigned code) {if(!condition)lrxo_fail(code);}
static int lrxo_initialize(void) {
    if(lrxo.initialized || protected_count>=RANGES ||
       selected_run_protect_add(0,(uintptr_t)&lrxo,sizeof lrxo))return PE_STATE;
    lrxo.initialized=1;return 0;
}
static struct lrxo_counts lrxo_counts(void) {
    return (struct lrxo_counts){PGC_VALUE(cold_attempts),PGC_VALUE(publications),PGC_VALUE(hits),
        pe.rx.code_opens,pe.rx.code_revokes,pe.rx.code_writes,pe.rx.code_syncs};
}
static void lrxo_build(uintptr_t entry) {
    if((entry!=UINT64_C(0x410200) && entry!=UINT64_C(0x412400)) || lrxo.epochs==3)return;
    lrxo_need(lrxo.initialized && !lrxo.active && !lrxo.busy,1);
    struct lrxo_epoch *e=&lrxo.epoch[lrxo.epochs];
    lrxo_need(!e->started && !e->complete,2);
    e->started=1;e->entry=entry;e->serial=pe.p.serial;e->before=lrxo_counts();
    lrxo.active=lrxo.epochs+1;
}
static void lrxo_member_begin(unsigned member,int prot) {
    if(!lrxo.active)return;
    lrxo_need(member<2 && (prot==PROT_READ || prot==(PROT_READ|PROT_EXEC)),3);
    struct lrxo_member *m=&lrxo.epoch[lrxo.active-1].member[member];
    const struct li2_pgd_ref *v=&pe.domain.work.view.member[member].identity;
    lrxo_need(!m->seen && v->slot<2 && v->bank<2,4);
    m->seen=1;m->prot=(unsigned)prot;m->slot=v->slot;m->bank=v->bank;
    m->generation=v->generation;m->serial=pe.rx.slot[v->slot].serial;
    m->root=v->root;m->entry=pe.domain.work.view.entry.target.pc;
    m->code=v->layout.generated[0];m->proof=v->proof;
    m->opens_before=pe.rx.code_opens;m->syncs_before=pe.rx.code_syncs;
}
static void lrxo_member_end(unsigned member) {
    if(!lrxo.active)return;
    lrxo_need(member<2,5);struct lrxo_member *m=&lrxo.epoch[lrxo.active-1].member[member];
    lrxo_need(m->seen==1,6);m->seen=2;
    m->opens_after=pe.rx.code_opens;m->syncs_after=pe.rx.code_syncs;
    m->retained=(pe.domain.work.rx_retained_mask>>member)&1U;
    lrxo_need(m->retained==(m->prot==(PROT_READ|PROT_EXEC)) &&
        m->opens_after-m->opens_before==3U*(1U-m->retained) &&
        m->syncs_after-m->syncs_before==3U*(1U-m->retained),7);
}
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
static void lrxo_result(unsigned index,int actual) {
    lrxo_need(index==lrxo.controls && index<LRXO_CONTROLS && actual==0,8);
    lrxo.result[index]=(struct lrxo_result){0,(unsigned)actual,0};++lrxo.controls;
}
static void lrxo_restored(unsigned index) {
    lrxo_need(index<lrxo.controls && !lrxo.result[index].restored,9);
    lrxo.result[index].restored=1;++lrxo.restorations;
}
static void lrxo_cell_controls(const struct pda_completion *original) {
    if(lrxo.cell_done || lrxo.epochs!=3)return;
    lrxo_need(original->count==2 && original->rx.retained_mask==2 &&
        pda_receipt(original) && lprx_complete_value(original),10);
    lrxo.busy=1;copy(&lrxo.saved,original,sizeof lrxo.saved);
    struct pda_completion *c=(struct pda_completion *)original;
    for(unsigned kind=0;kind<20;kind++) {
        lrxo_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ|PROT_WRITE,0,0,0),11);
        switch(kind) {
        case 0:c->rx.version=0;break;
        case 1:c->rx.count=0;break;
        case 2:c->rx.retained_mask=4;break;
        case 3:c->rx.reserved=1;break;
        case 4:c->rx.source.started=0;break;
        case 5:c->rx.source.complete=0;break;
        case 6:c->rx.source.count=0;break;
        case 7:c->rx.source.extents=0;break;
        case 8:c->rx.source.pages=0;break;
        case 9:c->rx.source.released_fetch.pc^=1;break;
        case 10:c->rx.source.released_fetch.progress.held=1;break;
        case 11:c->rx.source.query[0][0].actual_prot=PROT_READ;break;
        case 12:c->domain_source.closed=1;break;
        case 13:c->source.phase=LI2_PGS_RELEASED;break;
        case 14:c->source.closed_pages=1;break;
        case 15:c->source.source.key.entry^=1;break;
        case 16:c->rx.open[0][0].expected_prot=PROT_READ;break;
        case 17:c->rx.code[0][0].actual_prot=PROT_READ;break;
        case 18:c->rx.retained_mask^=1;break;
        default:c->rx.source.ref[0].generation^=1;break;
        }
        lrxo_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ,0,0,0),12);
        lrxo_need(!lprx_complete_value(c),13);lrxo_result(kind,pda_receipt(c));
        lrxo_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ|PROT_WRITE,0,0,0),14);
        copy(c,&lrxo.saved,sizeof *c);
        lrxo_need(!raw(SYS_mprotect,(long)c,sizeof *c,PROT_READ,0,0,0) &&
            equal(c,&lrxo.saved,sizeof *c) && !lrc_readonly((uintptr_t)c,sizeof *c) &&
            lprx_complete_value(c) && pda_receipt(c),15);
        lrxo_restored(kind);
    }
    unsigned slot=original->member[1].identity.slot;
    struct lprx_slot saved=pe.rx.slot[slot];
    lrxo_need(lprx_permitted(slot),16);
    for(unsigned kind=0;kind<5;kind++) {
        struct lprx_slot *v=&pe.rx.slot[slot];
        switch(kind) {
        case 0:v->phase=LPRX_REVOKED;break;
        case 1:v->bank^=1;break;
        case 2:v->generation^=1;break;
        case 3:v->serial=0;break;
        default:v->layout.generated[0]+=PAGE;break;
        }
        lrxo_result(20+kind,lprx_permitted(slot));*v=saved;
        lrxo_need(equal(v,&saved,sizeof saved) && lprx_permitted(slot) &&
            pda_receipt(original),17);lrxo_restored(20+kind);
    }
    lrxo.cell_done=1;lrxo.busy=0;
}
#endif
static void lrxo_complete(const struct pda_completion *c) {
    if(!lrxo.active)return;
    struct lrxo_epoch *e=&lrxo.epoch[lrxo.active-1];
    lrxo_need(c && c->complete==1 && c->serial==e->serial &&
        c->source.source.key.entry==e->entry && pda_receipt(c),18);
    e->count=c->count;e->mask=c->rx.retained_mask;e->warm=pe.warm;
    e->receipt=pe.domain.work.receipt;e->id=c->id;
    e->released_pc=c->rx.source.released_fetch.pc;
    e->root=c->domain_source.entry.target.root;e->head=c->domain_source.entry.target.head;
    for(unsigned i=0;i<c->count;i++) {
        const struct lrxo_member *m=&e->member[i];const struct li2_pgd_ref *v=&c->member[i].identity;
        lrxo_need(m->seen==2 && m->slot==v->slot && m->bank==v->bank &&
            m->generation==v->generation && m->root==v->root && m->code==v->layout.generated[0] &&
            m->proof==v->proof && m->retained==((e->mask>>i)&1U),19);
    }
    e->after=lrxo_counts();e->complete=1;++lrxo.epochs;lrxo.active=0;
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    lrxo_cell_controls(c);
#endif
}
/* Actual addresses at a genuine armed DIRECT boundary. These observations
   grant no execution authority and do not replace any original control. */
static void lrxo_targets(void) {
    if(lrxo.epochs!=3 || lrxo.targets.complete)return;
    const struct lprx_branch saved=pe.rx.branch;
    lrxo_need(lprx_armed_value() && saved.cell<LI2_PGD_RECEIPTS,26);
    const struct pda_completion *c=&pe.domain.completion[saved.cell];
    struct lrxo_targets *t=&lrxo.targets;
    lrxo_need(c->count==2 && c->rx.retained_mask==2 && pda_receipt(c) &&
        c->id==lrxo.epoch[2].id && c->serial==lrxo.epoch[2].serial &&
        protected_count<=RANGES,26);
    t->cell=saved.cell;t->id=c->id;t->serial=c->serial;t->target=saved.target;
    t->code=c->member[1].identity.layout.generated[0];
    t->proof=c->member[1].identity.proof;t->owner=(uintptr_t)&pe;
    const uintptr_t address[4]={t->target,t->code,t->proof,t->owner};
    for(unsigned i=0;i<4;i++) {
        t->known[i]=(unsigned)li2_lifecycle_known_code(address[i],1);
        t->strict[i]=(unsigned)li2_initial_code_protection_intersects(
            protected,initial_code_range,protected_count,address[i],1,PROT_READ|PROT_EXEC);
        t->allowed[i]=(unsigned)lprx_target_allowed(address[i]);
        lrxo_need(t->known[i]==(i==0) && t->strict[i]==(i!=0) &&
            t->allowed[i]==(i==0),27);++t->checks;
    }
    unsigned index=RANGES;
    for(unsigned i=0;i<protected_count;i++)
        if(t->target>=protected[i].first && t->target<protected[i].end &&
           initial_code_range[i]==1) {index=i;break;}
    lrxo_need(index<RANGES,28);t->kind_index=index;t->kind_before=initial_code_range[index];
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    unsigned char kinds[RANGES];copy(kinds,initial_code_range,sizeof kinds);
    size_t count=protected_count;struct li2_fork_range range=protected[index];
    initial_code_range[index]=0;t->mutation_executed=1;
    t->mutated_allowed=(unsigned)lprx_target_allowed(t->target);
    copy(initial_code_range,kinds,sizeof kinds); /* Restore even if rejection failed. */
    lrxo_need(!t->mutated_allowed && protected_count==count &&
        equal(&protected[index],&range,sizeof range) &&
        equal(initial_code_range,kinds,sizeof kinds),29);
    ++t->checks;++t->restorations;
#endif
    t->kind_after=initial_code_range[index];
    t->restored_allowed=(unsigned)lprx_target_allowed(t->target);
    t->armed=(unsigned)lprx_armed_value();t->receipt=(unsigned)pda_receipt(c);
    lrxo_need(t->kind_before==1 && t->kind_after==1 && t->restored_allowed==1 &&
        t->armed==1 && t->receipt==1 && equal(&pe.rx.branch,&saved,sizeof saved),30);
    t->complete=1;
}
static void lrxo_armed(void) {
    lrxo_targets();
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    if(!lrxo.cell_done || lrxo.branch_done)return;
    lrxo_need(!lrxo.busy && lrxo.controls==25 && lprx_armed_value(),20);
    struct lprx_branch saved=pe.rx.branch;
    for(unsigned kind=0;kind<7;kind++) {
        switch(kind) {
        case 0:pe.rx.branch.flags^=1;break;
        case 1:pe.rx.branch.target^=1;break;
        case 2:pe.rx.branch.id^=1;break;
        case 3:pe.rx.branch.chain_generation^=1;break;
        case 4:pe.rx.branch.chain_event^=1;break;
        case 5:pe.rx.branch.slot^=1;break;
        default:pe.rx.branch.phase=1;break;
        }
        lrxo_result(25+kind,lprx_armed_value());pe.rx.branch=saved;
        lrxo_need(equal(&pe.rx.branch,&saved,sizeof saved) && lprx_armed_value() &&
            pda_receipt(&pe.domain.completion[saved.cell]),21);
        lrxo_restored(25+kind);
    }
    lrxo.branch_done=1;
#endif
}
/* Separate genuine second-branch controls; the original 32 remain untouched. */
static void lrxo_transit_armed(void) {
    if(lrxo.epochs!=2 || lrxo.transit.complete)return;
    const struct lprx_branch saved=pe.rx.branch;
    lrxo_need(saved.branches==2 && lprx_armed_value() && saved.cell<LI2_PGD_RECEIPTS,31);
    const struct pda_completion *c=&pe.domain.completion[saved.cell];
    const struct lprx_transit *v=&saved.transit;struct lrxo_transit *t=&lrxo.transit;
    lrxo_need(c->id==lrxo.epoch[1].id && c->serial==lrxo.epoch[1].serial && pda_receipt(c) &&
        c->direct_exit.original.decoded.pc==UINT64_C(0x412416) &&
        v->original.decoded.pc==UINT64_C(0x413ffa) && saved.target==UINT64_C(0x410200),32);
    t->cell=saved.cell;t->branches=saved.branches;t->arm=v->arm;t->slot=saved.slot;
    t->previous_slot=v->previous_slot;t->id=saved.id;t->serial=saved.serial;
    t->pc=v->original.decoded.pc;t->target=saved.target;t->flags=saved.flags;
    t->code=v->original.decoded.code;t->length=v->original.decoded.length;
    t->available=v->source.length;t->pages=v->source.page_count;t->borrow=v->source.ref.sequence;
    t->source_page=v->source.pages[0].address;t->source_generation=v->source.pages[0].generation;
    t->generation=saved.chain_generation;t->event=saved.chain_event;
    t->previous_generation=v->previous_generation;t->previous_event=v->previous_event;
    for(unsigned i=0;i<6;i++)t->bytes|=(uint64_t)v->source.bytes[i]<<(8*i);
    ++t->checks;
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    for(unsigned kind=0;kind<LRXO_TRANSIT_CONTROLS;kind++) {
        struct lprx_branch *b=&pe.rx.branch;
        switch(kind) {
        case 0:b->branches=3;break;
        case 1:b->transit_reserved=1;break;
        case 2:b->chain_generation^=1;break;
        case 3:b->chain_event^=1;break;
        case 4:b->target^=1;break;
        case 5:b->flags^=1;break;
        case 6:b->transit.original.decoded.bytes[2]^=1;break;
        case 7:b->transit.direct.target[0]^=1;break;
        case 8:b->transit.source.ref.sequence^=1;break;
        case 9:b->transit.source.pages[0].generation^=1;break;
        case 10:b->transit.source.backing[0].stat.st_ino^=1;break;
        case 11:b->transit.previous_generation^=1;break;
        case 12:b->transit.previous_event^=1;break;
        case 13:b->transit.previous_slot^=1;break;
        case 14:b->transit.arm^=1;break;
        default:b->transit.source.pc^=1;break;
        }
        int actual=lprx_armed_value();*b=saved; /* Restore before any failure path. */
        t->result[kind]=(struct lrxo_result){0,(unsigned)actual,0};
        lrxo_need(!actual && equal(b,&saved,sizeof saved) && lprx_armed_value() &&
            pda_receipt(c),33);t->result[kind].restored=1;++t->checks;++t->restorations;
    }
#endif
    lrxo_need(equal(&pe.rx.branch,&saved,sizeof saved) && lprx_armed_value() && pda_receipt(c),34);
    t->complete=1;
}
static void lrxo_unsafe(unsigned reason) {
    if(lrxo.epochs!=3 || lrxo.unsafe_reason || reason==LPRX_COLD)return;
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    if(!lrxo.cell_done || !lrxo.branch_done)return;
#endif
    lrxo_need(!pe.rx.branch.phase && !pe_active && !pe.resuming && !pe_closing,22);
    for(unsigned i=0;i<2;i++)for(unsigned b=0;b<2;b++) {
        const struct ped_bank *bank=&pe.retained[i].banks[b];
        lrxo_need(bank->allocated && (bank->prot==PROT_READ || bank->prot==(PROT_READ|PROT_WRITE)),23);
        struct li2_private_code_query q[3]={0};
        lrxo_need(!pg_queries(&bank->layout,bank->prot,q),24);lrxo.unsafe_queries+=3;
    }
    lrxo.unsafe_reason=reason;lrxo.unsafe_opens=pe.rx.code_opens;
    lrxo.unsafe_closes=pe.rx.code_revokes;lrxo.unsafe_syncs=pe.rx.code_syncs;
    lrxo_need(lrxo.transit.complete==1 &&
        lrxo.transit.checks==1+LRXO_TRANSIT_CONTROLS*LI2_LOOP_RESIDENT_RX_CONTROL &&
        lrxo.transit.restorations==LRXO_TRANSIT_CONTROLS*LI2_LOOP_RESIDENT_RX_CONTROL,35);
    lrxo.complete=1;
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    lrxo_need(lrxo.controls==LRXO_CONTROLS && lrxo.restorations==LRXO_CONTROLS,25);
    selected_persistent_abort(PE_PUBLICATION,LRXO_STOP);
#endif
}
static void lrxo_emit(struct writer *w) {
    text(w,"}\n");
    if(raw(SYS_write,report_fd<0?2:report_fd,(long)w->bytes,w->used,0,0,0)!=(long)w->used) {
        (void)raw(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
    }
}
static void lrxo_report(unsigned status,unsigned code) {
    const struct lrxo_transit *v=&lrxo.transit;struct writer transit={0};
    text(&transit,"LI2_LOOP_RX_TRANSIT_TICKET {\"version\":1");
    field(&transit,",\"control\":",LI2_LOOP_RESIDENT_RX_CONTROL);
#define VF(n) field(&transit,",\"" #n "\":",v->n)
    VF(complete);VF(checks);VF(restorations);VF(cell);VF(branches);VF(arm);VF(slot);VF(previous_slot);
    VF(id);VF(serial);VF(pc);VF(target);VF(flags);VF(code);VF(length);VF(available);VF(pages);
    VF(borrow);VF(source_page);VF(source_generation);VF(generation);VF(event);
    VF(previous_generation);VF(previous_event);VF(bytes);
#undef VF
    lrxo_emit(&transit);
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1
    for(unsigned i=0;i<LRXO_TRANSIT_CONTROLS;i++) {
        const struct lrxo_result *r=&v->result[i];struct writer w={0};
        text(&w,"LI2_LOOP_RX_TRANSIT_CONTROL {\"version\":1");field(&w,",\"index\":",i);
        field(&w,",\"expected\":",r->expected);field(&w,",\"actual\":",r->actual);
        field(&w,",\"restored\":",r->restored);lrxo_emit(&w);
    }
#endif
    const struct lrxo_targets *t=&lrxo.targets;struct writer target={0};
    text(&target,"LI2_LOOP_RX_TARGET {\"version\":1");
    field(&target,",\"control\":",LI2_LOOP_RESIDENT_RX_CONTROL);
#define TF(n) field(&target,",\"" #n "\":",t->n)
    TF(complete);TF(checks);TF(restorations);TF(cell);TF(id);TF(serial);
    TF(target);TF(code);TF(proof);TF(owner);
    TF(kind_index);TF(kind_before);TF(kind_after);TF(mutation_executed);
    TF(mutated_allowed);TF(restored_allowed);TF(armed);TF(receipt);
#undef TF
    static const char *const names[4]={"original","code","proof","owner"};
    for(unsigned i=0;i<4;i++) {
        text(&target,",\"");text(&target,names[i]);field(&target,"_known\":",t->known[i]);
        text(&target,",\"");text(&target,names[i]);field(&target,"_strict\":",t->strict[i]);
        text(&target,",\"");text(&target,names[i]);field(&target,"_allowed\":",t->allowed[i]);
    }
    lrxo_emit(&target);
    for(unsigned i=0;i<3;i++) {
        const struct lrxo_epoch *e=&lrxo.epoch[i];struct writer w={0};
        text(&w,"LI2_LOOP_RX_EPOCH {\"version\":1");field(&w,",\"index\":",i);
#define EF(n) field(&w,",\"" #n "\":",e->n)
        EF(started);EF(complete);EF(count);EF(mask);EF(warm);EF(receipt);
        EF(entry);EF(released_pc);EF(root);EF(head);EF(id);EF(serial);
#undef EF
#define CF(side,n) field(&w,",\"" #side "_" #n "\":",e->side.n)
        CF(before,cold);CF(before,publications);CF(before,hits);CF(before,opens);CF(before,closes);CF(before,writes);CF(before,syncs);
        CF(after,cold);CF(after,publications);CF(after,hits);CF(after,opens);CF(after,closes);CF(after,writes);CF(after,syncs);
#undef CF
        lrxo_emit(&w);
        for(unsigned j=0;j<2;j++) {
            const struct lrxo_member *m=&e->member[j];struct writer row={0};
            text(&row,"LI2_LOOP_RX_MEMBER {\"version\":1");field(&row,",\"epoch\":",i);field(&row,",\"member\":",j);
#define MF(n) field(&row,",\"" #n "\":",m->n)
            MF(seen);MF(prot);MF(slot);MF(bank);MF(retained);MF(generation);MF(serial);
            MF(root);MF(entry);MF(code);MF(proof);MF(opens_before);MF(opens_after);MF(syncs_before);MF(syncs_after);
#undef MF
            lrxo_emit(&row);
        }
    }
    for(unsigned i=0;i<lrxo.controls;i++) {
        const struct lrxo_result *r=&lrxo.result[i];struct writer w={0};
        text(&w,"LI2_LOOP_RX_CONTROL {\"version\":1");field(&w,",\"index\":",i);
        field(&w,",\"expected\":",r->expected);field(&w,",\"actual\":",r->actual);
        field(&w,",\"restored\":",r->restored);lrxo_emit(&w);
    }
    struct writer w={0};text(&w,"LI2_LOOP_RX_ORACLE {\"version\":1");
    field(&w,",\"control\":",LI2_LOOP_RESIDENT_RX_CONTROL);
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
#define OF(n) field(&w,",\"" #n "\":",lrxo.n)
    OF(initialized);OF(active);OF(epochs);OF(failure);OF(busy);OF(cell_done);OF(branch_done);
    OF(controls);OF(restorations);OF(unsafe_reason);OF(unsafe_queries);OF(complete);
    OF(unsafe_opens);OF(unsafe_closes);OF(unsafe_syncs);
#undef OF
    lrxo_emit(&w);
}
