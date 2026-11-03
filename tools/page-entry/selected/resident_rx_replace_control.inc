/* Capture-only fault injection, not a guest mmap acceptance path. Include the
   declarations before rrx_bundle, then include again with IMPLEMENTATION after
   r3o_copy/r3o_compare. Only case7 calls the body, after the complete first
   r3o_terminal snapshot and before selected_fetch starts another borrow. */
#if !defined(LI2_RESIDENT_RX_CAPTURE) || LI2_RESIDENT_RX_CAPTURE != 1 || \
    !defined(LI2_RESIDENT_RX) || LI2_RESIDENT_RX != 1
#error "actual replacement control is confined to the distinct RX capture"
#endif
#ifndef LI2_RRX_REPLACE_DECLARED
#define LI2_RRX_REPLACE_DECLARED
#include "span_source.h"
struct rrx_replace_control {
    uint64_t started,quiet,invalidated,raw_started,raw_returned,complete;
    long number,args[6],effect_result,result,sync_result,seals,stat_result;
    struct stat backing;
    struct li2_r3_rx_progress rx[3];
    struct li2_rsl_progress source[3];
    struct li2_rsl_generation_progress generation[3];
    unsigned lifetime[3],references[3][3],closed[3][3];
    struct li2_fetch_page page[2][6];
    struct li2_fetch_backing page_backing[2][6];
    struct li2_fetch_progress release[2][6];
    struct li2_sealed_code_query code_revoked[3][3];
    int code_result[3];
    struct r3o_scan bytes_before,bytes_after;
    unsigned char source_after[6U*PAGE];
};
_Static_assert(sizeof(struct rrx_replace_control)<50U*1024U,
    "bounded additional complete replacement observation");
#endif

#ifdef LI2_RRX_REPLACE_IMPLEMENTATION
static void rrx_replace_snapshot(unsigned at) {
    struct rrx_replace_control *o=&rrx_bundle.replacement;
    r3_need(at<3,R3_STATE,150);
    r3o_copy(&o->rx[at],li2_r3_rx_progress(),sizeof o->rx[at]);
    r3o_copy(&o->source[at],li2_rsl_progress(),sizeof o->source[at]);
    r3o_copy(&o->generation[at],li2_rsl_generation_progress(),sizeof o->generation[at]);
    o->lifetime[at]=r3.rx_lifetime;
    for(unsigned i=0;i<3;i++) {
        o->references[at][i]=r3.certificate[i].active_refs;
        o->closed[at][i]=r3.certificate[i].closed;
    }
}
static void rrx_replace_pages(unsigned after) {
    struct rrx_replace_control *o=&rrx_bundle.replacement;
    r3_need(after<2,R3_STATE,151);
    for(unsigned i=0;i<6;i++) {
        uintptr_t page=(uintptr_t)o->args[0]+i*PAGE;
        const struct li2_pg_source_page *saved=&r3.certificate[i/2].mirror.source.page[i%2];
        struct li2_fetch_ref ref={0};struct li2_span_source actual={0};
        r3_need(saved->identity.address==page &&
            !li2_lifecycle_fetch_prepare(page,15,&ref) &&
            !li2_lifecycle_span_source(&ref,&actual) && actual.ready==1 &&
            actual.borrow.owner==ref.owner && actual.borrow.sequence==ref.sequence &&
            actual.key.entry==page && actual.key.page.address==page &&
            actual.key.page.logical==(PROT_READ|PROT_EXEC) &&
            actual.key.page.closed_prot==PROT_READ &&
            actual.key.page.offset==(uint64_t)o->args[5]+i*PAGE &&
            actual.key.backing.seals_observed==1 && actual.key.backing.seals==15 &&
            actual.key.backing.stat_observed==1 && !actual.key.backing.stat_result &&
            actual.key.backing.retained_fd==saved->backing.retained_fd &&
            actual.key.backing.stat.st_dev==o->backing.st_dev &&
            actual.key.backing.stat.st_ino==o->backing.st_ino &&
            actual.key.backing.stat.st_mode==o->backing.st_mode &&
            actual.key.backing.stat.st_size==o->backing.st_size,R3_SOURCE,152);
        /* Whole current physical page identities, including VMA boundaries,
           must be identical across the actual replacement. No normalization. */
        r3_need(equal(&actual.key.page,after?&o->page[0][i]:&saved->identity,
                      sizeof actual.key.page),R3_SOURCE,153);
        r3o_copy(&o->page[after][i],&actual.key.page,sizeof actual.key.page);
        r3o_copy(&o->page_backing[after][i],&actual.key.backing,sizeof actual.key.backing);
        r3_need(equal(actual.key.bytes,saved->bytes,PAGE),R3_SOURCE,154);
        r3o_compare(after?&o->bytes_after:&o->bytes_before,
            original_main.source+(size_t)o->args[5]+i*PAGE,actual.key.bytes,PAGE);
        if(after)r3o_copy(o->source_after+i*PAGE,actual.key.bytes,PAGE);
        r3_need(!li2_lifecycle_fetch_release(&ref),R3_SOURCE,155);
        r3o_copy(&o->release[after][i],li2_lifecycle_fetch_progress(),sizeof o->release[after][i]);
        const struct li2_fetch_progress *p=&o->release[after][i];
        r3_need(!p->held && p->complete==1 && !p->first_error &&
            p->sequence==ref.sequence && p->validation_calls==2 &&
            p->identity_observed==1 && p->last_backing_observed==1 &&
            p->pages_copied==1 && p->bytes_copied==15 &&
            !li2_lifecycle_fetch_interlock(),R3_SOURCE,156);
    }
}
static void rrx_replace(void) {
    if(LI2_RRX_CASE!=7)return;
    struct rrx_replace_control *o=&rrx_bundle.replacement;
    r3_need(!o->started && r3o_ready && !r3o_busy && !rrx_bundle.h[4] &&
        !rrx_bundle.h[5] && rrx_bundle.h[6]==1 && rrx_current_record.h[25]==1 &&
        !rrx_current_record.h[26] && !rrx_current_record.h[27] &&
        r3.phase==LI2_R3_DRAINED && r3.entries==1 && r3.completed==1 &&
        r3.publications==3 && r3.count==3 && r3.planned==3 &&
        !r3.busy && !r3.active && r3.released==1 &&
        r3.rx_lifetime==LI2_R3_RX_RESIDENT && !r3.first_error &&
        !selected_step_pending && selected_pending_route==SELECTED_NO_STEP &&
        !li2_lifecycle_fetch_interlock() && !li2_r3_rseq_progress()->active &&
        li2_rsl_owner_quiet() && li2_r3_rx_execution_quiet(),R3_STATE,157);
    o->started=1;
    uintptr_t first=LI2_R3_ROOT_RVA&~(PAGE-1);size_t bytes=6U*PAGE;
    r3_need(first==UINT64_C(0x410000) && !original_main.bias &&
        original_main.kind==IMAGE_MAIN && original_main.backing_fd>=0 &&
        original_main.source && original_main.ph && original_main.n &&
        original_main.n<=128,R3_SOURCE,158);
    size_t offset=0;unsigned found=0;
    for(size_t i=0;i<original_main.n;i++) {
        const Elf64_Phdr *p=&original_main.ph[i];
        if(p->p_type!=PT_LOAD || p->p_vaddr>first || first-p->p_vaddr>p->p_filesz ||
           bytes>p->p_filesz-(first-p->p_vaddr))continue;
        r3_need(p->p_flags==(PF_R|PF_X) && p->p_filesz==p->p_memsz &&
            p->p_offset<=original_main.source_size &&
            p->p_filesz<=original_main.source_size-p->p_offset,R3_SOURCE,159);
        offset=(size_t)p->p_offset+(first-(uintptr_t)p->p_vaddr);++found;
    }
    r3_need(found==1 && !(offset&(PAGE-1)) && offset==LI2_RRX_SOURCE_OFFSET &&
        offset<=original_main.source_size && bytes<=original_main.source_size-offset,
        R3_SOURCE,160);
    o->number=SYS_mmap;o->args[0]=(long)first;o->args[1]=(long)bytes;
    /* Original logical text remains executable-by-owner, physically R/NX.
       Never expose native RX source as part of this trusted experiment. */
    o->args[2]=PROT_READ;o->args[3]=MAP_PRIVATE|MAP_FIXED;
    o->args[4]=original_main.backing_fd;o->args[5]=(long)offset;
    o->seals=raw(SYS_fcntl,o->args[4],F_GET_SEALS,0,0,0,0);
    o->stat_result=raw(SYS_fstat,o->args[4],(long)&o->backing,0,0,0,0);
    r3_need(o->seals==15 && !o->stat_result && S_ISREG(o->backing.st_mode) &&
        o->backing.st_ino && o->backing.st_size>0 &&
        (uint64_t)o->backing.st_size>=offset+bytes,R3_SOURCE,161);
    rrx_replace_pages(0);rrx_replace_snapshot(0);
    r3_need(li2_rsl_owner_quiet() && li2_r3_rx_execution_quiet(),R3_STATE,162);
    o->quiet=1;
    /* The real source owner invalidates first and physically revokes all three
       publications. No lifetime/generation/claim field is assigned by a test. */
    o->effect_result=li2_rsl_before_effect(o->number,o->args);
    r3_need(!o->effect_result,R3_SOURCE,163);
    rrx_replace_snapshot(1);
    r3_need(o->lifetime[1]==LI2_R3_RX_RETIRED &&
        o->generation[0].state==LI2_RSG_LIVE &&
        o->generation[1].state==LI2_RSG_DIRTY &&
        o->generation[1].generation==o->generation[0].generation+1 &&
        o->generation[1].invalidations==o->generation[0].invalidations+1 &&
        o->rx[1].retirements==o->rx[0].retirements+1 &&
        o->source[1].epoch==o->source[0].epoch+1 &&
        o->source[1].invalidations==o->source[0].invalidations+1 &&
        !o->source[1].valid && !o->source[1].bound.owner &&
        !o->source[1].bound.serial && !li2_lifecycle_fetch_interlock() &&
        !li2_r3_rseq_progress()->active && li2_rsl_owner_quiet(),R3_STATE,164);
    for(unsigned i=0;i<3;i++) {
        r3_need(!o->references[1][i] && o->closed[1][i]==1,R3_STATE,165);
        o->code_result[i]=r3_code_query(i,PROT_READ,o->code_revoked[i]);
        r3_need(!o->code_result[i] && !r3_bytes(i),R3_PUBLICATION,166);
    }
    r3_need(r3_all_nx(),R3_PUBLICATION,167);o->invalidated=1;
    __asm__ volatile("":::"memory");o->raw_started=1;
    o->result=raw(o->number,o->args[0],o->args[1],o->args[2],o->args[3],o->args[4],o->args[5]);
    o->raw_returned=1;r3_need(o->result==(long)first,R3_PUBLICATION,168);
    o->sync_result=raw(SYS_membarrier,32,0,0,0,0,0);
    r3_need(!o->sync_result,R3_PUBLICATION,169);
    rrx_replace_pages(1);rrx_replace_snapshot(2);
    r3_need(equal(&o->rx[1],&o->rx[2],sizeof o->rx[1]) &&
        equal(&o->source[1],&o->source[2],sizeof o->source[1]) &&
        equal(&o->generation[1],&o->generation[2],sizeof o->generation[1]) &&
        o->lifetime[2]==LI2_R3_RX_RETIRED && r3_all_nx() &&
        li2_rsl_owner_quiet() && li2_r3_rx_execution_quiet() &&
        r3.entries==1 && r3.completed==1,R3_STATE,170);
    o->complete=1;
    /* Continue the original frontier/getters and reach the real root. Only
       its unchanged entry predicate may produce the expected stale refusal. */
}
#endif
