/* Actual lifecycle TU and native policy. Owner observations are supplied
   component inputs, never fabricated kernel frames or publication evidence. */
#include "lifecycle_loader.c"
#include <inttypes.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct li2_native_pair_progress observed;
static unsigned observed_quiet,raw_calls,current_controls,policy_controls;
static unsigned refault_controls,outcome_controls,terminal_controls,lifetime_cases;
static struct li2_span_source source;
static jmp_buf failed;
static unsigned failure_code;
static long failure_detail;
static int expecting_failure;
int equal(const void *a,const void *b,size_t n) {return !memcmp(a,b,n);}
void copy(void *a,const void *b,size_t n) {memcpy(a,b,n);}
const struct li2_native_pair_progress *li2_native_pair_progress(void) {return &observed;}
int li2_native_pair_quiet(void) {return observed_quiet;}
static void need(int yes,unsigned at) {
    if(!yes){fprintf(stderr,"native probe oracle failure %u\n",at);exit(1);}
}
static _Noreturn void die(unsigned code,long detail) {
    failure_code=code;failure_detail=detail;
    if(expecting_failure)longjmp(failed,1);
    fprintf(stderr,"unexpected lifecycle failure %u/%ld\n",code,detail);exit(1);
}
static long no_raw(long n,long a,long b,long c,long d,long e,long f) {
    (void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    ++raw_calls;die(999,0);
}
/* A complete supplied released snapshot, using the actual lifecycle types.
   No memory at its descriptive high address is dereferenced by the probe. */
static void snapshot(size_t index,uintptr_t pc) {
    const struct owned_page *p=&records[index];
    fetch.pc=pc;fetch.requested=15;fetch.page_count=1;fetch.pid=12345;fetch.tid=12345;
    fetch.allocation_epoch=allocation_id;fetch.generation_epoch=generation;
    fetch.records_epoch=used;fetch.transactions_epoch=counts.transactions;fetch.phase_epoch=tx.phase;
    fetch.progress=(struct li2_fetch_progress){.sequence=++fetch_sequence,.complete=1,.identity_observed=1};
    fetch.original[0]=*p;
    fetch.pages[0]=(struct li2_fetch_page){.address=p->address,.allocation=p->allocation,
        .generation=p->generation,.offset=p->offset,.initial_extent=p->initial_extent,
        .backing=p->backing,.object=p->object,.logical=p->logical,.closed_prot=PROT_READ,
        .vma_first=p->address,.vma_end=p->address+PAGE,.vma_major=1,.vma_minor=2,
        .vma_inode=3,.vma_offset=p->offset};
    fetch.last_backing=(struct li2_fetch_backing){.retained_fd=7,.seals=SEALS,
        .seals_observed=1,.stat_observed=1,.stat={.st_dev=1,.st_ino=3,.st_size=3*PAGE,.st_mode=0100600}};
    source=(struct li2_span_source){.ready=1,.borrow={.owner=&fetch,.sequence=fetch.progress.sequence}};
    source.key.entry=pc;source.key.page=fetch.pages[0];source.key.backing=fetch.last_backing;
    memset(source.key.bytes,0x90,sizeof source.key.bytes);memset(fetch.bytes,0x90,sizeof fetch.bytes);
}
static void setup(void) {
    memset(&lnp,0,sizeof lnp);memset(lnp_refused_generation,0,sizeof lnp_refused_generation);
    memset(&lnp_original,0,sizeof lnp_original);memset(&np_life,0,sizeof np_life);
    memset(&fetch,0,sizeof fetch);memset(records,0,sizeof records);memset(&tx,0,sizeof tx);
    memset(&counts,0,sizeof counts);memset(&native_counts,0,sizeof native_counts);
    memset(&native_close,0,sizeof native_close);memset(&linked_epoch,0,sizeof linked_epoch);
    memset(&pg_source,0,sizeof pg_source);memset(&rx_view,0,sizeof rx_view);
    memset(&custody_stats,0,sizeof custody_stats);memset(&maps_stats,0,sizeof maps_stats);
    memset(&mv,0,sizeof mv);memset(os_slots,0,sizeof os_slots);memset(&os_reuse,0,sizeof os_reuse);
    oneshot_held=0;os_used=0;active=1;used=1;allocation_id=7;generation=11;
    counts.transactions=9;counts.generations=generation;counts.retained_records=used;counts.live_pages=1;
    records[0]=(struct owned_page){.address=NATIVE_LOW_LIMIT+PAGE,.allocation=7,.generation=11,
        .offset=PAGE,.initial_extent=3*PAGE,.backing=SEALED,.object=0,
        .logical=PROT_READ|PROT_EXEC,.actual=PROT_READ,.live=1};
    observed=(struct li2_native_pair_progress){.initialized=1,.phase=LI2_NP_IDLE,
        .pid=12345,.tid=12345,.events=17,.seeds=5};observed_quiet=1;np_life.published=7;
    hooks.fail=die;hooks.raw=no_raw;failure_code=0;failure_detail=0;
    snapshot(0,records[0].address+256);
}
static int choose(const struct li2_span_source *s,uint64_t serial) {
    struct li2_fetch f=fetch;struct li2_span_source saved=source;
    struct li2_native_pair_lifecycle life=np_life;struct li2_native_pair_progress n=observed;
    struct owned_page r[3];memcpy(r,records,sizeof r);
    int result=li2_lifecycle_link_native_probe_choose(s,serial);
    need(!memcmp(&f,&fetch,sizeof f)&&!memcmp(&saved,&source,sizeof saved)&&
         !memcmp(&life,&np_life,sizeof life)&&!memcmp(&n,&observed,sizeof n)&&
         !memcmp(r,records,sizeof r)&&raw_calls==0,10);
    return result;
}
static void current_cases(void) {
    for(unsigned i=0;i<24;i++) {
        setup();const struct li2_span_source *s=&source;
        switch(i) {
        case 0:s=0;break;case 1:source.ready=0;break;
        case 2:source.borrow.owner=0;break;case 3:source.borrow.sequence++;break;
        case 4:fetch.progress.held=1;break;case 5:fetch.progress.complete=0;break;
        case 6:fetch.progress.first_error=1;break;case 7:fetch.progress.identity_observed=0;break;
        case 8:fetch.allocation_epoch++;break;case 9:fetch.generation_epoch++;break;
        case 10:fetch.records_epoch++;break;case 11:fetch.transactions_epoch++;break;
        case 12:fetch.phase_epoch++;break;case 13:fetch.tid++;break;
        case 14:fetch.requested=14;break;case 15:source.key.entry++;break;
        case 16:source.key.page.vma_end+=PAGE;break;case 17:source.key.backing.seals=0;break;
        case 18:source.key.bytes[256]^=1;break;case 19:records[0].generation++;break;
        case 20:records[0].live=0;break;case 21:records[0].actual|=PROT_EXEC;break;
        case 22:observed_quiet=0;break;case 23:linked_epoch.p.phase=LI2_LINK_HELD;break;
        }
        need(!choose(s,23)&&lnp.lookups==1&&lnp.current_declines==1&&
             !lnp.policy_checks&&!lnp.chosen&&!lnp.pending,20+i);++current_controls;
    }
    setup();records[0].address=NATIVE_LOW_LIMIT-PAGE;snapshot(0,records[0].address+256);
    need(!choose(&source,23)&&lnp.current_declines==1&&!lnp.policy_checks,50);++current_controls;
}
static void policy_cases(void) {
    static const unsigned char denied[][2]={{0x0f,0x31},{0x0f,0x01},{0xc7,0xf8}};
    for(unsigned i=0;i<3;i++) {
        setup();memcpy(source.key.bytes+PAGE-2,denied[i],2);
        need(!choose(&source,23)&&lnp.policy_checks==1&&lnp.policy_blocked==1&&
             !lnp.chosen&&!lnp_refused_generation[0],60+i);++policy_controls;
    }
    setup();need(choose(&source,23)==1&&lnp.policy_checks==1&&!lnp.policy_blocked&&
        lnp.pending==1&&lnp.chosen==1&&!lnp.refaults&&!lnp.next_nx&&
        lnp.selected_record==1&&lnp.selected_generation==11&&lnp.selected_serial==23,63);
    ++policy_controls;
}
static void selected(void) {setup();need(choose(&source,23)==1,70);}
static void refault_cases(void) {
    for(unsigned i=0;i<5;i++) {
        selected();uint64_t serial=23;
        switch(i) {case 0:serial=0;break;case 1:serial++;break;case 2:lnp.pending=0;break;
        case 3:lnp.chosen++;break;case 4:lnp.refaults=UINT64_MAX;break;}
        struct li2_link_native_probe_progress before=lnp;
        need(li2_lifecycle_link_native_probe_refault(serial)==LI2_NP_STATE&&
             !memcmp(&before,&lnp,sizeof lnp),71+i);++refault_controls;
    }
    selected();need(!li2_lifecycle_link_native_probe_refault(23)&&lnp.refaults==1,76);
    need(li2_lifecycle_link_native_probe_refault(23)==LI2_NP_STATE&&lnp.refaults==1,77);
    ++refault_controls;
}
/* Supplied actual-owner observations: no native instruction, mprotect or
   source publication occurs in this pure component. */
static void nx(int result) {
    observed.events=lnp.selected_event+1;observed.pc=lnp.selected_pc;
    observed.signal_number=SIGSEGV;observed.signal_code=SEGV_ACCERR;
    observed.signal_errno=0;observed.signal_address=observed.pc;observed.first_observed=1;
    if(result==LI2_NP_RESUME) {
        records[lnp.selected_record-1].actual=PROT_READ|PROT_EXEC;
        records[lnp.selected_record-1].admitted=1;
        observed.phase=LI2_NP_EXECUTING_ONE;observed.live=1;observed.seeds=lnp.selected_seeds+1;
        observed_quiet=0;np_life.published=lnp.selected_published+1;
        np_life.post_verified=1;np_life.live=1;np_life.slots[0].pc=observed.pc;
        np_life.slots[0].published=1;
    } else if(result>LI2_NP_REFAULT) {observed.first_error=(unsigned)result;observed.phase=LI2_NP_FAILED;observed_quiet=0;}
}
static void pending(int result) {selected();need(!li2_lifecycle_link_native_probe_refault(23),80);nx(result);}
static void halo_case(void) {
    /* Actual byte-policy witness, followed by a SUPPLIED native-owner refusal.
       This component does not execute a halo or authenticate native admission. */
    setup();unsigned char window[PAGE+28];memset(window,0x90,sizeof window);
    memcpy(window+14,source.key.bytes,PAGE);window[14+PAGE]=0x0f;window[15+PAGE]=0x31;
    need(!li2_native_policy(window+14,PAGE)&&li2_native_policy(window,sizeof window),64);
    need(choose(&source,23)==1&&lnp.policy_checks==1&&!lnp.policy_blocked,65);
    need(!li2_lifecycle_link_native_probe_refault(23),66);nx(LI2_NP_FALLBACK);
    need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_FALLBACK)&&lnp.refused==1&&
         !lnp.admitted&&lnp_refused_generation[0]==records[0].generation,67);
    ++policy_controls;
}
static void outcome_cases(void) {
    for(unsigned i=0;i<18;i++) {
        pending(LI2_NP_FALLBACK);int expected=LI2_NP_STATE;
        switch(i) {
        case 0:lnp.selected_record=0;break;case 1:lnp.selected_record=used+1;break;
        case 2:lnp.selected_generation++;expected=LI2_NP_STALE;break;
        case 3:lnp.selected_serial=0;break;case 4:lnp.refaults=0;break;
        case 5:observed.events++;break;case 6:observed.pc++;break;
        case 7:observed.signal_number=SIGTRAP;break;case 8:observed.signal_code=SEGV_MAPERR;break;
        case 9:observed.signal_errno=1;break;case 10:observed.signal_address++;break;
        case 11:observed.first_observed=0;break;case 12:records[0].live=0;expected=LI2_NP_STALE;break;
        case 13:records[0].generation++;expected=LI2_NP_STALE;break;
        case 14:observed_quiet=0;break;case 15:observed.first_error=LI2_NP_IDENTITY;break;
        case 16:observed.seeds++;break;case 17:np_life.published++;break;
        }
        need(li2_lifecycle_link_native_probe_outcome(LI2_NP_FALLBACK)==expected&&
             lnp.pending==1&&!lnp.outcome_complete&&!lnp.next_nx&&!lnp.refused&&
             !lnp_refused_generation[0],81+i);++outcome_controls;
    }
    for(unsigned i=0;i<6;i++) {
        pending(LI2_NP_RESUME);
        switch(i) {case 0:records[0].actual=PROT_READ;break;case 1:observed.seeds--;break;
        case 2:np_life.published--;break;case 3:np_life.post_verified=0;break;
        case 4:np_life.slots[0].pc++;break;case 5:np_life.slots[0].policy=1;break;}
        need(li2_lifecycle_link_native_probe_outcome(LI2_NP_RESUME)==LI2_NP_STATE&&
             lnp.pending==1&&!lnp.admitted&&!lnp.next_nx&&!lnp_refused_generation[0],100+i);
        ++outcome_controls;
    }
    pending(LI2_NP_IDENTITY);
    need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_IDENTITY)&&lnp.errors==1&&
         !lnp.refused&&!lnp.admitted&&!lnp_refused_generation[0]&&lnp.outcome_complete&&
         !lnp.pending&&lnp.next_nx==1&&lnp.outcome_result==LI2_NP_IDENTITY,106);++outcome_controls;
    pending(LI2_NP_IDENTITY);
    need(li2_lifecycle_link_native_probe_outcome(LI2_NP_MAPPING)==LI2_NP_STATE&&
         !lnp.errors&&!lnp.refused&&!lnp_refused_generation[0]&&lnp.pending==1,107);++outcome_controls;
    pending(LI2_NP_FALLBACK);
    need(li2_lifecycle_link_native_probe_outcome(LI2_NP_REFAULT)==LI2_NP_STATE&&
         !lnp.errors&&!lnp.refused&&!lnp_refused_generation[0]&&lnp.pending==1,108);++outcome_controls;
}
static void actual_renewal(void) {
    struct li2_oneshot_lifecycle *s=&os_slots[0];s->page_count=1;
    s->progress.prepared=1;s->progress.held=1;s->checked.pages[0].address=records[0].address;
    s->original[0]=records[0];s->current_generation[0]=records[0].generation;
    s->current_protection[0]=PROT_READ;oneshot_held=1;
    struct li2_oneshot_generation renewal={0};renewal.before[0]=records[0].generation;
    size_t old_used=used;uint64_t before=generation;
    need(!os_reusable_renew(s,0,&renewal)&&used==old_used&&generation==before+1&&
         records[0].generation==generation&&renewal.after[0]==generation&&
         renewal.attempted_mask==1&&renewal.completed_mask==1&&raw_calls==0,114);
    oneshot_held=0;memset(s,0,sizeof *s);
}
static void lifetime(void) {
    pending(LI2_NP_FALLBACK);
    need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_FALLBACK)&&lnp.refused==1&&
         lnp.next_nx==1&&lnp.outcome_complete==1&&!lnp.pending&&lnp_refused_generation[0]==11,110);
    snapshot(0,records[0].address+256);need(!choose(&source,24)&&lnp.negative_hits==1,111);
    snapshot(0,records[0].address+257);need(!choose(&source,25)&&lnp.negative_hits==2,112);
    append(NATIVE_LOW_LIMIT+9*PAGE,8,0,SEALED,0,PROT_READ|PROT_EXEC,PROT_READ);
    snapshot(0,records[0].address+256);need(!choose(&source,26)&&lnp.negative_hits==3,113);++lifetime_cases;

    /* Exercise the ACTUAL in-place renewal helper, with explicitly supplied
       exclusive source-owner prestate. It performs no RAW/source stores. */
    actual_renewal();
    snapshot(0,records[0].address+256);
    need(choose(&source,27)==1&&!lnp_refused_generation[0]&&lnp.policy_checks==2&&lnp.chosen==2,115);
    need(!li2_lifecycle_link_native_probe_refault(27),116);nx(LI2_NP_FALLBACK);
    need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_FALLBACK)&&
         lnp_refused_generation[0]==generation&&lnp.refused==2,117);++lifetime_cases;
    uintptr_t address=records[0].address;retire(&records[0]);
    append(address,9,PAGE,SEALED,0,PROT_READ|PROT_EXEC,PROT_READ);
    snapshot(used-1,address+256);need(choose(&source,28)==1&&lnp.selected_record==3&&
         lnp.selected_generation==records[2].generation&&!lnp_refused_generation[2],118);++lifetime_cases;

    pending(LI2_NP_RESUME);need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_RESUME)&&
        lnp.admitted==1&&!lnp.refused&&!lnp_refused_generation[0]&&lnp.next_nx==1,119);
    /* Supplied complete native close for the next selection, not execution. */
    records[0].actual=PROT_READ;records[0].admitted=0;observed.phase=LI2_NP_IDLE;
    observed.live=0;observed_quiet=1;np_life.live=0;
    snapshot(0,records[0].address+256);need(choose(&source,24)==1&&lnp.chosen==2&&
         lnp.policy_checks==2&&!lnp.negative_hits&&!lnp_refused_generation[0],120);++lifetime_cases;

    pending(LI2_NP_FALLBACK);need(!li2_lifecycle_link_native_probe_outcome(LI2_NP_FALLBACK),121);
    actual_renewal();snapshot(0,records[0].address+256);
    source.key.bytes[PAGE-2]=0x0f;source.key.bytes[PAGE-1]=0x31;
    need(!choose(&source,24)&&!lnp_refused_generation[0]&&lnp.policy_checks==2&&
         lnp.policy_blocked==1&&lnp.chosen==1&&lnp.refused==1&&!lnp.negative_hits,122);++lifetime_cases;
}
static void terminal(uint64_t serial,unsigned code,long detail) {
    expecting_failure=1;
    if(!setjmp(failed)){(void)choose(&source,serial);need(0,130);}
    expecting_failure=0;need(failure_code==code&&failure_detail==detail&&!lnp_refused_generation[0],140);
    ++terminal_controls;
}
static void terminal_cases(void) {
    for(unsigned i=0;i<6;i++) {
        setup();uint64_t serial=23;unsigned code=LI2_NP_STATE;long detail=90;
        switch(i) {case 0:serial=0;break;case 1:lnp.pending=1;break;
        case 2:lnp.chosen=1;break;case 3:observed.phase=LI2_NP_EXECUTING_ONE;detail=92;break;
        case 4:observed.events=UINT64_MAX;code=LI2_NP_OVERFLOW;break;
        case 5:np_life.published=UINT64_MAX;code=LI2_NP_OVERFLOW;break;}
        terminal(serial,code,detail);
    }
}
int main(void) {
    _Static_assert(RECORDS==8192&&LI2_REGION_PAGE==4096,"actual fixed source domains");
    current_cases();policy_cases();halo_case();refault_cases();outcome_cases();lifetime();terminal_cases();
    need(current_controls==25&&policy_controls==5&&refault_controls==6&&outcome_controls==27&&
         lifetime_cases==5&&terminal_controls==6&&!raw_calls,150);
    printf("{\"version\":1,\"component_only\":1,\"current_controls\":25,\"policy_controls\":5,"
        "\"refault_controls\":6,\"outcome_controls\":27,\"lifetime_cases\":5,"
        "\"terminal_controls\":6,\"actual_in_place_renewal\":1,\"raw_calls\":0}\n");
    return 0;
}
