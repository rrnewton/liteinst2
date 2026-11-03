/* Included after all existing owners. No reader of this record can authorize
   an instruction, source lease, current mapping, completion or cached proof.
   We terminate while the real offer is being prepared; no terminal owner
   conservation is asserted and no interrupted application state is resumed. */
_Static_assert(LI2_LTA_NODES==128 && LI2_PTR_SLOTS==8 && LI2_PGD_RECEIPTS==9,
    "the diagnostic does not change node, active binding or receipt bounds");
_Static_assert(__atomic_always_lock_free(4,0) && __atomic_always_lock_free(8,0),
    "exact scalar loads have no helper or kernel effect");
_Static_assert(sizeof(struct ltapf_core)==16U*8U && sizeof(struct ltapf_cache)==6U*8U &&
    sizeof(struct ltapf_rx)==17U*8U && sizeof(struct ltapf_arena)==12U*8U &&
    sizeof(struct ltapf_history)==11U*8U && sizeof(struct ltapf_common)==14U*8U &&
    sizeof(struct ltapf_byte)==13U*8U && sizeof(struct li2_maps_view_stats)==88 &&
    sizeof(struct li2_maps_stats)==64 && sizeof(struct ltapf_binding)==16 &&
    sizeof(struct ltapf_node)==56 && sizeof(struct ltapf_record)==8952,
    "complete fixed prefix wire, including raw flags rather than inferred state");
#define LTAPF_REASON(n,i) _Static_assert(LI2_PGD_##n==(i),"exact miss reason " #n);
LTAPF_REASONS(LTAPF_REASON)
#undef LTAPF_REASON
_Static_assert(LI2_PGD_REASON_COUNT==18 && sizeof(struct plr_counts)==72 &&
    sizeof(struct ple_counts)==72 && sizeof(struct ltapf_loop)==72 &&
    sizeof(struct ltapf_effects)==72,"complete actual miss/LOOP/effects populations");
#define LTAPF_LOOP_OFFSET(n) _Static_assert(offsetof(struct ltapf_loop,n)==offsetof(struct plr_counts,n),"LOOP offset " #n);
#define LTAPF_EFFECTS_OFFSET(n) _Static_assert(offsetof(struct ltapf_effects,n)==offsetof(struct ple_counts,n),"effects offset " #n);
LTAPF_LOOP(LTAPF_LOOP_OFFSET)
LTAPF_EFFECTS(LTAPF_EFFECTS_OFFSET)
#undef LTAPF_LOOP_OFFSET
#undef LTAPF_EFFECTS_OFFSET
_Static_assert(LI2_PG_IDLE==0 && SELECTED_GENERIC_TF==2 && SIGTRAP==5 && TRAP_TRACE==2 &&
    SELECTED_TF==0x100 && SELECTED_RF==0x10000,"literal pre-close checkpoint encoding");
_Static_assert(offsetof(struct ltapf_record,maps_view)==1408 &&
    offsetof(struct ltapf_record,maps)==1496 && offsetof(struct ltapf_record,phase)==1560 &&
    offsetof(struct ltapf_record,binding)==1656 && offsetof(struct ltapf_record,node)==1784,
    "exact complete scalar and node offsets");
static struct ltapf_record ltapf_saved;
#define LTAPF_LOAD(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
static _Noreturn void ltapf_stop(int sig,const siginfo_t *si,const ucontext_t *uc) {
    struct ltapf_record *o=&ltapf_saved;
    /* These are value loads only. In particular do not call PTR_SLOT_AT,
       lta_node_bound, pda_receipt, permission queries, RAW, or report here. */
#define LTAPF_COPY(n) o->core.n=LTAPF_LOAD(&pe.n);
    LTAPF_CORE(LTAPF_COPY)
#undef LTAPF_COPY
    for(unsigned i=0;i<LI2_PGD_REASON_COUNT;i++)o->misses[i]=LTAPF_LOAD(PGC_MISS_REF(i));
    o->pf_backward_refused=LTAPF_LOAD(&pe.pf_backward_refused);
    o->pf_backward_cancelled=LTAPF_LOAD(&pe.pf_backward_cancelled);
#define LTAPF_COPY(n) o->loop.n=LTAPF_LOAD(&pe.loop.counts.n);
    LTAPF_LOOP(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->effects.n=LTAPF_LOAD(&pe.effects.counts.n);
    LTAPF_EFFECTS(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->cache.n=LTAPF_LOAD(&pe.cache8.n);
    LTAPF_CACHE(LTAPF_COPY)
#undef LTAPF_COPY
    for(unsigned i=0;i<9;i++) {
        o->groups[0][i]=LTAPF_LOAD(&pe.cache8.bound_by_count[i]);
        o->groups[1][i]=LTAPF_LOAD(&pe.cache8.entered_by_count[i]);
        o->groups[2][i]=LTAPF_LOAD(&pe.cache8.completed_by_count[i]);
    }
#define LTAPF_COPY(n) o->rx.n=LTAPF_LOAD(&pe.rx.n);
    LTAPF_RX(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->arena.n=LTAPF_LOAD(&lta_writer.value.n);
    LTAPF_ARENA(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->history.n=LTAPF_LOAD(&lhc.counts.n);
    LTAPF_HISTORY(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->common.n=LTAPF_LOAD(&lgd_counts.n);
    LTAPF_COMMON(LTAPF_COPY)
#undef LTAPF_COPY
#define LTAPF_COPY(n) o->byte.n=LTAPF_LOAD(&sbc_observed.n);
    LTAPF_BYTE(LTAPF_COPY)
#undef LTAPF_COPY
    o->ingress[0]=LTAPF_LOAD(PGC_EVENT_REF);
    for(unsigned i=0;i<5;i++)o->ingress[i+1]=LTAPF_LOAD(PGC_SIGNAL_REF(i));
    o->phase[0]=LTAPF_LOAD(&pe.initialized);o->phase[1]=LTAPF_LOAD(&pe.registered);
    o->phase[2]=LTAPF_LOAD(&pe_active);o->phase[3]=LTAPF_LOAD(&pe_busy);
    o->phase[4]=LTAPF_LOAD(&pe_closing);o->phase[5]=LTAPF_LOAD(&pe_decoding);
    o->phase[6]=LTAPF_LOAD(&pe_failing);o->phase[7]=LTAPF_LOAD(&pe.resuming);
    o->phase[8]=LTAPF_LOAD(&pe.redirected);o->phase[9]=LTAPF_LOAD(&pe.warm);
    o->phase[10]=LTAPF_LOAD(&pe.consumed);o->phase[11]=LTAPF_LOAD(&pe.p.phase);
    o->phase[12]=LTAPF_LOAD(&pe.p.first_error);o->phase[13]=LTAPF_LOAD(&pe.domain.work.bound);
    o->phase[14]=LTAPF_LOAD(&pe.domain.work.completion);o->phase[15]=LTAPF_LOAD(&pe.domain.work.aborting);
    o->phase[16]=LTAPF_LOAD(&pe.selected_slot);o->phase[17]=LTAPF_LOAD(&pe.selected_bank);
    o->phase[18]=LTAPF_LOAD(&selected_pending_route);o->phase[19]=LTAPF_LOAD(&selected_step_pending);
    o->phase[20]=LTAPF_LOAD(&handling);o->phase[21]=LTAPF_LOAD(&pe.arena.initialized);
    o->phase[22]=LTAPF_LOAD(&pe.arena.rebind_mask);o->phase[23]=0;
    for(unsigned i=0;i<8;i++) {
        o->binding[i].generation=LTAPF_LOAD(&pe.arena.binding[i].generation);
        o->binding[i].node=LTAPF_LOAD(&pe.arena.binding[i].node);
        o->binding[i].reserved=LTAPF_LOAD(&pe.arena.binding[i].reserved);
    }
    for(unsigned i=0;i<128;i++) {
        const struct li2_ptr_slot *s=&pe.arena.node[i];
        const struct lta_dormant *d=&lta_writer.value.dormant[i];
        struct ltapf_node *n=&o->node[i];
        n->generation=LTAPF_LOAD(&s->identity.generation);
        n->root=LTAPF_LOAD(&s->publication.source.entry);
        n->node_epoch=LTAPF_LOAD(&lta_writer.value.node[i]);
        n->issued_epoch=LTAPF_LOAD(&d->node_epoch);n->reusable=LTAPF_LOAD(&d->reusable);
        n->installed=LTAPF_LOAD(&s->generation.installed);n->index=LTAPF_LOAD(&s->identity.index);
        n->claim=LTAPF_LOAD(&s->claim.valid);n->reserved=0;
    }
    /* Both existing getters are pure lock-free scalar copies. Their values
       are frozen with the other observations before the first output call. */
    li2_maps_view_snapshot(&o->maps_view);li2_maps_stats_read(&o->maps);
    o->h[0]=LTAPF_MAGIC;o->h[1]=1;o->h[2]=sizeof *o;o->h[3]=LTAPF_OFFERS;
    o->h[4]=128;o->h[5]=8;o->h[6]=160;o->h[7]=24;
    o->h[8]=(uint64_t)sig;o->h[9]=si?(uint64_t)(int64_t)si->si_code:0;
    o->h[10]=uc?(uint64_t)uc->uc_mcontext.gregs[REG_RIP]:0;
    o->h[11]=uc?(uint64_t)uc->uc_mcontext.gregs[REG_EFL]:0;
    o->h[12]=o->core.offers;o->h[13]=o->ingress[0];o->h[14]=1;o->h[15]=0;
    __asm__ volatile("":::"memory");
    /* Trusted gateway, output-only and then kernel process teardown. Never
       reenter a possibly active RAW wrapper or claim ordinary owner cleanup.
       A short/error write remains a failed observation (126), never 125. */
    long wrote=li2_raw6(SYS_write,report_fd,(long)o,sizeof *o,0,0,0);
    (void)li2_raw6(SYS_exit_group,wrote==(long)sizeof *o?125:126,0,0,0,0,0);
    __builtin_trap();
}
#undef LTAPF_LOAD
