/* Capture-only bounded native-hint excursion. Old relocation witness remains
   a separate required record. No observation grants execution authority. */
struct leto_hint_idle {
    unsigned initialized,phase,in_handler,first_error,live,entry_pending;
    long first_detail;
    uint64_t events,seeds,extensions,epochs_closed,one_page_closes,two_page_closes;
    uint64_t policy_closes,capacity_closes,refaults,refault_completed;
    struct li2_rseq_state rseq;
    struct li2_rseq_native_state rseq_native;
    struct li2_native_pair_lifecycle lifecycle;
    struct li2_rseq_pair_progress rseq_pair;
};
struct leto_hint {
    uint64_t h[32];
    struct li2_span_source source;
    struct li2_span_transfer_progress before_transfer,after_transfer;
    struct li2_fetch_progress fresh;
    uint64_t chain[16];
    struct li2_tf_chain_slot closed;
    struct le_frame before,returned,nx;
    struct li2_link_native_hint_progress before_hint,changed_hint,after_hint,outcome_hint;
    struct leto_hint_idle idle;
    struct leto_owners admitted,closed_native;
};
