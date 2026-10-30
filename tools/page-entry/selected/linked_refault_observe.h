/* Capture-only, bounded one-excursion witness. No field is execution authority. */
struct leto_refault {
    uint64_t h[24];
    struct li2_span_transfer_progress prior,before_transfer;
    struct li2_native_close prior_close;
    struct li2_fetch_progress before_fetch;
    struct li2_tf_chain closed_chain;
    struct le_record record;
    struct li2_link_plan scratch;
    struct le_frame returned,nx,changed;
    struct leto_owners native_before,native_admitted,native_closed;
};
