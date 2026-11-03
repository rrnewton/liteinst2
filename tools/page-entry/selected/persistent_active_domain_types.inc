/* Included after the original private generation/permit/slot types. These
   completion cells are separate from live replaceable slot storage. Only the
   protected claim mask changes while any member claim remains outstanding. */
struct pda_member_completion {
    struct li2_pgd_ref identity;
    struct pe_header header;
    struct li2_pg_source_key source;
    struct li2_pg_generation generation;
    struct pg_proof_query proof;
};
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
/* Saved before the completed plan can be replaced. No sibling pointer is
   needed to validate original bytes, selected arm or the closed member. */
struct pda_direct_exit {
    unsigned complete,member,heads,head,exits,index,arm,reserved;
    uint64_t flags;
    struct li2_pe_head row;
    struct li2_span_decoded original;
    struct li2_dd_descriptor direct;
};
_Static_assert(sizeof(struct pda_direct_exit)==528,"by-value direct exit custody");
#endif
#ifdef LI2_PERSISTENT_RET_DISPATCH
/* A completed guest load is not an ordinary original-PC exit. This value
   survives replacement of either retained generation without dereferencing it. */
struct pda_ret_exit {
    unsigned complete,member,heads,head;
    uintptr_t landing;
    struct li2_pe_head row;
    struct li2_span_decoded original;
    struct li2_rd_plan plan;
    struct li2_rd_recovered recovered;
    struct li2_rd_window window;
    struct li2_maps_call_stack stack;
};
#endif
#ifdef LI2_LOOP_RO_CERTIFICATE
struct __attribute__((aligned(PAGE))) pda_completion {
#else
struct pda_completion {
#endif
    uint64_t id,serial;
    unsigned count,complete;
    struct pda_member_completion member[LI2_PGD_MEMBERS];
    struct li2_pg_source_progress source;
    struct li2_pgd_source_progress domain_source;
    struct li2_pg_rseq_progress rseq;
    struct li2_fetch_progress fetch;
    struct li2_private_code_query directory_closed;
#ifdef LI2_LOOP_RESIDENT_RX
    struct {
        unsigned version,count,retained_mask,reserved;
        struct li2_pgd_rx_source_release source;
        struct li2_private_code_query open[LI2_PGD_MEMBERS][3],code[LI2_PGD_MEMBERS][3];
    } rx;
#endif
#ifdef LI2_PERSISTENT_RET_DISPATCH
    struct pda_ret_exit ret_exit;
#endif
#ifdef LI2_PERSISTENT_DIRECT_FRONTIER
    struct pda_direct_exit direct_exit;
#endif
};
struct pda_claim_observation {
    struct li2_private_code_query code[3],spill,slots;
    struct pg_proof_query proof;
};
struct pda_work {
    struct li2_pgd_view view;
    unsigned bound,peer,primary,primary_bank,exit_member,receipt;
    unsigned recovery_member,completion,aborting;
#ifdef LI2_LOOP_CACHE8
    unsigned peer_member;
    struct li2_pgd_view offer;
    struct pda_claim_observation peer_claim[LI2_PGD_MEMBERS-1U];
#else
    struct pda_claim_observation peer_claim;
#endif
    struct pg_proof_query proof_exit[LI2_PGD_MEMBERS];
    struct le_permission directory_write,directory_seal;
    struct li2_private_code_query directory_closed;
    struct li2_jd_domain_directory directory;
#ifdef LI2_LOOP_GROUP_DESCRIPTOR
    uint64_t descriptor_id,descriptor_epoch;
    struct li2_private_code_query descriptor_query;
#endif
#ifdef LI2_LOOP_RESIDENT_RX
    unsigned rx_retained_mask;
    struct li2_private_code_query rx_open[LI2_PGD_MEMBERS][3],rx_quiet[LI2_PGD_MEMBERS][3];
#endif
};
#ifdef LI2_PERSISTENT_LOOP_RUNTIME
struct plr_counts {
    uint64_t chooser_attempts,chooser_selected,chooser_no_envelope;
    uint64_t publications12,hits12,entries_with12,completed_with12,historical_reconstructions,actual_entries12;
};
#ifdef LI2_PERSISTENT_LOOP_EFFECTS
struct ple_counts {
    uint64_t chooser_attempts,chooser_selected,chooser_no_envelope;
    uint64_t publications13,hits13,entries_with13,completed_with13,historical_reconstructions,actual_entries13;
};
struct ple_state {
    unsigned choice_complete;
    struct ple_counts counts;
    struct li2_le_witness choice,check,historical;
};
#endif
struct plr_state {
    volatile sig_atomic_t scope;
    unsigned route,choice_complete;
    struct plr_counts counts;
    struct li2_le_witness choice,check,historical;
    uintptr_t pages[2];
    unsigned char source[2][LI2_REGION_PAGE];
    struct li2_dd_plan direct;
};
#endif
struct pda_state {
    uintptr_t directory;
    unsigned allocated,registered;
    uint64_t next_id,dual_entries,dual_completed;
    struct le_permission initial_seal;
    struct li2_private_code_query initial;
    struct pda_work work;
    struct pda_completion completion[LI2_PGD_RECEIPTS];
    unsigned claimed[LI2_PGD_RECEIPTS];
};
