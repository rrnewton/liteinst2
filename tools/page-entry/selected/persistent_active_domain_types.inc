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
struct pda_completion {
    uint64_t id,serial;
    unsigned count,complete;
    struct pda_member_completion member[LI2_PGD_MEMBERS];
    struct li2_pg_source_progress source;
    struct li2_pgd_source_progress domain_source;
    struct li2_pg_rseq_progress rseq;
    struct li2_fetch_progress fetch;
    struct li2_private_code_query directory_closed;
};
struct pda_claim_observation {
    struct li2_private_code_query code[3],spill,slots;
    struct pg_proof_query proof;
};
struct pda_work {
    struct li2_pgd_view view;
    unsigned bound,peer,primary,primary_bank,exit_member,receipt;
    unsigned recovery_member,completion,aborting;
    struct pda_claim_observation peer_claim;
    struct pg_proof_query proof_exit[LI2_PGD_MEMBERS];
    struct le_permission directory_write,directory_seal;
    struct li2_private_code_query directory_closed;
    struct li2_jd_domain_directory directory;
};
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
