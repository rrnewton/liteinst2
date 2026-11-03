/* Included after the actual generation and domain types. Mutable permission
   lifetime is outside each immutable completion/generation snapshot. */
enum lprx_lifetime { LPRX_EMPTY=0,LPRX_RESIDENT,LPRX_REVOKING,LPRX_REVOKED };
struct lprx_slot {
    unsigned phase,bank;
    uint64_t generation,serial;
    struct li2_pg_layout layout;
    struct le_permission revoke[3];
};
enum { LPRX_DIRECT_LIMIT=2 };
struct lprx_transit {
    struct li2_span_decoded original;
    struct li2_dd_descriptor direct;
    struct li2_chain_fetch source;
    uint64_t previous_generation,previous_event;
    unsigned previous_slot,arm;
};
struct lprx_branch {
    unsigned phase,cell,slot,reserved;
    uint64_t id,serial,chain_generation,chain_event;
    uintptr_t target;
    uint64_t flags;
    unsigned branches,transit_reserved;
    struct lprx_transit transit;
};
struct lprx_state {
    struct lprx_slot slot[LI2_PTR_SLOTS];
    struct lprx_branch branch;
    uint64_t entries,retained_entries,quiet_releases,direct_offers,direct_steps;
    uint64_t code_opens,code_revokes,code_writes,code_syncs,metadata_permissions,metadata_syncs;
    uint64_t terminal_attempts,terminal_closed;
    uint64_t transit_offers,transit_steps,transit_declined,transit_limit;
    uint64_t revocations[LPRX_REASON_COUNT];
};
