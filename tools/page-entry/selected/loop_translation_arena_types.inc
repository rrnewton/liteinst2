/* Included after li2_ptr_slot. No saved completion claim is an inactive
   translation's execution authority. Binding generations are independent of
   the globally nonwrapping compiled-generation identity. */
struct lta_binding {
    uint64_t generation;
    uint32_t node,reserved;
};
struct lta_state {
    struct li2_ptr_slot node[LI2_LTA_NODES];
    struct lta_binding binding[LI2_PTR_SLOTS];
    uint64_t next_binding;
    unsigned initialized,rebind_mask;
};
_Static_assert(LI2_PTR_SLOTS==8 && LI2_PGD_MEMBERS==8 && LI2_PGD_RECEIPTS==9,
    "arena capacity grants no additional active member or completion claim");
