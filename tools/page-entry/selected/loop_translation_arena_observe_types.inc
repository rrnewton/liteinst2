/* Test-only snapshots. No field is an input to production authority. */
struct ltao_node {
    uint64_t h[24];
    struct sbc_certificate issued,current;
};
struct ltao_raw {
    uint64_t h[32],epochs[2][LI2_LTA_NODES];
    struct li2_private_code_query query[3];
    unsigned char before[PAGE],changed[PAGE],restored[PAGE];
};
struct ltao_wire {
    uint64_t h[32];
    struct ltao_node node[14][2][LI2_LTA_NODES];
    uint64_t controls[20][4];
    struct ltao_raw raw;
    struct lc8o_frame reentry;
    uint64_t reentry_counts[48];
    uint64_t pending[48];
};
