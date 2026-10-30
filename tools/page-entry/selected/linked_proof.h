#ifndef LI2_LINKED_PROOF_H
#define LI2_LINKED_PROOF_H
#include "linked_source.h"
#include "private_code_query.h"
#define LI2_LINK_PROOF_BYTES (16U*4096U)
struct li2_link_proof_header {
    uint64_t version,bytes,registry,slot,generation,generated,plan_proof,none_proof;
    unsigned char archive[32],policy[32];
    uint64_t reserved[4];
};
struct li2_link_proof {
    struct li2_link_proof_header header;
    struct li2_span_source_key key;
    struct li2_link_plan plan;
};
_Static_assert(sizeof(struct li2_link_proof_header)==160,"linked proof header");
_Static_assert(sizeof(struct li2_link_proof)<LI2_LINK_PROOF_BYTES,"linked proof bound");
#endif
