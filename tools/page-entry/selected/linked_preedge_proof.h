#ifndef LI2_LINKED_PREEDGE_PROOF_H
#define LI2_LINKED_PREEDGE_PROOF_H
#include "linked_preedge_source.h"
#include "linked_proof.h"
#include "private_code_query.h"
struct li2_preedge_proof_header {
    uint64_t version,bytes,registry,slot,generation,generated,plan_proof,none_proof;
    unsigned char archive[32],policy[32];
    uint64_t reserved[4];
};
struct li2_preedge_proof {
    struct li2_preedge_proof_header header;
    struct li2_span_source_key key;
    struct li2_preedge_plan plan;
};
_Static_assert(sizeof(struct li2_preedge_proof_header)==160,"pre-edge proof header");
_Static_assert(sizeof(struct li2_preedge_proof)==45288,"pre-edge whole payload ABI");
_Static_assert(sizeof(struct li2_preedge_proof)<LI2_LINK_PROOF_BYTES,"pre-edge proof bound");
#endif
