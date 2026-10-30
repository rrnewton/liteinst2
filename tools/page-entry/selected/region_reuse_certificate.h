#ifndef LI2_REGION_REUSE_CERTIFICATE_H
#define LI2_REGION_REUSE_CERTIFICATE_H
#include <stddef.h>
#include "region_source.h"
#include "private_code_query.h"

/* A protected runtime publication, R/NX for exactly one reuse generation.
   A caller-supplied pointer, hash, ready flag or old source borrow is never
   authority. No certificate may become writable before the old completed
   generation's permit has been consumed and both dispatch authorities revoked. */
#define LI2_REUSE_CERTIFICATE_PAGES 16U
#define LI2_REUSE_CERTIFICATE_BYTES (LI2_REUSE_CERTIFICATE_PAGES*4096U)
struct li2_reuse_certificate_header {
    uint64_t version,bytes,registry,slot,generation,generated,plan_proof,rseq_proof;
    unsigned char archive[32],policy[32];
    uint64_t reserved[4];
};
struct li2_reuse_certificate {
    struct li2_reuse_certificate_header header;
    struct li2_region_source_key key;
    struct li2_region_plan plan;
};
struct li2_reuse_certificate_match {
    unsigned attempted,complete;
    int result;
    size_t compared;
    uint64_t generation;
};
struct li2_reuse_certificate_observation {
    struct li2_reuse_certificate_match match;
    struct li2_private_code_query mapping;
};
_Static_assert(sizeof(struct li2_reuse_certificate_header)==160,"complete certificate header");
_Static_assert(offsetof(struct li2_reuse_certificate,key)==160,"no header gap");
_Static_assert(offsetof(struct li2_reuse_certificate,plan)==160+sizeof(struct li2_region_source_key),
    "no source/plan gap");
_Static_assert(sizeof(struct li2_reuse_certificate)==160+sizeof(struct li2_region_source_key)+sizeof(struct li2_region_plan),
    "no payload tail gap");
_Static_assert(sizeof(struct li2_reuse_certificate)<=LI2_REUSE_CERTIFICATE_BYTES,"bounded certificate payload");
#endif
