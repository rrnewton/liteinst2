#ifndef LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE_H
#define LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE_H
#include "loop_group_descriptor.h"
#if !defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) || LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE != 1 || \
    !defined(LI2_PG_LOOP_GROUP_DESCRIPTOR_OBSERVE_BINDING_VERSION) || \
    LI2_PG_LOOP_GROUP_DESCRIPTOR_OBSERVE_BINDING_VERSION != 1 || \
    !defined(LI2_LOOP_CACHE8_CONTROL) || LI2_LOOP_CACHE8_CONTROL < 0 || LI2_LOOP_CACHE8_CONTROL > 6
#error "exact descriptor ABC255 observer/control binding required"
#endif
#if LI2_LOOP_CACHE8_CONTROL && !defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL)
#error "descriptor exposure controls retain every-hit original differential proofs"
#endif
/* Scalars describe actual owners. Complete permission records are copied;
   no callback, reader or supplied address grants execution authority. */
struct lgdo_snapshot {
    uint64_t h[32],descriptor[16],history[16],claim[8][8],cell[9][4];
    struct le_permission directory_write,directory_seal;
    struct li2_private_code_query directory_query;
};
struct lgdo_raw {
    uint64_t h[32],call[4][8],epoch[5][4],counts[3][32];
    struct li2_private_code_query query[3][2];
};
struct lgdo_wire {
    uint64_t h[16];
    struct lgdo_snapshot snapshot[5][4];
    struct lgdo_raw raw[1];
};
/* Separate terminal observations; the original binary wire is unchanged. */
struct lgdo_preentry_observation {
    uint64_t epochs,accepted,ordinary_refusals,attempted,refused,restorations;
    uint64_t serial[5],refusal[5],restore[5];
};
_Static_assert(sizeof(struct lgdo_preentry_observation)==168,
    "separate bounded preentry terminal observations");
/* Actual common-only cache decisions; no original binary row changes. */
struct lgdo_common_observation {
    uint64_t epochs,serial,cell,id,cell_serial,quiet_pairs;
    uint64_t token_misses,token_restorations,token_mask;
    uint64_t guard_unissued,guard_restorations,guard_mask;
    uint64_t raw_unissued,raw_restorations,raw_mask;
    uint64_t failed_full,failed_unissued,failed_restored,history_fallback;
};
_Static_assert(sizeof(struct lgdo_common_observation)==152,
    "separate fixed common-revalidation observations");
union lgdo_saved {
    union lhc_root_page root;
    union lhc_capsule capsule;
    unsigned char manifest[sizeof lgd_group],directory[LI2_JD_DOMAIN_BYTES];
};
_Static_assert(sizeof(struct li2_private_code_query)==296 && sizeof(struct le_permission)==336 &&
    sizeof(struct lgdo_snapshot)==2280 && sizeof(struct lgdo_raw)==3216 && sizeof(struct lgdo_wire)==48944,
    "independent descriptor appendage layout");
_Static_assert(sizeof(struct pda_completion)<=128U*PAGE && sizeof(union lhc_capsule)<=64U*PAGE &&
    sizeof lgd_group<=64U*PAGE && LI2_JD_DOMAIN_BYTES<=64U*PAGE,
    "two bounded physical queries cover every exact RAW-control object");
static void lgdo_snapshot(unsigned,unsigned);
static void lgdo_finished(const struct pda_completion *);
static void lgdo_preentry(unsigned);
static void lgdo_preentry_report(unsigned,unsigned);
static void lgdo_common_report(unsigned,unsigned);
#endif
