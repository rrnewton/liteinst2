#ifndef LI2_PERSISTENT_SUBENTRY_H
#define LI2_PERSISTENT_SUBENTRY_H
#include "persistent_group_lifetime.h"
#if !defined(LI2_PERSISTENT_SUBENTRY) || LI2_PERSISTENT_SUBENTRY != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_PERSISTENT_UNREGISTERED) || LI2_PERSISTENT_UNREGISTERED != 1
#error "distinct active-domain subentry profile required"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || (defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) && !defined(LI2_PERSISTENT_JOINT_SUBENTRY_CAPTURE)) || \
    defined(LI2_PERSISTENT_STARTUP_CAPTURE)
#error "subentry requires a distinct actual-entry capture contract"
#endif
#ifdef LI2_PERSISTENT_JOINT_SUBENTRY_CAPTURE
#if LI2_PERSISTENT_JOINT_SUBENTRY_CAPTURE != 1 || LI2_PERSISTENT_JOINT_STARTUP_CAPTURE != 1 || LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE != 1 || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE)
#error "distinct complete joint-subentry capture required"
#endif
#endif
/* Descriptive exact head, never authority without the actual owner/source
   and complete immutable-generation checks. Compiled root never changes. */
struct li2_pgs_target {
    uint32_t version,heads,head,member,local,source_page;
    uintptr_t root,pc,generated,page[2];
};
/* Retained by value in the completed domain source record. The original row
   survives replacement of the live slot; no stale slot dereference is needed. */
struct li2_pgs_entry {
    struct li2_pg_token token;
    uint64_t transfer_serial,generation,build_serial;
    struct li2_fetch_ref anchor;
    uint32_t slot,bank;
    struct li2_pgs_target target;
    struct li2_pe_head row;
    struct li2_span_decoded original;
    uint32_t complete,reserved;
};
/* 1 exact head, 0 absent (including external straddles), -1 malformed. */
int li2_pgs_head_lookup(const struct li2_pg_compact *,uintptr_t,struct li2_pgs_target *);
int li2_pgs_entry_source(const struct li2_pgs_entry *,uintptr_t,
    const struct li2_pg_sources *,const struct li2_pg_layout *);
int li2_pgs_entry_value(const struct li2_pgs_entry *,const struct li2_pg_source_key *,
    const struct li2_pg_sources *,const struct li2_pg_layout *);
int li2_pgs_source_pair_advisory(uintptr_t,const uintptr_t[2]);
const struct li2_pgs_entry *li2_pgs_owner_entry(const struct li2_pg_token *);
_Static_assert(sizeof(struct li2_pgs_target)==64,"separate compiled-root and actual-head identity");
_Static_assert(sizeof(struct li2_pgs_entry)==504,"complete by-value entry custody");
#endif
