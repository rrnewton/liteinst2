#ifndef LI2_PERSISTENT_CROSS_PAIR_H
#define LI2_PERSISTENT_CROSS_PAIR_H
/* Included after the actual domain reference/member declarations. */
#if LI2_PERSISTENT_CROSS_PAIR != 1 || !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1
#error "cross-pair source requires its distinct two-active-member profile"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_RESIDENT_CAPTURE) || \
    defined(LI2_PERSISTENT_RETAINED_TWO_CAPTURE) || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || \
    defined(LI2_PERSISTENT_STARTUP_CAPTURE) || defined(LI2_PERSISTENT_SUBENTRY_CAPTURE)
#error "cross-pair source requires a new exact typed capture schema"
#endif
enum li2_pgx_checkpoint { LI2_PGX_PREPARE,LI2_PGX_BIND,LI2_PGX_OPEN,LI2_PGX_CLOSE,LI2_PGX_CHECKS };
/* Each row is one actual maps/backing/whole-byte check. No physical I/O or
   independent acquisition is inferred from maintained maps observations. */
struct li2_pgx_check {
    struct li2_fetch_map_progress maps;
    struct li2_fetch_page page[2];
    struct li2_fetch_backing backing[2];
    unsigned started,pages,bytes[2],complete;
};
/* This is a peer source lease, not another fetch borrow or registration.
   Exact original roots and whole validated tables remain immutable values. */
struct li2_pgx_source {
    struct li2_pg_token token;
    struct li2_pgd_ref member;
    uint64_t allocation_epoch,generation_epoch,transactions_epoch;
    size_t records_epoch;
    struct li2_pg_source_key key;
    struct li2_mg_table table[2];
    struct li2_pgx_check checkpoint[LI2_PGX_CHECKS];
    unsigned started,complete,declined,decline_reason,checks,first_error;
    long first_detail;
};
/* The controller returns only its actual unclaimed protected peer proposal.
   A stale proposal may be declined before any peer permit is consumed. */
const struct li2_pgd_view *li2_pgx_owner_offer(const struct li2_pg_token *);
int li2_pgx_source_prepare(const struct li2_pg_token *,unsigned *);
#ifdef LI2_LOOP_CACHE8
/* Position is the actual pending owner-offer member, proposed only once. */
int li2_pgx_source_prepare_member(const struct li2_pg_token *,unsigned,unsigned *);
#endif
int li2_pgx_guard_union(const struct li2_pg_compact *,const struct li2_pg_compact *);
/* By-value historical validation; never follows a replaced sibling pointer. */
int li2_pgx_source_value(const struct li2_pgx_source *,const struct li2_pg_sources *,
    const struct li2_pg_token *,const struct li2_pgd_ref *,const struct li2_pg_source_key *,unsigned);
#endif
