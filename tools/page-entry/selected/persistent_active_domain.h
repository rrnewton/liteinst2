#ifndef LI2_PERSISTENT_ACTIVE_DOMAIN_H
#define LI2_PERSISTENT_ACTIVE_DOMAIN_H
#include "persistent_group_lifetime.h"
#include "linked_jmp_domain.h"
#if !defined(LI2_PERSISTENT_RETAINED_TWO) || LI2_PERSISTENT_RETAINED_TWO != 1 || \
    !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "active domain requires two retained resident certificates"
#endif
#define LI2_PGD_MEMBERS 2U
#define LI2_PGD_RECEIPTS 3U
#define LI2_PGD_VERSION 1U
/* Saved value identity remains meaningful after a different member is
   replaced. A pointer into a retired member is never completion evidence. */
struct li2_pgd_ref {
    uint64_t generation;
    uint32_t slot,bank;
    uintptr_t proof,root;
    struct li2_pg_layout layout;
};
struct li2_pgd_member {
    struct li2_pgd_ref identity;
    const struct li2_pg_compact *plan;
    const struct li2_pg_source_key *key;
};
struct li2_pgd_view {
    struct li2_pg_token token;
    uint32_t count,reserved;
    uintptr_t directory;
    struct li2_pgd_member member[LI2_PGD_MEMBERS];
};
struct li2_pgd_claim {
    uint64_t id;
    uint32_t cell,member,valid,reserved;
};
/* A real primary source observation plus independently observed additional
   code extents. Each raw query remains literal; no fabricated 34-page row. */
struct li2_pgd_source_progress {
    struct li2_pg_token token;
    uint32_t count,bound,opened,closed,released,first_error;
    long first_detail;
    struct li2_pgd_ref ref[LI2_PGD_MEMBERS];
    struct li2_private_code_query open[LI2_PGD_MEMBERS][3];
    struct li2_private_code_query close[LI2_PGD_MEMBERS][3];
};
/* The actual protected controller supplies this view, never a caller's
   proposed set. It authenticates fixed storage before returning pointers. */
const struct li2_pgd_view *li2_pgd_owner_view(const struct li2_pg_token *);
int li2_pgd_source_pair_equal(const struct li2_pg_source_key *,const struct li2_pg_source_key *);
int li2_pgd_source_bind(const struct li2_pg_token *);
int li2_pgd_source_opened(const struct li2_pg_token *);
int li2_pgd_source_release(const struct li2_pg_token *);
int li2_pgd_source_terminal(const struct li2_pg_token *);
const struct li2_pgd_source_progress *li2_pgd_source_progress(void);
int li2_pgd_rseq_bind(const struct li2_pg_token *,const ucontext_t *);
#endif
