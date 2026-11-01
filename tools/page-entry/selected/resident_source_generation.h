#ifndef LI2_RESIDENT_SOURCE_GENERATION_H
#define LI2_RESIDENT_SOURCE_GENERATION_H
#if !defined(LI2_RESIDENT_STABLE_GENERATION) || LI2_RESIDENT_STABLE_GENERATION != 1 || \
    !defined(LI2_RESIDENT_THREE) || LI2_RESIDENT_THREE != 1 || \
    !defined(LI2_EFFECT_PROVIDER) || LI2_EFFECT_PROVIDER != 1
#error "stable content requires the separate resident and actual effect owners"
#endif
#if defined(LI2_RESIDENT_THREE_CAPTURE) && \
    (!defined(LI2_RESIDENT_GENERATION_CAPTURE) || LI2_RESIDENT_GENERATION_CAPTURE != 1)
#error "version-2 generation proofs require the distinct repeated-owner capture"
#endif
/* A descriptive publication identity. It never grants a held fetch, entry,
   storage reference, RX permission or a replacement execution-lease epoch. */
struct li2_rsl_content_ref {
    const struct li2_rsl_owner *owner;
    uint64_t generation,publication_epoch;
};
enum li2_rsl_generation_state {
    LI2_RSG_UNISSUED,LI2_RSG_LIVE,LI2_RSG_SUSPENDED,LI2_RSG_DIRTY
};
struct li2_rsl_generation_progress {
    uint64_t generation,publication_epoch,effects,preserved,invalidations,source_mutations;
    uint64_t pending_epoch;
    long number,args[6],result;
    unsigned state,pending;
};
/* Real HELD binding and the full old source validation precede these calls.
   The provider independently authenticates the actual resident token. */
int li2_rsl_resident_content(const struct li2_r3_token *,struct li2_rsl_content_ref *);
int li2_rsl_resident_content_live(const struct li2_r3_token *,const struct li2_rsl_content_ref *);
/* The actual dispatcher alone calls the return seam after its native backend
   record and original postguards agree. There is no caller-selected preserve
   class, generation, quiet flag or fabricated completion receipt. */
int li2_rsl_generation_after_effect(long,const long[6],long);
int li2_rsl_generation_not_native(void);
/* Actual one-shot transfer, after old fetch release and before acquire/write.
   This first mode never renews content after temporary patch restoration. */
int li2_rsl_generation_source_mutation(void);
int li2_rsl_source_mutation_quiet(void);
const struct li2_rsl_generation_progress *li2_rsl_generation_progress(void);
#endif
