#ifndef LI2_LOOP_HISTORY_CERTIFICATE_H
#define LI2_LOOP_HISTORY_CERTIFICATE_H
/* Internal saved-value proof reuse for the explicit RO LOOP experiment.
   No current source, permission, claim or execution authority is cached. */
#if !defined(LI2_LOOP_RO_CERTIFICATE) || LI2_LOOP_RO_CERTIFICATE != 1 || \
    !defined(LI2_PERSISTENT_LOOP_EFFECTS) || LI2_PERSISTENT_LOOP_EFFECTS != 1 || \
    defined(LI2_PERSISTENT_RET_DISPATCH)
#error "history capsules require the separate LOOP RO profile, without RET"
#endif
struct pda_completion;
static int lhc_initialize(void);
static int lhc_begin(struct pda_completion *);
static int lhc_issue(const struct pda_completion *);
static int lhc_direct_value(const struct pda_completion *);
static void lhc_abort(void);
static void lhc_report(unsigned,unsigned);
#endif
