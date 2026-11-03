/* Distinct owner state. Nothing in an ordinary completion or directory is
   retagged. The immutable side proof has its own RAW epoch and issuer. */
#define LCX_ROUND(n) (((n)+PAGE-1U)&~(PAGE-1U))
struct lcx_bundle {
    uint64_t version,serial;
    unsigned members,count,reserved[2];
    struct li2_step_session session;
    unsigned char archive[32],policy[32];
    struct li2_pgd_ref ref[LI2_PGD_MEMBERS];
    struct li2_pg_source_key key[LI2_PGD_MEMBERS];
    struct li2_lcx_route route[LI2_DD_AUX_SLOTS];
    struct li2_lcx_image image[LI2_DD_AUX_SLOTS];
    struct li2_lcx_lease lease;
    struct li2_lcx_directory directory;
};
union lcx_bundle_pages {
    struct lcx_bundle value;
    unsigned char pages[LCX_ROUND(sizeof(struct lcx_bundle))];
};
struct lcx_side_value {
    uint64_t version,id,serial,epoch;
    const struct pda_completion *completion;
    struct li2_private_code_query code_closed,spill_closed;
    struct lcx_bundle bundle;
};
union lcx_side_pages {
    struct lcx_side_value value;
    unsigned char pages[LCX_ROUND(sizeof(struct lcx_side_value))];
};
struct lcx_issuance {
    uint64_t id,serial,epoch;
    unsigned members,auxiliary,retired,reserved;
    struct li2_pgd_ref ref[LI2_PGD_MEMBERS];
};
struct lcx_retirement {
    uint64_t id,serial;
    struct li2_pgd_ref ref;
    unsigned cell,member,valid,reserved;
};
struct lcx_work {
    struct lcx_bundle candidate,comparison;
    uint64_t serial,code_epoch,proof_epoch,directory_epoch;
    unsigned built,published,opened,closed;
    struct le_permission code_write,code_seal,code_open,code_close;
    struct le_permission proof_write,proof_seal;
    struct li2_private_code_query spill_before,spill_closed;
    unsigned recovery_owned,recovery_result;
    struct li2_dd_recovered recovered;
};
struct lcx_owner {
    unsigned initialized,poisoned;
    uintptr_t code,spill;
    uint64_t code_epoch,proof_epoch,directory_epoch,cell_epoch[LI2_PGD_RECEIPTS];
    struct lcx_issuance issued[LI2_PGD_RECEIPTS];
    struct lcx_retirement retired[LI2_LTA_NODES];
    uint64_t builds,opens,closes,entries,recoveries,retirements,invalidations;
    struct lcx_work work;
};
static union {
    struct lcx_owner value;
    unsigned char pages[LCX_ROUND(sizeof(struct lcx_owner))];
} lcx_runtime __attribute__((aligned(PAGE)));
static union lcx_bundle_pages lcx_live __attribute__((aligned(PAGE)));
static union lcx_side_pages lcx_cells[LI2_PGD_RECEIPTS] __attribute__((aligned(PAGE)));
_Static_assert(sizeof lcx_live<=64U*PAGE && sizeof lcx_cells[0]<=64U*PAGE,
    "each actual immutable LCX query fits the unchanged private API");
_Static_assert(sizeof lcx_runtime%PAGE==0 && sizeof lcx_live%PAGE==0 &&
    sizeof lcx_cells[0]%PAGE==0 && sizeof lcx_cells==LI2_PGD_RECEIPTS*sizeof lcx_cells[0],
    "complete isolated owner, current proof and individual side-proof extents");
static int lcx_initialize(void);
static void lcx_reset(void);
static int lcx_build(const ucontext_t *);
static int lcx_publish(void);
static int lcx_directory_equal(unsigned);
static int lcx_directory_equal_preentry(void);
static int lcx_open(void);
static int lcx_close(void);
static int lcx_complete(const struct pda_completion *);
static int lcx_receipt(const struct pda_completion *);
static int pda_receipt_base(const struct pda_completion *);
static int lcx_recover(uintptr_t,const uint64_t[16],uint64_t);
static void lcx_abort(void);
static int lcx_retire_invalid(void);
static int lcx_cold_pending(unsigned);
static int lcx_cold_retired(unsigned);
static int lcx_retirement_take(unsigned);
static int lcx_reclaimable(const struct pda_completion *);
static const struct lcx_bundle *lcx_current_bundle(void) __attribute__((unused));
static const struct lcx_side_value *lcx_completion_bundle(unsigned) __attribute__((unused));
int li2_lcx_rseq_value(const struct li2_pg_token *,const struct li2_lcx_lease *,
    const struct li2_lcx_image *,const ucontext_t *);
const struct li2_lcx_image *li2_lcx_pending_images(const struct li2_pg_token *);
void li2_lcx_before_raw(long,long,long,long,long,long,long);
