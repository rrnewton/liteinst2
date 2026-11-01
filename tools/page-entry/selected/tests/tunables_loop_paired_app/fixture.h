#ifndef LI2_TUNABLES_LOOP_PAIRED_FIXTURE_H
#define LI2_TUNABLES_LOOP_PAIRED_FIXTURE_H
#include "app.h"
#ifndef __ASSEMBLER__
#define LP_SOURCE (2U*UA_PAGE)
#define LP_FRAMES 128U
#define LP_CASES 7U
#define LP_PLACEMENTS 4U
#define LP_MAGIC UINT64_C(0x32504c5032494c)
#define LP_VERSION 2U
#define LP_DATA UINT64_C(0x500000000000)
#define LP_GUARD (LP_DATA+UA_DATA)
#define LP_ROW (LP_DATA+512)
#define LP_KEY (LP_DATA+4096)
#define LP_TF UINT64_C(0x100)
#define LP_RF UINT64_C(0x10000)

/* Separate paired-app wire2. Native lane retains every actual frame;
   maintained lane retains app brackets only, with zero native-frame counters.
   This is not the policy12 owner capture ABI and cannot replace that record. */
struct lp_prefix {
    uint64_t h[64];
    uint32_t hardware[67][6];
    struct ua_live seed;
    uint64_t machine[8];
    unsigned char source[LP_SOURCE],data[UA_DATA],stack[UA_STACK];
};
struct lp_suffix {
    uint64_t h[32];
    struct ua_live before,after;
    uint64_t machine_before[8],machine_after[8];
    unsigned char before_live[UA_LIVE],after_live[UA_LIVE];
    unsigned char source[LP_SOURCE],data[UA_DATA],stack[UA_STACK];
    struct ua_frame frame[LP_FRAMES];
};

/* Independent literal-instruction reference; never calls a candidate decoder,
   chooser, planner, emitter, recovery function or owner. */
struct lp_model {
    uint64_t g[16],flags;
    uintptr_t pc,base,endpoint,entry;
    uint64_t backward[6],cut[2];
};
extern const unsigned char loop_native_template[],loop_native_template_end[];
extern const unsigned lp_entry[LP_CASES],lp_steps[LP_CASES];
extern const unsigned lp_backwards[LP_CASES][6],lp_cuts[LP_CASES][2];
extern const uintptr_t lp_source_page[LP_PLACEMENTS];
extern const unsigned lp_base_offset[LP_PLACEMENTS];
extern const int32_t lp_predecessor_offset;
void lp_inputs(unsigned,struct ua_live *,unsigned char [UA_DATA]);
void lp_model_init(struct lp_model *,const struct ua_live *,uintptr_t,uintptr_t,unsigned);
int lp_advance(struct lp_model *,const unsigned char [UA_DATA],uint64_t *);
#endif
#endif
