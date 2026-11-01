#ifndef LI2_TUNABLES_LIFECYCLE_FIXTURE_H
#define LI2_TUNABLES_LIFECYCLE_FIXTURE_H
#include "app.h"
#ifndef __ASSEMBLER__
#define LC_PAGE UA_PAGE
#define LC_PAIR (2U*UA_PAGE)
#define LC_SOURCE LC_PAIR
#define LC_FRAMES 64U
#define LC_CASES 2U
#define LC_PLACEMENTS 2U
#define LC_MAGIC UINT64_C(0x31434c5032494c)
#define LC_VERSION 1U
#define LC_DATA UINT64_C(0x500000000000)
#define LC_TF UINT64_C(0x100)
#define LC_RF UINT64_C(0x10000)
/* Separate companion wire. A, B and C bind one actual immutable pair.
   Guard pages are never read; all decoded A/B/C heads remain disjoint. */
struct lc_prefix {
    uint64_t h[64];
    uint32_t hardware[67][6];
    struct ua_live seed;
    uint64_t machine[8];
    unsigned char source[LC_PAIR],data[UA_DATA],stack[UA_STACK];
};
struct lc_suffix {
    uint64_t h[32];
    struct ua_live before,after;
    uint64_t machine_before[8],machine_after[8];
    unsigned char before_live[UA_LIVE],after_live[UA_LIVE];
    unsigned char source[LC_PAIR],data[UA_DATA],stack[UA_STACK];
    struct ua_frame frame[LC_FRAMES];
    unsigned char frame_data[LC_FRAMES][UA_DATA];
    unsigned char frame_stack[LC_FRAMES][UA_STACK];
};
struct lc_model {
    uint64_t g[16],flags;
    uintptr_t pc,a,b,endpoint;
    uint64_t a_back,a_to_b,b_to_a,c_back,stores64,stores16;
    unsigned char data[UA_DATA];
};
extern const uintptr_t lc_source_page[LC_PLACEMENTS];
extern const unsigned lc_entry[LC_CASES],lc_steps[LC_CASES];
extern const unsigned lc_a_back[LC_CASES],lc_a_to_b[LC_CASES];
extern const unsigned lc_base_offset,lc_b_offset,lc_cancel_offset,lc_c_offset,lc_stub_offset;
extern const int32_t lc_predecessor_offset;
extern const unsigned char lc_a_template[35],lc_b_template[15];
void lc_inputs(struct ua_live *,unsigned char [UA_DATA]);
void lc_model_init(struct lc_model *,const struct ua_live *,const unsigned char [UA_DATA],uintptr_t,uintptr_t,unsigned);
int lc_advance(struct lc_model *,uint64_t *);
#endif
#endif
