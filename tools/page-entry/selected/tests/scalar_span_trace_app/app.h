#ifndef LI2_SCALAR_SPAN_TRACE_APP_H
#define LI2_SCALAR_SPAN_TRACE_APP_H
#define UA_FP 65536
#define UA_UC 1024
#define UA_LIVE 2116
#define UA_PAGE 4096
#define UA_DATA 8192
#define UA_STACK 224
#ifndef __ASSEMBLER__
#include <stdint.h>
struct ua_live { uint64_t g[16],flags; uint16_t selectors[6]; uint32_t reserved; };
struct ua_frame { uint64_t h[12]; unsigned char si[128],uc[UA_UC],fp[UA_FP]; };
struct ra_prefix {
    uint64_t h[48]; uint32_t hardware[67][6]; struct ua_live seed;
    uint64_t machine[8]; unsigned char source[UA_PAGE],stack[UA_STACK],data[UA_DATA];
};
struct ra_observation {
    uint64_t h[16]; struct ua_live before,after;
    unsigned char before_live[UA_LIVE],after_live[UA_LIVE];
    unsigned char source[UA_PAGE],stack[UA_STACK],data[UA_DATA];
    struct ua_frame frames[3];
};
struct ra_suffix { uint64_t h[16]; struct ra_observation observations[1]; };
extern struct ua_live ua_input,ua_before,ua_after;
extern uintptr_t ua_target;
extern unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
extern unsigned char region_app_page[],region_app_head[],region_app_source_end[];
extern unsigned char region_app_seed_x87[];
extern unsigned char region_app_predecessor[],region_app_miss_predecessor[],region_app_miss_head[];
extern unsigned char region_app_exit0[],region_app_exit1[],region_app_miss_exit[],region_app_constant[];
void region_app_enter(void);void region_app_capture(void);
#endif
#endif
