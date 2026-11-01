#ifndef LI2_RESIDENT_THREE_APP_H
#define LI2_RESIDENT_THREE_APP_H
#define UA_FP 65536
#define UA_UC 1024
#define UA_LIVE 2116
#define UA_PAGE 4096
#define UA_SOURCE (6*UA_PAGE)
#define UA_STACK 520
#ifndef __ASSEMBLER__
#include <stdint.h>
struct ua_live { uint64_t g[16],flags; uint16_t selectors[6]; uint32_t reserved; };
struct ua_frame { uint64_t h[12]; unsigned char si[128],uc[UA_UC],fp[UA_FP]; };
struct r3a_prefix {
    uint64_t h[48]; uint32_t hardware[67][6]; struct ua_live seed;
    uint64_t machine[8]; unsigned char stack[UA_STACK];
};
struct r3a_suffix {
    uint64_t h[16]; struct ua_live before,after;
    uint64_t machine_before[8],machine_after[8];
    unsigned char before_live[UA_LIVE],after_live[UA_LIVE],stack[UA_STACK];
    struct ua_frame frames[5];
};
extern struct ua_live ua_input,ua_before,ua_after;
extern uintptr_t ua_target;
extern unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
extern unsigned char region_app_page[],region_app_head[],region_app_source_end[];
extern unsigned char region_app_seed_x87[],region_app_predecessor[];
extern unsigned char region_app_block_b[],region_app_block_c[],region_app_terminal[];
extern unsigned char region_app_capture_pointer[];
void region_app_enter(void);void region_app_capture_high(void);
#endif
#endif
