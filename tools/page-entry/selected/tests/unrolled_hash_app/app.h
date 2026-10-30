#ifndef LI2_UNROLLED_APP_H
#define LI2_UNROLLED_APP_H
#define UA_FP 65536
#define UA_UC 1024
#define UA_LIVE 2116
#define UA_PAGE 4096
#define UA_DATA 8192
#define UA_STACK 160
#ifndef __ASSEMBLER__
#include <stdint.h>
struct ua_live { uint64_t g[16], flags; uint16_t selectors[6]; uint32_t reserved; };
/* Native-only real kernel frame. Full raw UC/SI retained; no invented model
   of unused kernel bookkeeping. Complete application FP bytes are compared. */
struct ua_frame { uint64_t h[12]; unsigned char si[128],uc[UA_UC],fp[UA_FP]; };
struct ua_prefix {
    uint64_t h[32]; uint32_t hardware[67][6]; struct ua_live seed;
    uint64_t machine[8]; unsigned char source[UA_PAGE],stack[UA_STACK],data[UA_DATA];
};
struct ua_suffix {
    uint64_t h[16]; struct ua_live before,after;
    unsigned char before_live[UA_LIVE],after_live[UA_LIVE];
    unsigned char source[UA_PAGE],stack[UA_STACK],data[UA_DATA];
    struct ua_frame frames[3];
};
extern struct ua_live ua_input,ua_before,ua_after;
extern unsigned char ua_before_live[UA_LIVE],ua_after_live[UA_LIVE];
extern unsigned char unrolled_app_head[],unrolled_app_stop[],unrolled_app_source_end[];
extern unsigned char unrolled_app_seed_x87[];
void unrolled_app_enter(void); void unrolled_app_capture(void);
#endif
#endif
