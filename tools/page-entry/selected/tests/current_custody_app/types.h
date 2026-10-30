#ifndef LI2_CURRENT_CUSTODY_APP_TYPES_H
#define LI2_CURRENT_CUSTODY_APP_TYPES_H
/* Included after the unchanged original app.h definitions. */
struct uct_sample {
 struct ua_frame frame;
 uint64_t tls[2];
 unsigned char stack[UA_STACK],data[UA_DATA];
};
struct uct_app {
 uint64_t h[24];
 unsigned char source[UA_PAGE];
 struct uct_sample samples[4];
};
struct uct_output {struct ua_suffix original;struct uct_app current;};
_Static_assert(sizeof(struct uct_sample)==75152&&sizeof(struct uct_app)==304896&&
               offsetof(struct uct_output,current)==sizeof(struct ua_suffix)&&
               sizeof(struct uct_output)==sizeof(struct ua_suffix)+sizeof(struct uct_app),
               "exact old suffix then new extension, one original output operation");
#endif
