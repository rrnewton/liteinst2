#ifndef LI2_EVENT_PROFILE_H
#define LI2_EVENT_PROFILE_H
#include <stddef.h>
#include <stdint.h>
#if !defined(LI2_EVENT_PROFILE) || LI2_EVENT_PROFILE != 1 || LI2_COST_PROFILE != 1 || LI2_NATIVE_PAIR != 1
#error "event observation requires the explicit cost/native-pair profile"
#endif
enum li2_event_region {
    LI2_EV_HANDLER,LI2_EV_MAPS,LI2_EV_OPEN,LI2_EV_READ,LI2_EV_CLOSE,LI2_EV_PARSE,
    LI2_EV_DECODE,LI2_EV_CLASSIFY,LI2_EV_FOOTPRINT,LI2_EV_SCAN,LI2_EV_POLICY,
    LI2_EV_PREPARE,LI2_EV_PUBLISH,LI2_EV_NATIVE_CLOSE,LI2_EV_REGIONS
};
unsigned li2_event_enter(unsigned);
void li2_event_leave(unsigned);
void li2_event_maps_result(int,size_t,size_t);
long li2_event_maps_return(unsigned,long);
void li2_event_raw_enter(long);
void li2_event_raw_return(long,long);
struct li2_fetch_page;
void li2_event_site(const struct li2_fetch_page *,uintptr_t,uint32_t,unsigned);
struct li2_event_scope { unsigned token; };
static inline void li2_event_scope_end(struct li2_event_scope *s) { li2_event_leave(s->token); }
#define LI2_EVENT_SCOPE(name,kind) \
    struct li2_event_scope name __attribute__((cleanup(li2_event_scope_end)))={li2_event_enter(kind)}
/* GNU11 statement expression evaluates the old call exactly once. Cleanup is
   outside it; returned values/arguments are never normalized by observation. */
#define LI2_EVENT_VALUE(kind,expression) \
    __extension__ ({ unsigned li2_ev_token=li2_event_enter(kind); \
        __auto_type li2_ev_result=(expression); li2_event_leave(li2_ev_token); li2_ev_result; })
#define LI2_EVENT_MAPS_VALUE(kind,expression) \
    li2_event_maps_return(kind,LI2_EVENT_VALUE(kind,expression))
#endif
