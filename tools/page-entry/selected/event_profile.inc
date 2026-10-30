/* Opt-in observation only. Included after the real fixed protection functions.
   No return value below is consumed as runtime permission or product status. */
#include "event_profile.h"
#define EVENT_DEPTH 8
#define EVENT_SITES 16384
#define EVENT_TOP 32
#include "../sha256.h"
struct event_clock_buffer { int64_t sec,nsec; };
__attribute__((visibility("hidden"))) struct event_clock_buffer li2_event_clock_buffer;
extern long li2_event_clock_raw(void);
#define EVENT_RAW 13
struct event_frame { uint64_t started; unsigned kind; };
struct event_site { uint64_t object,offset,code,reason,count; };
struct event_state {
    uint64_t initialized,sealed,valid,error;
    volatile sig_atomic_t busy,active;
    unsigned depth,signal_index,route_index;
    uint64_t clock_count[4],handlers[3],signals[5],routes[7];
    uint64_t signal_ns[5],route_ns[7];
    uint64_t calls[LI2_EV_REGIONS],returns[LI2_EV_REGIONS];
    uint64_t exclusive[LI2_EV_REGIONS],inclusive[LI2_EV_REGIONS];
    uint64_t maps[13],raw[EVENT_RAW][3],maps_start[10],maps_end[10];
    uint64_t owner_start[4],owner_end[4];
    uint64_t site_total,site_other,site_count,site_retained,site_start,site_end,last;
    struct event_site top[EVENT_TOP];
    unsigned char table_hash[32];
    struct event_frame stack[EVENT_DEPTH];
    struct event_site sites[EVENT_SITES];
    char output[8192];size_t output_used;
};
static struct event_state event;
_Static_assert(sizeof(li2_event_clock_buffer)==16,"exact syscall timespec write extent");
_Static_assert(sizeof(struct li2_maps_stats)==64,"complete maps snapshot, no hidden suffix");
_Static_assert(sizeof(struct event_site)==5*sizeof(uint64_t),"site row has no padding");
_Static_assert(sizeof event<1024*1024,"bounded whole protected observation state");
static void event_bad(unsigned code) {
    if(!event.error)event.error=code;
    event.valid=0;
}
static void event_add(uint64_t *value,uint64_t amount) {
    if(*value>UINT64_MAX-amount)event_bad(1);
    else *value+=amount;
}
static int event_enabled(void) {
    return event.initialized && event.valid && !event.sealed && event.active;
}
static void event_maps_snapshot(uint64_t out[10]) {
    struct li2_maps_stats m;li2_maps_stats_read(&m);
    out[0]=m.fresh_calls;out[1]=m.acquisitions;out[2]=m.reuses;
    out[3]=m.invalidations;out[4]=m.handler_id;out[5]=m.mutation_epoch;
    out[6]=m.active;out[7]=m.valid;out[8]=m.poisoned;out[9]=m.reserved;
    if(m.poisoned || m.reserved)event_bad(2);
}
static void event_owner_snapshot(uint64_t out[4]) {
    const struct li2_native_pair_lifecycle *p=li2_lifecycle_pair_progress();
    out[0]=selected_chain.event_id;out[1]=p->attempts;
    out[2]=p->published;out[3]=p->close_calls;
}
/* Fixed no-argument gateway call. Neither buffer nor clock id can come from
   application arguments. The complete state is already in protected[]. */
__attribute__((noinline)) static uint64_t event_clock(void) {
    if(!event_enabled() || event.busy || handling!=1) {event_bad(3);return 0;}
    event.busy=1;__asm__ volatile("":::"memory");
    struct li2_maps_stats before,after;li2_maps_stats_read(&before);
    li2_event_clock_buffer.sec=-1;li2_event_clock_buffer.nsec=-1;
    event_add(&event.clock_count[0],1);
    if(!event.valid){event.busy=0;return 0;}
    long result=li2_event_clock_raw();
    event_add(&event.clock_count[1],1);
    li2_maps_stats_read(&after);
    if(result || before.poisoned || before.reserved || !equal(&before,&after,sizeof before) || li2_event_clock_buffer.sec<0 ||
       li2_event_clock_buffer.nsec<0 || li2_event_clock_buffer.nsec>=1000000000 ||
       (uint64_t)li2_event_clock_buffer.sec>(UINT64_MAX-(uint64_t)li2_event_clock_buffer.nsec)/UINT64_C(1000000000)) {
        event_bad(4);event.busy=0;return 0;
    }
    uint64_t now=(uint64_t)li2_event_clock_buffer.sec*UINT64_C(1000000000)+(uint64_t)li2_event_clock_buffer.nsec;
    if(!now || (event.clock_count[1]>1 && now<event.clock_count[3]))event_bad(5);
    if(event.clock_count[1]==1)event.clock_count[2]=now;
    event.clock_count[3]=now;
    __asm__ volatile("":::"memory");event.busy=0;return now;
}
static uint64_t event_boundary(void) {
    uint64_t now=event_clock();
    if(!event.valid)return 0;
    if(event.depth) {
        if(now<event.last){event_bad(5);return 0;}
        event_add(&event.exclusive[event.stack[event.depth-1].kind],now-event.last);
    }
    event.last=now;return now;
}
unsigned li2_event_enter(unsigned kind) {
    if(!event_enabled())return 0;
    if(kind>=LI2_EV_REGIONS || event.depth>=EVENT_DEPTH ||
       (!event.depth && kind!=LI2_EV_HANDLER) || (event.depth && kind==LI2_EV_HANDLER)) {
        event_bad(6);return 0;
    }
    uint64_t now=event_boundary();if(!event.valid)return 0;
    event.stack[event.depth]=(struct event_frame){now,kind};++event.depth;
    event_add(&event.calls[kind],1);
    if(kind==LI2_EV_MAPS)event_add(&event.maps[0],1);
    if(kind==LI2_EV_OPEN)event_add(&event.maps[2],1);
    if(kind==LI2_EV_READ)event_add(&event.maps[4],1);
    if(kind==LI2_EV_CLOSE)event_add(&event.maps[8],1);
    if(kind==LI2_EV_PARSE)event_add(&event.maps[10],1);
    return event.depth;
}
void li2_event_leave(unsigned token) {
    if(!token || !event_enabled())return;
    if(token!=event.depth){event_bad(6);return;}
    uint64_t now=event_boundary();if(!event.valid)return;
    struct event_frame *s=&event.stack[event.depth-1];
    if(now<s->started){event_bad(5);return;}
    event_add(&event.inclusive[s->kind],now-s->started);
    event_add(&event.returns[s->kind],1);*s=(struct event_frame){0};--event.depth;
}
long li2_event_maps_return(unsigned kind,long result) {
    if(!event_enabled())return result;
    if(kind==LI2_EV_OPEN) { if(result>=0)event_add(&event.maps[3],1); }
    else if(kind==LI2_EV_READ) {
        if(result>=0)event_add(&event.maps[5],1);
        if(result>0)event_add(&event.maps[6],(uint64_t)result);
        if(!result)event_add(&event.maps[7],1);
    } else if(kind==LI2_EV_CLOSE) { if(!result)event_add(&event.maps[9],1); }
    else event_bad(7);
    return result;
}
void li2_event_maps_result(int result,size_t bytes,size_t rows) {
    (void)bytes;
    if(event_enabled() && !result) {
        event_add(&event.maps[1],1);event_add(&event.maps[11],1);
        event_add(&event.maps[12],rows);
    }
}
static unsigned event_raw_index(long n) {
    switch(n) {
    case SYS_openat:return 0;case SYS_read:return 1;case SYS_close:return 2;
    case SYS_pread64:return 3;case SYS_fstat:return 4;case SYS_fcntl:return 5;
    case SYS_mprotect:return 6;case SYS_membarrier:return 7;case SYS_getpid:return 8;
    case SYS_gettid:return 9;case SYS_clock_gettime:return 10;case SYS_ptrace:return 11;
    default:return 12;
    }
}
void li2_event_raw_enter(long n) {
    if(event_enabled())event_add(&event.raw[event_raw_index(n)][0],1);
}
void li2_event_raw_return(long n,long result) {
    if(!event_enabled())return;
    unsigned i=event_raw_index(n);event_add(&event.raw[i][1],1);
    if(result<0)event_add(&event.raw[i][2],1);
}
/* Diagnostic-local value bound to lifecycle_loader.c enum backing. */
enum { EVENT_SEALED_BACKING=1 };
void li2_event_site(const struct li2_fetch_page *p,uintptr_t pc,uint32_t code,unsigned reason) {
    if(!event_enabled())return;
    if(!p || p->backing!=EVENT_SEALED_BACKING || !reason || reason>LI2_CHAIN_NOT_CLASSIFIED || p->object>=34 ||
       pc<p->address || pc-p->address>=PAGE ||
       p->offset>UINT64_MAX-(pc-p->address)){event_bad(8);return;}
    uint64_t offset=p->offset+(pc-p->address);event_add(&event.site_total,1);
    uint64_t hash=(offset^(uint64_t)p->object*UINT64_C(0x9e3779b97f4a7c15)^((uint64_t)code<<17)^reason);
    hash^=hash>>33;hash*=UINT64_C(0xff51afd7ed558ccd);hash^=hash>>33;
    for(size_t n=0;n<EVENT_SITES;n++) {
        struct event_site *s=&event.sites[(hash+n)&(EVENT_SITES-1)];
        if(!s->count) {
            *s=(struct event_site){p->object,offset,code,reason,1};
            event_add(&event.site_count,1);event_add(&event.site_retained,1);return;
        }
        if(s->object==p->object && s->offset==offset && s->code==code && s->reason==reason) {
            event_add(&s->count,1);event_add(&event.site_retained,1);return;
        }
    }
    event_add(&event.site_other,1);
}
static int event_site_before(const struct event_site *a,const struct event_site *b) {
    if(a->count!=b->count)return a->count>b->count;
    if(a->object!=b->object)return a->object<b->object;
    if(a->offset!=b->offset)return a->offset<b->offset;
    if(a->code!=b->code)return a->code<b->code;
    return a->reason<b->reason;
}
static void event_sites_finish(void) {
    for(size_t i=0;i<EVENT_SITES;i++)if(event.sites[i].count) {
        const struct event_site *s=&event.sites[i];
        for(size_t j=0;j<EVENT_TOP;j++)if(!event.top[j].count || event_site_before(s,&event.top[j])) {
            for(size_t k=EVENT_TOP-1;k>j;k--)event.top[k]=event.top[k-1];
            event.top[j]=*s;break;
        }
    }
    digest((const unsigned char *)event.sites,sizeof event.sites,event.table_hash);
}

static void event_initialize(void) {
    /* Pure protection calls; no new RAW before first safe application ingress. */
    if(event.initialized || selected_run_protect_add(0,(uintptr_t)&event,sizeof event) ||
       selected_run_protect_contains(0,(uintptr_t)&event,sizeof event)!=1 ||
       selected_run_protect_add(0,(uintptr_t)&li2_event_clock_buffer,sizeof li2_event_clock_buffer) ||
       selected_run_protect_contains(0,(uintptr_t)&li2_event_clock_buffer,sizeof li2_event_clock_buffer)!=1) {event_bad(9);return;}
    event.initialized=1;event.valid=1;event_maps_snapshot(event.maps_start);
    event.site_start=selected_chain.fallbacks;event_owner_snapshot(event.owner_start);
}
static void event_handler_begin(int sig,unsigned route) {
    if(!event.initialized || event.sealed || !event.valid)return;
    if(event.active || event.depth || event.busy || handling!=1 || route>=7) {event_bad(10);return;}
    event.active=1;event_add(&event.handlers[0],1);event_add(&event.routes[route],1);
    unsigned i=sig==SIGSEGV?0:sig==SIGTRAP?1:sig==SIGSYS?2:sig==SIGILL?3:4;
    event.signal_index=i;event.route_index=route;
    event_add(&event.signals[i],1);(void)li2_event_enter(LI2_EV_HANDLER);
}
static void event_handler_end(unsigned terminal) {
    if(!event_enabled())return;
    if(event.depth!=1 || event.stack[0].kind!=LI2_EV_HANDLER) {event_bad(10);return;}
    uint64_t started=event.stack[0].started;
    li2_event_leave(1);
    if(event.valid) {
        event_add(&event.signal_ns[event.signal_index],event.last-started);
        event_add(&event.route_ns[event.route_index],event.last-started);
    }
    event_add(&event.handlers[terminal?2:1],1);event.active=0;
}
static void event_seal(void) {
    if(event.sealed)return;
    if(!event.initialized || !event.active)event_bad(11);
    event_handler_end(1);event_maps_snapshot(event.maps_end);event.sealed=1;
    event.site_end=selected_chain.fallbacks;event_owner_snapshot(event.owner_end);event_sites_finish();
}
static void event_text(const char *s) {
    while(*s) {
        if(event.output_used==sizeof event.output){event_bad(12);return;}
        event.output[event.output_used++]=*s++;
    }
}
static void event_number(uint64_t n) {
    char b[21];size_t used=0;do {b[used++]=(char)('0'+n%10);n/=10;}while(n);
    while(used){char s[2]={b[--used],0};event_text(s);}
}
static void event_field(const char *key,uint64_t n) {event_text(key);event_number(n);}
static void event_array(const char *key,const uint64_t *a,size_t n) {
    event_text(key);event_text("[");
    for(size_t i=0;i<n;i++){if(i)event_text(",");event_number(a[i]);}event_text("]");
}
static void event_report(void) {
    /* All timing/counts sealed before the old report's first syscall. The old
       writer size, rows and report results are not modified. */
    /* 373 numeric fields at full capacity: 341 arbitrary uint64 values
       (including 32*5 sites), plus 32 hash bytes with at most three digits.
       Each term includes its separator; 800 covers keys/brackets/prefix. */
    _Static_assert(341*21+32*4+800<8192,"entire fixed diagnostic line bound");
    event.output_used=0;event_text("LI2_EVENT {\"version\":1");
    event_field(",\"initialized\":",event.initialized);event_field(",\"sealed\":",event.sealed);
    event_field(",\"valid\":",event.valid);event_field(",\"error\":",event.error);
    event_field(",\"busy\":",(uint64_t)event.busy);event_field(",\"active\":",(uint64_t)event.active);
    event_field(",\"depth\":",event.depth);
    event_array(",\"clock\":",event.clock_count,4);event_array(",\"handlers\":",event.handlers,3);
    event_array(",\"signals\":",event.signals,5);event_array(",\"routes\":",event.routes,7);
    event_array(",\"signal_ns\":",event.signal_ns,5);event_array(",\"route_ns\":",event.route_ns,7);
    event_array(",\"region_calls\":",event.calls,LI2_EV_REGIONS);
    event_array(",\"region_returns\":",event.returns,LI2_EV_REGIONS);
    event_array(",\"exclusive_ns\":",event.exclusive,LI2_EV_REGIONS);
    event_array(",\"inclusive_ns\":",event.inclusive,LI2_EV_REGIONS);
    event_array(",\"maps\":",event.maps,13);
    event_array(",\"maps_start\":",event.maps_start,10);event_array(",\"maps_end\":",event.maps_end,10);
    event_array(",\"owner_start\":",event.owner_start,4);event_array(",\"owner_end\":",event.owner_end,4);
    event_text(",\"raw\":[");
    for(unsigned i=0;i<EVENT_RAW;i++)event_array(i?",":"",event.raw[i],3);
    event_text("]");
    event_field(",\"site_total\":",event.site_total);event_field(",\"site_other\":",event.site_other);
    event_field(",\"site_unique\":",event.site_count);event_field(",\"site_retained\":",event.site_retained);
    event_field(",\"site_start\":",event.site_start);event_field(",\"site_end\":",event.site_end);
    uint64_t hash[32];for(unsigned i=0;i<32;i++)hash[i]=event.table_hash[i];
    event_array(",\"site_sha256\":",hash,32);
    event_text(",\"sites\":[");
    for(size_t i=0;i<EVENT_TOP && event.top[i].count;i++)event_array(i?",":"",(const uint64_t *)&event.top[i],5);
    event_text("]}\n");
    (void)raw(SYS_write,report_fd<0?2:report_fd,(long)event.output,event.output_used,0,0,0);
}
