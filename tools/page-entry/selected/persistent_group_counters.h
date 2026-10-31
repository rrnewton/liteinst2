#ifndef LI2_PERSISTENT_GROUP_COUNTERS_H
#define LI2_PERSISTENT_GROUP_COUNTERS_H
#include <stdint.h>
#include <stddef.h>
#include "maps_phase.h"
#include "maps_view.h"
#include "native_pages.h"
#if !defined(LI2_PERSISTENT_GROUP_COUNTERS) || LI2_PERSISTENT_GROUP_COUNTERS != 1 || \
    !defined(LI2_PERSISTENT_GROUP) || LI2_PERSISTENT_GROUP != 1 || LI2_MAPS_MAINTAINED != 1
#error "final counter storage requires the explicit group maintained-map diagnostic"
#endif
#if defined(LI2_PERSISTENT_GROUP_CAPTURE) || defined(LI2_PERSISTENT_DYNAMIC) || \
    defined(LI2_PERSISTENT_EPOCH_CAPTURE) || defined(LI2_EVENT_PROFILE) || defined(LI2_COST_PROFILE)
#error "final counters have no capture wire or old observer compatibility"
#endif
#define LI2_PGC_MAGIC UINT64_C(0x31434f554e544750)
#define LI2_PGC_BYTES 752U
#define LI2_PGC_PAGE 4096U
#define LI2_PGC_INITIAL_SEALS 6U
#define LI2_PGC_FINAL_SEALS 23U
struct li2_pgc_ingress { uint64_t events,signals[5]; };
struct li2_pgc_group {
    uint64_t offers,publications,hits,cold_attempts,cancelled,retirements;
    uint64_t permit_claims,entries,completed,unexpected;
};
/* Header: magic/version/bytes/page/nonce/parent/dev/ino, then actual
   pid/tid/initial_seals/final_seals/address/protected/fd_closed/ready.
   The six bootstrap completion fields are descriptive, never guest authority. */
struct li2_pgc_record {
    uint64_t header[16];
    struct li2_pgc_ingress ingress;
    struct li2_pgc_group group;
    uint64_t misses[18];
    struct li2_maps_stats maps;
    struct li2_maps_view_stats view;
    struct li2_native_counts native;
};
_Static_assert(sizeof(struct li2_maps_stats)==64 && sizeof(struct li2_maps_view_stats)==88,"actual maps cells");
_Static_assert(sizeof(struct li2_native_counts)==200 && offsetof(struct li2_native_counts,last_block)==40 &&
               offsetof(struct li2_native_counts,first_admission_ns)==48,"actual native owner cells and padding");
_Static_assert(sizeof(struct li2_pgc_record)==LI2_PGC_BYTES && LI2_PGC_BYTES<=1024,"bounded logical final counters");
_Static_assert(offsetof(struct li2_pgc_record,ingress)==128 && offsetof(struct li2_pgc_record,group)==176 &&
               offsetof(struct li2_pgc_record,misses)==256 && offsetof(struct li2_pgc_record,maps)==400 &&
               offsetof(struct li2_pgc_record,view)==464 && offsetof(struct li2_pgc_record,native)==552,"exact final counter ABI");
_Static_assert(__atomic_always_lock_free(8,0) && __atomic_always_lock_free(4,0),"no counter lock gateway");
extern struct li2_pgc_record *li2_pgc_current;
int li2_pgc_bind_maps(struct li2_maps_stats *,struct li2_maps_view_stats *);
#endif
