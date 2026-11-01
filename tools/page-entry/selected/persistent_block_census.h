#ifndef LI2_PERSISTENT_BLOCK_CENSUS_H
#define LI2_PERSISTENT_BLOCK_CENSUS_H
#include <stdint.h>
#include <stddef.h>
#if !defined(LI2_PERSISTENT_BLOCK_CENSUS) || LI2_PERSISTENT_BLOCK_CENSUS != 1 || !defined(LI2_PERSISTENT_GROUP_COUNTERS) || !defined(LI2_PERSISTENT_SUBENTRY) || !defined(LI2_PERSISTENT_UNREGISTERED) || !defined(LI2_PERSISTENT_ACTIVE_DOMAIN)
#error "reuse census requires the separate release/subentry counter profile"
#endif
#if defined(LI2_PERSISTENT_SUBENTRY_CAPTURE) || defined(LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE) || defined(LI2_PERSISTENT_STARTUP_CAPTURE) || defined(LI2_PERSISTENT_RETAINED_EIGHT)
#error "reuse census is the original two-slot release observation only"
#endif
#if !defined(LI2_PERSISTENT_BLOCK_RUNTIME) || LI2_PERSISTENT_BLOCK_RUNTIME != 1 || !defined(LI2_PERSISTENT_CROSS_PAIR) || defined(LI2_REUSE_CENSUS) || defined(LI2_SEALED_BYTE_CERTIFICATE)
#error "separate PB census requires the unchanged PB two-slot counter owner, without old RCC or byte caching"
#endif
#define LI2_RCC_MAGIC UINT64_C(0x325342504e454352)
#define LI2_RCC_PHASES 17U
#define LI2_RCC_SCAN_HEADER 40U
#define LI2_RCC_BYTES (8U*1024U*1024U)
#define LI2_RCC_PAGES 256U
#define LI2_RCC_KEYS 8192U
#define LI2_RCC_GRAPHS 4096U
#define LI2_RCC_REGISTRIES 128U
#define LI2_RCC_ATTEMPTS 16384U
struct li2_rcc_page {uint64_t meta[32];unsigned char bytes[4096];};
struct li2_rcc_key {uint64_t words[8];};
struct li2_rcc_graph {uint64_t words[8];uint16_t heads[128];};
struct li2_rcc_registry {uint64_t words[512];};
struct li2_rcc_attempt {uint64_t words[32];};
/* Published only with the corresponding attempt's finish bit. word0 packs
   kind/member/slot/bank/head/exit/arm; words1..4 are graph/flags/PC/target.
   Kind1 is a selected branch-before frontier, never an executed successor.
   Kind2 is a non-direct original before-effect frontier with no target. */
struct li2_rcc_frontier {uint64_t words[5];};
/* h0..15: magic/version/extent/page/nonce/parent/dev/ino/pid/tid/
   initial/final seals/address/protected/fd_closed/ready.
   h16..23: error/pages/keys/graphs/registries/reserved_attempts/busy/finished.
   h24..29: exact capacities. h40..90: begin/success/error counts for each
   actual li2_pg_phase at a full pe_bytes call. Other header words stay zero.
   A kill or recorder stop may leave one full scan without a return count.
   Dictionary counts publish complete immutable entries. Attempt word31 is
   append-only phase bits: selection1/source2/plan4/bind8/finish16. */
struct li2_rcc_wire {
    uint64_t header[512];
    struct li2_rcc_page pages[LI2_RCC_PAGES];
    struct li2_rcc_key keys[LI2_RCC_KEYS];
    struct li2_rcc_graph graphs[LI2_RCC_GRAPHS];
    struct li2_rcc_registry registries[LI2_RCC_REGISTRIES];
    struct li2_rcc_attempt attempts[LI2_RCC_ATTEMPTS];
    struct li2_rcc_frontier frontiers[LI2_RCC_ATTEMPTS];
    unsigned char reserved[61440];
};
_Static_assert(sizeof(struct li2_rcc_wire)==LI2_RCC_BYTES,"fixed private sidecar extent");
_Static_assert(sizeof(struct li2_rcc_page)==4352 && sizeof(struct li2_rcc_key)==64 && sizeof(struct li2_rcc_graph)==320 && sizeof(struct li2_rcc_registry)==4096 && sizeof(struct li2_rcc_attempt)==256,"literal census sections");
_Static_assert(sizeof(struct li2_rcc_frontier)==40 && offsetof(struct li2_rcc_wire,frontiers)==7671808 && offsetof(struct li2_rcc_wire,reserved)==8327168,"same8MiB bounded PB frontier extension");
_Static_assert(__atomic_always_lock_free(8,0),"single-writer commit without locks");
#endif
