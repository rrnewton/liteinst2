#ifndef LI2_SEALED_BYTE_CERTIFICATE_H
#define LI2_SEALED_BYTE_CERTIFICATE_H
/* Private controller include. This value proves byte equality only; it is
   never a source, entry, mapping, rseq, or completion capability. */
#if !defined(LI2_SEALED_BYTE_CERTIFICATE) || LI2_SEALED_BYTE_CERTIFICATE != 1 || \
    !defined(LI2_PERSISTENT_SEALED_GENERATION) || LI2_PERSISTENT_SEALED_GENERATION != 1
#error "byte certificates require sealed storage and the complete writer-exclusion profile"
#endif
#if defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL) && LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL != 1
#error "the distinct qualification mode runs the original full scan at every decision"
#endif
#ifdef LI2_LOOP_RO_CERTIFICATE
#include "loop_ro_certificate.h"
#else
#if !defined(LI2_RESIDENT_SOURCE_LEASE) || LI2_RESIDENT_SOURCE_LEASE != 1
#error "the original certificate still requires its complete source-lease profile"
#endif
#include "resident_source_lease.h"
#endif
#ifdef LI2_LOOP_TRANSLATION_ARENA
/* Byte identity follows the immutable storage node, never a recycled active
   binding. These accessors grant neither source nor completion authority. */
#define SBC_NODE_COUNT PTR_NODE_COUNT
#define SBC_NODE_INDEX ptr_node_index(pe.selected_slot)
#define SBC_NODE_AT(i) PTR_NODE_AT(i)
#else
#define SBC_NODE_COUNT LI2_PTR_SLOTS
#define SBC_NODE_INDEX pe.selected_slot
#define SBC_NODE_AT(i) pe.retained[i]
#endif
struct sbc_certificate {
    unsigned valid,slot,bank,reserved;
    uint64_t serial,mirror_epoch,generation,build_serial;
    const struct li2_pg_epoch *owner;
    uintptr_t mirror;
    size_t mirror_bytes;
    struct li2_step_session session;
    struct li2_sealed_identity backing;
};
struct sbc_owner {
    uint64_t next_serial,mirror_epoch[SBC_NODE_COUNT],writer[SBC_NODE_COUNT];
    unsigned poisoned,reserved;
    struct sbc_certificate certificate[SBC_NODE_COUNT];
};
/* These protected observations are not consulted as equality authority. */
struct sbc_counts {
    uint64_t decisions,hits,misses,full_scans,full_scan_errors,disagreements;
    uint64_t full_scan_bytes,issues,invalidations,abort_invalidations;
    uint64_t live_queries,live_query_errors,postseal_bytes;
    unsigned initialized,last_failure;
    int last_full_result,reserved;
};
#ifdef LI2_LOOP_TRANSLATION_ARENA
_Static_assert(LI2_PTR_SLOTS==8 && SBC_NODE_COUNT==12 && sizeof(struct sbc_certificate)==200 &&
    sizeof(struct sbc_owner)==2608 && sizeof(struct sbc_counts)==120,
    "twelve immutable byte identities, eight active bindings");
#else
#ifdef LI2_LOOP_CACHE8
_Static_assert(LI2_PTR_SLOTS==8 && sizeof(struct sbc_certificate)==200 &&
    sizeof(struct sbc_owner)==1744 && sizeof(struct sbc_counts)==120,
    "literal eight-slot x86-64 byte-certificate metadata");
#else
_Static_assert(sizeof(struct sbc_certificate)==200 && sizeof(struct sbc_owner)==448 &&
    sizeof(struct sbc_counts)==120,"literal x86-64 byte-certificate metadata");
#endif
#endif
enum sbc_failure { SBC_NONE=0,SBC_FULL_SCAN_ERROR=1,SBC_DISAGREEMENT=2,SBC_LIVE_QUERY_ERROR=3 };
static int sbc_initialize(void);
static int sbc_replace_begin(void);
static int sbc_unpublished(void);
static int sbc_issue(void);
static void sbc_abort(void);
static void sbc_report(unsigned,unsigned);
#ifdef LI2_LOOP_TRANSLATION_ARENA
static int sbc_node_identity(unsigned,unsigned,const struct sbc_certificate *);
#endif
#endif
