#ifndef LI2_LOOP_RX_RECURRENCE_H
#define LI2_LOOP_RX_RECURRENCE_H
#include "persistent_group_config.h"
#include "persistent_group_lifetime.h"
#if LI2_LOOP_RX_RECURRENCE != 1 || LI2_LOOP_RESIDENT_RX != 1 || LI2_PG_LOOP_RX_RECURRENCE_BINDING_VERSION != 1
#error "recurrence requires its exact source-bound LOOP RX profile"
#endif
#if defined(LI2_LOOP_RESIDENT_RX_ORACLE) || defined(LI2_PERSISTENT_GROUP_COUNTERS) || defined(LI2_REUSE_CENSUS) || defined(LI2_PERSISTENT_BLOCK_CENSUS) || defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL)
#error "recurrence has a distinct release-only observation bank"
#endif
#define LI2_LRC_VERSION 7U
#define LI2_LRC_CAPACITY 1024U
#define LI2_LRC_BYTES 12382208UL
#define LI2_LRC_STORAGE 12582912UL
#define LI2_LRC_MAGIC UINT64_C(0x31434f554e544750)
#define LI2_LRC_STOP 8960U
/* words[127] is a release-store phase commit: BEGIN=1, PLAN=3,
   BOUND=7, FINISHED cancellation=11 or completion=15. */
struct li2_lrc_row {
    uint64_t words[128];
    struct li2_pg_source_key source;
    struct { uintptr_t first,end; } registry[128];
    uint16_t heads[128];
};
struct li2_lrc_bank {
    uint64_t header[512];
    struct li2_lrc_row row[LI2_LRC_CAPACITY];
    unsigned char tail[LI2_LRC_STORAGE-LI2_LRC_BYTES];
};
_Static_assert(sizeof(struct li2_fetch_page)==104 && sizeof(struct li2_fetch_backing)==176,
    "actual x86-64 page/backing ABI");
_Static_assert(offsetof(struct li2_fetch_backing,seals)==8 &&
    offsetof(struct li2_fetch_backing,stat_result)==16 && offsetof(struct li2_fetch_backing,stat)==24 &&
    offsetof(struct li2_fetch_backing,seals_observed)==168 && offsetof(struct li2_fetch_backing,stat_observed)==172 &&
    offsetof(struct stat,st_dev)==0 && offsetof(struct stat,st_ino)==8 &&
    offsetof(struct stat,st_mode)==24 && offsetof(struct stat,st_size)==48,
    "offline comparator uses actual stat field offsets");
_Static_assert(sizeof(struct li2_pg_source_key)==8760 && sizeof(struct li2_lrc_row)==12088,
    "whole actual source key and fixed row");
_Static_assert(offsetof(struct li2_lrc_row,source)==1024 &&
    offsetof(struct li2_lrc_row,registry)==9784 && offsetof(struct li2_lrc_row,heads)==11832,
    "literal wire offsets");
_Static_assert(offsetof(struct li2_lrc_bank,tail)==LI2_LRC_BYTES &&
    sizeof(struct li2_lrc_bank)==LI2_LRC_STORAGE,"complete observation backing");
extern struct li2_lrc_bank *li2_lrc_bank;
#endif
