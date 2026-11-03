#ifndef LI2_LOOP_CACHE8_PROFILE_H
#define LI2_LOOP_CACHE8_PROFILE_H
#include "persistent_group_config.h"
#include "loop_ro_profile.h"
/* Separate cache/active-domain shape. The per-plan source pair, physical
   images and placement banks remain exactly two; only ownership grows. */
#if !defined(LI2_LOOP_CACHE8) || LI2_LOOP_CACHE8 != 1 || \
    !defined(LI2_LOOP_RESIDENT_RX) || LI2_LOOP_RESIDENT_RX != 1 || \
    !defined(LI2_LOOP_RO_CERTIFICATE) || LI2_LOOP_RO_CERTIFICATE != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_PERSISTENT_CROSS_PAIR) || LI2_PERSISTENT_CROSS_PAIR != 1 || \
    !defined(LI2_PERSISTENT_SUBENTRY) || LI2_PERSISTENT_SUBENTRY != 1 || \
    !defined(LI2_PERSISTENT_UNREGISTERED) || LI2_PERSISTENT_UNREGISTERED != 1 || \
    !defined(LI2_PERSISTENT_LOOP_EFFECTS) || LI2_PERSISTENT_LOOP_EFFECTS != 1
#error "cache8 requires the complete LOOP RX cross-pair owner"
#endif
#if !defined(LI2_PG_LOOP_CACHE8_BINDING_VERSION) || LI2_PG_LOOP_CACHE8_BINDING_VERSION != 1
#error "cache8 requires its exact source and shape binding"
#endif
#if defined(LI2_LOOP_RESIDENT_RX_ORACLE) || defined(LI2_LOOP_RX_RECURRENCE) || \
    defined(LI2_LOOP_RO_REASONS) || defined(LI2_LOOP_RO_RETIRED) || \
    defined(LI2_PERSISTENT_RETAINED_EIGHT) || defined(LI2_PERSISTENT_RETAINED_EIGHT_HISTORY) || \
    defined(LI2_PERSISTENT_GROUP_COUNTERS) || defined(LI2_PERSISTENT_RETAINED_TWO_COUNTERS) || \
    defined(LI2_PERSISTENT_LOOP_COUNTERS) || defined(LI2_PERSISTENT_LOOP_EFFECTS_COUNTERS)
#error "cache8 has a distinct active-domain and observation layout"
#endif
#define LI2_LOOP_CACHE8_SLOTS 8U
#define LI2_LOOP_CACHE8_MEMBERS 8U
#define LI2_LOOP_CACHE8_RECEIPTS 9U
#endif
