#ifndef LI2_LOOP_RESIDENT_RX_ORACLE_H
#define LI2_LOOP_RESIDENT_RX_ORACLE_H
#include "persistent_group_config.h"
#if !defined(LI2_LOOP_RESIDENT_RX_ORACLE) || LI2_LOOP_RESIDENT_RX_ORACLE != 1 || \
    !defined(LI2_LOOP_RESIDENT_RX_CONTROL) || \
    (LI2_LOOP_RESIDENT_RX_CONTROL != 0 && LI2_LOOP_RESIDENT_RX_CONTROL != 1) || \
    !defined(LI2_PG_LOOP_RESIDENT_RX_ORACLE_BINDING_VERSION) || \
    LI2_PG_LOOP_RESIDENT_RX_ORACLE_BINDING_VERSION != 1
#error "distinct source-bound LOOP RX finite observer and causal profile"
#endif
#if LI2_LOOP_RESIDENT_RX_CONTROL == 1 && (!defined(LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL) || LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL != 1)
#error "actual restored causal controls require every-hit certificate DIFF"
#endif
struct pda_completion;
static int lrxo_initialize(void);
static void lrxo_build(uintptr_t);
static void lrxo_member_begin(unsigned,int);
static void lrxo_member_end(unsigned);
static void lrxo_complete(const struct pda_completion *);
static void lrxo_armed(void);
static void lrxo_transit_armed(void);
static void lrxo_unsafe(unsigned);
static void lrxo_report(unsigned,unsigned);
#endif
