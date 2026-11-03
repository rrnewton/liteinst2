#ifndef LI2_LOOP_TRANSLATION_ARENA_H
#define LI2_LOOP_TRANSLATION_ARENA_H
#include "loop_group_descriptor.h"
#if !defined(LI2_LOOP_TRANSLATION_ARENA) || LI2_LOOP_TRANSLATION_ARENA != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_BINDING_VERSION) || LI2_PG_LOOP_TRANSLATION_ARENA_BINDING_VERSION != 1
#error "translation arena requires its distinct source and lifetime binding"
#endif
#if defined(LI2_LOOP_CACHE8_EFFECTS) || defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) || \
    defined(LI2_LOOP_CACHE8_PROGRAM) || defined(LI2_LOOP_RESIDENT_RX_ORACLE)
#error "translation arena has a distinct observation and completion identity"
#endif
#define LI2_LTA_NODES 12U
#define LI2_LTA_VERSION 1U
/* Immutable translations keep their final addresses. Eight active bindings,
   nine completion cells and the original head/boundary bounds are unchanged. */
#endif
