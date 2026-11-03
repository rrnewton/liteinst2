#ifndef LI2_LOOP_TRANSLATION_ARENA_H
#define LI2_LOOP_TRANSLATION_ARENA_H
#include "loop_group_descriptor.h"
#if !defined(LI2_LOOP_TRANSLATION_ARENA) || LI2_LOOP_TRANSLATION_ARENA != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_BINDING_VERSION) || LI2_PG_LOOP_TRANSLATION_ARENA_BINDING_VERSION != 1
#error "translation arena requires its distinct source and lifetime binding"
#endif
#ifdef LI2_LOOP_TRANSLATION_ARENA_PROGRAM
#if LI2_LOOP_TRANSLATION_ARENA_PROGRAM != 1 || \
    !defined(LI2_LOOP_CACHE8_PROGRAM) || LI2_LOOP_CACHE8_PROGRAM != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_PROGRAM_BINDING_VERSION) || \
    LI2_PG_LOOP_TRANSLATION_ARENA_PROGRAM_BINDING_VERSION != 1 || \
    defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE) || defined(LI2_LOOP_CACHE8_EFFECTS) || \
    defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) || defined(LI2_LOOP_RESIDENT_RX_ORACLE)
#error "arena program terminal requires its exact separate source binding"
#endif
#else
#if defined(LI2_LOOP_CACHE8_EFFECTS) || defined(LI2_LOOP_GROUP_DESCRIPTOR_OBSERVE) || \
    defined(LI2_LOOP_CACHE8_PROGRAM) || defined(LI2_LOOP_RESIDENT_RX_ORACLE)
#error "translation arena has a distinct observation and completion identity"
#endif
#endif
#ifdef LI2_LOOP_TRANSLATION_ARENA_CAPACITY
#if LI2_LOOP_TRANSLATION_ARENA_CAPACITY != 128 || \
    !defined(LI2_LOOP_TRANSLATION_ARENA_PROGRAM) || LI2_LOOP_TRANSLATION_ARENA_PROGRAM != 1 || \
    !defined(LI2_PG_LOOP_TRANSLATION_ARENA_CAPACITY_BINDING_VERSION) || \
    LI2_PG_LOOP_TRANSLATION_ARENA_CAPACITY_BINDING_VERSION != 1 || \
    defined(LI2_LOOP_TRANSLATION_ARENA_OBSERVE)
#error "128 immutable nodes require the distinct program-only capacity binding"
#endif
#define LI2_LTA_NODES 128U
#define LI2_LTA_VERSION 2U
#else
#ifdef LI2_PG_LOOP_TRANSLATION_ARENA_CAPACITY_BINDING_VERSION
#error "capacity binding requires the explicit capacity selector"
#endif
#define LI2_LTA_NODES 12U
#define LI2_LTA_VERSION 1U
#endif
/* Immutable translations keep their final addresses. Eight active bindings,
   nine completion cells and the original head/boundary bounds are unchanged. */
#endif
