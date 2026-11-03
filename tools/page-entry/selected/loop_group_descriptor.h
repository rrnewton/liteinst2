#ifndef LI2_LOOP_GROUP_DESCRIPTOR_H
#define LI2_LOOP_GROUP_DESCRIPTOR_H
#include "loop_cache8_profile.h"
#if !defined(LI2_LOOP_GROUP_DESCRIPTOR) || LI2_LOOP_GROUP_DESCRIPTOR != 1 || \
    !defined(LI2_PG_LOOP_GROUP_DESCRIPTOR_BINDING_VERSION) || LI2_PG_LOOP_GROUP_DESCRIPTOR_BINDING_VERSION != 1 || \
    !defined(LI2_MAPS_MAINTAINED) || LI2_MAPS_MAINTAINED != 1
#error "group descriptors require their complete cache8 source binding"
#endif
/* The actual RAW gateway calls this before a potentially destructive kernel
   operation. It allocates nothing and invokes no RAW on its returning path. */
void li2_lgd_before_raw(long,long,long,long,long,long,long);
uint64_t li2_lgd_source_context(void);
#endif
