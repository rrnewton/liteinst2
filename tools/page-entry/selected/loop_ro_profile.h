#ifndef LI2_LOOP_RO_PROFILE_H
#define LI2_LOOP_RO_PROFILE_H
/* Macro-only contract shared by all runtime TUs. The actual generated binding
   is needed before the controller-specific declarations become visible. */
#include "persistent_group_config.h"
/* Separate experiment. The mirror/root exclusion proof replaces only the
   resident-source-lease requirement of the byte certificate. It grants no
   source lifetime, permission, rseq, entry, completion, or plan authority. */
#if !defined(LI2_LOOP_RO_CERTIFICATE) || LI2_LOOP_RO_CERTIFICATE != 1 || \
    !defined(LI2_SEALED_BYTE_CERTIFICATE) || LI2_SEALED_BYTE_CERTIFICATE != 1 || \
    !defined(LI2_PERSISTENT_SEALED_GENERATION) || LI2_PERSISTENT_SEALED_GENERATION != 1 || \
    !defined(LI2_PERSISTENT_LOOP_EFFECTS) || LI2_PERSISTENT_LOOP_EFFECTS != 1 || \
    !defined(LI2_PERSISTENT_LOOP_RUNTIME) || LI2_PERSISTENT_LOOP_RUNTIME != 1 || \
    !defined(LI2_PERSISTENT_RETAINED_TWO) || LI2_PERSISTENT_RETAINED_TWO != 1 || \
    !defined(LI2_PERSISTENT_ACTIVE_DOMAIN) || LI2_PERSISTENT_ACTIVE_DOMAIN != 1 || \
    !defined(LI2_INITIAL_CODE_PROTECTION) || LI2_INITIAL_CODE_PROTECTION != 1 || \
    !defined(LI2_RSEQ_INACTIVE) || LI2_RSEQ_INACTIVE != 1
#error "LOOP RO byte certificates require the exact serialized two-member owner"
#endif
#if defined(LI2_RESIDENT_SOURCE_LEASE) || defined(LI2_RESIDENT_THREE) || \
    defined(LI2_SEALED_BYTE_CERTIFICATE_OBSERVE) || \
    defined(LI2_PERSISTENT_LOOP_CAPTURE) || defined(LI2_PERSISTENT_LOOP_EFFECTS_CAPTURE) || \
    defined(LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE) || \
    defined(LI2_PERSISTENT_LOOP_EFFECTS_LIFECYCLE_CAPTURE)
#error "separate RO mirror layout: no old source-lease or capture-schema cast"
#endif
#if !defined(LI2_PG_LOOP_RO_BINDING_VERSION) || LI2_PG_LOOP_RO_BINDING_VERSION != 1
#error "LOOP RO certificate requires its separately bound complete source policy"
#endif
#endif
