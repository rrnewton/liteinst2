#ifndef LI2_LOOP_RESIDENT_RX_PROFILE_H
#define LI2_LOOP_RESIDENT_RX_PROFILE_H
/* Distinct execution lifetime. The existing RO certificate proves bytes,
   never permission to execute or release a source/registration claim. */
#if LI2_LOOP_RESIDENT_RX != 1 || !defined(LI2_LOOP_RO_CERTIFICATE) || \
    LI2_LOOP_RO_CERTIFICATE != 1 || !defined(LI2_PERSISTENT_DIRECT_FRONTIER) || \
    LI2_PERSISTENT_DIRECT_FRONTIER != 1 || !defined(LI2_PERSISTENT_SUBENTRY) || \
    LI2_PERSISTENT_SUBENTRY != 1 || !defined(LI2_TF_HANDOFF) || LI2_TF_HANDOFF != 1
#error "LOOP retained RX requires the exact RO two-slot DIRECT/TF owner"
#endif
#if defined(LI2_RESIDENT_SOURCE_LEASE) || defined(LI2_RESIDENT_THREE) || \
    defined(LI2_PERSISTENT_CALL_DISPATCH) || defined(LI2_PERSISTENT_RET_DISPATCH) || \
    defined(LI2_LOOP_RO_TEST) || defined(LI2_LOOP_RO_REASONS) || defined(LI2_LOOP_RO_RETIRED)
#error "distinct LOOP RX lifetime: no source-lease domain or old observation ABI"
#endif
#if !defined(LI2_PG_LOOP_RESIDENT_RX_BINDING_VERSION) || LI2_PG_LOOP_RESIDENT_RX_BINDING_VERSION != 1
#error "LOOP retained RX requires its complete distinct source binding"
#endif
#endif
