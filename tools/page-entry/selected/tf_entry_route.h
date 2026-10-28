#ifndef LI2_TF_ENTRY_ROUTE_H
#define LI2_TF_ENTRY_ROUTE_H
#include "decoder.h"
/* Shared by actual opt-in NX dispatch and TRACE entry. New Code values are
   UNKNOWN by default; new guarded routes must be installed here explicitly.
   This descriptive result is never a source, frame or permission permit. */
enum li2_tf_entry_route { LI2_TF_ENTRY_UNKNOWN, LI2_TF_ENTRY_PLAIN,
    LI2_TF_ENTRY_XGETBV, LI2_TF_ENTRY_RDSSPQ, LI2_TF_ENTRY_BND };
enum li2_tf_entry_route li2_tf_entry_route(const struct li2_decoded *);
#endif
