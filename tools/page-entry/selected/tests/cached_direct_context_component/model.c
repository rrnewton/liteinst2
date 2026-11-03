/* The complete independent DIRECT byte interpreter, with only its directory
   parameter renamed to the actual version2 type. No cast, schema rewrite or
   alternative interpreter; only count/PC/generated fields are read by it. */
#include "loop_cached_direct_context.h"
#define li2_jd_domain_directory li2_lcx_directory
#define dd_model_run lcx_model_run
#include "tests/persistent_direct_frontier/model.c"
#undef dd_model_run
#undef li2_jd_domain_directory
