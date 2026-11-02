/* Link around the unchanged complete LPF oracle. Its original assertions and
   three result rows run first; every LPF build/validate also runs the actual
   scalar compact TU with identical complete input and initial output bytes.
   This finite test uses only the original oracle's valid, disjoint storage.
   No generated instruction or runtime owner is executed. */
#include "persistent_loop_fused_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int __real_main(void);
int __real_li2_lpf_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int __real_li2_lpf_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);
int scalar_li2_lpf_compact_build(const struct li2_pg_plan *,struct li2_pg_plan *,struct li2_pg_compact *);
int scalar_li2_lpf_compact_validate(const struct li2_pg_compact *,struct li2_pg_plan *,struct li2_pg_compact *);

static struct li2_pg_plan scalar_scratch,plan_before;
static struct li2_pg_compact scalar_output,compact_before;
static unsigned builds,build_ok,build_corrupt,validations,validate_ok,validate_corrupt;

static void disjoint(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    assert(a && b && an<=UINTPTR_MAX-x && bn<=UINTPTR_MAX-y &&
        (x+an<=y || y+bn<=x));
}

int __wrap_li2_lpf_compact_build(const struct li2_pg_plan *p,
        struct li2_pg_plan *scratch,struct li2_pg_compact *out) {
    disjoint(p,sizeof *p,scratch,sizeof *scratch);
    disjoint(p,sizeof *p,out,sizeof *out);
    disjoint(scratch,sizeof *scratch,out,sizeof *out);
    memcpy(&plan_before,p,sizeof plan_before);
    memcpy(&scalar_scratch,scratch,sizeof scalar_scratch);
    memcpy(&scalar_output,out,sizeof scalar_output);
    int fast=__real_li2_lpf_compact_build(p,scratch,out);
    assert(!memcmp(p,&plan_before,sizeof *p));
    int scalar=scalar_li2_lpf_compact_build(p,&scalar_scratch,&scalar_output);
    assert(fast==scalar && !memcmp(p,&plan_before,sizeof *p) &&
        !memcmp(scratch,&scalar_scratch,sizeof *scratch) &&
        !memcmp(out,&scalar_output,sizeof *out));
    assert(fast==0 || fast==LI2_PG_CORRUPT);
    ++builds;if(!fast)++build_ok;else ++build_corrupt;
    return fast;
}

int __wrap_li2_lpf_compact_validate(const struct li2_pg_compact *p,
        struct li2_pg_plan *scratch,struct li2_pg_compact *out) {
    disjoint(p,sizeof *p,scratch,sizeof *scratch);
    disjoint(p,sizeof *p,out,sizeof *out);
    disjoint(scratch,sizeof *scratch,out,sizeof *out);
    memcpy(&compact_before,p,sizeof compact_before);
    memcpy(&scalar_scratch,scratch,sizeof scalar_scratch);
    memcpy(&scalar_output,out,sizeof scalar_output);
    int fast=__real_li2_lpf_compact_validate(p,scratch,out);
    assert(!memcmp(p,&compact_before,sizeof *p));
    int scalar=scalar_li2_lpf_compact_validate(p,&scalar_scratch,&scalar_output);
    assert(fast==scalar && !memcmp(p,&compact_before,sizeof *p) &&
        !memcmp(scratch,&scalar_scratch,sizeof *scratch) &&
        !memcmp(out,&scalar_output,sizeof *out));
    assert(fast==0 || fast==LI2_PG_CORRUPT);
    ++validations;if(!fast)++validate_ok;else ++validate_corrupt;
    return fast;
}

int __wrap_main(void) {
    int status=__real_main();assert(status==0);
    assert(builds==76 && build_ok==24 && build_corrupt==52 &&
        validations==324 && validate_ok==24 && validate_corrupt==300);
    assert(printf("{\"profile\":\"group-compact-fast-bytes-v1\",\"builds\":%u,"
        "\"build_ok\":%u,\"build_corrupt\":%u,\"validations\":%u,\"validate_ok\":%u,"
        "\"validate_corrupt\":%u,\"whole_input_scratch_output\":1,"
        "\"emitted_execution\":0,\"owner_credit\":0}\n",
        builds,build_ok,build_corrupt,validations,validate_ok,validate_corrupt)>0);
    return 0;
}
