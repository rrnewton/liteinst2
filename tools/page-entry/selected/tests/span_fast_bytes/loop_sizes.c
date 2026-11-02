/* Supplemental process only: the original 23-length oracle runs separately.
   Reuse its actual production wrappers, guarded mappings and bytewise model;
   do not alter its source, main, population or required output. */
#define main span_fast_bytes_original_main
#include "oracle.c"
#undef main
#include "persistent_loop_plan.h"

_Static_assert(sizeof(struct li2_pg_plan)==981320,"actual policy12 full plan extent");
_Static_assert(sizeof(struct li2_le_witness)==83320,"actual complete chooser extent");

int main(void) {
    int error=length(sizeof(struct li2_pg_plan));
    if(!error)error=length(sizeof(struct li2_le_witness));
    if(!error)error=mismatch_before_guard();
    int cleanup=release();if(!error)error=cleanup;
    if(!error && (lengths!=2 || placements!=14 || mismatches!=42 || zero_access!=32 ||
                  prefix_mismatches!=98 || overlaps!=0 || fp_cases!=0))error=28;
    if(printf("{\"version\":1,\"profile\":\"loop-plan-fast-bytes-sizes-v1\",\"status\":%d,"
              "\"plan_bytes\":%zu,\"witness_bytes\":%zu,\"lengths\":%u,\"placements\":%u,"
              "\"mismatches\":%u,\"zero_access\":%u,\"prefix_mismatches\":%u,"
              "\"overlaps\":%u,\"fp_cases\":%u}\n",error,sizeof(struct li2_pg_plan),
              sizeof(struct li2_le_witness),lengths,placements,mismatches,zero_access,
              prefix_mismatches,overlaps,fp_cases)<0)return 126;
    return error?125:0;
}
