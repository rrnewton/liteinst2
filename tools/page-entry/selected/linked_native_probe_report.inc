/* Separate actual probe row; old linked refaults remain relocation-only and
   old native-pair/domain wire layouts remain unchanged. */
#include "linked_native_probe.h"
static void selected_link_native_probe_report(unsigned status,unsigned code,long detail) {
    const struct li2_link_native_probe_progress *p=li2_lifecycle_link_native_probe_progress();
    _Static_assert(20U*21U+512U<4096U,"bounded native probe terminal row");
    struct writer w={0};text(&w,"LI2_LINKED_NATIVE_PROBE {\"version\":1");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"detail_abs\":",detail<0?0ULL-(uint64_t)detail:(uint64_t)detail);
    field(&w,",\"detail_negative\":",detail<0);
#define LNP_FIELD(name) field(&w,",\"" #name "\":",p->name)
    LNP_FIELD(pending);LNP_FIELD(outcome_complete);
    field(&w,",\"outcome_result_abs\":",p->outcome_result<0?0ULL-(uint64_t)p->outcome_result:(uint64_t)p->outcome_result);
    field(&w,",\"outcome_result_negative\":",p->outcome_result<0);
    LNP_FIELD(lookups);LNP_FIELD(current_declines);LNP_FIELD(negative_hits);
    LNP_FIELD(policy_checks);LNP_FIELD(policy_blocked);LNP_FIELD(chosen);LNP_FIELD(refaults);
    LNP_FIELD(next_nx);LNP_FIELD(admitted);LNP_FIELD(refused);LNP_FIELD(errors);
#undef LNP_FIELD
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
