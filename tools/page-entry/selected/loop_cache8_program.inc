/* Terminal observations only. No admission or lifetime path consumes this row. */
#if !defined(LI2_LOOP_CACHE8) || LI2_LOOP_CACHE8 != 1 || \
    !defined(LI2_LOOP_CACHE8_PROGRAM) || LI2_LOOP_CACHE8_PROGRAM != 1 || \
    !defined(LI2_PG_LOOP_CACHE8_PROGRAM_BINDING_VERSION) || \
    LI2_PG_LOOP_CACHE8_PROGRAM_BINDING_VERSION != 1 || defined(LI2_LOOP_CACHE8_OBSERVE)
#error "cache8 program counts require their distinct non-capture source binding"
#endif
_Static_assert(LI2_PTR_SLOTS==8 && LI2_PGD_MEMBERS==8 && LI2_PGD_RECEIPTS==9,
    "literal cache8 program terminal dimensions");
_Static_assert(63U*21U+1600U<=sizeof(((struct writer *)0)->bytes),
    "complete bounded cache8 program terminal");
#ifdef LI2_LOOP_TRANSLATION_ARENA_PROGRAM
#include "loop_translation_arena_program.inc"
#define LC8P_SLOT_AT(n) PTR_SLOT_AT(n)
#else
#define LC8P_SLOT_AT(n) pe.retained[n]
#endif
static void lc8p_report(unsigned status,unsigned code) {
#ifdef LI2_LOOP_TRANSLATION_ARENA_PROGRAM
    lta_program_report(status,code);
    struct writer w={0};text(&w,"LI2_LOOP_CACHE8_COUNTS {\"version\":2");
#else
    struct writer w={0};text(&w,"LI2_LOOP_CACHE8_COUNTS {\"version\":1");
#endif
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"slots\":",LI2_PTR_SLOTS);field(&w,",\"members\":",LI2_PGD_MEMBERS);
    field(&w,",\"receipts\":",LI2_PGD_RECEIPTS);
#define LC8P_VALUE(n) field(&w,",\"" #n "\":",pe.cache8.n)
    LC8P_VALUE(cold_calls);LC8P_VALUE(compact_build_calls);LC8P_VALUE(compact_validate_calls);
    LC8P_VALUE(attach_attempts);LC8P_VALUE(accepted);LC8P_VALUE(source_declines);
#undef LC8P_VALUE
#define LC8P_SLOT(n) \
    field(&w,",\"slot" #n "_generation\":",LC8P_SLOT_AT(n).identity.generation); \
    field(&w,",\"slot" #n "_permit\":",LC8P_SLOT_AT(n).claim.valid); \
    field(&w,",\"slot" #n "_completed_serial\":",LC8P_SLOT_AT(n).last_completed)
    LC8P_SLOT(0);LC8P_SLOT(1);LC8P_SLOT(2);LC8P_SLOT(3);
    LC8P_SLOT(4);LC8P_SLOT(5);LC8P_SLOT(6);LC8P_SLOT(7);
#undef LC8P_SLOT
#define LC8P_COUNT(n) \
    field(&w,",\"bound" #n "\":",pe.cache8.bound_by_count[n]); \
    field(&w,",\"entered" #n "\":",pe.cache8.entered_by_count[n]); \
    field(&w,",\"completed" #n "\":",pe.cache8.completed_by_count[n])
    LC8P_COUNT(0);LC8P_COUNT(1);LC8P_COUNT(2);LC8P_COUNT(3);LC8P_COUNT(4);
    LC8P_COUNT(5);LC8P_COUNT(6);LC8P_COUNT(7);LC8P_COUNT(8);
#undef LC8P_COUNT
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
#undef LC8P_SLOT_AT
