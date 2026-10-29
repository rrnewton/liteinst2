#ifndef LI2_ENTRY_TIMING_H
#define LI2_ENTRY_TIMING_H
#if LI2_ENTRY_TIMING != 1 || LI2_RUN_TIMING != 1 || LI2_EFFECT_PROVIDER != 1 || \
    LI2_TF_HANDOFF != 1 || LI2_TF_SAME_PAGE_LEASE != 1 || LI2_NATIVE_PAGES != 1
#error "entry timing requires the complete effect/TRACE timing composition"
#endif
/* Observation only. No function grants execution, source or continuation authority.
   These hooks read the actual controller owners; there is no scalar completion API. */
void li2_entry_time_initialize(void);
void li2_entry_time_start(uintptr_t);
void li2_entry_time_ingress(int,siginfo_t *,ucontext_t *);
void li2_entry_time_arm(void);
void li2_entry_time_run(void);
void li2_entry_time_step(void);
void li2_entry_time_report(unsigned,unsigned,long);
void li2_entry_time_origins_report(void);
#endif
