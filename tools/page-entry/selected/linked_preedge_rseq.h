#ifndef LI2_LINKED_PREEDGE_RSEQ_H
#define LI2_LINKED_PREEDGE_RSEQ_H
#include "linked_preedge_plan.h"
#include <sys/ucontext.h>
/* Cold proof of EMITTED heads only. Each head retains the unchanged actual
   static-NONE decoder and register-dependent only_none proof. The original
   PAGE_CUT instruction is not emitted, executed or included in this authority.
   Warm entries retain the existing current-frame/session/word live API. */
int li2_rseq_check_preedge_cold(const struct li2_preedge_plan *,const ucontext_t *);
#endif
