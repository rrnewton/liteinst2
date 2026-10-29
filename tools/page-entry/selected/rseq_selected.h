#ifndef LI2_RSEQ_SELECTED_H
#define LI2_RSEQ_SELECTED_H
#include "decoder.h"
#include <stdint.h>
/* Register-only selected classes; SYSCALL retains before/after_syscall.
   This does not add an accepted TF footprint or permit an active rseq CS. */
int li2_rseq_check_selected(const struct li2_decoded *);
uint64_t li2_rseq_selected_checks(void);
#endif
