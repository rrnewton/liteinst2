#ifndef LI2_LINKED_RSEQ_H
#define LI2_LINKED_RSEQ_H
#include "linked_plan.h"
#include "write_footprint.h"
#include <sys/ucontext.h>
/* New archive feature; no Registers argument. NONE is a static statement for
   the exact actual131 instruction, not a sampled effective-address result. */
uint32_t li2_decoder_link_none(uint64_t,const unsigned char *,size_t,struct li2_write_footprint *);
struct li2_link_rseq_live {
    unsigned attempted,complete,registered;
    int result;
    uintptr_t session;
    uint64_t epoch;
    struct li2_write_registers registers;
};
int li2_rseq_check_link_cold(const struct li2_link_plan *,const ucontext_t *);
/* Requires current generation's actual R/NX payload, full graph/static NONE
   proof and current held source/ref. The lifecycle epoch is separately HELD
   or RX only at its respective caller phases; pre-begin live guards retain
   the fresh held fetch. Live state is never cached in the payload. */
int li2_rseq_link_live(const ucontext_t *,struct li2_link_rseq_live *);
#ifdef LI2_LINKED_PREEDGE
#include "linked_preedge_rseq.h"
#endif
#endif
