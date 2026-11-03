#ifndef LI2_LOOP_RESIDENT_RX_H
#define LI2_LOOP_RESIDENT_RX_H
#ifdef LI2_LOOP_RESIDENT_RX_ORACLE
#include "loop_resident_rx_oracle.h"
#endif
struct li2_lpr_replay;
struct li2_span_decoded;
struct li2_dd_descriptor;
enum lprx_revoke_reason {
    LPRX_COLD=1,LPRX_DECLINED,LPRX_FETCH,LPRX_RAW,LPRX_NATIVE,
    LPRX_RETURN,LPRX_TERMINAL,LPRX_REASON_COUNT
};
static void lprx_before_unsafe(unsigned);
static void lprx_preentry(int,const siginfo_t *,const ucontext_t *);
static void lprx_handler_end(void);
static void lprx_report(unsigned,unsigned);
static void lprx_terminal(void);
static int lprx_direct_begin(const struct li2_lpr_replay *,
    const struct li2_span_decoded *,const struct li2_dd_descriptor *,unsigned,uint64_t);
static void lprx_direct_armed(void);
static void lprx_direct_closed(void);
static unsigned lprx_branch_phase(void);
struct li2_tf_chain;
struct li2_tf_chain_slot;
static void lprx_transit_prepared(const struct li2_tf_chain *,const struct li2_tf_chain_slot *,
    const struct li2_tf_chain_slot *,const ucontext_t *);
#endif
