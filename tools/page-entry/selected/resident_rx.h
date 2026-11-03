#ifndef LI2_RESIDENT_RX_H
#define LI2_RESIDENT_RX_H
#if !defined(LI2_RESIDENT_RX) || LI2_RESIDENT_RX != 1 || \
    !defined(LI2_RESIDENT_STABLE_GENERATION) || LI2_RESIDENT_STABLE_GENERATION != 1 || \
    !defined(LI2_RESIDENT_SOURCE_LEASE) || LI2_RESIDENT_SOURCE_LEASE != 1 || \
    !defined(LI2_RESIDENT_THREE) || LI2_RESIDENT_THREE != 1
#error "retained RX requires the actual three-region source/content owners"
#endif
#if defined(LI2_RESIDENT_THREE_CAPTURE) && \
    (!defined(LI2_RESIDENT_RX_CAPTURE) || LI2_RESIDENT_RX_CAPTURE != 1)
#error "retained RX never uses an older all-NX completion wire"
#endif
/* Publication lifetime is independent of the existing execution phase/token.
   RETIRED is terminal in this finite profile: no equal-byte/address ABA renews
   it. The old owner_closed/owner_quiet interfaces still mean physical NX. */
enum li2_r3_rx_lifetime {
    LI2_R3_RX_UNISSUED,LI2_R3_RX_RESIDENT,LI2_R3_RX_SUSPENDED,
    LI2_R3_RX_REVOKING,LI2_R3_RX_RETIRED
};
enum li2_r3_rx_operation {
    LI2_R3_RX_PLAN,LI2_R3_RX_COMPACT_BUILD,LI2_R3_RX_COMPACT_VALIDATE,
    LI2_R3_RX_PUBLISH,LI2_R3_RX_CODE_PERMISSION,LI2_R3_RX_PUBLICATION_SYNC,
    LI2_R3_RX_OWNER_PERMISSION,LI2_R3_RX_SOURCE_PERMISSION,LI2_R3_RX_OPERATIONS
};
struct li2_r3_rx_call { uint64_t attempted,succeeded; };
struct li2_r3_rx_progress {
    struct li2_r3_rx_call call[LI2_R3_RX_OPERATIONS];
    uint64_t retained_entries,execution_releases,suspensions,resumptions,retirements;
    uint64_t terminal_attempted,terminal_closed;
};
/* Only observations. The protected RW counters never grant an entry, source
   identity, permission or lifetime. Overflow refuses before an actual call. */
int li2_r3_rx_observe(unsigned,unsigned);
const struct li2_r3_rx_progress *li2_r3_rx_progress(void);
#define LI2_R3_RX_CALL(operation,expression) __extension__ ({ \
    int r3_rx_result__=li2_r3_rx_observe((operation),0); \
    if(!r3_rx_result__) { \
        r3_rx_result__=(int)(expression); \
        if(!r3_rx_result__)r3_rx_result__=li2_r3_rx_observe((operation),1); \
    } \
    r3_rx_result__; \
})
/* Actual source-owner callbacks; no caller-provided preservation flag, close
   count, source generation, context pointer or observed result is accepted. */
int li2_r3_rx_suspend(void);
int li2_r3_rx_resume(void);
int li2_r3_rx_retire(void);
void li2_r3_rx_terminal(void);
int li2_r3_rx_execution_quiet(void);
int li2_r3_rx_execution_closed(const struct li2_r3_token *);
int li2_r3_rseq_release(const struct li2_r3_token *,const ucontext_t *);
#endif
