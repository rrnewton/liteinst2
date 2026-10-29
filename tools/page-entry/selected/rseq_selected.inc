/* Included by rseq_guard.c only for the separate effect-provider profile. */
#include "rseq_selected.h"
#if LI2_EFFECT_PROVIDER != 1
#error "selected rseq guard requires the explicit effect profile"
#endif
static uint64_t selected_checks;
uint64_t li2_rseq_selected_checks(void) { return selected_checks; }
int li2_rseq_check_selected(const struct li2_decoded *d) {
    if(ready())return (int)state.first_error;
    if(!d || d->abi_version!=1 || d->reserved || d->decode_status!=LI2_VALID ||
       !d->length || d->length>d->available || d->available>15 ||
       d->pc>UINTPTR_MAX-d->available || d->next_pc!=d->pc+d->length ||
       d->step_disposition!=LI2_STEP_SELECTED)
        return bad(LI2_RSEQ_ARGUMENT,20);
    struct li2_decoded actual={0};
    if(li2_decoder_decode(d->pc,d->bytes,d->available,&actual)!=LI2_OK)
        return bad(LI2_RSEQ_FOOTPRINT,20);
    const unsigned char *a=(const void *)d,*b=(const void *)&actual;
    for(size_t i=0;i<sizeof(actual);i++)if(a[i]!=b[i])return bad(LI2_RSEQ_FOOTPRINT,21);
    if(d->kind==LI2_RDRAND || d->kind==LI2_RDSEED || d->kind==LI2_RDPID) {
        if(d->destination>15 || d->destination==4 ||
           (d->width_bits!=16 && d->width_bits!=32 && d->width_bits!=64) ||
           (d->kind==LI2_RDPID && d->width_bits!=64))
            return bad(LI2_RSEQ_UNSUPPORTED,20);
    } else if(d->kind==LI2_CPUID || d->kind==LI2_RDTSC || d->kind==LI2_RDTSCP) {
        /* decoder/src/abi.rs declares the non-register sentinel as 16. */
        if(d->destination!=16 || d->width_bits)return bad(LI2_RSEQ_UNSUPPORTED,21);
    } else return bad(LI2_RSEQ_UNSUPPORTED,22);
    if(state.registered) {
        if(state.registered!=1 || state.held!=1 || state.phase!=LI2_RSEQ_ACTIVE ||
           !state.tls_complete || state.length!=32 || !state.epoch ||
           state.pid<=0 || state.pid!=state.tid || (state.address&31) ||
           state.address>UINTPTR_MAX-32 || state.page!=(state.address&~(RSEQ_PAGE-1)) ||
           !state.data.complete || state.data.error || !state.data.allocation ||
           !state.data.generation || state.data.address!=state.address ||
           state.data.page!=state.page || state.data.pid!=state.pid || state.data.tid!=state.tid)
            return bad(LI2_RSEQ_STATE,20);
    } else if(state.held || state.phase!=LI2_RSEQ_IDLE)return bad(LI2_RSEQ_STATE,21);
    /* The authenticated opcode has no application memory write. The existing
       pin/exclusion invariant is the proof; this actual word observation is
       an additional check, not a substitute for that invariant. No raw call. */
    if(word_zero())return (int)state.first_error;
    if(selected_checks==UINT64_MAX)return bad(LI2_RSEQ_OVERFLOW,20);
    ++selected_checks;return 0;
}
