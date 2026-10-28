/* Exact production owner sources, plus a fixture-only negative entrypoint.
   No predicate, callback, phase or successful path is replaced. */
#include "step_owner.c"
void li2_chain_test_consume_actual(struct li2_tf_chain *c,int sig,siginfo_t *si,ucontext_t *uc) {
    chain_begin_trace(c,sig,si,uc);
}
