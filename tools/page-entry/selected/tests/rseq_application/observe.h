#ifndef LI2_APPLICATION_OBSERVER_H
#define LI2_APPLICATION_OBSERVER_H
#include "rseq_guard.h"
#include "tf_chain.h"
void application_dispatch_frame(const ucontext_t *);
void application_terminal(unsigned,unsigned,long,unsigned,unsigned,const struct li2_tf_chain *);
#endif
