#ifndef LI2_READONLY_QUERY_H
#define LI2_READONLY_QUERY_H
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>

/* Exact kernel write extents for three read-only query forms. These facts do
   not authorize a raw issue: the dispatcher still runs its shared guards and
   the registered-rseq owner checks every span against its pinned area. NULL
   outputs are passed unchanged to the kernel, including an arch_prctl EFAULT.
   No signal-mask setter, xstate permission request or getcpu cache is admitted. */
struct li2_readonly_query {
    unsigned count;
    struct { uintptr_t address; size_t bytes; } write[2];
};
static inline int li2_readonly_query(long number,const long args[6],
                                    struct li2_readonly_query *out) {
    if(!args)return 0;
    struct li2_readonly_query q={0};
    if(number==SYS_arch_prctl && (args[0]==0x1021 || args[0]==0x1022)) {
        /* ARCH_GET_XCOMP_SUPP / ARCH_GET_XCOMP_PERM: one unsigned long. */
        q.count=1;q.write[0].address=(uintptr_t)args[1];q.write[0].bytes=8;
    } else if(number==SYS_rt_sigprocmask && !args[1] && args[3]==8 &&
              args[0]>=0 && args[0]<=2) {
        if(args[2]) {q.count=1;q.write[0].address=(uintptr_t)args[2];q.write[0].bytes=8;}
    } else if(number==SYS_getcpu && !args[2]) {
        for(unsigned i=0;i<2;i++)if(args[i]) {
            q.write[q.count].address=(uintptr_t)args[i];q.write[q.count].bytes=4;++q.count;
        }
    } else return 0;
    if(out)*out=q;
    return 1;
}
#endif
