#ifndef LI2_PROVIDER_APP_H
#define LI2_PROVIDER_APP_H
#include <stddef.h>
#include <stdint.h>
#define PA_FP 65536U
#define PA_LIVE 2116U
#define PA_PAGE 4096U
#define PA_STACK 16384U
#define PA_STATE_ROUNDS 3U
#define PA_STRESS_ROUNDS 1536U
#define PA_MAGIC UINT64_C(0x315050415032494c)
#define PA_FLAGS UINT64_C(0xed7)
#define PA_KNOWN UINT64_C(0x2e7)
#define PA_ARCH_GET_XCOMP_SUPP 0x1021
#define PA_ARCH_GET_XCOMP_PERM 0x1022
enum { PA_CPUID, PA_GETPID, PA_RDTSC, PA_KINDS };
/* GPR order is the existing decoder/provider order. Live extended state is
   all 32 ZMM (2048 B), all 8 K (64 B), FCW and FSW (2 B each). It is NOT an
   XSAVE image. Complete kernel UC/FP and native ptrace records are separate. */
struct pa_view {
    unsigned module, kind;
    uint64_t site, next, endpoint, stack, mask, extent;
    const uint64_t *before, *after;
    const unsigned char *before_live, *after_live;
    unsigned char restored[5];
};
struct pa_image {
    uint64_t module, page, end, stack, sites[PA_KINDS], next[PA_KINDS], endpoint;
};
int pa_main_setup(uint64_t, uint64_t);
int pa_dso_setup(uint64_t, uint64_t);
int pa_main_step(unsigned, unsigned, int, uint64_t, const uint32_t[4], struct pa_view *);
int pa_dso_step(unsigned, unsigned, int, uint64_t, const uint32_t[4], struct pa_view *);
void pa_main_image(struct pa_image *);
void pa_dso_image(struct pa_image *);
int pa_main_final(void);
int pa_dso_final(void);
#endif
