#ifndef PA_SEED_PROBE_RECORD_H
#define PA_SEED_PROBE_RECORD_H
#include <stdint.h>
struct psp_machine { uint64_t h[16];uint32_t cpuid[67][6]; };
struct psp_seed { uint64_t h[8];unsigned char code[8],fp[2][512]; };
struct psp_record { uint64_t h[16];struct psp_machine machine[2];struct psp_seed seed[2]; };
_Static_assert(sizeof(struct psp_machine)==1736,"complete machine descriptor");
_Static_assert(sizeof(struct psp_seed)==1096,"complete two-buffer seed row");
_Static_assert(sizeof(struct psp_record)==5792,"complete seed probe record");
#endif
