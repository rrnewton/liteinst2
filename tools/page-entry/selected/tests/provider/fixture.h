#ifndef LI2_PROVIDER_FIXTURE_H
#define LI2_PROVIDER_FIXTURE_H
#include <stddef.h>
#include <stdint.h>
#include "../../provider.h"
#define FP_BYTES 65536
#define UC_BYTES 2048
#define STACK_BYTES 512
#define RECORD_MAGIC UINT64_C(0x315246505332494c)
/* Serialized in this exact order by main; no C structure padding in the file. */
extern uint64_t fixture_input[17],fixture_pre[24],fixture_post[24],fixture_host[8];
extern uint64_t fixture_target,fixture_mask,fixture_enabled;
extern unsigned char fixture_pre_fp[FP_BYTES],fixture_post_fp[FP_BYTES],fixture_host_fp[FP_BYTES];
void fixture_enter(void);
void fixture_post_entry(void);
void fixture_vector_clobber(void);
struct component { uint32_t bit,offset,size,reserved; };
extern struct component fixture_components[8];
int fixture_xstate_prepare(void);
long fixture_raw(long,long,long,long,long,long,long);
_Noreturn void fixture_die(unsigned,unsigned);
void fixture_copy(void *,const void *,size_t);
int fixture_equal(const void *,const void *,size_t);
#endif
