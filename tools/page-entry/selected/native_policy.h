#ifndef LI2_NATIVE_POLICY_H
#define LI2_NATIVE_POLICY_H
#include <stddef.h>
#include <stdint.h>
/* Byte facts only. The owner must authenticate a complete page and every
   logically executable 14-byte halo before using this result. No decoder
   validity, entry point, host CPUID result, or current NX bit is authority. */
enum li2_native_block {
    LI2_NATIVE_BLOCK_SELECTED=1, LI2_NATIVE_BLOCK_STATE=2, LI2_NATIVE_BLOCK_TRANSACTION=4
};
unsigned li2_native_policy(const unsigned char *,size_t);
#endif
