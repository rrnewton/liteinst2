/* Ordinary scalar functions, without patchable entry NOPs or explicit alignment. */
#include <stddef.h>
#include <stdint.h>
#define LEAF __attribute__((noinline, noclone, visibility("protected")))
LEAF uint64_t first_equal(const unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] == '=') return (uint64_t)i;
    return (uint64_t)length;
}
LEAF uint64_t uppercase_count(const unsigned char *bytes, size_t length) {
    uint64_t count = 0;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] >= 'A' && bytes[i] <= 'Z') ++count;
    return count;
}
