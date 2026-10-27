#include <stddef.h>
#include <stdint.h>

/* Normal scalar C symbol: no patchable NOP, alignment, invoke or terminal label.
 * The caller owns a readable immutable [bytes, bytes + length) for each call.
 * An actual compiler's complete body and every RET window must still be admitted.
 */
__attribute__((visibility("default"), noinline))
uint64_t ordinary_checksum(const uint8_t *bytes, size_t length) {
    uint64_t sum = 0;
    for (size_t i = 0; i < length; ++i) {
        sum += (uint64_t)(bytes[i] ^ 0x5aU);
    }
    return sum ^ UINT64_C(0x9e3779b97f4a7c15);
}

/* Separate nonempty-input API: the caller must supply length > 0 and a readable
 * immutable buffer of that length. Keep the empty-capable function above as a
 * real compiler-layout refusal case when its RET is a one-byte basic block.
 * This function adds no patch padding or alignment requirement.
 */
__attribute__((visibility("default"), noinline))
uint64_t ordinary_checksum_nonempty(const uint8_t *bytes, size_t length) {
    uint64_t sum = 0;
    size_t i = 0;
    do {
        sum += (uint64_t)(bytes[i] ^ 0x5aU);
        ++i;
    } while (i < length);
    return sum ^ UINT64_C(0x9e3779b97f4a7c15);
}
