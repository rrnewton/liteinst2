#include "csv_fields.c"

/* A real normal-ABI parent: retain the record length across the selected child
 * CALL, then pack length and field count in the result. Input acceptance and
 * bounds remain the application's responsibility; this function is not a CSV
 * validator. Emitted code must pass the complete parent/child admission rules.
 */
__attribute__((visibility("default"), noinline))
uint64_t csv_summary(const uint8_t *data, size_t size) {
    volatile size_t saved_size = size;
    uint64_t fields = csv_fields(data, size);
    return ((uint64_t)saved_size << 32) | fields;
}
