#include "csv_fields.c"

/* All four exports share the independently checked scalar pointer/length ABI.
 * The application validates and retains complete printable CSV records first.
 * These scanners do not establish input grammar, code identity or native state.
 */
__attribute__((visibility("default"), noinline))
uint64_t leaf_length(const uint8_t *data, size_t size) {
    size_t i = 0;
    while (i < size && data[i] != 0) {
        ++i;
    }
    return i;
}

__attribute__((visibility("default"), noinline))
uint64_t leaf_ascii_digits(const uint8_t *data, size_t size) {
    uint64_t count = 0;
    for (size_t i = 0; i < size; ++i) {
        unsigned c = data[i];
        if (c >= '0' && c <= '9') {
            ++count;
        }
    }
    return count;
}

__attribute__((visibility("default"), noinline))
uint64_t leaf_ascii_spaces(const uint8_t *data, size_t size) {
    uint64_t count = 0;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == ' ') {
            ++count;
        }
    }
    return count;
}
