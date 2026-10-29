#include <stddef.h>
#include <stdint.h>

/* Count fields in one valid CSV record, including quoted commas and doubled
 * quotes. The caller supplies the complete readable record without a newline.
 * This is a scalar byte scanner; it deliberately does not validate CSV syntax.
 */
__attribute__((visibility("default"), noinline))
uint64_t csv_fields(const uint8_t *data, size_t size) {
    uint64_t commas = 0;
    unsigned quoted = 0;
    size_t i = 0;
    while (i < size) {
        unsigned c = data[i++];
        if (c == '"') {
            if (quoted && i < size && data[i] == '"') {
                ++i;
            } else {
                quoted ^= 1;
            }
        } else if (c == ',' && !quoted) {
            ++commas;
        }
    }
    return commas + 1;
}
